//! Safety invariant checks for protocol upgrades.
//!
//! These functions verify the formal safety properties defined in
//! `spec/upgrade/UPGRADE_SPEC.md` section 7.
//!
//! # Invariants checked
//!
//! - **S1 (No Split Finality)**: At most one finalized block per height.
//! - **S2 (Finality Monotonic)**: `finalized_height` never decreases.
//! - **S3 (Deterministic PV)**: All correct nodes agree on `PV(height)`.
//! - **S4 (State Compatibility)**: Old PV not applied after activation.
//! - **M2 (Value Conservation)**: Token supply is conserved across state transitions.
//! - **M3 (Root Equivalence)**: State root unchanged after format-only migration.
//!
//! # Example
//!
//! ```
//! use iona::protocol::safety::{check_no_split_finality, check_finality_monotonic};
//!
//! check_no_split_finality(100, 1).unwrap();
//! check_finality_monotonic(99, 100).unwrap();
//! ```

use crate::types::Height;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// S1: No split finality
// -----------------------------------------------------------------------------

/// Verify that at most one block has been finalized at the given height.
///
/// `finalized_count` is the number of distinct block IDs that have been finalized
/// for this height (should be 0 or 1).
#[must_use]
pub fn check_no_split_finality(height: Height, finalized_count: usize) -> Result<(), String> {
    if finalized_count > 1 {
        let err = format!(
            "SAFETY VIOLATION S1: {finalized_count} blocks finalized at height {height}; \
             expected at most 1"
        );
        warn!("{}", err);
        return Err(err);
    }
    debug!(height, "S1 check passed (finalized_count={finalized_count})");
    Ok(())
}

// -----------------------------------------------------------------------------
// S2: Finality monotonic
// -----------------------------------------------------------------------------

/// Verify that the new finalized height is >= the previous one.
#[must_use]
pub fn check_finality_monotonic(
    prev_finalized: Height,
    new_finalized: Height,
) -> Result<(), String> {
    if new_finalized < prev_finalized {
        let err = format!(
            "SAFETY VIOLATION S2: finalized_height decreased from {prev_finalized} to {new_finalized}"
        );
        warn!("{}", err);
        return Err(err);
    }
    debug!(
        prev = prev_finalized,
        new = new_finalized,
        "S2 check passed (monotonic increase)"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// S3: Deterministic PV
// -----------------------------------------------------------------------------

/// Verify that the locally computed PV matches the block's PV.
///
/// This check ensures that all correct nodes agree on which protocol version
/// applies at a given height.
#[must_use]
pub fn check_deterministic_pv(
    height: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> Result<(), String> {
    // The block's PV must be compatible with what we compute locally for this height,
    // taking into account the grace window.
    if let Err(e) = crate::protocol::version::validate_block_version(block_pv, height, activations) {
        let err = format!(
            "SAFETY VIOLATION S3: block PV={block_pv} not accepted at height {height}: {e}"
        );
        warn!("{}", err);
        return Err(err);
    }

    let expected = crate::protocol::version::version_for_height(height, activations);
    if block_pv != expected && block_pv != local_pv {
        // This is a warning only (not a hard violation) because grace window may allow old PV.
        let msg = format!(
            "SAFETY NOTE S3: block PV={block_pv} differs from local PV={local_pv} \
             at height {height} (expected PV={expected}) – but may be within grace window"
        );
        debug!("{}", msg);
    }
    debug!(
        height,
        block_pv,
        local_pv,
        expected_pv = expected,
        "S3 check passed (PV compatibility verified)"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// S4: State compatibility
// -----------------------------------------------------------------------------

/// Verify that after activation, we're not applying old-PV execution rules.
#[must_use]
pub fn check_state_compat(
    height: Height,
    execution_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> Result<(), String> {
    let expected = crate::protocol::version::version_for_height(height, activations);
    if execution_pv < expected {
        // Check grace window
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            let err = format!(
                "SAFETY VIOLATION S4: executing with PV={execution_pv} at height {height}, \
                 but PV={expected} is mandatory (grace window expired)"
            );
            warn!("{}", err);
            return Err(err);
        } else {
            debug!(
                height,
                execution_pv,
                expected_pv = expected,
                "grace window active, old PV allowed"
            );
        }
    }
    debug!(height, execution_pv, "S4 check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// M2: Value conservation
// -----------------------------------------------------------------------------

/// Check that total token supply is conserved across a state transition.
///
/// `supply_before` = sum(balances) + sum(staked) before block execution.
/// `supply_after`  = sum(balances) + sum(staked) after block execution.
/// `minted`        = block rewards minted (epoch boundary).
/// `slashed`       = tokens destroyed by slashing.
/// `burned`        = tokens burned via EIP-1559 base fee.
///
/// Invariant: `supply_after == supply_before + minted - slashed - burned`
#[must_use]
pub fn check_value_conservation(
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
) -> Result<(), String> {
    let expected = supply_before
        .saturating_add(minted)
        .saturating_sub(slashed)
        .saturating_sub(burned);
    if supply_after != expected {
        let diff = (supply_after as i128) - (expected as i128);
        let err = format!(
            "SAFETY VIOLATION M2: value not conserved. \
             before={supply_before} + minted={minted} - slashed={slashed} - burned={burned} \
             = expected {expected}, got {supply_after} (diff={diff})"
        );
        warn!("{}", err);
        return Err(err);
    }
    debug!(
        supply_before,
        supply_after,
        minted,
        slashed,
        burned,
        "M2 check passed (value conserved)"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// M3: Root equivalence
// -----------------------------------------------------------------------------

/// Verify that a format-only migration preserves the state root.
///
/// `root_before` and `root_after` are the Merkle state roots computed
/// before and after the migration.
#[must_use]
pub fn check_root_equivalence(root_before: &[u8; 32], root_after: &[u8; 32]) -> Result<(), String> {
    if root_before != root_after {
        let err = format!(
            "SAFETY VIOLATION M3: state root changed after format migration. \
             before={}, after={}",
            hex::encode(root_before),
            hex::encode(root_after),
        );
        warn!("{}", err);
        return Err(err);
    }
    debug!("M3 check passed (state root unchanged after migration)");
    Ok(())
}

// -----------------------------------------------------------------------------
// Aggregate check (optional)
// -----------------------------------------------------------------------------

/// Result of a single safety check.
#[derive(Debug, Clone)]
pub struct SafetyCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Report from running all safety checks.
#[derive(Debug, Clone)]
pub struct SafetyReport {
    pub checks: Vec<SafetyCheck>,
    pub all_passed: bool,
}

impl std::fmt::Display for SafetyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Safety Report: {}",
            if self.all_passed { "ALL PASSED" } else { "FAILURES DETECTED" }
        )?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {}", c.name, c.detail)?;
        }
        Ok(())
    }
}

/// Run all safety checks that are possible with given data.
/// This is a convenience function that aggregates logs and returns a report.
#[must_use]
pub fn check_all_safety(
    height: Height,
    finalized_count: usize,
    prev_finalized: Height,
    new_finalized: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
    root_before: &[u8; 32],
    root_after: &[u8; 32],
) -> SafetyReport {
    let mut checks = Vec::new();

    // S1
    let r = check_no_split_finality(height, finalized_count);
    checks.push(SafetyCheck {
        name: "S1: No split finality".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    // S2
    let r = check_finality_monotonic(prev_finalized, new_finalized);
    checks.push(SafetyCheck {
        name: "S2: Finality monotonic".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    // S3
    let r = check_deterministic_pv(height, block_pv, local_pv, activations);
    checks.push(SafetyCheck {
        name: "S3: Deterministic PV".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    // S4
    let r = check_state_compat(height, block_pv, activations);
    checks.push(SafetyCheck {
        name: "S4: State compatibility".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    // M2
    let r = check_value_conservation(supply_before, supply_after, minted, slashed, burned);
    checks.push(SafetyCheck {
        name: "M2: Value conservation".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    // M3
    let r = check_root_equivalence(root_before, root_after);
    checks.push(SafetyCheck {
        name: "M3: Root equivalence".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| "ok".into()),
    });

    let all_passed = checks.iter().all(|c| c.passed);
    if all_passed {
        info!("All safety checks passed at height {}", height);
    } else {
        warn!(height, "Safety checks failed");
    }

    SafetyReport { checks, all_passed }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::default_activations;

    #[test]
    fn test_no_split_finality_ok() {
        assert!(check_no_split_finality(1, 0).is_ok());
        assert!(check_no_split_finality(1, 1).is_ok());
    }

    #[test]
    fn test_no_split_finality_violation() {
        assert!(check_no_split_finality(1, 2).is_err());
    }

    #[test]
    fn test_finality_monotonic_ok() {
        assert!(check_finality_monotonic(5, 5).is_ok());
        assert!(check_finality_monotonic(5, 6).is_ok());
    }

    #[test]
    fn test_finality_monotonic_violation() {
        assert!(check_finality_monotonic(5, 4).is_err());
    }

    #[test]
    fn test_value_conservation_ok() {
        assert!(check_value_conservation(1000, 1005, 10, 0, 5).is_ok());
    }

    #[test]
    fn test_value_conservation_violation() {
        assert!(check_value_conservation(1000, 1020, 10, 0, 0).is_err());
    }

    #[test]
    fn test_root_equivalence_ok() {
        let root = [42u8; 32];
        assert!(check_root_equivalence(&root, &root).is_ok());
    }

    #[test]
    fn test_root_equivalence_violation() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(check_root_equivalence(&a, &b).is_err());
    }

    #[test]
    fn test_state_compat_ok() {
        let activations = default_activations();
        assert!(check_state_compat(100, 1, &activations).is_ok());
    }

    #[test]
    fn test_deterministic_pv_ok() {
        let activations = default_activations();
        assert!(check_deterministic_pv(100, 1, 1, &activations).is_ok());
    }

    #[test]
    fn test_check_all_safety() {
        let activations = default_activations();
        let root = [0u8; 32];
        let report = check_all_safety(
            100, 1, 99, 100, 1, 1, &activations,
            1000, 1005, 10, 0, 5,
            &root, &root,
        );
        assert!(report.all_passed, "report: {report}");
        assert_eq!(report.checks.len(), 6);
    }
}
