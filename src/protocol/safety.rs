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
use std::time::Instant;
use tracing::{debug, info, warn, error};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum acceptable difference in supply for floating-point tolerance.
pub const MAX_SUPPLY_TOLERANCE: u128 = 1;

/// Maximum acceptable difference in state root (must be 0).
pub const MAX_ROOT_TOLERANCE: usize = 0;

// -----------------------------------------------------------------------------
// S1: No split finality
// -----------------------------------------------------------------------------

/// Verify that at most one block has been finalized at the given height.
///
/// # Arguments
/// * `height` – The block height to check.
/// * `finalized_count` – Number of distinct block IDs finalized for this height.
///
/// # Returns
/// `Ok(())` if `finalized_count <= 1`, `Err` otherwise.
#[must_use]
pub fn check_no_split_finality(height: Height, finalized_count: usize) -> Result<(), String> {
    if finalized_count > 1 {
        let err = format!(
            "SAFETY VIOLATION S1: {} blocks finalized at height {}; expected at most 1",
            finalized_count, height
        );
        error!("{}", err);
        return Err(err);
    }
    debug!(height, finalized_count, "S1 check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// S2: Finality monotonic
// -----------------------------------------------------------------------------

/// Verify that the new finalized height is >= the previous one.
///
/// # Arguments
/// * `prev_finalized` – Previously finalized height.
/// * `new_finalized` – Newly finalized height.
///
/// # Returns
/// `Ok(())` if `new_finalized >= prev_finalized`, `Err` otherwise.
#[must_use]
pub fn check_finality_monotonic(
    prev_finalized: Height,
    new_finalized: Height,
) -> Result<(), String> {
    if new_finalized < prev_finalized {
        let err = format!(
            "SAFETY VIOLATION S2: finalized_height decreased from {} to {}",
            prev_finalized, new_finalized
        );
        error!("{}", err);
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
///
/// # Arguments
/// * `height` – Block height.
/// * `block_pv` – Protocol version from the block header.
/// * `local_pv` – Locally computed protocol version.
/// * `activations` – Activation schedule.
///
/// # Returns
/// `Ok(())` if the block PV is valid at this height, `Err` otherwise.
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
            "SAFETY VIOLATION S3: block PV={} not accepted at height {}: {}",
            block_pv, height, e
        );
        error!("{}", err);
        return Err(err);
    }

    let expected = crate::protocol::version::version_for_height(height, activations);
    if block_pv != expected && block_pv != local_pv {
        // This is a warning only (not a hard violation) because grace window may allow old PV.
        let msg = format!(
            "SAFETY NOTE S3: block PV={} differs from local PV={} at height {} (expected PV={}) – but may be within grace window",
            block_pv, local_pv, height, expected
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
///
/// # Arguments
/// * `height` – Block height.
/// * `execution_pv` – Protocol version used for execution.
/// * `activations` – Activation schedule.
///
/// # Returns
/// `Ok(())` if the execution PV is valid at this height, `Err` otherwise.
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
                "SAFETY VIOLATION S4: executing with PV={} at height {}, but PV={} is mandatory (grace window expired)",
                execution_pv, height, expected
            );
            error!("{}", err);
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
    debug!(height, execution_pv, expected, "S4 check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// M2: Value conservation
// -----------------------------------------------------------------------------

/// Check that total token supply is conserved across a state transition.
///
/// Invariant: `supply_after == supply_before + minted - slashed - burned`
///
/// # Arguments
/// * `supply_before` – Total supply before block execution.
/// * `supply_after` – Total supply after block execution.
/// * `minted` – Block rewards minted.
/// * `slashed` – Tokens destroyed by slashing.
/// * `burned` – Tokens burned via EIP-1559 base fee.
///
/// # Returns
/// `Ok(())` if supply is conserved within tolerance, `Err` otherwise.
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

    let diff = if supply_after > expected {
        supply_after - expected
    } else {
        expected - supply_after
    };

    if diff > MAX_SUPPLY_TOLERANCE {
        let diff_signed = (supply_after as i128) - (expected as i128);
        let err = format!(
            "SAFETY VIOLATION M2: value not conserved. \
             before={} + minted={} - slashed={} - burned={} = expected {}, got {} (diff={})",
            supply_before, minted, slashed, burned, expected, supply_after, diff_signed
        );
        error!("{}", err);
        return Err(err);
    }
    debug!(
        supply_before,
        supply_after,
        minted,
        slashed,
        burned,
        expected,
        "M2 check passed (value conserved within tolerance)"
    );
    Ok(())
}

// -----------------------------------------------------------------------------
// M3: Root equivalence
// -----------------------------------------------------------------------------

/// Verify that a format-only migration preserves the state root.
///
/// # Arguments
/// * `root_before` – State root before migration.
/// * `root_after` – State root after migration.
///
/// # Returns
/// `Ok(())` if roots are identical, `Err` otherwise.
#[must_use]
pub fn check_root_equivalence(root_before: &[u8; 32], root_after: &[u8; 32]) -> Result<(), String> {
    if root_before != root_after {
        let err = format!(
            "SAFETY VIOLATION M3: state root changed after format migration. \
             before={}, after={}",
            hex::encode(root_before),
            hex::encode(root_after),
        );
        error!("{}", err);
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
    pub duration_ms: u64,
}

impl SafetyCheck {
    /// Create a new safety check result.
    #[must_use]
    pub fn new(name: &str, passed: bool, detail: &str, duration_ms: u64) -> Self {
        Self {
            name: name.to_string(),
            passed,
            detail: detail.to_string(),
            duration_ms,
        }
    }
}

/// Report from running all safety checks.
#[derive(Debug, Clone)]
pub struct SafetyReport {
    pub checks: Vec<SafetyCheck>,
    pub all_passed: bool,
    pub total_duration_ms: u64,
}

impl std::fmt::Display for SafetyReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Safety Report: {} ({} checks, {}ms)",
            if self.all_passed { "ALL PASSED" } else { "FAILURES DETECTED" },
            self.checks.len(),
            self.total_duration_ms
        )?;
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(f, "  [{}] {}: {} [{}ms]", mark, c.name, c.detail, c.duration_ms)?;
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
    let start = Instant::now();
    let mut checks = Vec::new();

    // S1: No split finality
    let check_start = Instant::now();
    let r = check_no_split_finality(height, finalized_count);
    checks.push(SafetyCheck::new(
        "S1: No split finality",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    // S2: Finality monotonic
    let check_start = Instant::now();
    let r = check_finality_monotonic(prev_finalized, new_finalized);
    checks.push(SafetyCheck::new(
        "S2: Finality monotonic",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    // S3: Deterministic PV
    let check_start = Instant::now();
    let r = check_deterministic_pv(height, block_pv, local_pv, activations);
    checks.push(SafetyCheck::new(
        "S3: Deterministic PV",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    // S4: State compatibility
    let check_start = Instant::now();
    let r = check_state_compat(height, block_pv, activations);
    checks.push(SafetyCheck::new(
        "S4: State compatibility",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    // M2: Value conservation
    let check_start = Instant::now();
    let r = check_value_conservation(supply_before, supply_after, minted, slashed, burned);
    checks.push(SafetyCheck::new(
        "M2: Value conservation",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    // M3: Root equivalence
    let check_start = Instant::now();
    let r = check_root_equivalence(root_before, root_after);
    checks.push(SafetyCheck::new(
        "M3: Root equivalence",
        r.is_ok(),
        &r.err().unwrap_or_else(|| "ok".into()),
        check_start.elapsed().as_millis() as u64,
    ));

    let all_passed = checks.iter().all(|c| c.passed);
    let total_duration_ms = start.elapsed().as_millis() as u64;

    if all_passed {
        info!(
            height,
            total_duration_ms,
            "All safety checks passed at height {}",
            height
        );
    } else {
        let failed: Vec<_> = checks.iter().filter(|c| !c.passed).map(|c| c.name.as_str()).collect();
        warn!(
            height,
            failed = ?failed,
            total_duration_ms,
            "Safety checks failed at height {}",
            height
        );
    }

    SafetyReport {
        checks,
        all_passed,
        total_duration_ms,
    }
}

// -----------------------------------------------------------------------------
// Safety check configuration
// -----------------------------------------------------------------------------

/// Configuration for safety checks.
#[derive(Debug, Clone)]
pub struct SafetyConfig {
    /// Whether to enable S1 check (No split finality).
    pub enable_s1: bool,
    /// Whether to enable S2 check (Finality monotonic).
    pub enable_s2: bool,
    /// Whether to enable S3 check (Deterministic PV).
    pub enable_s3: bool,
    /// Whether to enable S4 check (State compatibility).
    pub enable_s4: bool,
    /// Whether to enable M2 check (Value conservation).
    pub enable_m2: bool,
    /// Whether to enable M3 check (Root equivalence).
    pub enable_m3: bool,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            enable_s1: true,
            enable_s2: true,
            enable_s3: true,
            enable_s4: true,
            enable_m2: true,
            enable_m3: true,
        }
    }
}

/// Run safety checks with configuration (allows selective disabling).
#[must_use]
pub fn check_all_safety_with_config(
    config: &SafetyConfig,
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
    let start = Instant::now();
    let mut checks = Vec::new();

    // S1
    if config.enable_s1 {
        let check_start = Instant::now();
        let r = check_no_split_finality(height, finalized_count);
        checks.push(SafetyCheck::new(
            "S1: No split finality",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    // S2
    if config.enable_s2 {
        let check_start = Instant::now();
        let r = check_finality_monotonic(prev_finalized, new_finalized);
        checks.push(SafetyCheck::new(
            "S2: Finality monotonic",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    // S3
    if config.enable_s3 {
        let check_start = Instant::now();
        let r = check_deterministic_pv(height, block_pv, local_pv, activations);
        checks.push(SafetyCheck::new(
            "S3: Deterministic PV",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    // S4
    if config.enable_s4 {
        let check_start = Instant::now();
        let r = check_state_compat(height, block_pv, activations);
        checks.push(SafetyCheck::new(
            "S4: State compatibility",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    // M2
    if config.enable_m2 {
        let check_start = Instant::now();
        let r = check_value_conservation(supply_before, supply_after, minted, slashed, burned);
        checks.push(SafetyCheck::new(
            "M2: Value conservation",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    // M3
    if config.enable_m3 {
        let check_start = Instant::now();
        let r = check_root_equivalence(root_before, root_after);
        checks.push(SafetyCheck::new(
            "M3: Root equivalence",
            r.is_ok(),
            &r.err().unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    let all_passed = checks.iter().all(|c| c.passed);
    let total_duration_ms = start.elapsed().as_millis() as u64;

    SafetyReport {
        checks,
        all_passed,
        total_duration_ms,
    }
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
        assert!(report.all_passed, "report: {}", report);
        assert_eq!(report.checks.len(), 6);
    }

    #[test]
    fn test_check_all_safety_with_config() {
        let activations = default_activations();
        let root = [0u8; 32];
        let config = SafetyConfig {
            enable_s1: true,
            enable_s2: false,
            enable_s3: false,
            enable_s4: false,
            enable_m2: false,
            enable_m3: false,
        };
        let report = check_all_safety_with_config(
            &config, 100, 1, 99, 100, 1, 1, &activations,
            1000, 1005, 10, 0, 5,
            &root, &root,
        );
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 1);
    }
}
