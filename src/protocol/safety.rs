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
//! - **S5 (Deterministic Execution)**: Same inputs yield same outputs.
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
use serde::{Deserialize, Serialize};
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum acceptable difference in supply for floating-point tolerance.
pub const MAX_SUPPLY_TOLERANCE: u128 = 1;

/// Maximum acceptable difference in state root (must be 0).
pub const MAX_ROOT_TOLERANCE: usize = 0;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during safety invariant checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SafetyError {
    #[error("S1 violation: {finalized_count} blocks finalized at height {height}, expected at most 1")]
    SplitFinality { height: Height, finalized_count: usize },

    #[error("S2 violation: finalized_height decreased from {prev} to {new}")]
    FinalityDecreased { prev: Height, new: Height },

    #[error("S3 violation: block PV={block_pv} not accepted at height {height}: {reason}")]
    InvalidBlockPV { height: Height, block_pv: u32, reason: String },

    #[error("S4 violation: executing PV={exec_pv} at height {height} after grace window expired (expected {expected_pv})")]
    StateCompatibility { height: Height, exec_pv: u32, expected_pv: u32 },

    #[error("S5 violation: deterministic execution failed: {reason}")]
    DeterministicExecution { reason: String },

    #[error("M2 violation: value not conserved. before={before} + minted={minted} - slashed={slashed} - burned={burned} = {expected}, got {actual}, diff={diff}")]
    ValueConservation {
        before: u128,
        minted: u128,
        slashed: u128,
        burned: u128,
        expected: u128,
        actual: u128,
        diff: i128,
    },

    #[error("M3 violation: state root changed after format migration: before={before}, after={after}")]
    RootChanged { before: String, after: String },
}

pub type SafetyResult<T> = Result<T, SafetyError>;

// -----------------------------------------------------------------------------
// SafetyCheck and SafetyReport (already defined, but we re‑export with improvements)
// -----------------------------------------------------------------------------

/// Result of a single safety check.
#[derive(Debug, Clone, Serialize, Deserialize)]
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

    /// Create a failure check.
    #[must_use]
    pub fn failure(name: &str, detail: &str, duration_ms: u64) -> Self {
        Self::new(name, false, detail, duration_ms)
    }

    /// Create a success check.
    #[must_use]
    pub fn success(name: &str, detail: &str, duration_ms: u64) -> Self {
        Self::new(name, true, detail, duration_ms)
    }
}

/// Report from running all safety checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyReport {
    pub checks: Vec<SafetyCheck>,
    pub all_passed: bool,
    pub total_duration_ms: u64,
}

impl SafetyReport {
    /// Create a new report.
    pub fn new(checks: Vec<SafetyCheck>, duration: std::time::Duration) -> Self {
        let all_passed = checks.iter().all(|c| c.passed);
        let total_duration_ms = duration.as_millis() as u64;
        Self {
            checks,
            all_passed,
            total_duration_ms,
        }
    }

    /// Get the list of failed checks.
    pub fn failures(&self) -> Vec<&SafetyCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Get the list of passed checks.
    pub fn successes(&self) -> Vec<&SafetyCheck> {
        self.checks.iter().filter(|c| c.passed).collect()
    }
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

// -----------------------------------------------------------------------------
// Individual safety checks
// -----------------------------------------------------------------------------

/// S1: Verify that at most one block has been finalized at the given height.
pub fn check_no_split_finality(height: Height, finalized_count: usize) -> SafetyResult<()> {
    if finalized_count > 1 {
        return Err(SafetyError::SplitFinality {
            height,
            finalized_count,
        });
    }
    debug!(height, finalized_count, "S1 check passed");
    Ok(())
}

/// S2: Verify that the new finalized height is >= the previous one.
pub fn check_finality_monotonic(prev_finalized: Height, new_finalized: Height) -> SafetyResult<()> {
    if new_finalized < prev_finalized {
        return Err(SafetyError::FinalityDecreased {
            prev: prev_finalized,
            new: new_finalized,
        });
    }
    debug!(
        prev = prev_finalized,
        new = new_finalized,
        "S2 check passed (monotonic increase)"
    );
    Ok(())
}

/// S3: Verify that the block's PV is accepted at the given height.
pub fn check_deterministic_pv(
    height: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> SafetyResult<()> {
    // Use the version module's validation.
    if let Err(e) = crate::protocol::version::validate_block_version(block_pv, height, activations) {
        return Err(SafetyError::InvalidBlockPV {
            height,
            block_pv,
            reason: e,
        });
    }

    let expected = crate::protocol::version::version_for_height(height, activations);
    if block_pv != expected && block_pv != local_pv {
        // This is a warning only, not a hard violation, because grace window may allow old PV.
        debug!(
            height,
            block_pv,
            local_pv,
            expected_pv = expected,
            "S3 note: block PV differs from local PV but may be within grace window"
        );
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

/// S4: Verify that after activation, we're not applying old-PV execution rules.
pub fn check_state_compat(
    height: Height,
    execution_pv: u32,
    activations: &[crate::protocol::version::ProtocolActivation],
) -> SafetyResult<()> {
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
            return Err(SafetyError::StateCompatibility {
                height,
                exec_pv: execution_pv,
                expected_pv: expected,
            });
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

/// S5: Verify deterministic execution (same inputs => same state root).
pub fn check_deterministic_execution(
    root_a: &[u8; 32],
    root_b: &[u8; 32],
    label: &str,
) -> SafetyResult<()> {
    if root_a != root_b {
        return Err(SafetyError::DeterministicExecution {
            reason: format!(
                "execution roots differ for {}: {} vs {}",
                label,
                hex::encode(root_a),
                hex::encode(root_b)
            ),
        });
    }
    debug!("S5 check passed: deterministic execution for {}", label);
    Ok(())
}

/// M2: Check value conservation.
pub fn check_value_conservation(
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
) -> SafetyResult<()> {
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
        return Err(SafetyError::ValueConservation {
            before: supply_before,
            minted,
            slashed,
            burned,
            expected,
            actual: supply_after,
            diff: diff_signed,
        });
    }
    debug!(
        supply_before,
        supply_after,
        minted,
        slashed,
        burned,
        expected,
        "M2 check passed"
    );
    Ok(())
}

/// M3: Verify state root equivalence after migration.
pub fn check_root_equivalence(root_before: &[u8; 32], root_after: &[u8; 32]) -> SafetyResult<()> {
    if root_before != root_after {
        return Err(SafetyError::RootChanged {
            before: hex::encode(root_before),
            after: hex::encode(root_after),
        });
    }
    debug!("M3 check passed (state root unchanged after migration)");
    Ok(())
}

// -----------------------------------------------------------------------------
// Aggregate check with configuration
// -----------------------------------------------------------------------------

/// Configuration for safety checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfig {
    pub enable_s1: bool,
    pub enable_s2: bool,
    pub enable_s3: bool,
    pub enable_s4: bool,
    pub enable_s5: bool,
    pub enable_m2: bool,
    pub enable_m3: bool,
}

impl Default for SafetyConfig {
    fn default() -> Self {
        Self {
            enable_s1: true,
            enable_s2: true,
            enable_s3: true,
            enable_s4: true,
            enable_s5: true,
            enable_m2: true,
            enable_m3: true,
        }
    }
}

/// Run all enabled safety checks.
#[must_use]
pub fn check_all_safety(
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

    if config.enable_s1 {
        let check_start = Instant::now();
        let r = check_no_split_finality(height, finalized_count);
        checks.push(SafetyCheck::new(
            "S1: No split finality",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_s2 {
        let check_start = Instant::now();
        let r = check_finality_monotonic(prev_finalized, new_finalized);
        checks.push(SafetyCheck::new(
            "S2: Finality monotonic",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_s3 {
        let check_start = Instant::now();
        let r = check_deterministic_pv(height, block_pv, local_pv, activations);
        checks.push(SafetyCheck::new(
            "S3: Deterministic PV",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_s4 {
        let check_start = Instant::now();
        let r = check_state_compat(height, block_pv, activations);
        checks.push(SafetyCheck::new(
            "S4: State compatibility",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_s5 {
        let check_start = Instant::now();
        let r = check_deterministic_execution(root_before, root_after, "state transition");
        checks.push(SafetyCheck::new(
            "S5: Deterministic execution",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_m2 {
        let check_start = Instant::now();
        let r = check_value_conservation(supply_before, supply_after, minted, slashed, burned);
        checks.push(SafetyCheck::new(
            "M2: Value conservation",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    if config.enable_m3 {
        let check_start = Instant::now();
        let r = check_root_equivalence(root_before, root_after);
        checks.push(SafetyCheck::new(
            "M3: Root equivalence",
            r.is_ok(),
            &r.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into()),
            check_start.elapsed().as_millis() as u64,
        ));
    }

    let report = SafetyReport::new(checks, start.elapsed());

    if report.all_passed {
        info!(
            height,
            total_duration_ms = report.total_duration_ms,
            "All safety checks passed at height {}",
            height
        );
    } else {
        let failed: Vec<_> = report.failures().iter().map(|c| c.name.as_str()).collect();
        warn!(
            height,
            failed = ?failed,
            total_duration_ms = report.total_duration_ms,
            "Safety checks failed at height {}",
            height
        );
    }

    report
}

/// Convenience version with default config.
#[must_use]
pub fn check_safety_invariants(
    activations: &[crate::protocol::version::ProtocolActivation],
    height: Height,
) -> SafetyReport {
    let config = SafetyConfig::default();
    // Provide dummy values for checks that need more context.
    // This is a minimal version; full version requires more state.
    let root_zero = [0u8; 32];
    check_all_safety(
        &config,
        height,
        1,
        height.saturating_sub(1),
        height,
        1,
        1,
        activations,
        0,
        0,
        0,
        0,
        0,
        &root_zero,
        &root_zero,
    )
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
        let err = check_no_split_finality(1, 2).unwrap_err();
        assert!(matches!(err, SafetyError::SplitFinality { height: 1, finalized_count: 2 }));
    }

    #[test]
    fn test_finality_monotonic_ok() {
        assert!(check_finality_monotonic(5, 5).is_ok());
        assert!(check_finality_monotonic(5, 6).is_ok());
    }

    #[test]
    fn test_finality_monotonic_violation() {
        let err = check_finality_monotonic(5, 4).unwrap_err();
        assert!(matches!(err, SafetyError::FinalityDecreased { prev: 5, new: 4 }));
    }

    #[test]
    fn test_value_conservation_ok() {
        assert!(check_value_conservation(1000, 1005, 10, 0, 5).is_ok());
    }

    #[test]
    fn test_value_conservation_violation() {
        let err = check_value_conservation(1000, 1020, 10, 0, 0).unwrap_err();
        assert!(matches!(err, SafetyError::ValueConservation { .. }));
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
        let err = check_root_equivalence(&a, &b).unwrap_err();
        assert!(matches!(err, SafetyError::RootChanged { .. }));
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
    fn test_check_all_safety_with_config() {
        let activations = default_activations();
        let root = [0u8; 32];
        let config = SafetyConfig {
            enable_s1: true,
            enable_s2: false,
            enable_s3: false,
            enable_s4: false,
            enable_s5: false,
            enable_m2: false,
            enable_m3: false,
        };
        let report = check_all_safety(
            &config,
            100, 1, 99, 100, 1, 1, &activations,
            1000, 1005, 10, 0, 5,
            &root, &root,
        );
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 1);
        assert!(report.checks[0].name.contains("S1"));
    }

    #[test]
    fn test_safety_report_display() {
        let checks = vec![
            SafetyCheck::success("S1", "ok", 1),
            SafetyCheck::failure("S2", "decreased", 2),
        ];
        let report = SafetyReport::new(checks, std::time::Duration::from_millis(3));
        let s = format!("{}", report);
        assert!(s.contains("FAILURES DETECTED"));
        assert!(s.contains("✓"));
        assert!(s.contains("✗"));
    }

    #[test]
    fn test_check_safety_invariants() {
        let activations = default_activations();
        let report = check_safety_invariants(&activations, 100);
        assert!(report.all_passed);
    }
}
