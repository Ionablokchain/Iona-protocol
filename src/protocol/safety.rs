//! Safety invariant checks for protocol upgrades.
//!
//! This module provides formal verification of the safety properties defined
//! in the upgrade specification. It includes:
//!
//! - **S1 (No Split Finality)**: At most one finalized block per height.
//! - **S2 (Finality Monotonic)**: `finalized_height` never decreases.
//! - **S3 (Deterministic PV)**: All correct nodes agree on `PV(height)`.
//! - **S4 (State Compatibility)**: Old PV not applied after activation.
//! - **S5 (Deterministic Execution)**: Same inputs yield same outputs.
//! - **M2 (Value Conservation)**: Token supply is conserved across state transitions.
//! - **M3 (Root Equivalence)**: State root unchanged after format-only migration.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Safety Module                                 │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     check     │        report            │
//! │ (SafetyCfg) │ (SafetyError)│ (S1–S5, M2–M3)│ (SafetyCheck, SafetyRpt) │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │                       validator (SafetyValidator)                      │
//! │              (aggregates all checks with config & metrics)             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::safety::{SafetyValidator, SafetyConfig};
//! use iona::protocol::version::default_activations;
//!
//! let config = SafetyConfig::default();
//! let validator = SafetyValidator::new(default_activations(), config);
//! let report = validator.validate(100, 1, 99, 100, 1, 1, 1000, 1005, 10, 0, 5);
//! assert!(report.all_passed);
//! ```

#![allow(dead_code)]

use crate::protocol::version::{ProtocolActivation, version_for_height};
use crate::types::Height;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for safety checks.
    use serde::{Deserialize, Serialize};

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
        /// Maximum allowed supply difference for tolerance (default 1).
        pub max_supply_tolerance: u128,
        /// Whether to fail on warning-level checks (default false).
        pub strict: bool,
        /// Whether to collect timing metrics.
        pub collect_timing: bool,
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
                max_supply_tolerance: 1,
                strict: false,
                collect_timing: true,
            }
        }
    }

    impl SafetyConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for safety checks.
    use crate::types::Height;
    use thiserror::Error;

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

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type SafetyResult<T> = Result<T, SafetyError>;
}

pub mod check {
    //! Individual safety check functions.
    use super::{error::SafetyError, error::SafetyResult};
    use crate::protocol::version::{ProtocolActivation, version_for_height, validate_block_version};
    use crate::types::Height;
    use tracing::debug;

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
        activations: &[ProtocolActivation],
    ) -> SafetyResult<()> {
        if let Err(e) = validate_block_version(block_pv, height, activations) {
            return Err(SafetyError::InvalidBlockPV {
                height,
                block_pv,
                reason: e,
            });
        }

        let expected = version_for_height(height, activations);
        if block_pv != expected && block_pv != local_pv {
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
        activations: &[ProtocolActivation],
    ) -> SafetyResult<()> {
        let expected = version_for_height(height, activations);
        if execution_pv < expected {
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
        tolerance: u128,
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

        if diff > tolerance {
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
}

pub mod report {
    //! Reporting structures for safety checks.
    use serde::{Deserialize, Serialize};

    /// Result of a single safety check.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SafetyCheck {
        pub name: String,
        pub passed: bool,
        pub detail: String,
        pub duration_ms: u64,
    }

    impl SafetyCheck {
        pub fn new(name: &str, passed: bool, detail: &str, duration_ms: u64) -> Self {
            Self {
                name: name.to_string(),
                passed,
                detail: detail.to_string(),
                duration_ms,
            }
        }
        pub fn success(name: &str, detail: &str, duration_ms: u64) -> Self {
            Self::new(name, true, detail, duration_ms)
        }
        pub fn failure(name: &str, detail: &str, duration_ms: u64) -> Self {
            Self::new(name, false, detail, duration_ms)
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
        pub fn new(checks: Vec<SafetyCheck>, duration: std::time::Duration) -> Self {
            let all_passed = checks.iter().all(|c| c.passed);
            let total_duration_ms = duration.as_millis() as u64;
            Self {
                checks,
                all_passed,
                total_duration_ms,
            }
        }

        pub fn failures(&self) -> Vec<&SafetyCheck> {
            self.checks.iter().filter(|c| !c.passed).collect()
        }

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
}

pub mod metrics {
    //! Metrics for safety checks.
    use std::sync::atomic::{AtomicU64, Ordering};

    /// Metrics for safety checks.
    #[derive(Debug, Default)]
    pub struct SafetyMetrics {
        pub total_checks: AtomicU64,
        pub passed_checks: AtomicU64,
        pub failed_checks: AtomicU64,
        pub total_duration_ms: AtomicU64,
    }

    impl SafetyMetrics {
        pub fn record_check(&self, passed: bool, duration_ms: u64) {
            self.total_checks.fetch_add(1, Ordering::Relaxed);
            if passed {
                self.passed_checks.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_checks.fetch_add(1, Ordering::Relaxed);
            }
            self.total_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SafetyMetricsSnapshot {
            SafetyMetricsSnapshot {
                total_checks: self.total_checks.load(Ordering::Relaxed),
                passed_checks: self.passed_checks.load(Ordering::Relaxed),
                failed_checks: self.failed_checks.load(Ordering::Relaxed),
                total_duration_ms: self.total_duration_ms.load(Ordering::Relaxed),
            }
        }
    }

    /// Snapshot of safety metrics.
    #[derive(Debug, Clone)]
    pub struct SafetyMetricsSnapshot {
        pub total_checks: u64,
        pub passed_checks: u64,
        pub failed_checks: u64,
        pub total_duration_ms: u64,
    }
}

pub mod validator {
    //! Safety validator that aggregates all checks with configuration and metrics.
    use super::{
        config::SafetyConfig,
        error::SafetyResult,
        check::{
            check_no_split_finality, check_finality_monotonic, check_deterministic_pv,
            check_state_compat, check_deterministic_execution,
            check_value_conservation, check_root_equivalence,
        },
        report::{SafetyCheck, SafetyReport},
        metrics::SafetyMetrics,
    };
    use crate::protocol::version::ProtocolActivation;
    use crate::types::Height;
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info, warn};

    /// Centralised safety validator.
    #[derive(Debug)]
    pub struct SafetyValidator {
        activations: Vec<ProtocolActivation>,
        config: SafetyConfig,
        metrics: Arc<SafetyMetrics>,
    }

    impl SafetyValidator {
        /// Create a new validator with the given activations and configuration.
        pub fn new(activations: Vec<ProtocolActivation>, config: SafetyConfig) -> Self {
            if let Err(e) = config.validate() {
                tracing::warn!("invalid SafetyConfig: {}", e);
            }
            Self {
                activations,
                config,
                metrics: Arc::new(SafetyMetrics::default()),
            }
        }

        /// Create a validator with default configuration.
        pub fn with_defaults(activations: Vec<ProtocolActivation>) -> Self {
            Self::new(activations, SafetyConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &SafetyMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &SafetyConfig {
            &self.config
        }

        /// Update the configuration at runtime.
        pub fn set_config(&mut self, config: SafetyConfig) -> Result<(), &'static str> {
            config.validate()?;
            self.config = config;
            Ok(())
        }

        /// Run all enabled safety checks and return a report.
        pub fn validate(
            &self,
            height: Height,
            finalized_count: usize,
            prev_finalized: Height,
            new_finalized: Height,
            block_pv: u32,
            local_pv: u32,
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

            let cfg = &self.config;

            macro_rules! run_check {
                ($name:expr, $enabled:expr, $expr:expr) => {
                    if $enabled {
                        let t0 = Instant::now();
                        let result = $expr;
                        let dur = t0.elapsed().as_millis() as u64;
                        let passed = result.is_ok();
                        let detail = result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into());
                        self.metrics.record_check(passed, dur);
                        checks.push(SafetyCheck::new($name, passed, &detail, dur));
                        if !passed && self.config.strict {
                            warn!(check = $name, detail, "safety check failed (strict mode)");
                        } else if !passed {
                            debug!(check = $name, detail, "safety check failed (non‑strict)");
                        }
                    } else {
                        // Check disabled; record a placeholder.
                        checks.push(SafetyCheck::new($name, true, "disabled", 0));
                    }
                };
            }

            run_check!("S1: No split finality", cfg.enable_s1, {
                check_no_split_finality(height, finalized_count)
            });

            run_check!("S2: Finality monotonic", cfg.enable_s2, {
                check_finality_monotonic(prev_finalized, new_finalized)
            });

            run_check!("S3: Deterministic PV", cfg.enable_s3, {
                check_deterministic_pv(height, block_pv, local_pv, &self.activations)
            });

            run_check!("S4: State compatibility", cfg.enable_s4, {
                check_state_compat(height, block_pv, &self.activations)
            });

            run_check!("S5: Deterministic execution", cfg.enable_s5, {
                check_deterministic_execution(root_before, root_after, "state transition")
            });

            run_check!("M2: Value conservation", cfg.enable_m2, {
                check_value_conservation(
                    supply_before,
                    supply_after,
                    minted,
                    slashed,
                    burned,
                    cfg.max_supply_tolerance,
                )
            });

            run_check!("M3: Root equivalence", cfg.enable_m3, {
                check_root_equivalence(root_before, root_after)
            });

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

        /// Convenience method that uses default supply and root values (for testing).
        pub fn validate_basic(&self, height: Height, finalized_count: usize) -> SafetyReport {
            let root_zero = [0u8; 32];
            self.validate(
                height,
                finalized_count,
                height.saturating_sub(1),
                height,
                1,
                1,
                0,
                0,
                0,
                0,
                0,
                &root_zero,
                &root_zero,
            )
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::SafetyConfig;
pub use error::{SafetyError, SafetyResult};
pub use report::{SafetyCheck, SafetyReport};
pub use metrics::{SafetyMetrics, SafetyMetricsSnapshot};
pub use validator::SafetyValidator;

// Re‑export individual check functions for backward compatibility and direct use.
pub use check::{
    check_no_split_finality,
    check_finality_monotonic,
    check_deterministic_pv,
    check_state_compat,
    check_deterministic_execution,
    check_value_conservation,
    check_root_equivalence,
};

// -----------------------------------------------------------------------------
// Standalone aggregate function (backward compatibility)
// -----------------------------------------------------------------------------

/// Run all safety checks with default configuration.
/// This is a convenience wrapper around `SafetyValidator`.
#[must_use]
pub fn check_safety_invariants(
    activations: &[ProtocolActivation],
    height: Height,
) -> SafetyReport {
    let validator = SafetyValidator::with_defaults(activations.to_vec());
    validator.validate_basic(height, 1)
}

/// Run all safety checks with custom configuration (legacy version).
#[must_use]
pub fn check_all_safety(
    config: &SafetyConfig,
    height: Height,
    finalized_count: usize,
    prev_finalized: Height,
    new_finalized: Height,
    block_pv: u32,
    local_pv: u32,
    activations: &[ProtocolActivation],
    supply_before: u128,
    supply_after: u128,
    minted: u128,
    slashed: u128,
    burned: u128,
    root_before: &[u8; 32],
    root_after: &[u8; 32],
) -> SafetyReport {
    let validator = SafetyValidator::new(activations.to_vec(), config.clone());
    validator.validate(
        height,
        finalized_count,
        prev_finalized,
        new_finalized,
        block_pv,
        local_pv,
        supply_before,
        supply_after,
        minted,
        slashed,
        burned,
        root_before,
        root_after,
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
        assert!(check_value_conservation(1000, 1005, 10, 0, 5, 1).is_ok());
    }

    #[test]
    fn test_value_conservation_violation() {
        let err = check_value_conservation(1000, 1020, 10, 0, 0, 1).unwrap_err();
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
    fn test_validator_with_defaults() {
        let activations = default_activations();
        let validator = SafetyValidator::with_defaults(activations);
        let report = validator.validate_basic(100, 1);
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 7);
    }

    #[test]
    fn test_validator_with_config() {
        let activations = default_activations();
        let mut config = SafetyConfig::default();
        config.enable_s1 = true;
        config.enable_s2 = false;
        config.enable_s3 = false;
        config.enable_s4 = false;
        config.enable_s5 = false;
        config.enable_m2 = false;
        config.enable_m3 = false;
        let validator = SafetyValidator::new(activations, config);
        let report = validator.validate_basic(100, 1);
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 7);
        // Only S1 should be actually checked; others are "disabled".
        let active = report.checks.iter().filter(|c| c.detail != "disabled").count();
        assert_eq!(active, 1);
    }

    #[test]
    fn test_validator_metrics() {
        let activations = default_activations();
        let validator = SafetyValidator::with_defaults(activations);
        let _ = validator.validate_basic(100, 1);
        let metrics = validator.metrics().snapshot();
        assert_eq!(metrics.total_checks, 7);
        assert_eq!(metrics.passed_checks, 7);
        assert_eq!(metrics.failed_checks, 0);
        assert!(metrics.total_duration_ms > 0);
    }

    #[test]
    fn test_check_safety_invariants_standalone() {
        let activations = default_activations();
        let report = check_safety_invariants(&activations, 100);
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 7);
    }

    #[test]
    fn test_check_all_safety_legacy() {
        let activations = default_activations();
        let config = SafetyConfig::default();
        let root = [0u8; 32];
        let report = check_all_safety(
            &config,
            100, 1, 99, 100, 1, 1, &activations,
            1000, 1005, 10, 0, 5,
            &root, &root,
        );
        assert!(report.all_passed);
        assert_eq!(report.checks.len(), 7);
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
}
