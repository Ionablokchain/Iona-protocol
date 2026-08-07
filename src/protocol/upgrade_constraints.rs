//! Upgrade compatibility constraints.
//!
//! Defines and enforces the rules that govern when and how upgrades can occur.
//! These constraints prevent unsafe upgrade paths and ensure that the network
//! can always reach consensus during transitions.
//!
//! # Constraint Categories
//!
//! | ID    | Name                     | Description                                      |
//! |-------|--------------------------|--------------------------------------------------|
//! | UC-1  | PV gap limit             | Cannot skip more than 1 major PV at a time       |
//! | UC-2  | SV forward-only          | Schema version must only increase                |
//! | UC-3  | Activation height future | Activation height must be in the future           |
//! | UC-4  | Grace window minimum     | Grace window must be >= MIN_GRACE_BLOCKS          |
//! | UC-5  | Binary supports target   | Binary must support the target PV                |
//! | UC-6  | Migration path exists    | SV migration path must be contiguous              |
//! | UC-7  | No concurrent upgrades   | Only one PV upgrade active at a time              |
//! | UC-8  | Quorum before activation | Sufficient nodes must be upgraded before activation|
//! | UC-9  | Strictly increasing heights | Activation heights must be strictly increasing |
//! | UC-10 | Grace windows non‑overlap| Grace windows must not overlap                    |
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                    Upgrade Constraints Module                          │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │   constraint  │        report            │
//! │ (ConstraintCfg)│ (ConstraintError)│ (UC-1–UC-10)│ (ConstraintResult, Rpt)│
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │                 validator (ConstraintValidator)                        │
//! │              (aggregates all checks with config & metrics)             │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::upgrade_constraints::{ConstraintValidator, ConstraintConfig};
//!
//! let config = ConstraintConfig::default();
//! let validator = ConstraintValidator::new(activations, current_height, current_sv, config);
//! let report = validator.check_upgrade(2, 5, Some(1000), 100);
//! if !report.can_upgrade {
//!     eprintln!("{}", report);
//! }
//! ```

#![allow(dead_code)]

use crate::protocol::version::{
    ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::storage::CURRENT_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum grace window for any activation (blocks).
pub const MIN_GRACE_BLOCKS: u64 = 100;

/// Maximum PV gap allowed in a single upgrade step.
pub const MAX_PV_GAP: u32 = 1;

/// Maximum grace window allowed.
pub const MAX_GRACE_BLOCKS: u64 = 100_000;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for upgrade constraints.
    use serde::{Deserialize, Serialize};

    /// Configuration for which constraints to enforce.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConstraintConfig {
        pub enable_uc1: bool,
        pub enable_uc2: bool,
        pub enable_uc3: bool,
        pub enable_uc4: bool,
        pub enable_uc5: bool,
        pub enable_uc6: bool,
        pub enable_uc7: bool,
        pub enable_uc8: bool,
        pub enable_uc9: bool,
        pub enable_uc10: bool,
        /// Hard vs soft for each constraint (true = hard).
        pub hard_uc1: bool,
        pub hard_uc2: bool,
        pub hard_uc3: bool,
        pub hard_uc4: bool,
        pub hard_uc5: bool,
        pub hard_uc6: bool,
        pub hard_uc7: bool,
        pub hard_uc8: bool,
        pub hard_uc9: bool,
        pub hard_uc10: bool,
        /// Minimum grace window (overrides global).
        pub min_grace_blocks: u64,
        /// Maximum PV gap.
        pub max_pv_gap: u32,
        /// Whether to collect timing metrics.
        pub collect_timing: bool,
    }

    impl Default for ConstraintConfig {
        fn default() -> Self {
            Self {
                enable_uc1: true,
                enable_uc2: true,
                enable_uc3: true,
                enable_uc4: true,
                enable_uc5: true,
                enable_uc6: true,
                enable_uc7: true,
                enable_uc8: true,
                enable_uc9: true,
                enable_uc10: true,
                hard_uc1: true,
                hard_uc2: true,
                hard_uc3: true,
                hard_uc4: false,
                hard_uc5: true,
                hard_uc6: true,
                hard_uc7: true,
                hard_uc8: false,
                hard_uc9: true,
                hard_uc10: true,
                min_grace_blocks: MIN_GRACE_BLOCKS,
                max_pv_gap: MAX_PV_GAP,
                collect_timing: true,
            }
        }
    }

    impl ConstraintConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.min_grace_blocks == 0 {
                return Err("min_grace_blocks must be > 0");
            }
            if self.max_pv_gap == 0 {
                return Err("max_pv_gap must be > 0");
            }
            Ok(())
        }

        /// Create a config with all hard constraints.
        pub fn all_hard() -> Self {
            let mut cfg = Self::default();
            cfg.hard_uc4 = true;
            cfg.hard_uc8 = true;
            cfg
        }

        /// Create a config with all soft constraints (warnings only).
        pub fn all_soft() -> Self {
            let mut cfg = Self::default();
            cfg.hard_uc1 = false;
            cfg.hard_uc2 = false;
            cfg.hard_uc3 = false;
            cfg.hard_uc4 = false;
            cfg.hard_uc5 = false;
            cfg.hard_uc6 = false;
            cfg.hard_uc7 = false;
            cfg.hard_uc8 = false;
            cfg.hard_uc9 = false;
            cfg.hard_uc10 = false;
            cfg
        }

        /// Create a minimal config (only essential checks).
        pub fn minimal() -> Self {
            Self {
                enable_uc1: true,
                enable_uc2: true,
                enable_uc3: true,
                enable_uc4: false,
                enable_uc5: true,
                enable_uc6: true,
                enable_uc7: true,
                enable_uc8: false,
                enable_uc9: true,
                enable_uc10: true,
                hard_uc1: true,
                hard_uc2: true,
                hard_uc3: true,
                hard_uc4: false,
                hard_uc5: true,
                hard_uc6: true,
                hard_uc7: true,
                hard_uc8: false,
                hard_uc9: true,
                hard_uc10: true,
                min_grace_blocks: MIN_GRACE_BLOCKS,
                max_pv_gap: MAX_PV_GAP,
                collect_timing: true,
            }
        }
    }
}

pub mod error {
    //! Error types for upgrade constraints.
    use super::config::ConstraintConfig;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum ConstraintError {
        #[error("constraint {constraint} failed: {detail}")]
        ConstraintFailed { constraint: String, detail: String },

        #[error("configuration error: {0}")]
        Config(String),

        #[error("activation schedule is empty")]
        EmptySchedule,

        #[error("invalid activation: {0}")]
        InvalidActivation(String),
    }

    pub type ConstraintResult<T> = Result<T, ConstraintError>;
}

pub mod constraint {
    //! Individual constraint checks (UC-1 through UC-10).
    use super::error::{ConstraintError, ConstraintResult};
    use crate::protocol::version::{
        ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    };
    use crate::storage::CURRENT_SCHEMA_VERSION;
    use tracing::debug;

    /// UC-1: PV gap limit.
    pub fn check_pv_gap(target_pv: u32, max_gap: u32) -> ConstraintResult<()> {
        let current = CURRENT_PROTOCOL_VERSION;
        let gap = target_pv.saturating_sub(current);
        if gap > max_gap {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-1".into(),
                detail: format!("PV gap {} exceeds max {}", gap, max_gap),
            });
        }
        debug!("UC-1 passed: gap={} <= {}", gap, max_gap);
        Ok(())
    }

    /// UC-2: SV forward-only.
    pub fn check_sv_forward(target_sv: u32, current_sv: u32) -> ConstraintResult<()> {
        if target_sv < current_sv {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-2".into(),
                detail: format!("SV {} < current SV {}", target_sv, current_sv),
            });
        }
        debug!("UC-2 passed: SV {} -> {}", current_sv, target_sv);
        Ok(())
    }

    /// UC-3: Activation height future.
    pub fn check_activation_future(activation_height: Option<u64>, current_height: u64) -> ConstraintResult<()> {
        if let Some(ah) = activation_height {
            if ah <= current_height {
                return Err(ConstraintError::ConstraintFailed {
                    constraint: "UC-3".into(),
                    detail: format!("activation height {} is not in future (current={})", ah, current_height),
                });
            }
            debug!("UC-3 passed: activation height {} > {}", ah, current_height);
        }
        Ok(())
    }

    /// UC-4: Grace window minimum.
    pub fn check_grace_minimum(grace_blocks: u64, min_grace: u64, target_pv: u32) -> ConstraintResult<()> {
        if target_pv > CURRENT_PROTOCOL_VERSION && grace_blocks < min_grace {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-4".into(),
                detail: format!("grace_blocks {} < min {}", grace_blocks, min_grace),
            });
        }
        debug!("UC-4 passed: grace_blocks {} >= {}", grace_blocks, min_grace);
        Ok(())
    }

    /// UC-5: Binary supports target PV.
    pub fn check_binary_supports(target_pv: u32) -> ConstraintResult<()> {
        if !SUPPORTED_PROTOCOL_VERSIONS.contains(&target_pv) {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-5".into(),
                detail: format!("PV {} not supported by binary", target_pv),
            });
        }
        debug!("UC-5 passed: PV {} supported", target_pv);
        Ok(())
    }

    /// UC-6: Migration path exists.
    pub fn check_migration_path(target_sv: u32, current_sv: u32) -> ConstraintResult<()> {
        let migrations = &crate::storage::migrations::MIGRATIONS;
        let mut covered = current_sv;

        for e in migrations.iter() {
            if e.from_version == covered {
                covered += 1;
            }
        }

        let has_direct = migrations.iter().any(|e| {
            e.from_version == current_sv && e.to_version == target_sv
        });

        let fully_covered = covered >= target_sv || target_sv <= current_sv || has_direct;

        if !fully_covered {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-6".into(),
                detail: format!("migration path from SV {} to {} not found", current_sv, target_sv),
            });
        }
        debug!("UC-6 passed: migration path exists from {} to {}", current_sv, target_sv);
        Ok(())
    }

    /// UC-7: No concurrent upgrades.
    pub fn check_no_concurrent(
        target_pv: u32,
        activations: &[ProtocolActivation],
        current_height: u64,
    ) -> ConstraintResult<()> {
        let in_progress = activations.iter().any(|a| {
            a.activation_height
                .map(|ah| {
                    let end = ah + a.grace_blocks;
                    current_height >= ah && current_height < end && a.protocol_version != target_pv
                })
                .unwrap_or(false)
        });

        if in_progress {
            return Err(ConstraintError::ConstraintFailed {
                constraint: "UC-7".into(),
                detail: "another upgrade is currently in grace window".into(),
            });
        }
        debug!("UC-7 passed: no concurrent upgrades");
        Ok(())
    }

    /// UC-8: Quorum readiness (simplified: local check only).
    pub fn check_quorum_readiness() -> ConstraintResult<()> {
        // In production, this would check actual peer upgrade status.
        // At compile time, we assume the node is ready.
        debug!("UC-8 passed: local binary ready");
        Ok(())
    }

    /// UC-9: Strictly increasing heights.
    pub fn check_strictly_increasing(
        activation_height: Option<u64>,
        activations: &[ProtocolActivation],
    ) -> ConstraintResult<()> {
        if let Some(ah) = activation_height {
            let mut prev_height: Option<u64> = None;
            for a in activations {
                if let Some(h) = a.activation_height {
                    if let Some(prev) = prev_height {
                        if h <= prev {
                            return Err(ConstraintError::ConstraintFailed {
                                constraint: "UC-9".into(),
                                detail: format!("existing heights not strictly increasing: {} <= {}", h, prev),
                            });
                        }
                    }
                    prev_height = Some(h);
                }
            }
            if let Some(prev) = prev_height {
                if ah <= prev {
                    return Err(ConstraintError::ConstraintFailed {
                        constraint: "UC-9".into(),
                        detail: format!("proposed height {} <= previous {}", ah, prev),
                    });
                }
            }
            debug!("UC-9 passed: activation heights strictly increasing");
        }
        Ok(())
    }

    /// UC-10: Grace windows non‑overlap.
    pub fn check_grace_overlap(
        new_activation: Option<u64>,
        new_grace: u64,
        target_pv: u32,
        activations: &[ProtocolActivation],
    ) -> ConstraintResult<()> {
        let mut intervals = Vec::new();
        for a in activations {
            if let Some(h) = a.activation_height {
                intervals.push((h, h + a.grace_blocks, a.protocol_version));
            }
        }

        if let Some(h) = new_activation {
            intervals.push((h, h + new_grace, target_pv));
        }

        intervals.sort_by_key(|(start, _, _)| *start);

        for i in 1..intervals.len() {
            let (prev_start, prev_end, prev_pv) = intervals[i - 1];
            let (curr_start, curr_end, curr_pv) = intervals[i];
            if curr_start < prev_end {
                return Err(ConstraintError::ConstraintFailed {
                    constraint: "UC-10".into(),
                    detail: format!(
                        "grace overlap: PV{} [{},{}] overlaps PV{} [{},{}]",
                        prev_pv, prev_start, prev_end, curr_pv, curr_start, curr_end
                    ),
                });
            }
        }

        debug!("UC-10 passed: no grace window overlap");
        Ok(())
    }
}

pub mod report {
    //! Reports for upgrade constraint checks.
    use serde::{Deserialize, Serialize};
    use std::time::Duration;

    /// Result of a single upgrade constraint check.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConstraintResult {
        pub id: String,
        pub name: String,
        pub passed: bool,
        pub detail: String,
        pub hard: bool,
        pub severity: u8,
    }

    impl ConstraintResult {
        pub fn new(id: &str, name: &str, passed: bool, hard: bool, detail: &str, severity: u8) -> Self {
            Self {
                id: id.to_string(),
                name: name.to_string(),
                passed,
                hard,
                detail: detail.to_string(),
                severity,
            }
        }

        pub fn success(id: &str, name: &str, hard: bool, detail: &str) -> Self {
            Self::new(id, name, true, hard, detail, 0)
        }

        pub fn failure(id: &str, name: &str, hard: bool, detail: &str, severity: u8) -> Self {
            Self::new(id, name, false, hard, detail, severity)
        }
    }

    /// Aggregate report of all upgrade constraint checks.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ConstraintReport {
        pub results: Vec<ConstraintResult>,
        pub can_upgrade: bool,
        pub total_duration_ms: u64,
        pub summary: String,
    }

    impl ConstraintReport {
        pub fn new(results: Vec<ConstraintResult>, duration: Duration) -> Self {
            let can_upgrade = results.iter().filter(|r| r.hard).all(|r| r.passed);
            let summary = if can_upgrade {
                "All hard constraints satisfied".to_string()
            } else {
                let blockers: Vec<_> = results.iter().filter(|r| r.hard && !r.passed).map(|r| r.id.clone()).collect();
                format!("Blocked by constraints: {}", blockers.join(", "))
            };
            Self {
                results,
                can_upgrade,
                total_duration_ms: duration.as_millis() as u64,
                summary,
            }
        }

        pub fn blockers(&self) -> Vec<&ConstraintResult> {
            self.results.iter().filter(|r| r.hard && !r.passed).collect()
        }

        pub fn warnings(&self) -> Vec<&ConstraintResult> {
            self.results.iter().filter(|r| !r.hard && !r.passed).collect()
        }

        pub fn failures(&self) -> Vec<&ConstraintResult> {
            self.results.iter().filter(|r| !r.passed).collect()
        }

        pub fn success_count(&self) -> usize {
            self.results.iter().filter(|r| r.passed).count()
        }
    }

    impl std::fmt::Display for ConstraintReport {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            writeln!(
                f,
                "Upgrade Constraints: {} ({})",
                if self.can_upgrade { "ALLOWED" } else { "BLOCKED" },
                self.summary
            )?;
            for r in &self.results {
                let status = if r.passed {
                    "OK"
                } else if r.hard {
                    "BLOCK"
                } else {
                    "WARN"
                };
                let sev = if r.severity == 2 { "ERR" } else if r.severity == 1 { "WARN" } else { "INFO" };
                writeln!(
                    f,
                    "  [{}] [{}] {}: {} — {}",
                    status, sev, r.id, r.name, r.detail
                )?;
            }
            Ok(())
        }
    }
}

pub mod metrics {
    //! Metrics for upgrade constraints.
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct ConstraintMetrics {
        pub total_checks: AtomicU64,
        pub passed_checks: AtomicU64,
        pub failed_checks: AtomicU64,
        pub total_duration_ms: AtomicU64,
    }

    impl ConstraintMetrics {
        pub fn record_check(&self, passed: bool, duration_ms: u64) {
            self.total_checks.fetch_add(1, Ordering::Relaxed);
            if passed {
                self.passed_checks.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_checks.fetch_add(1, Ordering::Relaxed);
            }
            self.total_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ConstraintMetricsSnapshot {
            ConstraintMetricsSnapshot {
                total_checks: self.total_checks.load(Ordering::Relaxed),
                passed_checks: self.passed_checks.load(Ordering::Relaxed),
                failed_checks: self.failed_checks.load(Ordering::Relaxed),
                total_duration_ms: self.total_duration_ms.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct ConstraintMetricsSnapshot {
        pub total_checks: u64,
        pub passed_checks: u64,
        pub failed_checks: u64,
        pub total_duration_ms: u64,
    }
}

pub mod validator {
    //! Centralised validator for upgrade constraints.
    use super::{
        config::ConstraintConfig,
        constraint::{
            check_pv_gap, check_sv_forward, check_activation_future, check_grace_minimum,
            check_binary_supports, check_migration_path, check_no_concurrent,
            check_quorum_readiness, check_strictly_increasing, check_grace_overlap,
        },
        report::{ConstraintResult, ConstraintReport},
        metrics::ConstraintMetrics,
    };
    use crate::protocol::version::ProtocolActivation;
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info, warn};

    /// Upgrade compatibility constraint checker.
    #[derive(Debug)]
    pub struct ConstraintValidator {
        activations: Vec<ProtocolActivation>,
        current_height: u64,
        current_sv: u32,
        config: ConstraintConfig,
        metrics: Arc<ConstraintMetrics>,
    }

    impl ConstraintValidator {
        /// Create a new validator with default configuration.
        pub fn new(activations: Vec<ProtocolActivation>, current_height: u64, current_sv: u32) -> Self {
            Self::with_config(activations, current_height, current_sv, ConstraintConfig::default())
        }

        /// Create a new validator with custom configuration.
        pub fn with_config(
            activations: Vec<ProtocolActivation>,
            current_height: u64,
            current_sv: u32,
            config: ConstraintConfig,
        ) -> Self {
            if let Err(e) = config.validate() {
                tracing::warn!("invalid ConstraintConfig: {}", e);
            }
            debug!(
                current_height,
                current_sv,
                activations_len = activations.len(),
                "constraint validator created"
            );
            Self {
                activations,
                current_height,
                current_sv,
                config,
                metrics: Arc::new(ConstraintMetrics::default()),
            }
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &ConstraintMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &ConstraintConfig {
            &self.config
        }

        /// Update configuration at runtime.
        pub fn set_config(&mut self, config: ConstraintConfig) -> Result<(), &'static str> {
            config.validate()?;
            self.config = config;
            Ok(())
        }

        /// Check all constraints for a proposed upgrade.
        pub fn check_upgrade(
            &self,
            target_pv: u32,
            target_sv: u32,
            activation_height: Option<u64>,
            grace_blocks: u64,
        ) -> ConstraintReport {
            let start = Instant::now();
            let mut results = Vec::new();

            macro_rules! run_check {
                ($id:expr, $name:expr, $enabled:expr, $hard:expr, $expr:expr) => {
                    if $enabled {
                        let t0 = Instant::now();
                        let result = $expr;
                        let dur = t0.elapsed().as_millis() as u64;
                        let passed = result.is_ok();
                        let detail = result.err().map(|e| e.to_string()).unwrap_or_else(|| "ok".into());
                        self.metrics.record_check(passed, dur);
                        results.push(ConstraintResult::new($id, $name, passed, $hard, &detail, if passed { 0 } else { 2 }));
                        if !passed && $hard {
                            warn!(check = $id, detail, "constraint failed (hard)");
                        } else if !passed && !$hard {
                            debug!(check = $id, detail, "constraint failed (soft)");
                        }
                    } else {
                        results.push(ConstraintResult::new($id, $name, true, false, "disabled", 0));
                    }
                };
            }

            run_check!("UC-1", "PV gap limit", self.config.enable_uc1, self.config.hard_uc1, {
                check_pv_gap(target_pv, self.config.max_pv_gap)
            });

            run_check!("UC-2", "SV forward-only", self.config.enable_uc2, self.config.hard_uc2, {
                check_sv_forward(target_sv, self.current_sv)
            });

            run_check!("UC-3", "Activation height future", self.config.enable_uc3, self.config.hard_uc3, {
                check_activation_future(activation_height, self.current_height)
            });

            run_check!("UC-4", "Grace window minimum", self.config.enable_uc4, self.config.hard_uc4, {
                check_grace_minimum(grace_blocks, self.config.min_grace_blocks, target_pv)
            });

            run_check!("UC-5", "Binary supports target PV", self.config.enable_uc5, self.config.hard_uc5, {
                check_binary_supports(target_pv)
            });

            run_check!("UC-6", "Migration path exists", self.config.enable_uc6, self.config.hard_uc6, {
                check_migration_path(target_sv, self.current_sv)
            });

            run_check!("UC-7", "No concurrent upgrades", self.config.enable_uc7, self.config.hard_uc7, {
                check_no_concurrent(target_pv, &self.activations, self.current_height)
            });

            run_check!("UC-8", "Quorum readiness", self.config.enable_uc8, self.config.hard_uc8, {
                check_quorum_readiness()
            });

            run_check!("UC-9", "Strictly increasing heights", self.config.enable_uc9, self.config.hard_uc9, {
                check_strictly_increasing(activation_height, &self.activations)
            });

            run_check!("UC-10", "Grace windows non‑overlap", self.config.enable_uc10, self.config.hard_uc10, {
                check_grace_overlap(activation_height, grace_blocks, target_pv, &self.activations)
            });

            let report = ConstraintReport::new(results, start.elapsed());

            if report.can_upgrade {
                info!(
                    target_pv,
                    target_sv,
                    activation_height = ?activation_height,
                    "upgrade constraints satisfied"
                );
            } else {
                let blockers = report.blockers();
                let block_ids: Vec<_> = blockers.iter().map(|r| r.id.as_str()).collect();
                warn!(
                    target_pv,
                    target_sv,
                    activation_height = ?activation_height,
                    blockers = ?block_ids,
                    "upgrade constraints failed"
                );
            }

            report
        }

        /// Validate the entire activation schedule against all constraints.
        pub fn validate_schedule(&self) -> ConstraintReport {
            let start = Instant::now();
            let mut results = Vec::new();

            if self.activations.is_empty() {
                results.push(ConstraintResult::failure(
                    "SCHEDULE",
                    "Schedule non‑empty",
                    true,
                    "activation schedule is empty",
                    2,
                ));
                return ConstraintReport::new(results, start.elapsed());
            }

            // Check each activation in the schedule.
            for a in &self.activations {
                // UC-1: PV gap from previous.
                // UC-3: Activation in future.
                // UC-4: Grace minimum.
                // UC-5: Binary support.
                // UC-9: Strictly increasing heights.
                // UC-10: Grace overlap.

                run_check!("UC-1", "PV gap limit", self.config.enable_uc1, self.config.hard_uc1, {
                    check_pv_gap(a.protocol_version, self.config.max_pv_gap)
                });

                run_check!("UC-3", "Activation height future", self.config.enable_uc3, self.config.hard_uc3, {
                    check_activation_future(a.activation_height, self.current_height)
                });

                run_check!("UC-4", "Grace window minimum", self.config.enable_uc4, self.config.hard_uc4, {
                    check_grace_minimum(a.grace_blocks, self.config.min_grace_blocks, a.protocol_version)
                });

                run_check!("UC-5", "Binary supports target PV", self.config.enable_uc5, self.config.hard_uc5, {
                    check_binary_supports(a.protocol_version)
                });
            }

            // UC-9: Strictly increasing heights (aggregate).
            run_check!("UC-9", "Strictly increasing heights", self.config.enable_uc9, self.config.hard_uc9, {
                check_strictly_increasing(None, &self.activations)
            });

            // UC-10: Grace windows non‑overlap (aggregate).
            run_check!("UC-10", "Grace windows non‑overlap", self.config.enable_uc10, self.config.hard_uc10, {
                check_grace_overlap(None, 0, 0, &self.activations)
            });

            // UC-7: No concurrent upgrades (check the schedule itself).
            for a in &self.activations {
                run_check!("UC-7", "No concurrent upgrades", self.config.enable_uc7, self.config.hard_uc7, {
                    check_no_concurrent(a.protocol_version, &self.activations, self.current_height)
                });
            }

            let report = ConstraintReport::new(results, start.elapsed());

            if !report.can_upgrade {
                let blockers = report.blockers();
                warn!(
                    blockers = ?blockers.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(),
                    "schedule validation failed"
                );
            } else {
                info!("schedule validation passed");
            }

            report
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ConstraintConfig;
pub use error::{ConstraintError, ConstraintResult};
pub use report::{ConstraintResult as ConstraintCheckResult, ConstraintReport};
pub use metrics::{ConstraintMetrics, ConstraintMetricsSnapshot};
pub use validator::ConstraintValidator;

// -----------------------------------------------------------------------------
// Convenience function (backward compatibility)
// -----------------------------------------------------------------------------

/// Quick check: can we upgrade to the given PV/SV from current state?
#[must_use]
pub fn can_upgrade(
    target_pv: u32,
    target_sv: u32,
    activation_height: Option<u64>,
    grace_blocks: u64,
    current_height: u64,
    activations: &[ProtocolActivation],
) -> bool {
    let validator = ConstraintValidator::new(activations.to_vec(), current_height, CURRENT_SCHEMA_VERSION);
    validator
        .check_upgrade(target_pv, target_sv, activation_height, grace_blocks)
        .can_upgrade
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::default_activations;

    fn validator(height: u64) -> ConstraintValidator {
        ConstraintValidator::new(default_activations(), height, CURRENT_SCHEMA_VERSION)
    }

    #[test]
    fn test_same_version_upgrade_ok() {
        let v = validator(100);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        assert!(report.can_upgrade, "report: {report}");
    }

    #[test]
    fn test_pv_gap_too_large() {
        let v = validator(100);
        let report = v.check_upgrade(5, CURRENT_SCHEMA_VERSION, Some(200), 1000);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-1"));
    }

    #[test]
    fn test_sv_backward_rejected() {
        let v = validator(100);
        let report = v.check_upgrade(1, 1, None, 0);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-2"));
    }

    #[test]
    fn test_activation_in_past_rejected() {
        let v = validator(500);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(100), 0);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-3"));
    }

    #[test]
    fn test_unsupported_pv_rejected() {
        let v = validator(100);
        let report = v.check_upgrade(99, CURRENT_SCHEMA_VERSION, Some(200), 1000);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-5"));
    }

    #[test]
    fn test_grace_warning_not_blocking() {
        let v = validator(100);
        // PV upgrade with grace < MIN_GRACE_BLOCKS but UC-4 is soft by default.
        let report = v.check_upgrade(2, CURRENT_SCHEMA_VERSION, Some(200), 10);
        assert!(report.can_upgrade);
    }

    #[test]
    fn test_report_display() {
        let v = validator(100);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        let s = format!("{report}");
        assert!(s.contains("Upgrade Constraints"));
    }

    #[test]
    fn test_can_upgrade_convenience() {
        let activations = default_activations();
        assert!(can_upgrade(
            1,
            CURRENT_SCHEMA_VERSION,
            None,
            0,
            100,
            &activations
        ));
    }

    #[test]
    fn test_blockers_and_warnings() {
        let v = validator(100);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        assert!(report.blockers().is_empty());
    }

    #[test]
    fn test_no_concurrent_upgrades() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(50),
                grace_blocks: 100,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(200),
                grace_blocks: 100,
            },
        ];
        let v = ConstraintValidator::new(activations, 80, CURRENT_SCHEMA_VERSION);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(300), 100);
        assert!(report.can_upgrade);
    }

    #[test]
    fn test_validate_schedule() {
        let v = validator(100);
        let report = v.validate_schedule();
        assert!(report.can_upgrade);
    }

    #[test]
    fn test_validate_schedule_with_overlap() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(100),
                grace_blocks: 50,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(120),
                grace_blocks: 50,
            },
        ];
        let v = ConstraintValidator::new(activations, 50, CURRENT_SCHEMA_VERSION);
        let report = v.validate_schedule();
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-10"));
    }

    #[test]
    fn test_validate_schedule_with_decreasing_heights() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(200),
                grace_blocks: 50,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 50,
            },
        ];
        let v = ConstraintValidator::new(activations, 50, CURRENT_SCHEMA_VERSION);
        let report = v.validate_schedule();
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-9"));
    }

    #[test]
    fn test_constraint_config_default() {
        let config = ConstraintConfig::default();
        assert!(config.enable_uc1);
        assert!(config.hard_uc1);
        assert!(!config.hard_uc4);
    }

    #[test]
    fn test_constraint_config_all_hard() {
        let config = ConstraintConfig::all_hard();
        assert!(config.hard_uc4);
        assert!(config.hard_uc8);
    }

    #[test]
    fn test_constraint_config_all_soft() {
        let config = ConstraintConfig::all_soft();
        assert!(!config.hard_uc1);
        assert!(!config.hard_uc10);
    }

    #[test]
    fn test_validator_metrics() {
        let v = validator(100);
        let _ = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        let metrics = v.metrics().snapshot();
        assert!(metrics.total_checks >= 5);
        assert_eq!(metrics.failed_checks, 0);
    }

    #[test]
    fn test_constraint_config_validation() {
        let mut config = ConstraintConfig::default();
        config.min_grace_blocks = 0;
        assert!(config.validate().is_err());

        config.min_grace_blocks = 10;
        config.max_pv_gap = 0;
        assert!(config.validate().is_err());

        config.max_pv_gap = 1;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_set_config() {
        let mut v = validator(100);
        let mut new_config = ConstraintConfig::default();
        new_config.min_grace_blocks = 200;
        assert!(v.set_config(new_config).is_ok());
        assert_eq!(v.config().min_grace_blocks, 200);
    }

    #[test]
    fn test_check_grace_overlap_with_new_activation() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(100),
                grace_blocks: 100,
            },
        ];
        let v = ConstraintValidator::new(activations, 50, CURRENT_SCHEMA_VERSION);
        let report = v.check_upgrade(2, CURRENT_SCHEMA_VERSION, Some(150), 100);
        // Overlap: first ends at 200, new starts at 150 -> overlap.
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-10"));
    }

    #[test]
    fn test_report_success_count() {
        let v = validator(100);
        let report = v.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        assert_eq!(report.success_count(), report.results.len());
    }
}
