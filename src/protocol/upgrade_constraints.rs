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
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::upgrade_constraints::{ConstraintChecker, ConstraintConfig, can_upgrade};
//!
//! let config = ConstraintConfig::default();
//! let checker = ConstraintChecker::new(activations, current_height, current_sv, config);
//! let report = checker.check_upgrade(2, 5, Some(1000), 100);
//! if !report.can_upgrade {
//!     eprintln!("{}", report);
//! }
//! ```

use crate::protocol::version::{
    ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::storage::CURRENT_SCHEMA_VERSION;
use serde::{Deserialize, Serialize};
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
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during constraint validation.
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

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

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
        }
    }
}

impl ConstraintConfig {
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
        }
    }
}

// -----------------------------------------------------------------------------
// Constraint result structures
// -----------------------------------------------------------------------------

/// Result of a single upgrade constraint check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConstraintResult {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Whether this constraint is hard (blocks upgrade) or soft (warning).
    pub hard: bool,
    pub severity: u8, // 0=info, 1=warning, 2=error
}

impl ConstraintResult {
    /// Create a new constraint result.
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

    /// Create a success result.
    pub fn success(id: &str, name: &str, hard: bool, detail: &str) -> Self {
        Self::new(id, name, true, hard, detail, 0)
    }

    /// Create a failure result.
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
    /// Create a report from a list of results and duration.
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

    /// Get only failed hard constraints.
    pub fn blockers(&self) -> Vec<&ConstraintResult> {
        self.results
            .iter()
            .filter(|r| r.hard && !r.passed)
            .collect()
    }

    /// Get soft warnings (non‑hard failures).
    pub fn warnings(&self) -> Vec<&ConstraintResult> {
        self.results
            .iter()
            .filter(|r| !r.hard && !r.passed)
            .collect()
    }

    /// Get all failed constraints (hard + soft).
    pub fn failures(&self) -> Vec<&ConstraintResult> {
        self.results.iter().filter(|r| !r.passed).collect()
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

// -----------------------------------------------------------------------------
// ConstraintChecker
// -----------------------------------------------------------------------------

/// Upgrade compatibility constraint checker.
#[derive(Debug)]
pub struct ConstraintChecker {
    activations: Vec<ProtocolActivation>,
    current_height: u64,
    current_sv: u32,
    config: ConstraintConfig,
}

impl ConstraintChecker {
    /// Create a new constraint checker with default configuration.
    pub fn new(activations: Vec<ProtocolActivation>, current_height: u64, current_sv: u32) -> Self {
        Self::with_config(activations, current_height, current_sv, ConstraintConfig::default())
    }

    /// Create a new constraint checker with custom configuration.
    pub fn with_config(
        activations: Vec<ProtocolActivation>,
        current_height: u64,
        current_sv: u32,
        config: ConstraintConfig,
    ) -> Self {
        debug!(
            current_height,
            current_sv,
            activations_len = activations.len(),
            "constraint checker created"
        );
        Self {
            activations,
            current_height,
            current_sv,
            config,
        }
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

        if self.config.enable_uc1 {
            results.push(self.check_pv_gap(target_pv));
        }
        if self.config.enable_uc2 {
            results.push(self.check_sv_forward(target_sv));
        }
        if self.config.enable_uc3 {
            results.push(self.check_activation_future(activation_height));
        }
        if self.config.enable_uc4 {
            results.push(self.check_grace_minimum(grace_blocks, target_pv));
        }
        if self.config.enable_uc5 {
            results.push(self.check_binary_supports(target_pv));
        }
        if self.config.enable_uc6 {
            results.push(self.check_migration_path(target_sv));
        }
        if self.config.enable_uc7 {
            results.push(self.check_no_concurrent(target_pv));
        }
        if self.config.enable_uc8 {
            results.push(self.check_quorum_readiness());
        }
        if self.config.enable_uc9 {
            results.push(self.check_strictly_increasing(activation_height));
        }
        if self.config.enable_uc10 {
            results.push(self.check_grace_overlap(activation_height, grace_blocks, target_pv));
        }

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

    // -------------------------------------------------------------------------
    // UC-1: PV gap limit
    // -------------------------------------------------------------------------

    fn check_pv_gap(&self, target_pv: u32) -> ConstraintResult {
        let current = CURRENT_PROTOCOL_VERSION;
        let gap = target_pv.saturating_sub(current);
        let max_gap = self.config.max_pv_gap;
        let passed = gap <= max_gap;
        let detail = format!(
            "current PV={current}, target PV={target_pv}, gap={gap} (max={max_gap})"
        );
        if !passed {
            warn!("UC-1 failed: {}", detail);
        } else {
            debug!("UC-1: {}", detail);
        }
        ConstraintResult::new(
            "UC-1",
            "PV gap limit",
            passed,
            self.config.hard_uc1,
            &detail,
            if passed { 0 } else { 2 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-2: SV forward-only
    // -------------------------------------------------------------------------

    fn check_sv_forward(&self, target_sv: u32) -> ConstraintResult {
        let passed = target_sv >= self.current_sv;
        let detail = format!("current SV={}, target SV={target_sv}", self.current_sv);
        if !passed {
            warn!("UC-2 failed: {}", detail);
        } else {
            debug!("UC-2: {}", detail);
        }
        ConstraintResult::new(
            "UC-2",
            "SV forward-only",
            passed,
            self.config.hard_uc2,
            &detail,
            if passed { 0 } else { 2 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-3: Activation height future
    // -------------------------------------------------------------------------

    fn check_activation_future(&self, activation_height: Option<u64>) -> ConstraintResult {
        match activation_height {
            Some(ah) => {
                let in_future = ah > self.current_height;
                let detail = format!(
                    "activation_height={ah}, current_height={} ({})",
                    self.current_height,
                    if in_future { "in future" } else { "in past!" }
                );
                if !in_future {
                    warn!("UC-3 failed: {}", detail);
                } else {
                    debug!("UC-3: {}", detail);
                }
                ConstraintResult::new(
                    "UC-3",
                    "Activation height future",
                    in_future,
                    self.config.hard_uc3,
                    &detail,
                    if in_future { 0 } else { 2 },
                )
            }
            None => ConstraintResult::success(
                "UC-3",
                "Activation height future",
                false,
                "no activation height (genesis or rolling upgrade)",
            ),
        }
    }

    // -------------------------------------------------------------------------
    // UC-4: Grace window minimum
    // -------------------------------------------------------------------------

    fn check_grace_minimum(&self, grace_blocks: u64, target_pv: u32) -> ConstraintResult {
        // Only enforce for PV upgrades (not rolling/minor).
        if target_pv <= CURRENT_PROTOCOL_VERSION {
            return ConstraintResult::success(
                "UC-4",
                "Grace window minimum",
                false,
                "not a PV upgrade; grace window not required",
            );
        }

        let min_grace = self.config.min_grace_blocks;
        let passed = grace_blocks >= min_grace;
        let detail = format!("grace_blocks={grace_blocks} (min={min_grace})");
        if !passed {
            warn!("UC-4: {}", detail);
        } else {
            debug!("UC-4: {}", detail);
        }
        ConstraintResult::new(
            "UC-4",
            "Grace window minimum",
            passed,
            self.config.hard_uc4,
            &detail,
            if passed { 0 } else { 1 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-5: Binary supports target PV
    // -------------------------------------------------------------------------

    fn check_binary_supports(&self, target_pv: u32) -> ConstraintResult {
        let supported = SUPPORTED_PROTOCOL_VERSIONS.contains(&target_pv);
        let detail = format!(
            "target PV={target_pv}, supported={:?}",
            SUPPORTED_PROTOCOL_VERSIONS
        );
        if !supported {
            warn!("UC-5 failed: {}", detail);
        } else {
            debug!("UC-5: {}", detail);
        }
        ConstraintResult::new(
            "UC-5",
            "Binary supports target PV",
            supported,
            self.config.hard_uc5,
            &detail,
            if supported { 0 } else { 2 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-6: Migration path exists
    // -------------------------------------------------------------------------

    fn check_migration_path(&self, target_sv: u32) -> ConstraintResult {
        let migrations = &crate::storage::migrations::MIGRATIONS;
        let mut covered = self.current_sv;

        for e in migrations.iter() {
            if e.from_version == covered {
                covered += 1;
            }
        }

        // Also check if we already have a direct migration from current_sv to target_sv.
        let has_direct = migrations.iter().any(|e| {
            e.from_version == self.current_sv && e.to_version == target_sv
        });

        let fully_covered = covered >= target_sv || target_sv <= self.current_sv || has_direct;
        let detail = format!(
            "current SV={}, target SV={target_sv}, migrations cover up to SV={covered}, direct={has_direct}",
            self.current_sv
        );
        if !fully_covered {
            warn!("UC-6 failed: {}", detail);
        } else {
            debug!("UC-6: {}", detail);
        }
        ConstraintResult::new(
            "UC-6",
            "Migration path exists",
            fully_covered,
            self.config.hard_uc6,
            &detail,
            if fully_covered { 0 } else { 2 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-7: No concurrent upgrades
    // -------------------------------------------------------------------------

    fn check_no_concurrent(&self, target_pv: u32) -> ConstraintResult {
        let in_progress = self.activations.iter().any(|a| {
            a.activation_height
                .map(|ah| {
                    let end = ah + a.grace_blocks;
                    self.current_height >= ah
                        && self.current_height < end
                        && a.protocol_version != target_pv
                })
                .unwrap_or(false)
        });

        let detail = if in_progress {
            "another upgrade is currently in grace window".into()
        } else {
            "no concurrent upgrades detected".into()
        };
        if in_progress {
            warn!("UC-7 failed: {}", detail);
        } else {
            debug!("UC-7: {}", detail);
        }
        ConstraintResult::new(
            "UC-7",
            "No concurrent upgrades",
            !in_progress,
            self.config.hard_uc7,
            &detail,
            if in_progress { 2 } else { 0 },
        )
    }

    // -------------------------------------------------------------------------
    // UC-8: Quorum readiness
    // -------------------------------------------------------------------------

    fn check_quorum_readiness(&self) -> ConstraintResult {
        // In production, this would check actual peer upgrade status.
        // At compile time, we assume the node is ready.
        ConstraintResult::success(
            "UC-8",
            "Quorum readiness",
            false,
            &format!(
                "local binary: PV={CURRENT_PROTOCOL_VERSION}, SV={CURRENT_SCHEMA_VERSION} (ready)"
            ),
        )
    }

    // -------------------------------------------------------------------------
    // UC-9: Strictly increasing heights
    // -------------------------------------------------------------------------

    fn check_strictly_increasing(&self, activation_height: Option<u64>) -> ConstraintResult {
        if let Some(ah) = activation_height {
            // Check against existing activations.
            let mut prev_height: Option<u64> = None;
            for a in &self.activations {
                if let Some(h) = a.activation_height {
                    if let Some(prev) = prev_height {
                        if h <= prev {
                            let detail = format!(
                                "activation heights not strictly increasing: {} <= {}",
                                h, prev
                            );
                            return ConstraintResult::failure(
                                "UC-9",
                                "Strictly increasing heights",
                                self.config.hard_uc9,
                                &detail,
                                2,
                            );
                        }
                    }
                    prev_height = Some(h);
                }
            }
            // Now check the new height against the last one.
            if let Some(prev) = prev_height {
                if ah <= prev {
                    let detail = format!(
                        "proposed activation height {} is not > previous height {}",
                        ah, prev
                    );
                    return ConstraintResult::failure(
                        "UC-9",
                        "Strictly increasing heights",
                        self.config.hard_uc9,
                        &detail,
                        2,
                    );
                }
            }
            ConstraintResult::success(
                "UC-9",
                "Strictly increasing heights",
                self.config.hard_uc9,
                &format!("activation height {} is strictly increasing", ah),
            )
        } else {
            ConstraintResult::success(
                "UC-9",
                "Strictly increasing heights",
                false,
                "no activation height provided",
            )
        }
    }

    // -------------------------------------------------------------------------
    // UC-10: Grace windows non‑overlap
    // -------------------------------------------------------------------------

    fn check_grace_overlap(
        &self,
        new_activation: Option<u64>,
        new_grace: u64,
        target_pv: u32,
    ) -> ConstraintResult {
        // Build intervals for existing activations.
        let mut intervals = Vec::new();
        for a in &self.activations {
            if let Some(h) = a.activation_height {
                intervals.push((h, h + a.grace_blocks, a.protocol_version));
            }
        }

        // Add the new activation if provided.
        if let Some(h) = new_activation {
            intervals.push((h, h + new_grace, target_pv));
        }

        intervals.sort_by_key(|(start, _, _)| *start);

        // Check for overlaps.
        for i in 1..intervals.len() {
            let (prev_start, prev_end, prev_pv) = intervals[i - 1];
            let (curr_start, curr_end, curr_pv) = intervals[i];
            if curr_start < prev_end {
                let detail = format!(
                    "grace window overlap: PV={} [{}, {}] overlaps with PV={} [{}, {}]",
                    prev_pv, prev_start, prev_end, curr_pv, curr_start, curr_end
                );
                return ConstraintResult::failure(
                    "UC-10",
                    "Grace windows non‑overlap",
                    self.config.hard_uc10,
                    &detail,
                    2,
                );
            }
        }

        let detail = format!("no grace window overlap detected ({} intervals)", intervals.len());
        ConstraintResult::success(
            "UC-10",
            "Grace windows non‑overlap",
            self.config.hard_uc10,
            &detail,
        )
    }

    // -------------------------------------------------------------------------
    // Additional helper: validate entire schedule
    // -------------------------------------------------------------------------

    /// Validate the entire activation schedule against all constraints (except UC-8).
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

        // UC-1: PV gap (across all activations)
        if self.config.enable_uc1 {
            let mut prev_pv = 0;
            for a in &self.activations {
                let gap = a.protocol_version.saturating_sub(prev_pv);
                if gap > self.config.max_pv_gap && prev_pv > 0 {
                    results.push(ConstraintResult::failure(
                        "UC-1",
                        "PV gap limit",
                        self.config.hard_uc1,
                        &format!("PV {} to {} gap={} > max={}", prev_pv, a.protocol_version, gap, self.config.max_pv_gap),
                        2,
                    ));
                }
                prev_pv = a.protocol_version;
            }
        }

        // UC-2: SV forward (if multiple SV values, they should increase)
        // We don't have SV in activations, so skip.

        // UC-3: All activation heights in future (if set)
        for a in &self.activations {
            if let Some(h) = a.activation_height {
                if h <= self.current_height {
                    results.push(ConstraintResult::failure(
                        "UC-3",
                        "Activation height future",
                        self.config.hard_uc3,
                        &format!("activation height {} is not in future (current={})", h, self.current_height),
                        2,
                    ));
                }
            }
        }

        // UC-4: Grace window minimum
        for a in &self.activations {
            if a.protocol_version > 1 && a.grace_blocks < self.config.min_grace_blocks {
                results.push(ConstraintResult::failure(
                    "UC-4",
                    "Grace window minimum",
                    self.config.hard_uc4,
                    &format!("PV {} grace={} < min={}", a.protocol_version, a.grace_blocks, self.config.min_grace_blocks),
                    1,
                ));
            }
        }

        // UC-5: Binary supports all PVs
        for a in &self.activations {
            if !SUPPORTED_PROTOCOL_VERSIONS.contains(&a.protocol_version) {
                results.push(ConstraintResult::failure(
                    "UC-5",
                    "Binary supports target PV",
                    self.config.hard_uc5,
                    &format!("PV {} not supported by binary", a.protocol_version),
                    2,
                ));
            }
        }

        // UC-7: No overlapping grace windows
        if self.config.enable_uc10 {
            let mut intervals = Vec::new();
            for a in &self.activations {
                if let Some(h) = a.activation_height {
                    intervals.push((h, h + a.grace_blocks, a.protocol_version));
                }
            }
            intervals.sort_by_key(|(start, _, _)| *start);
            for i in 1..intervals.len() {
                let (prev_start, prev_end, prev_pv) = intervals[i - 1];
                let (curr_start, curr_end, curr_pv) = intervals[i];
                if curr_start < prev_end {
                    results.push(ConstraintResult::failure(
                        "UC-10",
                        "Grace windows non‑overlap",
                        self.config.hard_uc10,
                        &format!("PV{} ({},{}) overlaps PV{} ({},{})",
                            prev_pv, prev_start, prev_end, curr_pv, curr_start, curr_end),
                        2,
                    ));
                }
            }
        }

        // UC-9: Strictly increasing heights
        if self.config.enable_uc9 {
            let mut prev_height: Option<u64> = None;
            for a in &self.activations {
                if let Some(h) = a.activation_height {
                    if let Some(prev) = prev_height {
                        if h <= prev {
                            results.push(ConstraintResult::failure(
                                "UC-9",
                                "Strictly increasing heights",
                                self.config.hard_uc9,
                                &format!("height {} <= previous {}", h, prev),
                                2,
                            ));
                        }
                    }
                    prev_height = Some(h);
                }
            }
        }

        // UC-6: Migration paths (simplified: check if SV increments are contiguous)
        // Not enough info here.

        let report = ConstraintReport::new(results, start.elapsed());
        if !report.can_upgrade {
            let blockers = report.blockers();
            warn!(blockers = ?blockers.iter().map(|r| r.id.as_str()).collect::<Vec<_>>(), "schedule validation failed");
        } else {
            info!("schedule validation passed");
        }
        report
    }
}

// -----------------------------------------------------------------------------
// Convenience function
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
    let checker = ConstraintChecker::new(activations.to_vec(), current_height, CURRENT_SCHEMA_VERSION);
    checker
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

    fn checker(height: u64) -> ConstraintChecker {
        ConstraintChecker::new(default_activations(), height, CURRENT_SCHEMA_VERSION)
    }

    #[test]
    fn test_same_version_upgrade_ok() {
        let c = checker(100);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        assert!(report.can_upgrade, "report: {report}");
    }

    #[test]
    fn test_pv_gap_too_large() {
        let c = checker(100);
        let report = c.check_upgrade(5, CURRENT_SCHEMA_VERSION, Some(200), 1000);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-1"));
    }

    #[test]
    fn test_sv_backward_rejected() {
        let c = checker(100);
        let report = c.check_upgrade(1, 1, None, 0);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-2"));
    }

    #[test]
    fn test_activation_in_past_rejected() {
        let c = checker(500);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(100), 0);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-3"));
    }

    #[test]
    fn test_unsupported_pv_rejected() {
        let c = checker(100);
        let report = c.check_upgrade(99, CURRENT_SCHEMA_VERSION, Some(200), 1000);
        assert!(!report.can_upgrade);
        let blockers: Vec<_> = report.blockers();
        assert!(blockers.iter().any(|b| b.id == "UC-5"));
    }

    #[test]
    fn test_grace_warning() {
        let c = checker(100);
        // PV upgrade with grace < MIN_GRACE_BLOCKS (but not a PV upgrade)
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(200), 10);
        assert!(report.can_upgrade);
    }

    #[test]
    fn test_report_display() {
        let c = checker(100);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
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
        let c = checker(100);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0);
        assert!(report.blockers().is_empty());
    }

    #[test]
    fn test_no_concurrent_upgrades() {
        let activations = vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: Some(50),
            grace_blocks: 100,
        }];
        let c = ConstraintChecker::new(activations, 80, CURRENT_SCHEMA_VERSION);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(200), 100);
        assert!(report.can_upgrade);
    }

    #[test]
    fn test_validate_schedule() {
        let c = checker(100);
        let report = c.validate_schedule();
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
        let c = ConstraintChecker::new(activations, 50, CURRENT_SCHEMA_VERSION);
        let report = c.validate_schedule();
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
        let c = ConstraintChecker::new(activations, 50, CURRENT_SCHEMA_VERSION);
        let report = c.validate_schedule();
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
    fn test_constraint_result_helpers() {
        let success = ConstraintResult::success("UC-1", "Test", true, "ok");
        assert!(success.passed);
        assert!(success.hard);
        assert_eq!(success.severity, 0);

        let failure = ConstraintResult::failure("UC-2", "Test", false, "fail", 2);
        assert!(!failure.passed);
        assert!(!failure.hard);
        assert_eq!(failure.severity, 2);
    }
}
