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
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::upgrade_constraints::{ConstraintChecker, can_upgrade};
//!
//! let checker = ConstraintChecker::new(activations, current_height, current_sv);
//! let report = checker.check_upgrade(2, 5, Some(1000), 100);
//! if !report.can_upgrade {
//!     eprintln!("{}", report);
//! }
//! ```

use crate::protocol::version::{
    ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::storage::CURRENT_SCHEMA_VERSION;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum grace window for any activation (blocks).
pub const MIN_GRACE_BLOCKS: u64 = 100;

/// Maximum PV gap allowed in a single upgrade step.
pub const MAX_PV_GAP: u32 = 1;

// -----------------------------------------------------------------------------
// Constraint result structures
// -----------------------------------------------------------------------------

/// Result of a single upgrade constraint check.
#[derive(Debug, Clone)]
pub struct ConstraintResult {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Whether this constraint is hard (blocks upgrade) or soft (warning).
    pub hard: bool,
}

/// Aggregate report of all upgrade constraint checks.
#[derive(Debug, Clone)]
pub struct ConstraintReport {
    pub results: Vec<ConstraintResult>,
    pub can_upgrade: bool,
}

impl ConstraintReport {
    /// Create a report from a list of results.
    #[must_use]
    pub fn from_results(results: Vec<ConstraintResult>) -> Self {
        let can_upgrade = results.iter().filter(|r| r.hard).all(|r| r.passed);
        Self {
            results,
            can_upgrade,
        }
    }

    /// Get only failed hard constraints.
    #[must_use]
    pub fn blockers(&self) -> Vec<&ConstraintResult> {
        self.results
            .iter()
            .filter(|r| r.hard && !r.passed)
            .collect()
    }

    /// Get soft warnings.
    #[must_use]
    pub fn warnings(&self) -> Vec<&ConstraintResult> {
        self.results
            .iter()
            .filter(|r| !r.hard && !r.passed)
            .collect()
    }
}

impl std::fmt::Display for ConstraintReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Upgrade Constraints: {}",
            if self.can_upgrade {
                "ALLOWED"
            } else {
                "BLOCKED"
            }
        )?;
        for r in &self.results {
            let mark = if r.passed {
                "OK"
            } else if r.hard {
                "BLOCK"
            } else {
                "WARN"
            };
            writeln!(f, "  [{mark}] {}: {} — {}", r.id, r.name, r.detail)?;
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
}

impl ConstraintChecker {
    /// Create a new constraint checker.
    #[must_use]
    pub fn new(activations: Vec<ProtocolActivation>, current_height: u64, current_sv: u32) -> Self {
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
        }
    }

    /// Check all constraints for a proposed upgrade.
    #[must_use]
    pub fn check_upgrade(
        &self,
        target_pv: u32,
        target_sv: u32,
        activation_height: Option<u64>,
        grace_blocks: u64,
    ) -> ConstraintReport {
        let mut results = Vec::new();

        results.push(self.check_pv_gap(target_pv));
        results.push(self.check_sv_forward(target_sv));
        results.push(self.check_activation_future(activation_height));
        results.push(self.check_grace_minimum(grace_blocks, target_pv));
        results.push(self.check_binary_supports(target_pv));
        results.push(self.check_migration_path(target_sv));
        results.push(self.check_no_concurrent(target_pv));
        results.push(self.check_quorum_readiness());

        let report = ConstraintReport::from_results(results);
        if report.can_upgrade {
            info!(
                target_pv,
                target_sv,
                activation_height = ?activation_height,
                "upgrade constraints satisfied"
            );
        } else {
            warn!(
                target_pv,
                target_sv,
                activation_height = ?activation_height,
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

        let passed = gap <= MAX_PV_GAP;
        let detail = format!(
            "current PV={current}, target PV={target_pv}, gap={gap} (max={MAX_PV_GAP})"
        );
        if !passed {
            warn!("UC-1 failed: {}", detail);
        } else {
            debug!("UC-1: {}", detail);
        }

        ConstraintResult {
            id: "UC-1".into(),
            name: "PV gap limit".into(),
            passed,
            detail,
            hard: true,
        }
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

        ConstraintResult {
            id: "UC-2".into(),
            name: "SV forward-only".into(),
            passed,
            detail,
            hard: true,
        }
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
                ConstraintResult {
                    id: "UC-3".into(),
                    name: "Activation height future".into(),
                    passed: in_future,
                    detail,
                    hard: true,
                }
            }
            None => ConstraintResult {
                id: "UC-3".into(),
                name: "Activation height future".into(),
                passed: true,
                detail: "no activation height (genesis or rolling upgrade)".into(),
                hard: false,
            },
        }
    }

    // -------------------------------------------------------------------------
    // UC-4: Grace window minimum
    // -------------------------------------------------------------------------

    fn check_grace_minimum(&self, grace_blocks: u64, target_pv: u32) -> ConstraintResult {
        // Only enforce minimum grace for PV upgrades (not rolling/minor).
        if target_pv <= CURRENT_PROTOCOL_VERSION {
            return ConstraintResult {
                id: "UC-4".into(),
                name: "Grace window minimum".into(),
                passed: true,
                detail: "not a PV upgrade; grace window not required".into(),
                hard: false,
            };
        }

        let passed = grace_blocks >= MIN_GRACE_BLOCKS;
        let detail = format!("grace_blocks={grace_blocks} (min={MIN_GRACE_BLOCKS})");
        if !passed {
            warn!("UC-4: {}", detail);
        } else {
            debug!("UC-4: {}", detail);
        }

        ConstraintResult {
            id: "UC-4".into(),
            name: "Grace window minimum".into(),
            passed,
            detail,
            hard: false, // Advisory; some testnets may use zero grace.
        }
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

        ConstraintResult {
            id: "UC-5".into(),
            name: "Binary supports target PV".into(),
            passed: supported,
            detail,
            hard: true,
        }
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

        let fully_covered = covered >= target_sv || target_sv <= self.current_sv;
        let detail = format!(
            "current SV={}, target SV={target_sv}, migrations cover up to SV={covered}",
            self.current_sv
        );
        if !fully_covered {
            warn!("UC-6 failed: {}", detail);
        } else {
            debug!("UC-6: {}", detail);
        }

        ConstraintResult {
            id: "UC-6".into(),
            name: "Migration path exists".into(),
            passed: fully_covered,
            detail,
            hard: true,
        }
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

        ConstraintResult {
            id: "UC-7".into(),
            name: "No concurrent upgrades".into(),
            passed: !in_progress,
            detail,
            hard: true,
        }
    }

    // -------------------------------------------------------------------------
    // UC-8: Quorum readiness
    // -------------------------------------------------------------------------

    fn check_quorum_readiness(&self) -> ConstraintResult {
        // This is a runtime check that requires peer information.
        // At compile time, we can only verify the local binary is ready.
        ConstraintResult {
            id: "UC-8".into(),
            name: "Quorum readiness".into(),
            passed: true,
            detail: format!(
                "local binary: PV={CURRENT_PROTOCOL_VERSION}, SV={CURRENT_SCHEMA_VERSION} (ready)"
            ),
            hard: false, // Cannot enforce at compile time.
        }
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
        // PV upgrade with grace < MIN_GRACE_BLOCKS
        // Note: PV=1 is current, so grace check says "not a PV upgrade".
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
        // Warnings may or may not exist depending on checks.
    }

    #[test]
    fn test_no_concurrent_upgrades() {
        // Create activation in progress.
        let activations = vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: Some(50),
            grace_blocks: 100,
        }];
        let c = ConstraintChecker::new(activations, 80, CURRENT_SCHEMA_VERSION);
        let report = c.check_upgrade(1, CURRENT_SCHEMA_VERSION, Some(200), 100);
        assert!(report.can_upgrade);
    }
}
