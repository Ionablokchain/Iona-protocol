//! Upgrade compatibility constraints.
//!
//! Defines and enforces the rules that govern when and how upgrades can occur.
//! These constraints prevent unsafe upgrade paths and ensure that the network
//! can always reach consensus during transitions.
//!
//! # Constraint Categories
//!
//! | ID    | Name                      | Description                                               |
//! |-------|---------------------------|-----------------------------------------------------------|
//! | UC-0  | Activation schedule valid | Existing activation schedule must be well-formed          |
//! | UC-1  | PV gap limit              | Cannot skip more than 1 protocol version at a time        |
//! | UC-2  | SV forward-only           | Schema version must only increase                         |
//! | UC-3  | Activation height future  | Activation height must be in the future for PV upgrades   |
//! | UC-4  | Grace window minimum      | Grace window should be >= MIN_GRACE_BLOCKS                |
//! | UC-5  | Binary supports target    | Binary must support the target PV                         |
//! | UC-6  | Migration path exists     | SV migration path must be contiguous                      |
//! | UC-7  | No concurrent upgrades    | Upgrade windows must not overlap                          |
//! | UC-8  | Quorum readiness          | Sufficient nodes should be ready before activation        |
//! | UC-9  | Downgrade protection      | Downgrades are not allowed                                |

use crate::protocol::version::{version_for_height, ProtocolActivation, SUPPORTED_PROTOCOL_VERSIONS};
use crate::storage::CURRENT_SCHEMA_VERSION;

/// Minimum grace window for any PV activation, in blocks.
pub const MIN_GRACE_BLOCKS: u64 = 100;

/// Maximum protocol-version gap allowed in a single upgrade.
pub const MAX_PV_GAP: u32 = 1;

/// Result of a single constraint check.
#[derive(Debug, Clone)]
pub struct ConstraintResult {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
    /// Hard constraint = blocks the upgrade if false.
    pub hard: bool,
}

/// Aggregate report of all upgrade constraint checks.
#[derive(Debug, Clone)]
pub struct ConstraintReport {
    pub results: Vec<ConstraintResult>,
    pub can_upgrade: bool,
}

impl ConstraintReport {
    pub fn from_results(results: Vec<ConstraintResult>) -> Self {
        let can_upgrade = results
            .iter()
            .filter(|r| r.hard)
            .all(|r| r.passed);

        Self { results, can_upgrade }
    }

    pub fn blockers(&self) -> Vec<&ConstraintResult> {
        self.results
            .iter()
            .filter(|r| r.hard && !r.passed)
            .collect()
    }

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
            if self.can_upgrade { "ALLOWED" } else { "BLOCKED" }
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

/// Upgrade compatibility constraint checker.
pub struct ConstraintChecker {
    /// Existing activation schedule.
    activations: Vec<ProtocolActivation>,
    /// Current chain height.
    current_height: u64,
    /// Current schema version on disk.
    current_sv: u32,
}

impl ConstraintChecker {
    /// Create a new checker, validating the existing activation schedule first.
    pub fn new(
        activations: Vec<ProtocolActivation>,
        current_height: u64,
        current_sv: u32,
    ) -> Result<Self, String> {
        validate_activation_schedule(&activations)?;
        Ok(Self {
            activations,
            current_height,
            current_sv,
        })
    }

    fn current_pv(&self) -> u32 {
        version_for_height(self.current_height, &self.activations)
    }

    /// Check all constraints for a proposed upgrade.
    pub fn check_upgrade(
        &self,
        target_pv: u32,
        target_sv: u32,
        activation_height: Option<u64>,
        grace_blocks: u64,
    ) -> ConstraintReport {
        let current_pv = self.current_pv();
        let mut results = Vec::new();

        results.push(self.check_schedule_valid());
        results.push(self.check_downgrade(target_pv, current_pv));
        results.push(self.check_pv_gap(target_pv, current_pv));
        results.push(self.check_sv_forward(target_sv));
        results.push(self.check_activation_future(target_pv, current_pv, activation_height));
        results.push(self.check_grace_minimum(target_pv, current_pv, grace_blocks));
        results.push(self.check_binary_supports(target_pv));
        results.push(self.check_migration_path(target_sv));
        results.push(self.check_no_concurrent(target_pv, activation_height, grace_blocks));
        results.push(self.check_quorum_readiness());

        ConstraintReport::from_results(results)
    }

    fn check_schedule_valid(&self) -> ConstraintResult {
        match validate_activation_schedule(&self.activations) {
            Ok(()) => ConstraintResult {
                id: "UC-0".into(),
                name: "Activation schedule valid".into(),
                passed: true,
                detail: format!("{} activations validated", self.activations.len()),
                hard: true,
            },
            Err(e) => ConstraintResult {
                id: "UC-0".into(),
                name: "Activation schedule valid".into(),
                passed: false,
                detail: e,
                hard: true,
            },
        }
    }

    fn check_downgrade(&self, target_pv: u32, current_pv: u32) -> ConstraintResult {
        ConstraintResult {
            id: "UC-9".into(),
            name: "Downgrade protection".into(),
            passed: target_pv >= current_pv,
            detail: format!("current PV={current_pv}, target PV={target_pv}"),
            hard: true,
        }
    }

    fn check_pv_gap(&self, target_pv: u32, current_pv: u32) -> ConstraintResult {
        if target_pv <= current_pv {
            return ConstraintResult {
                id: "UC-1".into(),
                name: "PV gap limit".into(),
                passed: true,
                detail: format!(
                    "target PV={target_pv} <= current PV={current_pv}; gap check not applicable"
                ),
                hard: false,
            };
        }

        let gap = target_pv - current_pv;
        ConstraintResult {
            id: "UC-1".into(),
            name: "PV gap limit".into(),
            passed: gap <= MAX_PV_GAP,
            detail: format!(
                "current PV={current_pv}, target PV={target_pv}, gap={gap}, max={MAX_PV_GAP}"
            ),
            hard: true,
        }
    }

    fn check_sv_forward(&self, target_sv: u32) -> ConstraintResult {
        ConstraintResult {
            id: "UC-2".into(),
            name: "SV forward-only".into(),
            passed: target_sv >= self.current_sv,
            detail: format!("current SV={}, target SV={target_sv}", self.current_sv),
            hard: true,
        }
    }

    fn check_activation_future(
        &self,
        target_pv: u32,
        current_pv: u32,
        activation_height: Option<u64>,
    ) -> ConstraintResult {
        if target_pv > current_pv {
            match activation_height {
                Some(ah) => {
                    let passed = ah > self.current_height;
                    ConstraintResult {
                        id: "UC-3".into(),
                        name: "Activation height future".into(),
                        passed,
                        detail: format!(
                            "activation_height={ah}, current_height={} ({})",
                            self.current_height,
                            if passed { "future" } else { "not future" }
                        ),
                        hard: true,
                    }
                }
                None => ConstraintResult {
                    id: "UC-3".into(),
                    name: "Activation height future".into(),
                    passed: false,
                    detail: "PV upgrade requires activation_height, but none provided".into(),
                    hard: true,
                },
            }
        } else {
            ConstraintResult {
                id: "UC-3".into(),
                name: "Activation height future".into(),
                passed: true,
                detail: "not a PV upgrade; activation height not required".into(),
                hard: false,
            }
        }
    }

    fn check_grace_minimum(
        &self,
        target_pv: u32,
        current_pv: u32,
        grace_blocks: u64,
    ) -> ConstraintResult {
        if target_pv <= current_pv {
            return ConstraintResult {
                id: "UC-4".into(),
                name: "Grace window minimum".into(),
                passed: true,
                detail: "not a PV upgrade; grace window not required".into(),
                hard: false,
            };
        }

        ConstraintResult {
            id: "UC-4".into(),
            name: "Grace window minimum".into(),
            passed: grace_blocks >= MIN_GRACE_BLOCKS,
            detail: format!("grace_blocks={grace_blocks}, minimum={MIN_GRACE_BLOCKS}"),
            hard: false,
        }
    }

    fn check_binary_supports(&self, target_pv: u32) -> ConstraintResult {
        let passed = SUPPORTED_PROTOCOL_VERSIONS.contains(&target_pv);
        ConstraintResult {
            id: "UC-5".into(),
            name: "Binary supports target PV".into(),
            passed,
            detail: format!(
                "target PV={target_pv}, supported={:?}",
                SUPPORTED_PROTOCOL_VERSIONS
            ),
            hard: true,
        }
    }

    fn check_migration_path(&self, target_sv: u32) -> ConstraintResult {
        if target_sv <= self.current_sv {
            return ConstraintResult {
                id: "UC-6".into(),
                name: "Migration path exists".into(),
                passed: true,
                detail: format!(
                    "target SV={target_sv} <= current SV={}; no migration required",
                    self.current_sv
                ),
                hard: false,
            };
        }

        for step in self.current_sv..target_sv {
            let exists = crate::storage::migrations::MIGRATIONS
                .iter()
                .any(|(from, _, _)| *from == step);

            if !exists {
                return ConstraintResult {
                    id: "UC-6".into(),
                    name: "Migration path exists".into(),
                    passed: false,
                    detail: format!("missing migration for step {step} -> {}", step + 1),
                    hard: true,
                };
            }
        }

        ConstraintResult {
            id: "UC-6".into(),
            name: "Migration path exists".into(),
            passed: true,
            detail: format!(
                "current SV={}, target SV={target_sv}; contiguous migration path found",
                self.current_sv
            ),
            hard: true,
        }
    }

    fn check_no_concurrent(
        &self,
        target_pv: u32,
        activation_height: Option<u64>,
        grace_blocks: u64,
    ) -> ConstraintResult {
        let Some(proposed_start) = activation_height else {
            return ConstraintResult {
                id: "UC-7".into(),
                name: "No concurrent upgrades".into(),
                passed: true,
                detail: "no activation window proposed".into(),
                hard: false,
            };
        };

        let proposed_end = proposed_start.saturating_add(grace_blocks);

        for act in &self.activations {
            let Some(existing_start) = act.activation_height else {
                continue;
            };
            let existing_end = existing_start.saturating_add(act.grace_blocks);

            if act.protocol_version == target_pv {
                return ConstraintResult {
                    id: "UC-7".into(),
                    name: "No concurrent upgrades".into(),
                    passed: false,
                    detail: format!(
                        "an activation for target PV={} already exists at height {}",
                        target_pv, existing_start
                    ),
                    hard: true,
                };
            }

            if intervals_overlap(proposed_start, proposed_end, existing_start, existing_end) {
                return ConstraintResult {
                    id: "UC-7".into(),
                    name: "No concurrent upgrades".into(),
                    passed: false,
                    detail: format!(
                        "proposed window [{}, {}) overlaps existing PV={} window [{}, {})",
                        proposed_start,
                        proposed_end,
                        act.protocol_version,
                        existing_start,
                        existing_end
                    ),
                    hard: true,
                };
            }
        }

        ConstraintResult {
            id: "UC-7".into(),
            name: "No concurrent upgrades".into(),
            passed: true,
            detail: "no overlapping or duplicate upgrade windows detected".into(),
            hard: true,
        }
    }

    fn check_quorum_readiness(&self) -> ConstraintResult {
        ConstraintResult {
            id: "UC-8".into(),
            name: "Quorum readiness".into(),
            passed: true,
            detail: format!(
                "local check only; current PV={}, current SV={}",
                self.current_pv(),
                self.current_sv
            ),
            hard: false,
        }
    }
}

/// Validates that the activation schedule is structurally sane.
pub fn validate_activation_schedule(activations: &[ProtocolActivation]) -> Result<(), String> {
    if activations.is_empty() {
        return Err("activation schedule cannot be empty".into());
    }

    let first = &activations[0];
    if first.protocol_version != 1 {
        return Err(format!(
            "first activation must start at PV=1, got PV={}",
            first.protocol_version
        ));
    }
    if first.activation_height.is_some() {
        return Err("first activation must have activation_height=None".into());
    }

    let mut prev_pv = first.protocol_version;
    let mut prev_height: Option<u64> = None;

    for act in activations.iter().skip(1) {
        if act.protocol_version <= prev_pv {
            return Err(format!(
                "protocol versions must be strictly increasing: {} <= {}",
                act.protocol_version, prev_pv
            ));
        }

        let Some(ah) = act.activation_height else {
            return Err(format!(
                "activation for PV={} must specify activation_height",
                act.protocol_version
            ));
        };

        if let Some(prev) = prev_height {
            if ah <= prev {
                return Err(format!(
                    "activation heights must be strictly increasing: {} <= {}",
                    ah, prev
                ));
            }
        }

        prev_pv = act.protocol_version;
        prev_height = Some(ah);
    }

    Ok(())
}

/// Half-open interval overlap check for [start, end).
fn intervals_overlap(start1: u64, end1: u64, start2: u64, end2: u64) -> bool {
    !(end1 <= start2 || end2 <= start1)
}

/// Convenience helper.
pub fn can_upgrade(
    target_pv: u32,
    target_sv: u32,
    activation_height: Option<u64>,
    grace_blocks: u64,
    current_height: u64,
    activations: &[ProtocolActivation],
) -> bool {
    let checker = match ConstraintChecker::new(
        activations.to_vec(),
        current_height,
        CURRENT_SCHEMA_VERSION,
    ) {
        Ok(c) => c,
        Err(_) => return false,
    };

    checker
        .check_upgrade(target_pv, target_sv, activation_height, grace_blocks)
        .can_upgrade
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(500),
                grace_blocks: 150,
            },
        ]
    }

    fn checker(height: u64, current_sv: u32) -> ConstraintChecker {
        ConstraintChecker::new(valid_activations(), height, current_sv).unwrap()
    }

    #[test]
    fn test_validate_activation_schedule_ok() {
        assert!(validate_activation_schedule(&valid_activations()).is_ok());
    }

    #[test]
    fn test_validate_activation_schedule_invalid_first() {
        let acts = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: None,
            grace_blocks: 0,
        }];
        assert!(validate_activation_schedule(&acts).is_err());
    }

    #[test]
    fn test_validate_activation_schedule_non_increasing_height() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(500),
                grace_blocks: 100,
            },
            ProtocolActivation {
                protocol_version: 3,
                activation_height: Some(500),
                grace_blocks: 100,
            },
        ];
        assert!(validate_activation_schedule(&acts).is_err());
    }

    #[test]
    fn test_same_pv_schema_only_ok() {
        let c = checker(100, 5);
        let report = c.check_upgrade(1, 5, None, 0);
        assert!(report.can_upgrade, "report: {report}");
    }

    #[test]
    fn test_downgrade_blocked() {
        let c = checker(100, 5);
        let report = c.check_upgrade(0, 5, None, 0);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-9"));
    }

    #[test]
    fn test_pv_gap_too_large() {
        let c = checker(100, 5);
        let report = c.check_upgrade(3, 5, Some(700), 150);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-1"));
    }

    #[test]
    fn test_sv_backward_rejected() {
        let c = checker(100, 5);
        let report = c.check_upgrade(1, 4, None, 0);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-2"));
    }

    #[test]
    fn test_pv_upgrade_requires_activation_height() {
        let c = checker(100, 5);
        let report = c.check_upgrade(2, 5, None, 150);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-3"));
    }

    #[test]
    fn test_activation_must_be_in_future() {
        let c = checker(400, 5);
        let report = c.check_upgrade(2, 5, Some(100), 150);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-3"));
    }

    #[test]
    fn test_grace_warning_soft() {
        let c = checker(100, 5);
        let report = c.check_upgrade(2, 5, Some(700), 10);
        let uc4 = report.results.iter().find(|r| r.id == "UC-4").unwrap();
        assert!(!uc4.passed);
        assert!(!uc4.hard);
    }

    #[test]
    fn test_duplicate_target_pv_blocked() {
        let c = checker(100, 5);
        let report = c.check_upgrade(2, 5, Some(900), 100);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-7"));
    }

    #[test]
    fn test_overlap_blocked() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(500),
                grace_blocks: 150, // [500, 650)
            },
        ];
        let c = ConstraintChecker::new(acts, 100, 5).unwrap();
        let report = c.check_upgrade(3, 5, Some(600), 100); // [600, 700) overlaps
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-7"));
    }

    #[test]
    fn test_non_overlap_allowed() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(500),
                grace_blocks: 150, // [500, 650)
            },
        ];
        let c = ConstraintChecker::new(acts, 100, 5).unwrap();
        let report = c.check_upgrade(3, 5, Some(700), 100); // [700, 800) no overlap
        assert!(report.can_upgrade, "report: {report}");
    }

    #[test]
    fn test_binary_supports_target() {
        let c = checker(100, 5);
        let report = c.check_upgrade(99, 5, Some(900), 150);
        assert!(!report.can_upgrade);
        assert!(report.blockers().iter().any(|r| r.id == "UC-5"));
    }

    #[test]
    fn test_migration_noop_ok() {
        let c = checker(100, 5);
        let report = c.check_upgrade(1, 5, None, 0);
        let uc6 = report.results.iter().find(|r| r.id == "UC-6").unwrap();
        assert!(uc6.passed);
    }

    #[test]
    fn test_report_display() {
        let c = checker(100, 5);
        let report = c.check_upgrade(1, 5, None, 0);
        let s = format!("{report}");
        assert!(s.contains("Upgrade Constraints"));
    }

    #[test]
    fn test_can_upgrade_convenience() {
        let acts = valid_activations();
        assert!(can_upgrade(1, CURRENT_SCHEMA_VERSION, None, 0, 100, &acts));
        assert!(!can_upgrade(3, CURRENT_SCHEMA_VERSION, Some(700), 150, 100, &acts));
    }

    #[test]
    fn test_intervals_overlap_half_open() {
        assert!(intervals_overlap(10, 20, 15, 25));
        assert!(intervals_overlap(10, 20, 5, 15));
        assert!(!intervals_overlap(10, 20, 20, 30));
        assert!(!intervals_overlap(10, 20, 0, 10));
    }
}
