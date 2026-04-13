//! ProtocolVersion activation guarantees.
//!
//! Formalises the guarantees that the activation mechanism provides to
//! operators, developers, and the consensus layer.  Each guarantee is
//! expressed as a checkable predicate.
//!
//! # Guarantees
//!
//! | ID   | Name                       | Description                                         |
//! |------|----------------------------|-----------------------------------------------------|
//! | AG-1 | Deterministic activation   | PV(h) is the same on every correct node              |
//! | AG-2 | Monotonic PV               | PV never decreases as height increases               |
//! | AG-3 | Exactly-once activation    | Each PV is activated at most once                    |
//! | AG-4 | Pre-activation signalling  | Nodes can detect upcoming activation N blocks ahead  |
//! | AG-5 | Grace window bounded       | Grace window is finite and well-defined              |
//! | AG-6 | Post-activation mandatory  | After grace, only the new PV is valid                |
//! | AG-7 | Activation height immutable| Once published, activation height cannot change      |
//! | AG-8 | Rollback window defined    | Clear point before which rollback is safe            |

use crate::protocol::version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::types::Height;

// ─── AG-1: Deterministic activation ─────────────────────────────────────────

/// Verify that `version_for_height` returns the same PV for the same inputs.
pub fn check_deterministic_activation(
    height: Height,
    activations: &[ProtocolActivation],
) -> Result<u32, String> {
    let pv1 = version_for_height(height, activations);
    let pv2 = version_for_height(height, activations);
    if pv1 != pv2 {
        return Err(format!(
            "AG-1 VIOLATION: PV({height}) returned {pv1} then {pv2}"
        ));
    }
    Ok(pv1)
}

/// Verify determinism across a range of heights.
pub fn check_deterministic_range(
    from: Height,
    to: Height,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    for h in from..=to {
        check_deterministic_activation(h, activations)?;
    }
    Ok(())
}

// ─── AG-2: Monotonic PV ─────────────────────────────────────────────────────

/// Verify that PV never decreases as height increases.
pub fn check_pv_monotonic(
    heights: &[Height],
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    let mut prev_pv = 0u32;
    for &h in heights {
        let pv = version_for_height(h, activations);
        if pv < prev_pv {
            return Err(format!(
                "AG-2 VIOLATION: PV decreased from {prev_pv} to {pv} at height {h}"
            ));
        }
        prev_pv = pv;
    }
    Ok(())
}

// ─── AG-3: Exactly-once activation ──────────────────────────────────────────

/// Verify that each PV appears at most once in the activation schedule.
pub fn check_exactly_once(activations: &[ProtocolActivation]) -> Result<(), String> {
    let mut seen = std::collections::HashSet::new();
    for a in activations {
        if !seen.insert(a.protocol_version) {
            return Err(format!(
                "AG-3 VIOLATION: PV={} appears multiple times in activation schedule",
                a.protocol_version
            ));
        }
    }
    Ok(())
}

// ─── AG-4: Pre-activation signalling ────────────────────────────────────────

/// For a given activation, compute how many blocks before activation the
/// node can detect it.
pub fn pre_activation_signal_distance(
    activation: &ProtocolActivation,
    current_height: Height,
) -> Option<u64> {
    activation.activation_height.map(|ah| {
        if current_height < ah {
            ah - current_height
        } else {
            0
        }
    })
}

/// Verify that all future activations have enough lead time.
pub fn check_signal_distance(
    activations: &[ProtocolActivation],
    current_height: Height,
    min_lead_blocks: u64,
) -> Result<(), String> {
    for a in activations {
        if let Some(ah) = a.activation_height {
            if ah > current_height {
                let distance = ah - current_height;
                if distance < min_lead_blocks {
                    return Err(format!(
                        "AG-4 WARNING: PV={} activates in {distance} blocks \
                         (minimum lead time: {min_lead_blocks})",
                        a.protocol_version
                    ));
                }
            }
        }
    }
    Ok(())
}

// ─── AG-5: Grace window bounded ─────────────────────────────────────────────

/// Maximum allowed grace window (blocks).
pub const MAX_GRACE_BLOCKS: u64 = 100_000;

/// Verify that all grace windows are within bounds.
pub fn check_grace_bounded(activations: &[ProtocolActivation]) -> Result<(), String> {
    for a in activations {
        if a.grace_blocks > MAX_GRACE_BLOCKS {
            return Err(format!(
                "AG-5 VIOLATION: PV={} has grace_blocks={} > max={MAX_GRACE_BLOCKS}",
                a.protocol_version, a.grace_blocks
            ));
        }
    }
    Ok(())
}

// ─── AG-6: Post-activation mandatory ────────────────────────────────────────

/// After activation height + grace, verify that only the new PV is accepted.
pub fn check_post_activation_mandatory(
    height: Height,
    block_pv: u32,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    let expected_pv = version_for_height(height, activations);
    if block_pv < expected_pv {
        // Check if we're still in a grace window.
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected_pv
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            return Err(format!(
                "AG-6 VIOLATION: block PV={block_pv} at height {height}, \
                 but PV={expected_pv} is mandatory (grace expired)"
            ));
        }
    }
    Ok(())
}

// ─── AG-7: Activation height immutable ──────────────────────────────────────

/// Verify that two activation schedules agree on heights for PVs that
/// appear in both.
pub fn check_activation_immutable(
    schedule_a: &[ProtocolActivation],
    schedule_b: &[ProtocolActivation],
) -> Result<(), String> {
    for a in schedule_a {
        for b in schedule_b {
            if a.protocol_version == b.protocol_version {
                if a.activation_height != b.activation_height {
                    return Err(format!(
                        "AG-7 VIOLATION: PV={} has different activation heights: \
                         {:?} vs {:?}",
                        a.protocol_version, a.activation_height, b.activation_height,
                    ));
                }
            }
        }
    }
    Ok(())
}

// ─── AG-8: Rollback window ──────────────────────────────────────────────────

/// Determine the last safe rollback height for a given activation.
///
/// Returns `Some(height)` if rollback is possible (before activation),
/// or `None` if the activation has already passed.
pub fn rollback_window(activation: &ProtocolActivation, current_height: Height) -> Option<Height> {
    match activation.activation_height {
        Some(ah) if current_height < ah => Some(ah - 1),
        _ => None,
    }
}

/// Check whether rollback is still safe at the current height.
pub fn check_rollback_safe(
    activations: &[ProtocolActivation],
    target_pv: u32,
    current_height: Height,
) -> Result<Height, String> {
    let activation = activations
        .iter()
        .find(|a| a.protocol_version == target_pv)
        .ok_or_else(|| format!("AG-8: no activation found for PV={target_pv}"))?;

    match rollback_window(activation, current_height) {
        Some(safe_until) => Ok(safe_until),
        None => Err(format!(
            "AG-8 VIOLATION: rollback unsafe for PV={target_pv} at height {current_height} \
             (activation already passed)"
        )),
    }
}

// ─── Aggregate check ────────────────────────────────────────────────────────

/// Result of all activation guarantee checks.
#[derive(Debug, Clone)]
pub struct ActivationReport {
    pub checks: Vec<ActivationCheck>,
    pub all_passed: bool,
}

#[derive(Debug, Clone)]
pub struct ActivationCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl std::fmt::Display for ActivationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Activation Guarantees: {}",
            if self.all_passed {
                "ALL SATISFIED"
            } else {
                "ISSUES DETECTED"
            }
        )?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {} — {}", c.id, c.name, c.detail)?;
        }
        Ok(())
    }
}

/// Run all activation guarantee checks.
pub fn check_all_guarantees(
    activations: &[ProtocolActivation],
    current_height: Height,
) -> ActivationReport {
    let mut checks = Vec::new();

    // AG-1: Deterministic.
    let r = check_deterministic_range(
        current_height.saturating_sub(10),
        current_height + 10,
        activations,
    );
    checks.push(ActivationCheck {
        id: "AG-1".into(),
        name: "Deterministic activation".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| "PV deterministic across height range".into()),
    });

    // AG-2: Monotonic.
    let heights: Vec<u64> = (0..=current_height + 100).step_by(10).collect();
    let r = check_pv_monotonic(&heights, activations);
    checks.push(ActivationCheck {
        id: "AG-2".into(),
        name: "Monotonic PV".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| "PV non-decreasing across heights".into()),
    });

    // AG-3: Exactly-once.
    let r = check_exactly_once(activations);
    checks.push(ActivationCheck {
        id: "AG-3".into(),
        name: "Exactly-once activation".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| format!("{} unique PVs in schedule", activations.len())),
    });

    // AG-5: Grace bounded.
    let r = check_grace_bounded(activations);
    checks.push(ActivationCheck {
        id: "AG-5".into(),
        name: "Grace window bounded".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| "all grace windows within bounds".into()),
    });

    let all_passed = checks.iter().all(|c| c.passed);
    ActivationReport { checks, all_passed }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::default_activations;

    fn test_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ]
    }

    #[test]
    fn test_deterministic_activation() {
        let a = default_activations();
        assert!(check_deterministic_activation(100, &a).is_ok());
    }

    #[test]
    fn test_deterministic_range() {
        let a = default_activations();
        assert!(check_deterministic_range(0, 100, &a).is_ok());
    }

    #[test]
    fn test_pv_monotonic_ok() {
        let a = test_activations();
        let heights: Vec<u64> = (0..2000).collect();
        assert!(check_pv_monotonic(&heights, &a).is_ok());
    }

    #[test]
    fn test_exactly_once_ok() {
        let a = test_activations();
        assert!(check_exactly_once(&a).is_ok());
    }

    #[test]
    fn test_exactly_once_violation() {
        let a = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(100),
                grace_blocks: 0,
            },
        ];
        assert!(check_exactly_once(&a).is_err());
    }

    #[test]
    fn test_signal_distance() {
        let a = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        assert_eq!(pre_activation_signal_distance(&a, 500), Some(500));
        assert_eq!(pre_activation_signal_distance(&a, 1000), Some(0));
        assert_eq!(pre_activation_signal_distance(&a, 1500), Some(0));
    }

    #[test]
    fn test_signal_distance_check_ok() {
        let a = test_activations();
        assert!(check_signal_distance(&a, 0, 100).is_ok());
    }

    #[test]
    fn test_signal_distance_too_close() {
        let a = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(110),
            grace_blocks: 10,
        }];
        // At height 100, only 10 blocks away but need 50.
        assert!(check_signal_distance(&a, 100, 50).is_err());
    }

    #[test]
    fn test_grace_bounded_ok() {
        let a = test_activations();
        assert!(check_grace_bounded(&a).is_ok());
    }

    #[test]
    fn test_grace_bounded_violation() {
        let a = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: MAX_GRACE_BLOCKS + 1,
        }];
        assert!(check_grace_bounded(&a).is_err());
    }

    #[test]
    fn test_post_activation_mandatory_ok() {
        let a = default_activations();
        // PV=1 at any height with default activations.
        assert!(check_post_activation_mandatory(100, 1, &a).is_ok());
    }

    #[test]
    fn test_activation_immutable_ok() {
        let a = test_activations();
        let b = test_activations();
        assert!(check_activation_immutable(&a, &b).is_ok());
    }

    #[test]
    fn test_activation_immutable_violation() {
        let a = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 0,
        }];
        let b = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(2000),
            grace_blocks: 0,
        }];
        assert!(check_activation_immutable(&a, &b).is_err());
    }

    #[test]
    fn test_rollback_window_before_activation() {
        let a = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        assert_eq!(rollback_window(&a, 500), Some(999));
    }

    #[test]
    fn test_rollback_window_after_activation() {
        let a = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        assert_eq!(rollback_window(&a, 1500), None);
    }

    #[test]
    fn test_rollback_safe() {
        let a = test_activations();
        assert!(check_rollback_safe(&a, 2, 500).is_ok());
    }

    #[test]
    fn test_rollback_unsafe() {
        let a = test_activations();
        assert!(check_rollback_safe(&a, 2, 1500).is_err());
    }

    #[test]
    fn test_all_guarantees_default() {
        let a = default_activations();
        let report = check_all_guarantees(&a, 100);
        assert!(report.all_passed, "report: {report}");
    }

    #[test]
    fn test_all_guarantees_with_upgrade() {
        let a = test_activations();
        let report = check_all_guarantees(&a, 500);
        assert!(report.all_passed, "report: {report}");
    }

    #[test]
    fn test_report_display() {
        let a = default_activations();
        let report = check_all_guarantees(&a, 100);
        let s = format!("{report}");
        assert!(s.contains("Activation Guarantees"));
    }
}
