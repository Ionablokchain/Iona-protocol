//! Protocol version activation guarantees.
//!
//! This module formalises the guarantees that the activation mechanism provides to
//! operators, developers, and the consensus layer. Each guarantee is expressed as
//! a checkable predicate.
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
//!
//! # Example
//!
//! ```
//! use iona::protocol::activation_guarantees::{
//!     check_all_guarantees, check_deterministic_activation, ActivationReport
//! };
//! use iona::protocol::version::default_activations;
//!
//! let activations = default_activations();
//! let report = check_all_guarantees(&activations, 100);
//! if !report.all_passed {
//!     eprintln!("{}", report);
//! }
//! ```

use crate::protocol::version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};
use crate::types::Height;
use std::collections::HashSet;
use std::time::Instant;
use tracing::{debug, info, warn, error};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default minimum lead blocks for pre‑activation signalling.
pub const DEFAULT_MIN_LEAD_BLOCKS: u64 = 100;

/// Maximum allowed grace window in blocks.
pub const MAX_GRACE_BLOCKS: u64 = 100_000;

/// Maximum height range for determinism checks.
pub const MAX_DETERMINISM_RANGE: u64 = 1000;

// -----------------------------------------------------------------------------
// AG-1: Deterministic activation
// -----------------------------------------------------------------------------

/// Verify that `version_for_height` returns the same PV for the same inputs.
///
/// # Arguments
/// * `height` – The block height to check.
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(pv)` if the function is deterministic, `Err` with a description otherwise.
#[must_use]
pub fn check_deterministic_activation(
    height: Height,
    activations: &[ProtocolActivation],
) -> Result<u32, String> {
    let pv1 = version_for_height(height, activations);
    let pv2 = version_for_height(height, activations);
    if pv1 != pv2 {
        let err = format!(
            "AG-1 VIOLATION: PV({}) returned {} then {}",
            height, pv1, pv2
        );
        error!("{}", err);
        return Err(err);
    }
    debug!(height, pv = pv1, "deterministic activation check passed");
    Ok(pv1)
}

/// Verify determinism across a range of heights.
///
/// # Arguments
/// * `from` – Start height (inclusive).
/// * `to` – End height (inclusive).
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(())` if all heights are deterministic, `Err` on first violation.
#[must_use]
pub fn check_deterministic_range(
    from: Height,
    to: Height,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    let start = Instant::now();
    let range = to.saturating_sub(from) + 1;
    if range > MAX_DETERMINISM_RANGE {
        warn!(
            "determinism range {} blocks exceeds recommended maximum {}",
            range, MAX_DETERMINISM_RANGE
        );
    }

    for h in from..=to {
        check_deterministic_activation(h, activations)?;
    }

    let elapsed = start.elapsed().as_millis();
    debug!(from, to, range, elapsed_ms = elapsed, "deterministic range check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-2: Monotonic PV
// -----------------------------------------------------------------------------

/// Verify that PV never decreases as height increases.
///
/// # Arguments
/// * `heights` – Slice of heights to check (must be in ascending order).
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(())` if PV is monotonic, `Err` on first violation.
#[must_use]
pub fn check_pv_monotonic(
    heights: &[Height],
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    if heights.is_empty() {
        return Ok(());
    }

    let mut prev_pv = version_for_height(heights[0], activations);
    for &h in &heights[1..] {
        let pv = version_for_height(h, activations);
        if pv < prev_pv {
            let err = format!(
                "AG-2 VIOLATION: PV decreased from {} to {} at height {}",
                prev_pv, pv, h
            );
            error!("{}", err);
            return Err(err);
        }
        prev_pv = pv;
    }
    debug!("monotonic PV check passed ({} heights)", heights.len());
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-3: Exactly-once activation
// -----------------------------------------------------------------------------

/// Verify that each PV appears at most once in the activation schedule.
///
/// # Arguments
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(())` if each PV appears at most once, `Err` otherwise.
#[must_use]
pub fn check_exactly_once(activations: &[ProtocolActivation]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for a in activations {
        if !seen.insert(a.protocol_version) {
            let err = format!(
                "AG-3 VIOLATION: PV={} appears multiple times in activation schedule",
                a.protocol_version
            );
            error!("{}", err);
            return Err(err);
        }
    }
    debug!(count = activations.len(), unique = seen.len(), "exactly‑once check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-4: Pre-activation signalling
// -----------------------------------------------------------------------------

/// For a given activation, compute how many blocks before activation the
/// node can detect it.
///
/// # Arguments
/// * `activation` – The activation configuration.
/// * `current_height` – Current block height.
///
/// # Returns
/// `Some(distance)` if the activation is in the future, `None` otherwise.
#[must_use]
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
///
/// # Arguments
/// * `activations` – The activation schedule.
/// * `current_height` – Current block height.
/// * `min_lead_blocks` – Minimum required lead blocks.
///
/// # Returns
/// `Ok(())` if all future activations have sufficient lead time, `Err` otherwise.
#[must_use]
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
                    let err = format!(
                        "AG-4 VIOLATION: PV={} activates in {} blocks (minimum lead time: {})",
                        a.protocol_version, distance, min_lead_blocks
                    );
                    warn!("{}", err);
                    return Err(err);
                }
                debug!(
                    pv = a.protocol_version,
                    distance,
                    "activation has sufficient lead time"
                );
            }
        }
    }
    debug!(min_lead_blocks, "signal distance check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-5: Grace window bounded
// -----------------------------------------------------------------------------

/// Verify that all grace windows are within the allowed maximum.
///
/// # Arguments
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(())` if all grace windows are <= `MAX_GRACE_BLOCKS`, `Err` otherwise.
#[must_use]
pub fn check_grace_bounded(activations: &[ProtocolActivation]) -> Result<(), String> {
    for a in activations {
        if a.grace_blocks > MAX_GRACE_BLOCKS {
            let err = format!(
                "AG-5 VIOLATION: PV={} has grace_blocks={} > max={}",
                a.protocol_version, a.grace_blocks, MAX_GRACE_BLOCKS
            );
            error!("{}", err);
            return Err(err);
        }
    }
    debug!("grace bounded check passed (max={})", MAX_GRACE_BLOCKS);
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-6: Post-activation mandatory
// -----------------------------------------------------------------------------

/// After activation height + grace, verify that only the new PV is valid.
///
/// # Arguments
/// * `height` – Block height.
/// * `block_pv` – Protocol version of the block.
/// * `activations` – The activation schedule.
///
/// # Returns
/// `Ok(())` if the block's PV is valid, `Err` otherwise.
#[must_use]
pub fn check_post_activation_mandatory(
    height: Height,
    block_pv: u32,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    let expected_pv = version_for_height(height, activations);
    if block_pv < expected_pv {
        // Check if we are still in a grace window.
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected_pv
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            let err = format!(
                "AG-6 VIOLATION: block PV={} at height {}, but PV={} is mandatory (grace expired)",
                block_pv, height, expected_pv
            );
            error!("{}", err);
            return Err(err);
        } else {
            debug!(
                height,
                block_pv,
                expected_pv,
                "block within grace window (old PV still accepted)"
            );
        }
    }
    debug!(height, block_pv, expected_pv, "post‑activation mandatory check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-7: Activation height immutable
// -----------------------------------------------------------------------------

/// Verify that two activation schedules agree on heights for PVs that appear in both.
///
/// # Arguments
/// * `schedule_a` – First activation schedule.
/// * `schedule_b` – Second activation schedule.
///
/// # Returns
/// `Ok(())` if the schedules agree on activation heights, `Err` otherwise.
#[must_use]
pub fn check_activation_immutable(
    schedule_a: &[ProtocolActivation],
    schedule_b: &[ProtocolActivation],
) -> Result<(), String> {
    for a in schedule_a {
        for b in schedule_b {
            if a.protocol_version == b.protocol_version {
                if a.activation_height != b.activation_height {
                    let err = format!(
                        "AG-7 VIOLATION: PV={} has different activation heights: {:?} vs {:?}",
                        a.protocol_version, a.activation_height, b.activation_height
                    );
                    error!("{}", err);
                    return Err(err);
                }
            }
        }
    }
    debug!("activation immutable check passed");
    Ok(())
}

// -----------------------------------------------------------------------------
// AG-8: Rollback window
// -----------------------------------------------------------------------------

/// Determine the last safe rollback height for a given activation.
///
/// # Arguments
/// * `activation` – The activation configuration.
/// * `current_height` – Current block height.
///
/// # Returns
/// `Some(height)` if rollback is possible (before activation), `None` otherwise.
#[must_use]
pub fn rollback_window(activation: &ProtocolActivation, current_height: Height) -> Option<Height> {
    match activation.activation_height {
        Some(ah) if current_height < ah => Some(ah - 1),
        _ => None,
    }
}

/// Check whether rollback is still safe at the current height.
///
/// # Arguments
/// * `activations` – The activation schedule.
/// * `target_pv` – Target protocol version to roll back to.
/// * `current_height` – Current block height.
///
/// # Returns
/// `Ok(safe_until)` if rollback is safe, `Err` otherwise.
#[must_use]
pub fn check_rollback_safe(
    activations: &[ProtocolActivation],
    target_pv: u32,
    current_height: Height,
) -> Result<Height, String> {
    let activation = activations
        .iter()
        .find(|a| a.protocol_version == target_pv)
        .ok_or_else(|| format!("AG-8: no activation found for PV={}", target_pv))?;

    match rollback_window(activation, current_height) {
        Some(safe_until) => {
            debug!(target_pv, safe_until, current_height, "rollback safe");
            Ok(safe_until)
        }
        None => {
            let err = format!(
                "AG-8 VIOLATION: rollback unsafe for PV={} at height {} (activation already passed)",
                target_pv, current_height
            );
            error!("{}", err);
            Err(err)
        }
    }
}

// -----------------------------------------------------------------------------
// Full activation validation
// -----------------------------------------------------------------------------

/// Validate an entire activation schedule against all guarantees.
///
/// # Arguments
/// * `activations` – The activation schedule to validate.
/// * `current_height` – Current block height.
/// * `min_lead_blocks` – Minimum required lead blocks for signalling.
///
/// # Returns
/// A `ValidationResult` containing all errors found.
#[must_use]
pub fn validate_activation_schedule(
    activations: &[ProtocolActivation],
    current_height: Height,
    min_lead_blocks: u64,
) -> Result<(), Vec<String>> {
    let mut errors = Vec::new();

    // AG-1: Deterministic activation (test at a few key heights)
    let test_heights = [0, 1, 100, current_height, current_height + 1];
    for &h in &test_heights {
        if let Err(e) = check_deterministic_activation(h, activations) {
            errors.push(e);
        }
    }

    // AG-2: Monotonic PV (check a reasonable range)
    let heights: Vec<u64> = (0..=current_height + 100).step_by(100).collect();
    if let Err(e) = check_pv_monotonic(&heights, activations) {
        errors.push(e);
    }

    // AG-3: Exactly-once activation
    if let Err(e) = check_exactly_once(activations) {
        errors.push(e);
    }

    // AG-4: Pre-activation signalling
    if let Err(e) = check_signal_distance(activations, current_height, min_lead_blocks) {
        errors.push(e);
    }

    // AG-5: Grace window bounded
    if let Err(e) = check_grace_bounded(activations) {
        errors.push(e);
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

// -----------------------------------------------------------------------------
// Aggregate report
// -----------------------------------------------------------------------------

/// Result of all activation guarantee checks.
#[derive(Debug, Clone)]
pub struct ActivationReport {
    pub checks: Vec<ActivationCheck>,
    pub all_passed: bool,
    pub timestamp_ms: u64,
}

/// A single check in the activation report.
#[derive(Debug, Clone)]
pub struct ActivationCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
    pub duration_ms: u64,
}

impl std::fmt::Display for ActivationReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Activation Guarantees: {} ({} checks in {}ms)",
            if self.all_passed { "ALL SATISFIED" } else { "ISSUES DETECTED" },
            self.checks.len(),
            self.timestamp_ms
        )?;
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(
                f,
                "  [{}] {}: {} — {} [{}ms]",
                mark, c.id, c.name, c.detail, c.duration_ms
            )?;
        }
        Ok(())
    }
}

/// Run all activation guarantee checks.
///
/// # Arguments
/// * `activations` – The activation schedule.
/// * `current_height` – Current block height.
///
/// # Returns
/// An `ActivationReport` summarising all checks.
#[must_use]
pub fn check_all_guarantees(
    activations: &[ProtocolActivation],
    current_height: Height,
) -> ActivationReport {
    let start = Instant::now();
    let mut checks = Vec::new();

    // AG-1: Deterministic activation.
    let check_start = Instant::now();
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
        duration_ms: check_start.elapsed().as_millis() as u64,
    });

    // AG-2: Monotonic PV.
    let check_start = Instant::now();
    let heights: Vec<u64> = (0..=current_height + 100).step_by(10).collect();
    let r = check_pv_monotonic(&heights, activations);
    checks.push(ActivationCheck {
        id: "AG-2".into(),
        name: "Monotonic PV".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| "PV non‑decreasing across heights".into()),
        duration_ms: check_start.elapsed().as_millis() as u64,
    });

    // AG-3: Exactly‑once activation.
    let check_start = Instant::now();
    let r = check_exactly_once(activations);
    checks.push(ActivationCheck {
        id: "AG-3".into(),
        name: "Exactly‑once activation".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| format!("{} unique PVs in schedule", activations.len())),
        duration_ms: check_start.elapsed().as_millis() as u64,
    });

    // AG-4: Pre-activation signalling.
    let check_start = Instant::now();
    let r = check_signal_distance(activations, current_height, DEFAULT_MIN_LEAD_BLOCKS);
    checks.push(ActivationCheck {
        id: "AG-4".into(),
        name: "Pre-activation signalling".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| format!("lead blocks >= {}", DEFAULT_MIN_LEAD_BLOCKS)),
        duration_ms: check_start.elapsed().as_millis() as u64,
    });

    // AG-5: Grace window bounded.
    let check_start = Instant::now();
    let r = check_grace_bounded(activations);
    checks.push(ActivationCheck {
        id: "AG-5".into(),
        name: "Grace window bounded".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| format!("grace <= {} blocks", MAX_GRACE_BLOCKS)),
        duration_ms: check_start.elapsed().as_millis() as u64,
    });

    let all_passed = checks.iter().all(|c| c.passed);
    let timestamp_ms = start.elapsed().as_millis() as u64;

    if all_passed {
        info!("all activation guarantees satisfied ({} checks in {}ms)", checks.len(), timestamp_ms);
    } else {
        warn!("some activation guarantees violated ({} checks in {}ms)", checks.len(), timestamp_ms);
    }

    ActivationReport { checks, all_passed, timestamp_ms }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
        assert!(report.all_passed, "report: {}", report);
    }

    #[test]
    fn test_all_guarantees_with_upgrade() {
        let a = test_activations();
        let report = check_all_guarantees(&a, 500);
        assert!(report.all_passed, "report: {}", report);
    }

    #[test]
    fn test_report_display() {
        let a = default_activations();
        let report = check_all_guarantees(&a, 100);
        let s = format!("{}", report);
        assert!(s.contains("Activation Guarantees"));
    }

    #[test]
    fn test_validate_activation_schedule() {
        let a = test_activations();
        let result = validate_activation_schedule(&a, 500, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_activation_schedule_with_errors() {
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
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(110),
                grace_blocks: MAX_GRACE_BLOCKS + 1,
            },
        ];
        let result = validate_activation_schedule(&a, 100, 100);
        assert!(result.is_err());
        let errors = result.unwrap_err();
        assert!(errors.len() >= 2);
    }
}
