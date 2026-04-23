//! ProtocolVersion transition state machine.
//!
//! Manages the lifecycle of protocol version transitions, including:
//!   - Transition scheduling and validation
//!   - Pre-activation readiness checks
//!   - Activation execution
//!   - Post-activation cleanup
//!   - Rollback support (pre-activation only)
//!
//! # State Machine
//!
//! ```text
//!   Idle ──▶ Scheduled ──▶ PreActivation ──▶ Activating ──▶ Active ──▶ Finalized
//!                │                │                                        │
//!                ▼                ▼                                        │
//!            Cancelled       RolledBack ◀─────────────────────────────────┘
//!                                                        (only with snapshot)
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! let mut mgr = TransitionManager::new(activations, current_height);
//! mgr.on_block(height);
//! let state = mgr.state();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::{debug, info, warn};

use super::version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};

// -----------------------------------------------------------------------------
// TransitionState
// -----------------------------------------------------------------------------

/// State of a protocol version transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransitionState {
    /// No transition in progress; running at stable PV.
    Idle,
    /// A transition has been scheduled but activation height is far away.
    Scheduled {
        target_pv: u32,
        activation_height: u64,
    },
    /// Within the pre-activation window; shadow validation may be running.
    PreActivation {
        target_pv: u32,
        activation_height: u64,
        /// How many blocks until activation.
        blocks_remaining: u64,
    },
    /// Activation height reached; transitioning now.
    Activating {
        from_pv: u32,
        to_pv: u32,
        activation_height: u64,
    },
    /// New PV is active; grace window still open for old‑PV blocks.
    Active { pv: u32, grace_remaining: u64 },
    /// Transition fully finalized; grace window expired.
    Finalized { pv: u32 },
    /// Transition was cancelled before activation.
    Cancelled { target_pv: u32, reason: String },
    /// Transition was rolled back (requires snapshot).
    RolledBack {
        from_pv: u32,
        to_pv: u32,
        reason: String,
    },
}

impl std::fmt::Display for TransitionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Idle => write!(f, "Idle"),
            Self::Scheduled {
                target_pv,
                activation_height,
            } => write!(f, "Scheduled(PV={target_pv} at height={activation_height})"),
            Self::PreActivation {
                target_pv,
                blocks_remaining,
                ..
            } => write!(
                f,
                "PreActivation(PV={target_pv}, {blocks_remaining} blocks remaining)"
            ),
            Self::Activating { from_pv, to_pv, .. } => {
                write!(f, "Activating(PV {from_pv} -> {to_pv})")
            }
            Self::Active {
                pv,
                grace_remaining,
            } => write!(f, "Active(PV={pv}, grace={grace_remaining} blocks)"),
            Self::Finalized { pv } => write!(f, "Finalized(PV={pv})"),
            Self::Cancelled { target_pv, reason } => {
                write!(f, "Cancelled(PV={target_pv}: {reason})")
            }
            Self::RolledBack {
                from_pv,
                to_pv,
                reason,
            } => write!(f, "RolledBack(PV {from_pv} -> {to_pv}: {reason})"),
        }
    }
}

// -----------------------------------------------------------------------------
// TransitionEvent
// -----------------------------------------------------------------------------

/// Events emitted during transition lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransitionEvent {
    /// Transition scheduled for future activation.
    TransitionScheduled {
        target_pv: u32,
        activation_height: u64,
    },
    /// Entered pre-activation window.
    EnteredPreActivation {
        target_pv: u32,
        blocks_remaining: u64,
    },
    /// Activation height reached.
    ActivationReached {
        from_pv: u32,
        to_pv: u32,
        height: u64,
    },
    /// New PV is now active (grace window open).
    PvActivated { pv: u32, grace_blocks: u64 },
    /// Grace window expired; old PV blocks rejected.
    GraceExpired { pv: u32 },
    /// Transition fully finalized.
    TransitionFinalized { pv: u32 },
    /// Transition cancelled.
    TransitionCancelled { target_pv: u32, reason: String },
    /// Transition rolled back.
    TransitionRolledBack { from_pv: u32, to_pv: u32 },
}

// -----------------------------------------------------------------------------
// ReadinessReport
// -----------------------------------------------------------------------------

/// Result of a pre-activation readiness check.
#[derive(Debug, Clone)]
pub struct ReadinessReport {
    /// Whether the node is ready for the transition.
    pub ready: bool,
    /// Individual check results.
    pub checks: Vec<ReadinessCheck>,
}

/// A single readiness check.
#[derive(Debug, Clone)]
pub struct ReadinessCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl ReadinessReport {
    /// Create a report from a list of checks.
    #[must_use]
    pub fn from_checks(checks: Vec<ReadinessCheck>) -> Self {
        let ready = checks.iter().all(|c| c.passed);
        Self { ready, checks }
    }
}

impl std::fmt::Display for ReadinessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Readiness: {}",
            if self.ready { "READY" } else { "NOT READY" }
        )?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {}", c.name, c.detail)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Pre‑activation window constant
// -----------------------------------------------------------------------------

/// Pre‑activation window size (blocks before activation to enter PreActivation state).
const PRE_ACTIVATION_WINDOW: u64 = 1000;

// -----------------------------------------------------------------------------
// TransitionManager
// -----------------------------------------------------------------------------

/// Manages protocol version transitions.
#[derive(Debug)]
pub struct TransitionManager {
    activations: Vec<ProtocolActivation>,
    state: TransitionState,
    history: Vec<(u64, TransitionState)>,
    events: Vec<TransitionEvent>,
    current_height: u64,
    current_pv: u32,
    snapshot_heights: Vec<u64>,
}

impl TransitionManager {
    /// Create a new transition manager.
    #[must_use]
    pub fn new(activations: Vec<ProtocolActivation>, current_height: u64) -> Self {
        let current_pv = version_for_height(current_height, &activations);
        let state = Self::compute_initial_state(&activations, current_height, current_pv);
        info!(current_height, current_pv, state = %state, "transition manager created");
        Self {
            activations,
            state,
            history: Vec::new(),
            events: Vec::new(),
            current_height,
            current_pv,
            snapshot_heights: Vec::new(),
        }
    }

    /// Compute the initial state based on the activation schedule and current height.
    fn compute_initial_state(
        activations: &[ProtocolActivation],
        height: u64,
        current_pv: u32,
    ) -> TransitionState {
        let next = activations.iter().find(|a| {
            a.protocol_version > current_pv
                || a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });

        match next {
            Some(a) => {
                let ah = a.activation_height.unwrap_or(0);
                let pv = a.protocol_version;

                if height < ah {
                    let blocks_remaining = ah - height;
                    if blocks_remaining <= PRE_ACTIVATION_WINDOW {
                        TransitionState::PreActivation {
                            target_pv: pv,
                            activation_height: ah,
                            blocks_remaining,
                        }
                    } else {
                        TransitionState::Scheduled {
                            target_pv: pv,
                            activation_height: ah,
                        }
                    }
                } else if height < ah + a.grace_blocks {
                    TransitionState::Active {
                        pv,
                        grace_remaining: ah + a.grace_blocks - height,
                    }
                } else {
                    TransitionState::Finalized { pv: current_pv }
                }
            }
            None => TransitionState::Idle,
        }
    }

    /// Get the current transition state.
    #[must_use]
    pub fn state(&self) -> &TransitionState {
        &self.state
    }

    /// Get the current protocol version.
    #[must_use]
    pub fn current_pv(&self) -> u32 {
        self.current_pv
    }

    /// Get the transition history.
    #[must_use]
    pub fn history(&self) -> &[(u64, TransitionState)] {
        &self.history
    }

    /// Drain pending events.
    #[must_use]
    pub fn drain_events(&mut self) -> Vec<TransitionEvent> {
        let events = std::mem::take(&mut self.events);
        debug!(count = events.len(), "drained transition events");
        events
    }

    /// Register a snapshot height for potential rollback.
    pub fn register_snapshot(&mut self, height: u64) {
        self.snapshot_heights.push(height);
        self.snapshot_heights.sort_unstable();
        debug!(height, "snapshot registered for transition manager");
    }

    /// Process a new block at the given height.
    /// Updates internal state and emits events as transitions occur.
    pub fn on_block(&mut self, height: u64) {
        self.current_height = height;
        let new_pv = version_for_height(height, &self.activations);
        let old_pv = self.current_pv;

        if new_pv != old_pv {
            debug!(old_pv, new_pv, height, "protocol version changed");
            self.current_pv = new_pv;
        }

        let new_state = self.compute_next_state(height, old_pv, new_pv);

        if new_state != self.state {
            debug!(old = %self.state, new = %new_state, height, "transition state changed");
            self.emit_transition_events(&self.state.clone(), &new_state, height, old_pv, new_pv);
            self.history.push((height, self.state.clone()));
            self.state = new_state;
        }
    }

    /// Compute the next state based on current height and PV.
    fn compute_next_state(&self, height: u64, old_pv: u32, new_pv: u32) -> TransitionState {
        let next_activation = self
            .activations
            .iter()
            .find(|a| a.protocol_version > self.current_pv && a.activation_height.is_some());

        let current_activation = self
            .activations
            .iter()
            .find(|a| a.protocol_version == new_pv && a.activation_height.is_some());

        match (&self.state, next_activation, current_activation) {
            (TransitionState::Idle, Some(next), _) => {
                let ah = next.activation_height.unwrap();
                if height >= ah + next.grace_blocks {
                    TransitionState::Finalized { pv: new_pv }
                } else if height >= ah {
                    TransitionState::Active {
                        pv: new_pv,
                        grace_remaining: ah + next.grace_blocks - height,
                    }
                } else if ah - height <= PRE_ACTIVATION_WINDOW {
                    TransitionState::PreActivation {
                        target_pv: next.protocol_version,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    }
                } else {
                    TransitionState::Scheduled {
                        target_pv: next.protocol_version,
                        activation_height: ah,
                    }
                }
            }

            (
                TransitionState::Scheduled {
                    target_pv,
                    activation_height,
                },
                _,
                _,
            ) => {
                let ah = *activation_height;
                let tpv = *target_pv;
                if height >= ah {
                    if old_pv != new_pv {
                        TransitionState::Activating {
                            from_pv: old_pv,
                            to_pv: new_pv,
                            activation_height: ah,
                        }
                    } else {
                        TransitionState::Active {
                            pv: new_pv,
                            grace_remaining: 0,
                        }
                    }
                } else if ah - height <= PRE_ACTIVATION_WINDOW {
                    TransitionState::PreActivation {
                        target_pv: tpv,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    }
                } else {
                    self.state.clone()
                }
            }

            (
                TransitionState::PreActivation {
                    target_pv,
                    activation_height,
                    ..
                },
                _,
                _,
            ) => {
                let ah = *activation_height;
                let tpv = *target_pv;
                if height >= ah {
                    TransitionState::Activating {
                        from_pv: old_pv,
                        to_pv: new_pv,
                        activation_height: ah,
                    }
                } else {
                    TransitionState::PreActivation {
                        target_pv: tpv,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    }
                }
            }

            (
                TransitionState::Activating {
                    to_pv,
                    activation_height,
                    ..
                },
                _,
                _,
            ) => {
                let grace = self
                    .activations
                    .iter()
                    .find(|a| a.protocol_version == *to_pv)
                    .map(|a| a.grace_blocks)
                    .unwrap_or(0);
                let ah = *activation_height;
                if grace > 0 && height < ah + grace {
                    TransitionState::Active {
                        pv: new_pv,
                        grace_remaining: ah + grace - height,
                    }
                } else {
                    TransitionState::Finalized { pv: new_pv }
                }
            }

            (
                TransitionState::Active {
                    pv,
                    grace_remaining,
                },
                _,
                _,
            ) => {
                if *grace_remaining <= 1 {
                    TransitionState::Finalized { pv: *pv }
                } else {
                    TransitionState::Active {
                        pv: *pv,
                        grace_remaining: grace_remaining - 1,
                    }
                }
            }

            (TransitionState::Finalized { .. }, Some(next), _) => {
                let ah = next.activation_height.unwrap();
                if height < ah {
                    if ah - height <= PRE_ACTIVATION_WINDOW {
                        TransitionState::PreActivation {
                            target_pv: next.protocol_version,
                            activation_height: ah,
                            blocks_remaining: ah - height,
                        }
                    } else {
                        TransitionState::Scheduled {
                            target_pv: next.protocol_version,
                            activation_height: ah,
                        }
                    }
                } else {
                    self.state.clone()
                }
            }

            _ => self.state.clone(),
        }
    }

    /// Emit events for a state transition.
    fn emit_transition_events(
        &mut self,
        old: &TransitionState,
        new: &TransitionState,
        height: u64,
        old_pv: u32,
        new_pv: u32,
    ) {
        match new {
            TransitionState::Scheduled {
                target_pv,
                activation_height,
            } => {
                self.events.push(TransitionEvent::TransitionScheduled {
                    target_pv: *target_pv,
                    activation_height: *activation_height,
                });
            }
            TransitionState::PreActivation {
                target_pv,
                blocks_remaining,
                ..
            } => {
                self.events.push(TransitionEvent::EnteredPreActivation {
                    target_pv: *target_pv,
                    blocks_remaining: *blocks_remaining,
                });
            }
            TransitionState::Activating {
                from_pv,
                to_pv,
                activation_height,
            } => {
                self.events.push(TransitionEvent::ActivationReached {
                    from_pv: *from_pv,
                    to_pv: *to_pv,
                    height: *activation_height,
                });
            }
            TransitionState::Active {
                pv,
                grace_remaining,
            } => {
                self.events.push(TransitionEvent::PvActivated {
                    pv: *pv,
                    grace_blocks: *grace_remaining,
                });
            }
            TransitionState::Finalized { pv } => {
                self.events
                    .push(TransitionEvent::TransitionFinalized { pv: *pv });
            }
            TransitionState::Cancelled { target_pv, reason } => {
                self.events.push(TransitionEvent::TransitionCancelled {
                    target_pv: *target_pv,
                    reason: reason.clone(),
                });
            }
            TransitionState::RolledBack { from_pv, to_pv, .. } => {
                self.events.push(TransitionEvent::TransitionRolledBack {
                    from_pv: *from_pv,
                    to_pv: *to_pv,
                });
            }
            _ => {}
        }
    }

    /// Cancel a scheduled transition (only valid before activation).
    pub fn cancel(&mut self, reason: &str) -> Result<(), String> {
        match &self.state {
            TransitionState::Scheduled { target_pv, .. }
            | TransitionState::PreActivation { target_pv, .. } => {
                let tpv = *target_pv;
                info!(target_pv = tpv, reason, "cancelling scheduled transition");
                self.history.push((self.current_height, self.state.clone()));
                self.state = TransitionState::Cancelled {
                    target_pv: tpv,
                    reason: reason.to_string(),
                };
                self.events.push(TransitionEvent::TransitionCancelled {
                    target_pv: tpv,
                    reason: reason.to_string(),
                });
                Ok(())
            }
            _ => {
                let err = format!("cannot cancel transition in state: {}", self.state);
                warn!("{}", err);
                Err(err)
            }
        }
    }

    /// Attempt rollback to a previous PV (requires snapshot before activation).
    pub fn rollback(&mut self, reason: &str) -> Result<u64, String> {
        let activation_height = match &self.state {
            TransitionState::Active { .. } | TransitionState::Activating { .. } => self
                .activations
                .iter()
                .filter(|a| a.protocol_version == self.current_pv)
                .filter_map(|a| a.activation_height)
                .max()
                .ok_or_else(|| {
                    let err = "no activation height found".to_string();
                    warn!("{}", err);
                    err
                })?,
            _ => {
                let err = format!("cannot rollback in state: {}", self.state);
                warn!("{}", err);
                return Err(err);
            }
        };

        let snapshot = self
            .snapshot_heights
            .iter()
            .rev()
            .find(|&&h| h < activation_height)
            .copied()
            .ok_or_else(|| {
                let err = "no snapshot available before activation height".to_string();
                warn!("{}", err);
                err
            })?;

        let from_pv = self.current_pv;
        let to_pv = version_for_height(snapshot, &self.activations);

        info!(
            from_pv,
            to_pv,
            snapshot,
            reason,
            "rolling back transition"
        );
        self.history.push((self.current_height, self.state.clone()));
        self.state = TransitionState::RolledBack {
            from_pv,
            to_pv,
            reason: reason.to_string(),
        };
        self.events
            .push(TransitionEvent::TransitionRolledBack { from_pv, to_pv });
        self.current_pv = to_pv;

        Ok(snapshot)
    }

    /// Run pre‑activation readiness checks.
    #[must_use]
    pub fn check_readiness(&self) -> ReadinessReport {
        debug!("running readiness checks");
        let mut checks = Vec::new();

        let target_pv = match &self.state {
            TransitionState::Scheduled { target_pv, .. }
            | TransitionState::PreActivation { target_pv, .. } => Some(*target_pv),
            _ => None,
        };

        if let Some(tpv) = target_pv {
            checks.push(ReadinessCheck {
                name: "binary_supports_target_pv".into(),
                passed: SUPPORTED_PROTOCOL_VERSIONS.contains(&tpv),
                detail: format!("target PV={tpv}, supported={SUPPORTED_PROTOCOL_VERSIONS:?}"),
            });
        }

        checks.push(ReadinessCheck {
            name: "current_pv_supported".into(),
            passed: SUPPORTED_PROTOCOL_VERSIONS.contains(&self.current_pv),
            detail: format!("current PV={}", self.current_pv),
        });

        checks.push(ReadinessCheck {
            name: "snapshot_available".into(),
            passed: !self.snapshot_heights.is_empty(),
            detail: format!("{} snapshots registered", self.snapshot_heights.len()),
        });

        let schedule_valid = self.activations.windows(2).all(|w| {
            let a = &w[0];
            let b = &w[1];
            b.protocol_version > a.protocol_version
        });
        checks.push(ReadinessCheck {
            name: "activation_schedule_valid".into(),
            passed: schedule_valid,
            detail: format!("{} activations defined", self.activations.len()),
        });

        checks.push(ReadinessCheck {
            name: "no_pending_state".into(),
            passed: !matches!(
                self.state,
                TransitionState::Cancelled { .. } | TransitionState::RolledBack { .. }
            ),
            detail: format!("current state: {}", self.state),
        });

        let report = ReadinessReport::from_checks(checks);
        if report.ready {
            info!("readiness check passed");
        } else {
            warn!("readiness check failed");
        }
        report
    }

    /// Validate that a block's PV is correct for the given height.
    pub fn validate_block_pv(&self, block_pv: u32, height: u64) -> Result<(), String> {
        super::version::validate_block_version(block_pv, height, &self.activations)
    }

    /// Get a summary of the transition manager's state.
    #[must_use]
    pub fn summary(&self) -> TransitionSummary {
        TransitionSummary {
            current_height: self.current_height,
            current_pv: self.current_pv,
            state: format!("{}", self.state),
            history_len: self.history.len(),
            snapshots: self.snapshot_heights.len(),
            pending_events: self.events.len(),
        }
    }
}

// -----------------------------------------------------------------------------
// TransitionSummary
// -----------------------------------------------------------------------------

/// Summary of the transition manager state (for RPC / metrics).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionSummary {
    pub current_height: u64,
    pub current_pv: u32,
    pub state: String,
    pub history_len: usize,
    pub snapshots: usize,
    pub pending_events: usize,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn basic_activations() -> Vec<ProtocolActivation> {
        vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }]
    }

    fn upgrade_activations() -> Vec<ProtocolActivation> {
        vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 10,
            },
        ]
    }

    #[test]
    fn test_initial_state_idle() {
        let mgr = TransitionManager::new(basic_activations(), 50);
        assert!(matches!(mgr.state(), TransitionState::Idle));
        assert_eq!(mgr.current_pv(), 1);
    }

    #[test]
    fn test_initial_state_scheduled() {
        let mgr = TransitionManager::new(upgrade_activations(), 1);
        // Height 1 with activation at 100: blocks_remaining = 99 < PRE_ACTIVATION_WINDOW (1000) → PreActivation
        assert!(matches!(mgr.state(), TransitionState::PreActivation { .. }));
    }

    #[test]
    fn test_transition_to_pre_activation() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1);
        assert!(matches!(mgr.state(), TransitionState::Scheduled { .. }));

        mgr.on_block(1001);
        assert!(matches!(mgr.state(), TransitionState::PreActivation { .. }));
    }

    #[test]
    fn test_cancel_scheduled() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1);
        assert!(matches!(mgr.state(), TransitionState::Scheduled { .. }));

        let result = mgr.cancel("critical bug found");
        assert!(result.is_ok());
        assert!(matches!(mgr.state(), TransitionState::Cancelled { .. }));

        let events = mgr.drain_events();
        assert!(events
            .iter()
            .any(|e| matches!(e, TransitionEvent::TransitionCancelled { .. })));
    }

    #[test]
    fn test_cancel_invalid_state() {
        let mut mgr = TransitionManager::new(basic_activations(), 50);
        assert!(mgr.cancel("test").is_err());
    }

    #[test]
    fn test_readiness_check() {
        let mut mgr = TransitionManager::new(upgrade_activations(), 50);
        mgr.register_snapshot(40);

        let report = mgr.check_readiness();
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "current_pv_supported" && c.passed));
        assert!(report
            .checks
            .iter()
            .any(|c| c.name == "snapshot_available" && c.passed));
    }

    #[test]
    fn test_summary() {
        let mgr = TransitionManager::new(basic_activations(), 50);
        let summary = mgr.summary();
        assert_eq!(summary.current_height, 50);
        assert_eq!(summary.current_pv, 1);
    }

    #[test]
    fn test_state_display() {
        assert_eq!(format!("{}", TransitionState::Idle), "Idle");
        assert_eq!(
            format!("{}", TransitionState::Finalized { pv: 2 }),
            "Finalized(PV=2)"
        );
    }

    #[test]
    fn test_history_tracking() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(2000),
                grace_blocks: 10,
            },
        ];
        let mut mgr = TransitionManager::new(activations, 1);
        assert!(mgr.history().is_empty());

        mgr.on_block(1001);
        assert!(!mgr.history().is_empty());
    }
}
