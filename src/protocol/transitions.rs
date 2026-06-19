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
//! use iona::protocol::transitions::{TransitionManager, TransitionConfig};
//!
//! let config = TransitionConfig::default();
//! let mut mgr = TransitionManager::new(activations, current_height, config);
//! mgr.on_block(height);
//! let state = mgr.state();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use super::version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default pre‑activation window size (blocks before activation to enter PreActivation state).
pub const DEFAULT_PRE_ACTIVATION_WINDOW: u64 = 1000;

/// Maximum grace window allowed.
pub const MAX_GRACE_WINDOW: u64 = 100_000;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during transition management.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TransitionError {
    #[error("transition cannot be cancelled in state {state}")]
    NotCancellable { state: String },

    #[error("transition cannot be rolled back in state {state}")]
    NotRollbackable { state: String },

    #[error("no snapshot available before activation height {height}")]
    NoSnapshot { height: u64 },

    #[error("activation height {height} is not in the future")]
    ActivationInPast { height: u64, current: u64 },

    #[error("target protocol version {pv} is not supported")]
    UnsupportedTarget { pv: u32 },

    #[error("grace window {grace} exceeds maximum {max}")]
    GraceTooLarge { grace: u64, max: u64 },

    #[error("invalid transition: {0}")]
    InvalidTransition(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type TransitionResult<T> = Result<T, TransitionError>;

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
    /// Within the pre‑activation window; shadow validation may be running.
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
    Active {
        pv: u32,
        grace_remaining: u64,
    },
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

impl TransitionState {
    /// Check if the state is terminal (Idle, Cancelled, RolledBack, or Finalized).
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            TransitionState::Idle
                | TransitionState::Cancelled { .. }
                | TransitionState::RolledBack { .. }
                | TransitionState::Finalized { .. }
        )
    }

    /// Check if the state is active (Scheduled, PreActivation, Activating, Active).
    pub fn is_active(&self) -> bool {
        !self.is_terminal()
    }

    /// Get the target protocol version if in a transition state.
    pub fn target_pv(&self) -> Option<u32> {
        match self {
            TransitionState::Scheduled { target_pv, .. } => Some(*target_pv),
            TransitionState::PreActivation { target_pv, .. } => Some(*target_pv),
            TransitionState::Activating { to_pv, .. } => Some(*to_pv),
            TransitionState::Active { pv, .. } => Some(*pv),
            TransitionState::Finalized { pv } => Some(*pv),
            _ => None,
        }
    }

    /// Get the activation height if applicable.
    pub fn activation_height(&self) -> Option<u64> {
        match self {
            TransitionState::Scheduled {
                activation_height, ..
            } => Some(*activation_height),
            TransitionState::PreActivation {
                activation_height, ..
            } => Some(*activation_height),
            TransitionState::Activating {
                activation_height, ..
            } => Some(*activation_height),
            _ => None,
        }
    }
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
    TransitionScheduled {
        target_pv: u32,
        activation_height: u64,
    },
    EnteredPreActivation {
        target_pv: u32,
        blocks_remaining: u64,
    },
    ActivationReached {
        from_pv: u32,
        to_pv: u32,
        height: u64,
    },
    PvActivated {
        pv: u32,
        grace_blocks: u64,
    },
    GraceExpired { pv: u32 },
    TransitionFinalized { pv: u32 },
    TransitionCancelled { target_pv: u32, reason: String },
    TransitionRolledBack { from_pv: u32, to_pv: u32 },
}

// -----------------------------------------------------------------------------
// ReadinessReport
// -----------------------------------------------------------------------------

/// Result of a pre‑activation readiness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessReport {
    pub ready: bool,
    pub checks: Vec<ReadinessCheck>,
    pub timestamp_ms: u64,
}

impl ReadinessReport {
    /// Create a report from a list of checks and duration.
    pub fn new(checks: Vec<ReadinessCheck>, duration: Duration) -> Self {
        let ready = checks.iter().all(|c| c.passed);
        Self {
            ready,
            checks,
            timestamp_ms: duration.as_millis() as u64,
        }
    }

    /// Get the list of failed checks.
    pub fn failures(&self) -> Vec<&ReadinessCheck> {
        self.checks.iter().filter(|c| !c.passed).collect()
    }

    /// Get the list of passed checks.
    pub fn successes(&self) -> Vec<&ReadinessCheck> {
        self.checks.iter().filter(|c| c.passed).collect()
    }
}

impl std::fmt::Display for ReadinessReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Readiness: {} ({} checks, {}ms)",
            if self.ready { "READY" } else { "NOT READY" },
            self.checks.len(),
            self.timestamp_ms
        )?;
        for c in &self.checks {
            let mark = if c.passed { "✓" } else { "✗" };
            writeln!(f, "  [{}] {}: {}", mark, c.name, c.detail)?;
        }
        Ok(())
    }
}

/// A single readiness check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl ReadinessCheck {
    /// Create a new readiness check.
    pub fn new(name: &str, passed: bool, detail: &str) -> Self {
        Self {
            name: name.to_string(),
            passed,
            detail: detail.to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the transition manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransitionConfig {
    /// Pre‑activation window size (blocks before activation).
    pub pre_activation_window: u64,
    /// Maximum grace window allowed.
    pub max_grace_window: u64,
    /// Whether to enable automatic transition processing.
    pub auto_process: bool,
    /// Whether to log detailed transition events.
    pub verbose_logging: bool,
}

impl Default for TransitionConfig {
    fn default() -> Self {
        Self {
            pre_activation_window: DEFAULT_PRE_ACTIVATION_WINDOW,
            max_grace_window: MAX_GRACE_WINDOW,
            auto_process: true,
            verbose_logging: true,
        }
    }
}

impl TransitionConfig {
    /// Create a config with all features enabled.
    pub fn full() -> Self {
        Self {
            pre_activation_window: DEFAULT_PRE_ACTIVATION_WINDOW,
            max_grace_window: MAX_GRACE_WINDOW,
            auto_process: true,
            verbose_logging: true,
        }
    }

    /// Create a config for production (minimal logging).
    pub fn production() -> Self {
        Self {
            pre_activation_window: DEFAULT_PRE_ACTIVATION_WINDOW,
            max_grace_window: MAX_GRACE_WINDOW,
            auto_process: true,
            verbose_logging: false,
        }
    }

    /// Create a config for testing (fast transitions).
    pub fn test() -> Self {
        Self {
            pre_activation_window: 10,
            max_grace_window: 100,
            auto_process: true,
            verbose_logging: true,
        }
    }
}

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
    config: TransitionConfig,
}

impl TransitionManager {
    /// Create a new transition manager with default configuration.
    pub fn new(activations: Vec<ProtocolActivation>, current_height: u64) -> Self {
        Self::with_config(activations, current_height, TransitionConfig::default())
    }

    /// Create a new transition manager with custom configuration.
    pub fn with_config(
        activations: Vec<ProtocolActivation>,
        current_height: u64,
        config: TransitionConfig,
    ) -> Self {
        // Validate configuration.
        if config.pre_activation_window == 0 {
            warn!("pre_activation_window is 0; transitions will not have a pre-activation phase");
        }

        let current_pv = version_for_height(current_height, &activations);
        let state = Self::compute_initial_state(&activations, current_height, current_pv, &config);
        info!(
            current_height,
            current_pv,
            state = %state,
            "transition manager created"
        );
        Self {
            activations,
            state,
            history: Vec::new(),
            events: Vec::new(),
            current_height,
            current_pv,
            snapshot_heights: Vec::new(),
            config,
        }
    }

    /// Compute the initial state based on the activation schedule and current height.
    fn compute_initial_state(
        activations: &[ProtocolActivation],
        height: u64,
        current_pv: u32,
        config: &TransitionConfig,
    ) -> TransitionState {
        let next = activations.iter().find(|a| {
            a.protocol_version > current_pv
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });

        match next {
            Some(a) => {
                let ah = a.activation_height.unwrap_or(0);
                let pv = a.protocol_version;

                if height < ah {
                    let blocks_remaining = ah - height;
                    if blocks_remaining <= config.pre_activation_window {
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
    pub fn state(&self) -> &TransitionState {
        &self.state
    }

    /// Get the current protocol version.
    pub fn current_pv(&self) -> u32 {
        self.current_pv
    }

    /// Get the transition history.
    pub fn history(&self) -> &[(u64, TransitionState)] {
        &self.history
    }

    /// Get the transition events.
    pub fn events(&self) -> &[TransitionEvent] {
        &self.events
    }

    /// Drain pending events.
    pub fn drain_events(&mut self) -> Vec<TransitionEvent> {
        let events = std::mem::take(&mut self.events);
        debug!(count = events.len(), "drained transition events");
        events
    }

    /// Register a snapshot height for potential rollback.
    pub fn register_snapshot(&mut self, height: u64) {
        if !self.snapshot_heights.contains(&height) {
            self.snapshot_heights.push(height);
            self.snapshot_heights.sort_unstable();
            debug!(height, "snapshot registered");
        }
    }

    /// Process a new block at the given height.
    /// Updates internal state and emits events as transitions occur.
    pub fn on_block(&mut self, height: u64) -> TransitionResult<()> {
        self.current_height = height;
        let new_pv = version_for_height(height, &self.activations);
        let old_pv = self.current_pv;

        if new_pv != old_pv {
            debug!(old_pv, new_pv, height, "protocol version changed");
            self.current_pv = new_pv;
        }

        let new_state = self.compute_next_state(height, old_pv, new_pv)?;

        if new_state != self.state {
            debug!(old = %self.state, new = %new_state, height, "transition state changed");
            self.emit_transition_events(&self.state.clone(), &new_state, height, old_pv, new_pv);
            self.history.push((height, self.state.clone()));
            self.state = new_state;
        }

        // If auto_process is enabled, we could trigger additional actions.
        if self.config.auto_process && self.state.is_active() {
            debug!(height, state = %self.state, "auto-processing transition");
        }

        Ok(())
    }

    /// Compute the next state based on current height and PV.
    fn compute_next_state(&self, height: u64, old_pv: u32, new_pv: u32) -> TransitionResult<TransitionState> {
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
                    Ok(TransitionState::Finalized { pv: new_pv })
                } else if height >= ah {
                    Ok(TransitionState::Active {
                        pv: new_pv,
                        grace_remaining: ah + next.grace_blocks - height,
                    })
                } else if ah - height <= self.config.pre_activation_window {
                    Ok(TransitionState::PreActivation {
                        target_pv: next.protocol_version,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    })
                } else {
                    Ok(TransitionState::Scheduled {
                        target_pv: next.protocol_version,
                        activation_height: ah,
                    })
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
                        Ok(TransitionState::Activating {
                            from_pv: old_pv,
                            to_pv: new_pv,
                            activation_height: ah,
                        })
                    } else {
                        Ok(TransitionState::Active {
                            pv: new_pv,
                            grace_remaining: 0,
                        })
                    }
                } else if ah - height <= self.config.pre_activation_window {
                    Ok(TransitionState::PreActivation {
                        target_pv: tpv,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    })
                } else {
                    Ok(self.state.clone())
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
                    Ok(TransitionState::Activating {
                        from_pv: old_pv,
                        to_pv: new_pv,
                        activation_height: ah,
                    })
                } else {
                    Ok(TransitionState::PreActivation {
                        target_pv: tpv,
                        activation_height: ah,
                        blocks_remaining: ah - height,
                    })
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
                    Ok(TransitionState::Active {
                        pv: new_pv,
                        grace_remaining: ah + grace - height,
                    })
                } else {
                    Ok(TransitionState::Finalized { pv: new_pv })
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
                    Ok(TransitionState::Finalized { pv: *pv })
                } else {
                    Ok(TransitionState::Active {
                        pv: *pv,
                        grace_remaining: grace_remaining - 1,
                    })
                }
            }

            (TransitionState::Finalized { .. }, Some(next), _) => {
                let ah = next.activation_height.unwrap();
                if height < ah {
                    if ah - height <= self.config.pre_activation_window {
                        Ok(TransitionState::PreActivation {
                            target_pv: next.protocol_version,
                            activation_height: ah,
                            blocks_remaining: ah - height,
                        })
                    } else {
                        Ok(TransitionState::Scheduled {
                            target_pv: next.protocol_version,
                            activation_height: ah,
                        })
                    }
                } else {
                    Ok(self.state.clone())
                }
            }

            _ => Ok(self.state.clone()),
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
        if self.config.verbose_logging {
            debug!(old = %old, new = %new, height, "state transition");
        }

        match new {
            TransitionState::Scheduled {
                target_pv,
                activation_height,
            } => {
                self.events.push(TransitionEvent::TransitionScheduled {
                    target_pv: *target_pv,
                    activation_height: *activation_height,
                });
                info!(target_pv, activation_height, "transition scheduled");
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
                info!(target_pv, blocks_remaining, "entered pre-activation window");
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
                info!(from_pv, to_pv, height = activation_height, "activation reached");
            }
            TransitionState::Active {
                pv,
                grace_remaining,
            } => {
                self.events.push(TransitionEvent::PvActivated {
                    pv: *pv,
                    grace_blocks: *grace_remaining,
                });
                info!(pv, grace_remaining, "PV activated (grace window open)");
            }
            TransitionState::Finalized { pv } => {
                self.events
                    .push(TransitionEvent::TransitionFinalized { pv: *pv });
                info!(pv, "transition finalized");
            }
            TransitionState::Cancelled { target_pv, reason } => {
                self.events.push(TransitionEvent::TransitionCancelled {
                    target_pv: *target_pv,
                    reason: reason.clone(),
                });
                info!(target_pv, reason, "transition cancelled");
            }
            TransitionState::RolledBack { from_pv, to_pv, .. } => {
                self.events.push(TransitionEvent::TransitionRolledBack {
                    from_pv: *from_pv,
                    to_pv: *to_pv,
                });
                info!(from_pv, to_pv, "transition rolled back");
            }
            _ => {}
        }
    }

    /// Cancel a scheduled transition (only valid before activation).
    pub fn cancel(&mut self, reason: &str) -> TransitionResult<()> {
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
                Err(TransitionError::NotCancellable {
                    state: format!("{}", self.state),
                })
            }
        }
    }

    /// Attempt rollback to a previous PV (requires snapshot before activation).
    pub fn rollback(&mut self, reason: &str) -> TransitionResult<u64> {
        let activation_height = match &self.state {
            TransitionState::Active { .. } | TransitionState::Activating { .. } => self
                .activations
                .iter()
                .filter(|a| a.protocol_version == self.current_pv)
                .filter_map(|a| a.activation_height)
                .max()
                .ok_or_else(|| TransitionError::InvalidTransition("no activation height found".into()))?,
            TransitionState::PreActivation { activation_height, .. } => *activation_height,
            _ => {
                return Err(TransitionError::NotRollbackable {
                    state: format!("{}", self.state),
                });
            }
        };

        let snapshot = self
            .snapshot_heights
            .iter()
            .rev()
            .find(|&&h| h < activation_height)
            .copied()
            .ok_or(TransitionError::NoSnapshot {
                height: activation_height,
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
    pub fn check_readiness(&self) -> ReadinessReport {
        let start = Instant::now();
        debug!("running readiness checks");
        let mut checks = Vec::new();

        let target_pv = match &self.state {
            TransitionState::Scheduled { target_pv, .. }
            | TransitionState::PreActivation { target_pv, .. } => Some(*target_pv),
            _ => None,
        };

        if let Some(tpv) = target_pv {
            checks.push(ReadinessCheck::new(
                "binary_supports_target_pv",
                SUPPORTED_PROTOCOL_VERSIONS.contains(&tpv),
                &format!("target PV={tpv}, supported={SUPPORTED_PROTOCOL_VERSIONS:?}"),
            ));
        }

        checks.push(ReadinessCheck::new(
            "current_pv_supported",
            SUPPORTED_PROTOCOL_VERSIONS.contains(&self.current_pv),
            &format!("current PV={}", self.current_pv),
        ));

        checks.push(ReadinessCheck::new(
            "snapshot_available",
            !self.snapshot_heights.is_empty(),
            &format!("{} snapshots registered", self.snapshot_heights.len()),
        ));

        let schedule_valid = self.activations.windows(2).all(|w| {
            let a = &w[0];
            let b = &w[1];
            b.protocol_version > a.protocol_version
        });
        checks.push(ReadinessCheck::new(
            "activation_schedule_valid",
            schedule_valid,
            &format!("{} activations defined", self.activations.len()),
        ));

        checks.push(ReadinessCheck::new(
            "no_pending_state",
            !matches!(
                self.state,
                TransitionState::Cancelled { .. } | TransitionState::RolledBack { .. }
            ),
            &format!("current state: {}", self.state),
        ));

        let grace_bounds_ok = self.activations.iter().all(|a| a.grace_blocks <= MAX_GRACE_WINDOW);
        checks.push(ReadinessCheck::new(
            "grace_window_bounded",
            grace_bounds_ok,
            &format!("max grace window: {}", MAX_GRACE_WINDOW),
        ));

        let report = ReadinessReport::new(checks, start.elapsed());
        if report.ready {
            info!("readiness check passed");
        } else {
            warn!("readiness check failed");
        }
        report
    }

    /// Validate that a block's PV is correct for the given height.
    pub fn validate_block_pv(&self, block_pv: u32, height: u64) -> TransitionResult<()> {
        super::version::validate_block_version(block_pv, height, &self.activations)
            .map_err(|e| TransitionError::InvalidTransition(e))
    }

    /// Get a summary of the transition manager's state.
    pub fn summary(&self) -> TransitionSummary {
        TransitionSummary {
            current_height: self.current_height,
            current_pv: self.current_pv,
            state: format!("{}", self.state),
            history_len: self.history.len(),
            snapshots: self.snapshot_heights.len(),
            pending_events: self.events.len(),
            is_terminal: self.state.is_terminal(),
        }
    }

    /// Get the next scheduled transition (if any).
    pub fn next_transition(&self) -> Option<&ProtocolActivation> {
        self.activations
            .iter()
            .find(|a| a.protocol_version > self.current_pv && a.activation_height.is_some())
    }

    /// Check if a transition is currently in progress.
    pub fn is_transitioning(&self) -> bool {
        matches!(
            self.state,
            TransitionState::Scheduled { .. }
                | TransitionState::PreActivation { .. }
                | TransitionState::Activating { .. }
                | TransitionState::Active { .. }
        )
    }

    /// Get the current transition progress (0.0 to 1.0) if in PreActivation or Activating.
    pub fn progress(&self) -> Option<f64> {
        match &self.state {
            TransitionState::PreActivation {
                blocks_remaining,
                activation_height,
                ..
            } => {
                let total = *activation_height - self.current_height + blocks_remaining;
                if total > 0 {
                    Some(1.0 - (*blocks_remaining as f64 / total as f64))
                } else {
                    Some(1.0)
                }
            }
            TransitionState::Activating { .. } => Some(1.0),
            _ => None,
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
    pub is_terminal: bool,
}

// -----------------------------------------------------------------------------
// Validation functions (standalone)
// -----------------------------------------------------------------------------

/// Validate an activation schedule for correctness.
pub fn validate_schedule(activations: &[ProtocolActivation]) -> TransitionResult<()> {
    if activations.is_empty() {
        return Err(TransitionError::InvalidTransition(
            "activation schedule cannot be empty".into(),
        ));
    }

    let mut prev_pv = 0;
    let mut prev_height: Option<u64> = None;

    for a in activations {
        if a.protocol_version <= prev_pv {
            return Err(TransitionError::InvalidTransition(format!(
                "protocol versions must be strictly increasing: {} <= {}",
                a.protocol_version, prev_pv
            )));
        }
        prev_pv = a.protocol_version;

        if let Some(h) = a.activation_height {
            if let Some(prev_h) = prev_height {
                if h <= prev_h {
                    return Err(TransitionError::InvalidTransition(format!(
                        "activation heights must be strictly increasing: {} <= {}",
                        h, prev_h
                    )));
                }
            }
            prev_height = Some(h);
        }

        if a.grace_blocks > MAX_GRACE_WINDOW {
            return Err(TransitionError::GraceTooLarge {
                grace: a.grace_blocks,
                max: MAX_GRACE_WINDOW,
            });
        }
    }

    Ok(())
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

    fn two_upgrade_activations() -> Vec<ProtocolActivation> {
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
            ProtocolActivation {
                protocol_version: 3,
                activation_height: Some(500),
                grace_blocks: 20,
            },
        ]
    }

    #[test]
    fn test_validate_schedule_ok() {
        let schedule = upgrade_activations();
        assert!(validate_schedule(&schedule).is_ok());
    }

    #[test]
    fn test_validate_schedule_invalid_order() {
        let schedule = vec![
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100),
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
        ];
        assert!(validate_schedule(&schedule).is_err());
    }

    #[test]
    fn test_initial_state_idle() {
        let mgr = TransitionManager::new(basic_activations(), 50);
        assert!(matches!(mgr.state(), TransitionState::Idle));
        assert_eq!(mgr.current_pv(), 1);
    }

    #[test]
    fn test_initial_state_scheduled() {
        let config = TransitionConfig::test();
        let mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        // With test config, pre_activation_window=10, so at height 1 it's Scheduled.
        assert!(matches!(mgr.state(), TransitionState::Scheduled { .. }));
    }

    #[test]
    fn test_transition_to_pre_activation() {
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        mgr.on_block(95).unwrap();
        // With test config (window=10), at height 95 we are 5 blocks before activation = PreActivation.
        assert!(matches!(mgr.state(), TransitionState::PreActivation { .. }));
    }

    #[test]
    fn test_cancel_scheduled() {
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
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
        let result = mgr.cancel("test");
        assert!(matches!(result, Err(TransitionError::NotCancellable { .. })));
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
        assert!(!summary.is_terminal);
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
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        assert!(mgr.history().is_empty());

        mgr.on_block(95).unwrap();
        assert!(!mgr.history().is_empty());
    }

    #[test]
    fn test_rollback_pre_activation() {
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        mgr.register_snapshot(50);

        mgr.on_block(95).unwrap();
        assert!(matches!(mgr.state(), TransitionState::PreActivation { .. }));

        let snapshot = mgr.rollback("test rollback").unwrap();
        assert_eq!(snapshot, 50);
        assert!(matches!(mgr.state(), TransitionState::RolledBack { .. }));
    }

    #[test]
    fn test_rollback_after_activation_fails_without_snapshot() {
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        // Go to activation.
        mgr.on_block(100).unwrap();
        assert!(matches!(mgr.state(), TransitionState::Activating { .. }));

        // No snapshot registered.
        let result = mgr.rollback("test");
        assert!(matches!(result, Err(TransitionError::NoSnapshot { .. })));
    }

    #[test]
    fn test_progress() {
        let config = TransitionConfig::test();
        let mut mgr = TransitionManager::with_config(upgrade_activations(), 1, config);
        mgr.on_block(95).unwrap();
        let prog = mgr.progress();
        assert!(prog.is_some());
        assert!(prog.unwrap() > 0.0 && prog.unwrap() <= 1.0);
    }

    #[test]
    fn test_next_transition() {
        let mgr = TransitionManager::new(two_upgrade_activations(), 50);
        let next = mgr.next_transition();
        assert!(next.is_some());
        assert_eq!(next.unwrap().protocol_version, 2);
    }

    #[test]
    fn test_is_transitioning() {
        let mgr = TransitionManager::new(upgrade_activations(), 50);
        assert!(mgr.is_transitioning());

        let mgr2 = TransitionManager::new(basic_activations(), 50);
        assert!(!mgr2.is_transitioning());
    }

    #[test]
    fn test_readiness_report_display() {
        let checks = vec![
            ReadinessCheck::new("test1", true, "ok"),
            ReadinessCheck::new("test2", false, "failed"),
        ];
        let report = ReadinessReport::new(checks, Duration::from_millis(5));
        let s = format!("{}", report);
        assert!(s.contains("NOT READY"));
        assert!(s.contains("✓"));
        assert!(s.contains("✗"));
    }
}
