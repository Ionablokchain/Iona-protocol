//! Protocol versioning, upgrade safety, and compatibility enforcement.
//!
//! This module implements the core logic for managing protocol versions (PV),
//! schema versions (SV), and the transition between them. It provides:
//!
//! - **Version management**: constants, supported sets, and activation scheduling.
//! - **Activation guarantees**: formal properties (AG‑1 to AG‑8) checked at runtime.
//! - **Backward compatibility**: rules for wire, state, RPC, and consensus changes.
//! - **Dual‑validation**: shadow validation of new PV rules before activation.
//! - **Safety invariants**: consensus safety properties (S1‑S5).
//! - **State invariants**: storage format constraints.
//! - **Upgrade constraints**: bounds checks for activation heights and grace windows.
//! - **Wire compatibility**: version negotiation and handshake logic.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                           Protocol Versioning                              │
//! ├─────────────────┬─────────────────┬─────────────────┬─────────────────────┤
//! │    version.rs   │   compat.rs     │ activation_     │   dual_validate.rs  │
//! │  (PV constants, │ (backward compat│ guarantees.rs   │ (shadow validation  │
//! │   activations)  │  enforcement)   │  AG-1 to AG-8)  │  for new PV rules)  │
//! ├─────────────────┼─────────────────┼─────────────────┼─────────────────────┤
//! │    safety.rs    │ state_invariants│   transitions.rs│ upgrade_constraints │
//! │  (consensus     │ (storage format │  (PV transition │ (bounds checks for  │
//! │   safety S1-S5) │  validation)    │   validation)   │ activation heights) │
//! ├─────────────────┼─────────────────┼─────────────────┼─────────────────────┤
//! │    rolling.rs   │     wire.rs     │                 │                     │
//! │  (no‑downtime   │ (handshake &    │                 │                     │
//! │   upgrades)     │  negotiation)   │                 │                     │
//! └─────────────────┴─────────────────┴─────────────────┴─────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::protocol::{ProtocolConfig, init};
//!
//! let config = ProtocolConfig::default();
//! init(&config)?;
//! ```
//!
//! # Error Handling
//!
//! All initialization and validation functions return `ProtocolResult<T>`,
//! which uses `ProtocolError` for uniform error reporting.

use std::time::Duration;
use thiserror::Error;
use tracing::{error, info, warn};

// -----------------------------------------------------------------------------
// Submodule declarations (each module is implemented in its own file)
// -----------------------------------------------------------------------------

pub mod activation_guarantees;
pub mod compat;
pub mod dual_validate;
pub mod rolling;
pub mod safety;
pub mod state_invariants;
pub mod transitions;
pub mod upgrade_constraints;
pub mod version;
pub mod wire;

// -----------------------------------------------------------------------------
// Re‑exports for a convenient top‑level API
// -----------------------------------------------------------------------------

// Version management
pub use version::{
    version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
    default_activations, is_supported, max_supported_pv, min_supported_pv, version_string,
};

// Activation guarantees (formal properties AG‑1 to AG‑8)
pub use activation_guarantees::{
    check_all_guarantees, check_deterministic_activation, check_deterministic_range,
    check_exactly_once, check_grace_bounded, check_monotonic, check_post_activation_mandatory,
    check_rollback_safe, check_signal_distance, ActivationCheck, ActivationReport,
    pre_activation_signal_distance, rollback_window, DEFAULT_MIN_LEAD_BLOCKS, MAX_GRACE_BLOCKS,
    validate_activation_schedule,
};

// Compatibility enforcement
pub use compat::{
    CompatChecker, CompatDomain, CompatLevel, CompatMatrixEntry, CompatReport, CompatRule,
    build_compat_matrix, check_version_compat,
};

// Dual‑validation (shadow validation for new protocol versions)
pub use dual_validate::{
    ShadowValidator, ShadowValidatorConfig, ShadowStats,
};

// Rolling upgrade utilities (no‑downtime upgrades)
pub use rolling::{
    RollingUpgrade, RollingUpgradeStatus, RollingUpgradeConfig,
};

// Safety invariants (consensus safety properties S1–S5)
pub use safety::{
    check_no_split_finality, check_finality_monotonic, check_deterministic_pv,
    check_state_compat, check_value_conservation, check_root_equivalence,
    SafetyReport, SafetyCheck,
};

// State invariants (storage format validation)
pub use state_invariants::{
    check_state_invariants, StateInvariantReport, StateInvariant,
};

// Transition validation (between protocol versions)
pub use transitions::{
    validate_transition, TransitionValidation, TransitionResult,
};

// Upgrade constraints (bounds checks)
pub use upgrade_constraints::{
    check_activation_bounds, check_grace_bounds, check_upgrade_sequence,
    UpgradeConstraintReport, UpgradeConstraint,
};

// Wire compatibility helpers (handshake)
pub use wire::{
    Hello, handshake, HandshakeError, HandshakeResult, check_hello_compat,
};

// -----------------------------------------------------------------------------
// Protocol error type
// -----------------------------------------------------------------------------

/// Errors that can occur during protocol initialisation or validation.
#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("activation schedule validation failed: {0}")]
    ActivationValidation(String),

    #[error("compatibility check failed: {0}")]
    Compatibility(String),

    #[error("safety invariant violation: {0}")]
    SafetyViolation(String),

    #[error("state invariant violation: {0}")]
    StateInvariant(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result type for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

// -----------------------------------------------------------------------------
// Protocol configuration
// -----------------------------------------------------------------------------

/// Configuration for the protocol subsystem.
#[derive(Debug, Clone)]
pub struct ProtocolConfig {
    /// Protocol activation schedule.
    pub activations: Vec<ProtocolActivation>,
    /// Current block height (for validation).
    pub current_height: u64,
    /// Minimum lead blocks for pre‑activation signalling.
    pub min_lead_blocks: u64,
    /// Whether to enable shadow validation.
    pub enable_shadow_validation: bool,
    /// Shadow validation sample rate (0.0 = none, 1.0 = all).
    pub shadow_sample_rate: f64,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            activations: default_activations(),
            current_height: 0,
            min_lead_blocks: DEFAULT_MIN_LEAD_BLOCKS,
            enable_shadow_validation: true,
            shadow_sample_rate: 0.1,
        }
    }
}

impl ProtocolConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> ProtocolResult<()> {
        if self.min_lead_blocks == 0 {
            return Err(ProtocolError::Config("min_lead_blocks must be > 0".into()));
        }
        if !(0.0..=1.0).contains(&self.shadow_sample_rate) {
            return Err(ProtocolError::Config(format!(
                "shadow_sample_rate must be between 0.0 and 1.0, got {}",
                self.shadow_sample_rate
            )));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Initialisation
// -----------------------------------------------------------------------------

/// Initialise the protocol subsystem with the given configuration.
///
/// This function:
/// 1. Validates the activation schedule (AG‑1 to AG‑8).
/// 2. Runs compatibility checks.
/// 3. Sets up shadow validation if enabled.
///
/// # Errors
/// Returns `ProtocolError` if any validation fails.
pub fn init(config: &ProtocolConfig) -> ProtocolResult<()> {
    let _span = tracing::info_span!("protocol::init").entered();
    info!("initialising protocol subsystem");

    // Validate configuration.
    config.validate()?;

    // Validate activation schedule.
    let validation_result = activation_guarantees::validate_activation_schedule(
        &config.activations,
        config.current_height,
        config.min_lead_blocks,
    );

    if let Err(errors) = validation_result {
        let msg = errors.join("; ");
        error!("activation schedule validation failed: {}", msg);
        return Err(ProtocolError::ActivationValidation(msg));
    }

    // Run compatibility checks.
    let checker = CompatChecker::new(config.activations.clone());
    let compat_report = checker.check_all();
    if !compat_report.passed {
        let failures: Vec<_> = compat_report.failures().iter().map(|r| r.detail.clone()).collect();
        let msg = failures.join("; ");
        error!("compatibility check failed: {}", msg);
        return Err(ProtocolError::Compatibility(msg));
    }

    // Set up shadow validation if enabled.
    if config.enable_shadow_validation {
        let shadow_config = ShadowValidatorConfig {
            enabled: true,
            sample_rate: config.shadow_sample_rate,
            ..Default::default()
        };
        match ShadowValidator::new(config.activations.clone(), shadow_config) {
            Ok(_validator) => {
                info!(
                    sample_rate = config.shadow_sample_rate,
                    "shadow validator initialised"
                );
                // In a real system, we would store this validator in a global state.
            }
            Err(e) => {
                warn!("shadow validator initialisation failed: {}", e);
            }
        }
    }

    // Run safety invariants (S1–S5) at current height.
    let safety_report = safety::check_safety_invariants(&config.activations, config.current_height);
    if !safety_report.passed {
        let failures: Vec<_> = safety_report.failures().iter().map(|c| c.detail.clone()).collect();
        let msg = failures.join("; ");
        error!("safety invariants violated: {}", msg);
        return Err(ProtocolError::SafetyViolation(msg));
    }

    info!("protocol subsystem initialised successfully");
    Ok(())
}

/// Shorthand for initialising with default configuration.
pub fn init_default() -> ProtocolResult<()> {
    init(&ProtocolConfig::default())
}

// -----------------------------------------------------------------------------
// Version information
// -----------------------------------------------------------------------------

/// Returns the protocol version string for logging and RPC.
pub fn protocol_version_string() -> String {
    format!(
        "protocol v{} (schema v{})",
        CURRENT_PROTOCOL_VERSION,
        crate::storage::CURRENT_SCHEMA_VERSION
    )
}

/// Returns a summary of the protocol configuration.
pub fn protocol_summary(activations: &[ProtocolActivation]) -> String {
    let mut summary = String::new();
    summary.push_str(&format!("Current PV: {}\n", CURRENT_PROTOCOL_VERSION));
    summary.push_str(&format!("Supported PVs: {:?}\n", SUPPORTED_PROTOCOL_VERSIONS));
    summary.push_str("Activations:\n");
    for a in activations {
        summary.push_str(&format!(
            "  PV {} -> height {:?}, grace {}\n",
            a.protocol_version, a.activation_height, a.grace_blocks
        ));
    }
    summary
}

// -----------------------------------------------------------------------------
// Prelude: import commonly used items
// -----------------------------------------------------------------------------

/// A prelude module that re‑exports the most common types and functions
/// from the protocol module.
///
/// # Example
///
/// ```
/// use iona::protocol::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        version_for_height, ProtocolActivation, ProtocolConfig, ProtocolError, ProtocolResult,
        CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS,
        default_activations, is_supported, version_string,
        check_all_guarantees, check_hello_compat,
        CompatChecker, CompatDomain, CompatLevel, CompatReport,
        ShadowValidator, ShadowValidatorConfig, ShadowStats,
        RollingUpgrade, RollingUpgradeStatus,
        SafetyReport,
        StateInvariantReport,
        UpgradeConstraintReport,
        Hello, handshake, HandshakeError, HandshakeResult,
        init, init_default, protocol_version_string, protocol_summary,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init_default() {
        let result = init_default();
        assert!(result.is_ok(), "init_default failed: {:?}", result);
    }

    #[test]
    fn test_protocol_config_validation() {
        let mut config = ProtocolConfig::default();
        config.min_lead_blocks = 0;
        assert!(config.validate().is_err());

        config.shadow_sample_rate = 1.5;
        assert!(config.validate().is_err());

        config.min_lead_blocks = 10;
        config.shadow_sample_rate = 0.5;
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_protocol_summary_contains_info() {
        let activations = default_activations();
        let summary = protocol_summary(&activations);
        assert!(summary.contains("Current PV:"));
        assert!(summary.contains("Activations:"));
    }

    #[test]
    fn test_protocol_version_string() {
        let s = protocol_version_string();
        assert!(s.contains("protocol v"));
        assert!(s.contains("schema v"));
    }
}
