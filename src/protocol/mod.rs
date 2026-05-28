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
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::prelude::*;
//!
//! let activations = default_activations();
//! let checker = CompatChecker::new(activations);
//! let report = checker.check_all();
//! if !report.passed {
//!     eprintln!("{}", report);
//! }
//! ```

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
// Initialisation
// -----------------------------------------------------------------------------

/// Initialise the protocol subsystem with the given activation schedule.
/// Validates the schedule and sets up shadow validation if needed.
pub fn init(activations: &[ProtocolActivation], current_height: u64) -> Result<(), Vec<String>> {
    use tracing::info;

    info!("initialising protocol subsystem");

    // Validate activation schedule
    let validation_result = activation_guarantees::validate_activation_schedule(
        activations,
        current_height,
        DEFAULT_MIN_LEAD_BLOCKS,
    );

    if let Err(errors) = validation_result {
        return Err(errors);
    }

    info!("protocol subsystem initialised successfully");
    Ok(())
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
        version_for_height, ProtocolActivation,
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
    };
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
