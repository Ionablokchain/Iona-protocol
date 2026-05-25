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
    default_activations, is_supported,
};

// Activation guarantees (formal properties AG‑1 to AG‑8)
pub use activation_guarantees::{
    check_all_guarantees, check_deterministic_activation, check_deterministic_range,
    check_exactly_once, check_grace_bounded, check_monotonic, check_post_activation_mandatory,
    check_rollback_safe, check_signal_distance, ActivationCheck, ActivationReport,
    pre_activation_signal_distance, rollback_window, MAX_GRACE_BLOCKS,
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
    Hello, handshake, HandshakeError, HandshakeResult,
};

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
        default_activations, is_supported,
        CompatChecker, CompatDomain, CompatLevel, CompatReport,
        ShadowValidator, ShadowValidatorConfig, ShadowStats,
        RollingUpgrade, RollingUpgradeStatus,
        SafetyReport,
        StateInvariantReport,
        UpgradeConstraintReport,
        Hello, handshake,
    };
}
