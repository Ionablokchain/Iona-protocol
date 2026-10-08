//! Staking and governance module for IONA.
//!
//! Provides validator bonding/unbonding, delegations, reward distribution,
//! slashing, and on-chain governance.
//!
//! # Submodules
//!
//! | Module | Responsibility |
//! |--------|----------------|
//! | [`params`] | Configuration parameters shared by staking and governance. |
//! | [`staking`] | Core staking state: validators, delegations, unbonding queue. |
//! | [`governance`] | On-chain proposals for parameter changes and upgrades. |
//! | [`rewards`] | Block reward distribution to validators and delegators. |
//! | [`staking_tx`] | Transaction types and validation for staking operations. |
//!
//! # Re-export policy
//!
//! Every public item lives in exactly one submodule and is re-exported here
//! flat, so callers can write `iona::staking::StakingState` without knowing
//! which submodule defines it. The submodules themselves are `pub` so
//! intra-doc links resolve and advanced callers can reach them directly, but
//! **the flat path is the supported API** — submodule paths may be
//! reorganised across minor versions.
//!
//! # Example
//!
//! ```no_run
//! use iona::staking::{apply_staking_tx, StakingState, StakingTx, StakingError};
//!
//! fn delegate() -> Result<(), StakingError> {
//!     let mut state = StakingState::default();
//!     let tx = StakingTx::Delegate {
//!         delegator: "alice".into(),
//!         validator: "val1".into(),
//!         amount: 1_000,
//!     };
//!     apply_staking_tx(&mut state, tx)?;
//!     Ok(())
//! }
//! ```
//!
//! # Panics
//!
//! No function in this module is documented to panic. If you need to treat
//! failures as data, always propagate the `Result` — never `unwrap` on
//! transaction or proposal outcomes.

// ── Submodule declarations ────────────────────────────────────────────────
//
// Declared before the re-exports so the file reads top-to-bottom: "what
// modules exist" → "what surface they expose".

pub mod governance;
pub mod params;
pub mod rewards;
pub mod staking;
pub mod staking_tx;

// ── Flat re-exports ───────────────────────────────────────────────────────
//
// Grouped by submodule so the file stays legible as it grows.

pub use params::StakingParams;

pub use staking::{
    apply_staking_tx, Delegation, StakingError, StakingState, UnbondingEntry, Validator,
};

pub use governance::{
    process_proposals, submit_proposal, vote, GovernanceParams, GovernanceState, Proposal,
    ProposalKind, ProposalResult,
};

pub use rewards::{distribute_rewards, RewardConfig, RewardState};

pub use staking_tx::{validate_staking_tx, StakingTx, StakingTxKind};

// ── Backward-compatible error alias ──────────────────────────────────────
//
// `StakingError` is the canonical error for the whole module. The bare
// `Error` alias is kept for callers written against an earlier revision.
//
// New code should use `StakingError` directly — and `governance` callers
// should pattern-match the module-specific error types
// (`governance::SubmitError`, `governance::VoteError`, …) exposed through
// `pub mod governance`.

pub use staking::StakingError as Error;

// ── Prelude ───────────────────────────────────────────────────────────────

/// Convenience imports for typical callers.
///
/// ```
/// use iona::staking::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        apply_staking_tx, distribute_rewards, process_proposals, submit_proposal,
        validate_staking_tx, vote, Delegation, GovernanceParams, GovernanceState, Proposal,
        ProposalKind, ProposalResult, RewardConfig, RewardState, StakingError, StakingParams,
        StakingState, StakingTx, StakingTxKind, UnbondingEntry, Validator,
    };
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Re-export surface ──────────────────────────────────────────────
    //
    // These tests do not exercise business logic — they guard the flat
    // re-export surface against accidental removal.

    #[test]
    fn flat_surface_types_are_constructible() {
        let _ = StakingState::default();
        let _ = GovernanceState::default();
        let _ = RewardState::default();
        let _ = StakingParams::default();
        let _ = GovernanceParams::default();
        let _ = RewardConfig::default();
    }

    #[test]
    fn backward_compat_error_alias_resolves() {
        // `Error` must be the same type as `StakingError`.
        fn _assert_same<T>(_: T, _: T) {}
        fn _type_check(e: Error) -> StakingError {
            e
        }
    }

    #[test]
    fn prelude_exposes_the_supported_surface() {
        use crate::staking::prelude::*;

        let _ = StakingState::default();
        let _ = GovernanceState::default();
        let _ = RewardState::default();
        let _ = StakingParams::default();
        let _ = GovernanceParams::default();
        let _ = RewardConfig::default();
    }

    #[test]
    fn submodules_are_reachable_by_path() {
        // Advanced callers reach submodules directly; verify the paths
        // still resolve so intra-doc links keep working.
        let _ = crate::staking::params::StakingParams::default();
        let _ = crate::staking::staking::StakingState::default();
        let _ = crate::staking::governance::GovernanceState::default();
        let _ = crate::staking::rewards::RewardState::default();
    }

    #[test]
    fn integration_staking_and_governance_coexist() {
        // Both states must be constructible side-by-side without touching
        // the same resources. Replace with a real scenario once the
        // submodules expose their full APIs.
        let staking = StakingState::default();
        let gov = GovernanceState::default();
        let rewards = RewardState::default();
        let _ = (staking, gov, rewards);
    }
}
