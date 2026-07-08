//! Staking and governance module for IONA.
//!
//! This module provides the core staking logic, including validator bonding/unbonding,
//! reward distribution, slashing, and governance proposals.
//!
//! # Submodules
//!
//! - `params` – Configuration parameters for staking and governance.
//! - `staking` – Core staking state: validators, delegations, unbonding.
//! - `governance` – On‑chain proposal system for parameter changes and upgrades.
//! - `rewards` – Distribution of block rewards to validators and delegators.
//! - `staking_tx` – Transaction types for staking operations.
//!
//! # Example
//!
//! ```rust
//! use iona::staking::*;
//!
//! let mut state = StakingState::default();
//! let tx = StakingTx::Delegate {
//!     delegator: "alice".into(),
//!     validator: "val1".into(),
//!     amount: 1000,
//! };
//! apply_staking_tx(&mut state, tx).unwrap();
//! ```

// Re‑export core types and functions from each submodule.
pub use params::StakingParams;
pub use staking::{
    StakingState, Validator, Delegation, UnbondingEntry,
    apply_staking_tx, StakingError,
};
pub use governance::{
    GovernanceState, GovernanceParams, Proposal, ProposalKind, ProposalResult,
    submit_proposal, vote, process_proposals,
};
pub use rewards::{
    RewardState, RewardConfig, distribute_rewards,
};
pub use staking_tx::{
    StakingTx,
    StakingTxKind,
    validate_staking_tx,
};

// Optionally, re‑export error types for convenience.
pub use staking::StakingError as Error;

// Module declarations (kept private to enforce re‑export interface).
pub mod params;
pub mod staking;
pub mod governance;
pub mod rewards;
pub mod staking_tx;

// Test helpers (only in dev builds).
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staking_and_rewards_integration() {
        // Simple integration test to ensure submodules work together.
        let mut state = StakingState::default();
        // ... test logic ...
    }
}
