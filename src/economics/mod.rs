//! Economic parameters, staking, rewards, and governance for IONA.
//!
//! This module provides:
//! - `params`: Economic configuration (base fee, gas target, inflation, etc.)
//! - `rewards`: Block reward and fee distribution logic
//! - `staking`: Validator staking, delegation, and slashing
//! - `staking_tx`: Transaction handlers for staking operations
//! - `governance`: On-chain parameter change proposals (if not moved)
//!
//! # Example
//!
//! ```
//! use iona::economics::{EconomicsParams, EconomicsError};
//!
//! let params = EconomicsParams::default();
//! assert!(params.validate().is_ok());
//! ```

pub mod governance;
pub mod params;
pub mod rewards;
pub mod staking;
pub mod staking_tx;

use thiserror::Error;

// -----------------------------------------------------------------------------
// Unified error type
// -----------------------------------------------------------------------------

/// Errors that can occur in the economics module.
#[derive(Debug, Error)]
pub enum EconomicsError {
    #[error("parameter validation failed: {0}")]
    InvalidParam(String),

    #[error("staking error: {0}")]
    Staking(#[from] staking::StakingError),

    #[error("staking transaction error: {0}")]
    StakingTx(#[from] staking_tx::StakingTxError),

    #[error("reward calculation error: {0}")]
    Reward(String),

    #[error("governance error: {0}")]
    Governance(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Result alias for economics operations.
pub type EconomicsResult<T> = Result<T, EconomicsError>;

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

pub use params::EconomicsParams;
pub use rewards::{compute_block_reward, distribute_rewards, RewardConfig};
pub use staking::{StakeLedger, ValidatorRecord, StakingError};
pub use staking_tx::{try_apply_staking_tx, StakingTxError};

// If governance is moved here (not a separate top‑level module):
pub use governance::GovernanceState;

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

/// Validate economic parameters against sensible bounds.
pub fn validate_economics(params: &EconomicsParams) -> EconomicsResult<()> {
    if params.base_fee_per_gas == 0 {
        return Err(EconomicsError::InvalidParam("base_fee_per_gas must be > 0".into()));
    }
    if params.gas_target == 0 {
        return Err(EconomicsError::InvalidParam("gas_target must be > 0".into()));
    }
    if params.block_reward == 0 {
        return Err(EconomicsError::InvalidParam("block_reward must be > 0".into()));
    }
    if params.inflation_rate > 1_000_000 {
        return Err(EconomicsError::InvalidParam("inflation_rate must be <= 1_000_000 (100%)".into()));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Prelude for convenient importing of common economics items.
pub mod prelude {
    pub use super::{
        EconomicsError, EconomicsResult,
        EconomicsParams,
        compute_block_reward, distribute_rewards,
        StakeLedger, ValidatorRecord,
        try_apply_staking_tx,
    };
}
