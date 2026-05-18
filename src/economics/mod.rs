//! Economic parameters, staking, rewards, and governance for IONA.
//!
//! This module provides:
//! - `params`: Economic configuration (base fee, gas target, inflation, etc.)
//! - `rewards`: Block reward and fee distribution logic
//! - `staking`: Validator staking, delegation, and slashing
//! - `staking_tx`: Transaction handlers for staking operations
//! - `governance`: On-chain parameter change proposals
//!
//! # Example
//!
//! ```
//! use iona::economics::{EconomicsParams, EconomicsError, validate_economics};
//!
//! let params = EconomicsParams::default();
//! assert!(validate_economics(&params).is_ok());
//! ```

pub mod governance;
pub mod params;
pub mod rewards;
pub mod staking;
pub mod staking_tx;

use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default base fee per gas (1 gwei equivalent in micro-units).
pub const DEFAULT_BASE_FEE: u64 = 1;

/// Default gas target per block (30 million).
pub const DEFAULT_GAS_TARGET: u64 = 30_000_000;

/// Default block reward (in micro-units).
pub const DEFAULT_BLOCK_REWARD: u64 = 2_000_000_000;

/// Default inflation rate (basis points, 500 = 5%).
pub const DEFAULT_INFLATION_RATE_BPS: u64 = 500;

/// Maximum inflation rate (10,000 bps = 100%).
pub const MAX_INFLATION_RATE_BPS: u64 = 10_000;

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

pub use governance::GovernanceState;
pub use params::EconomicsParams;
pub use rewards::{compute_block_reward, distribute_rewards, RewardConfig};
pub use staking::{StakeLedger, StakingError, ValidatorRecord};
pub use staking_tx::{try_apply_staking_tx, StakingTxError};

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

/// Validate economic parameters against sensible bounds.
pub fn validate_economics(params: &EconomicsParams) -> EconomicsResult<()> {
    if params.base_fee_per_gas == 0 {
        return Err(EconomicsError::InvalidParam(
            "base_fee_per_gas must be > 0".into(),
        ));
    }
    if params.gas_target == 0 {
        return Err(EconomicsError::InvalidParam(
            "gas_target must be > 0".into(),
        ));
    }
    if params.block_reward == 0 {
        return Err(EconomicsError::InvalidParam(
            "block_reward must be > 0".into(),
        ));
    }
    if params.inflation_rate > MAX_INFLATION_RATE_BPS {
        return Err(EconomicsError::InvalidParam(format!(
            "inflation_rate must be <= {} (100%), got {}",
            MAX_INFLATION_RATE_BPS, params.inflation_rate
        )));
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Convenience initialization
// -----------------------------------------------------------------------------

/// Create a default `EconomicsParams` instance (same as `Default`).
pub fn default_economics_params() -> EconomicsParams {
    EconomicsParams::default()
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Prelude for convenient importing of common economics items.
pub mod prelude {
    pub use super::{
        compute_block_reward, default_economics_params, distribute_rewards,
        validate_economics, EconomicsError, EconomicsParams, EconomicsResult,
        StakeLedger, StakingTxError, ValidatorRecord,
        try_apply_staking_tx,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_economics_ok() {
        let params = EconomicsParams::default();
        assert!(validate_economics(&params).is_ok());
    }

    #[test]
    fn test_validate_economics_zero_base_fee() {
        let mut params = EconomicsParams::default();
        params.base_fee_per_gas = 0;
        assert!(validate_economics(&params).is_err());
    }

    #[test]
    fn test_validate_economics_zero_gas_target() {
        let mut params = EconomicsParams::default();
        params.gas_target = 0;
        assert!(validate_economics(&params).is_err());
    }

    #[test]
    fn test_validate_economics_zero_block_reward() {
        let mut params = EconomicsParams::default();
        params.block_reward = 0;
        assert!(validate_economics(&params).is_err());
    }

    #[test]
    fn test_validate_economics_inflation_too_high() {
        let mut params = EconomicsParams::default();
        params.inflation_rate = MAX_INFLATION_RATE_BPS + 1;
        assert!(validate_economics(&params).is_err());
    }

    #[test]
    fn test_default_economics_params() {
        let params = default_economics_params();
        assert_eq!(params.base_fee_per_gas, DEFAULT_BASE_FEE);
        assert_eq!(params.gas_target, DEFAULT_GAS_TARGET);
        assert_eq!(params.block_reward, DEFAULT_BLOCK_REWARD);
    }
}
