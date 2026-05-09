//! Default execution environment for REVM.
//!
//! Provides a helper to create an `Env` with sensible defaults for IONA.

use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default gas limit for the block.
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Default chain ID for IONA testnet (can be overridden).
pub const DEFAULT_CHAIN_ID: u64 = 6126151;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when building the environment.
#[derive(Debug, Error)]
pub enum EnvError {
    #[error("chain ID cannot be zero")]
    ZeroChainId,
}

pub type EnvResult<T> = Result<T, EnvError>;

// -----------------------------------------------------------------------------
// Environment builder
// -----------------------------------------------------------------------------

/// Create a default EVM execution environment with the given chain ID.
///
/// The returned `Env` has:
/// - `chain_id` set to the provided value
/// - `block.number` = 0
/// - `block.coinbase` = zero address
/// - `block.timestamp` = 0
/// - `block.basefee` = 0
/// - `block.gas_limit` = `DEFAULT_BLOCK_GAS_LIMIT`
/// - empty transaction environment (to be filled by the caller)
///
/// # Example
/// ```
/// use iona::evm::executor_env::{default_env, EnvError};
///
/// let env = default_env(6126151)?;
/// assert_eq!(env.cfg.chain_id, 6126151);
/// # Ok::<(), EnvError>(())
/// ```
pub fn default_env(chain_id: u64) -> EnvResult<Env> {
    if chain_id == 0 {
        return Err(EnvError::ZeroChainId);
    }

    let mut env = Env::default();
    env.cfg = CfgEnv::default();
    env.cfg.chain_id = chain_id;

    env.block = BlockEnv::default();
    env.block.number = U256::from(0);
    env.block.coinbase = Address::ZERO;
    env.block.timestamp = U256::from(0);
    env.block.basefee = U256::from(0);
    env.block.gas_limit = U256::from(DEFAULT_BLOCK_GAS_LIMIT);

    env.tx = TxEnv::default();
    Ok(env)
}

/// Alternative version that does not validate (for backward compatibility).
/// Prefer `default_env` which returns a `Result`.
#[deprecated(since = "30.0.0", note = "use default_env which returns Result")]
pub fn default_env_unchecked(chain_id: u64) -> Env {
    default_env(chain_id).unwrap_or_else(|_| {
        let mut env = Env::default();
        env.cfg.chain_id = chain_id;
        env
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_env_ok() {
        let env = default_env(1).unwrap();
        assert_eq!(env.cfg.chain_id, 1);
        assert_eq!(env.block.gas_limit, U256::from(DEFAULT_BLOCK_GAS_LIMIT));
    }

    #[test]
    fn test_default_env_zero_chain_id() {
        let err = default_env(0).unwrap_err();
        assert!(matches!(err, EnvError::ZeroChainId));
    }

    #[test]
    fn test_default_env_unchecked_deprecated() {
        #[allow(deprecated)]
        let env = default_env_unchecked(42);
        assert_eq!(env.cfg.chain_id, 42);
    }
}
