//! Default execution environment for REVM.
//!
//! Provides helpers to create an `Env` with sensible defaults for IONA,
//! as well as a flexible builder for custom configurations.
//!
//! Supports:
//! - EIP-1559 (base fee)
//! - EIP-4844 (blob transactions)
//! - EIP-4399 (prevrandao)
//! - EIP-155 chain ID validation
//! - Custom coinbase, timestamp, gas limit
//! - Fork simulation with real time
//!
//! # Example
//!
//! ```
//! use iona::evm::executor_env::{EnvBuilder, default_env};
//!
//! // Quick default
//! let env = default_env(6126151)?;
//!
//! // Custom builder
//! let env = EnvBuilder::new(6126151)
//!     .block_number(1000)
//!     .block_timestamp(1700000000)
//!     .base_fee(10)
//!     .gas_limit(15_000_000)
//!     .build()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default gas limit for the block (30 million).
pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 30_000_000;

/// Default chain ID for IONA testnet (can be overridden).
pub const DEFAULT_CHAIN_ID: u64 = 6126151;

/// Default base fee (1 gwei = 1_000_000_000 wei).
pub const DEFAULT_BASE_FEE: u64 = 1_000_000_000;

/// Default blob gas limit (EIP‑4844, 262,144).
pub const DEFAULT_BLOB_GAS_LIMIT: u64 = 262_144;

/// Maximum block gas limit (safety cap, 50 million).
pub const MAX_BLOCK_GAS_LIMIT: u64 = 50_000_000;

/// Minimum base fee (1 wei).
pub const MIN_BASE_FEE: u64 = 1;

/// Maximum base fee (1e12 wei = 1000 gwei).
pub const MAX_BASE_FEE: u64 = 1_000_000_000_000;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when building the environment.
#[derive(Debug, Error)]
pub enum EnvError {
    /// Chain ID cannot be zero.
    #[error("chain ID cannot be zero")]
    ZeroChainId,

    /// Block number overflow (exceeds 2^64).
    #[error("block number overflow: {0}")]
    BlockNumberOverflow(u64),

    /// Timestamp overflow.
    #[error("timestamp overflow: {0}")]
    TimestampOverflow(u64),

    /// Gas limit exceeds maximum allowed.
    #[error("gas limit {0} exceeds maximum {MAX_BLOCK_GAS_LIMIT}")]
    GasLimitTooHigh(u64),

    /// Gas limit is zero.
    #[error("gas limit must be > 0, got {0}")]
    GasLimitZero(u64),

    /// Base fee exceeds maximum.
    #[error("base fee {0} exceeds maximum {MAX_BASE_FEE}")]
    BaseFeeTooHigh(u64),

    /// Base fee is zero.
    #[error("base fee must be > 0, got {0}")]
    BaseFeeZero(u64),

    /// Difficulty overflow.
    #[error("difficulty overflow: {0}")]
    DifficultyOverflow(u64),
}

pub type EnvResult<T> = Result<T, EnvError>;

// -----------------------------------------------------------------------------
// Environment builder
// -----------------------------------------------------------------------------

/// Builder for creating custom EVM execution environments.
///
/// Supports all EIPs relevant to IONA (EIP‑1559, EIP‑4844, EIP‑4399).
#[derive(Debug, Clone, Default)]
pub struct EnvBuilder {
    chain_id: Option<u64>,
    block_number: Option<u64>,
    block_timestamp: Option<u64>,
    block_coinbase: Option<Address>,
    block_base_fee: Option<u64>,
    block_gas_limit: Option<u64>,
    block_blob_gas_limit: Option<u64>,
    block_difficulty: Option<U256>,
    block_prevrandao: Option<U256>,
    enable_blob: bool,
    // Performance options
    perf_analyse_bytecode_accesses: bool,
    perf_analyse_created_bytecodes: bool,
}

impl EnvBuilder {
    /// Create a new builder with the given chain ID.
    pub fn new(chain_id: u64) -> Self {
        Self {
            chain_id: Some(chain_id),
            ..Default::default()
        }
    }

    /// Set the block number.
    pub fn block_number(mut self, number: u64) -> Self {
        self.block_number = Some(number);
        self
    }

    /// Set the block timestamp (Unix seconds).
    pub fn block_timestamp(mut self, timestamp: u64) -> Self {
        self.block_timestamp = Some(timestamp);
        self
    }

    /// Use the current system time as the block timestamp.
    pub fn block_timestamp_now(mut self) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.block_timestamp = Some(now);
        self
    }

    /// Set the block coinbase (fee recipient).
    pub fn block_coinbase(mut self, coinbase: Address) -> Self {
        self.block_coinbase = Some(coinbase);
        self
    }

    /// Set the base fee (per gas) in wei.
    pub fn base_fee(mut self, base_fee: u64) -> Self {
        self.block_base_fee = Some(base_fee);
        self
    }

    /// Set the block gas limit.
    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.block_gas_limit = Some(gas_limit);
        self
    }

    /// Set the blob gas limit (EIP‑4844).
    pub fn blob_gas_limit(mut self, blob_gas_limit: u64) -> Self {
        self.block_blob_gas_limit = Some(blob_gas_limit);
        self
    }

    /// Enable blob transactions (EIP‑4844).
    pub fn enable_blob(mut self, enable: bool) -> Self {
        self.enable_blob = enable;
        self
    }

    /// Set the block difficulty (for PoW chains, unused in PoS).
    pub fn difficulty(mut self, difficulty: U256) -> Self {
        self.block_difficulty = Some(difficulty);
        self
    }

    /// Set the prevrandao value (PoS randomness, EIP‑4399).
    pub fn prevrandao(mut self, prevrandao: U256) -> Self {
        self.block_prevrandao = Some(prevrandao);
        self
    }

    /// Enable performance analysis of bytecode accesses.
    pub fn analyse_bytecode_accesses(mut self, enable: bool) -> Self {
        self.perf_analyse_bytecode_accesses = enable;
        self
    }

    /// Enable performance analysis of created bytecodes.
    pub fn analyse_created_bytecodes(mut self, enable: bool) -> Self {
        self.perf_analyse_created_bytecodes = enable;
        self
    }

    /// Validate the configuration.
    fn validate(&self) -> EnvResult<()> {
        if let Some(chain_id) = self.chain_id {
            if chain_id == 0 {
                return Err(EnvError::ZeroChainId);
            }
        } else {
            return Err(EnvError::ZeroChainId);
        }

        if let Some(gas_limit) = self.block_gas_limit {
            if gas_limit == 0 {
                return Err(EnvError::GasLimitZero(gas_limit));
            }
            if gas_limit > MAX_BLOCK_GAS_LIMIT {
                return Err(EnvError::GasLimitTooHigh(gas_limit));
            }
        }

        if let Some(base_fee) = self.block_base_fee {
            if base_fee == 0 {
                return Err(EnvError::BaseFeeZero(base_fee));
            }
            if base_fee > MAX_BASE_FEE {
                return Err(EnvError::BaseFeeTooHigh(base_fee));
            }
        }

        Ok(())
    }

    /// Build the EVM environment.
    pub fn build(self) -> EnvResult<Env> {
        self.validate()?;

        let chain_id = self.chain_id.unwrap();
        let mut env = Env::default();

        // Configure chain (CfgEnv)
        env.cfg = CfgEnv::default();
        env.cfg.chain_id = chain_id;
        env.cfg.perf_analyse_created_bytecodes = self.perf_analyse_created_bytecodes;
        env.cfg.perf_analyse_bytecode_accesses = self.perf_analyse_bytecode_accesses;

        // Configure block (BlockEnv)
        env.block = BlockEnv::default();
        env.block.number = U256::from(self.block_number.unwrap_or(0));
        env.block.timestamp = U256::from(self.block_timestamp.unwrap_or(0));
        env.block.coinbase = self.block_coinbase.unwrap_or(Address::ZERO);
        env.block.basefee = U256::from(self.block_base_fee.unwrap_or(DEFAULT_BASE_FEE));
        env.block.gas_limit = U256::from(self.block_gas_limit.unwrap_or(DEFAULT_BLOCK_GAS_LIMIT));
        env.block.blob_gas_limit = if self.enable_blob {
            Some(U256::from(self.block_blob_gas_limit.unwrap_or(DEFAULT_BLOB_GAS_LIMIT)))
        } else {
            None
        };
        env.block.difficulty = self.block_difficulty.unwrap_or(U256::ZERO);
        env.block.prevrandao = self.block_prevrandao;

        // Empty transaction (to be filled by executor)
        env.tx = TxEnv::default();

        Ok(env)
    }
}

// -----------------------------------------------------------------------------
// Quick creation helpers
// -----------------------------------------------------------------------------

/// Create a default EVM execution environment with the given chain ID.
///
/// The returned `Env` has:
/// - `chain_id` set to the provided value
/// - `block.number` = 0
/// - `block.coinbase` = zero address
/// - `block.timestamp` = 0
/// - `block.basefee` = 1 gwei
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
    env.block.basefee = U256::from(DEFAULT_BASE_FEE);
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

/// Create an environment with the current block timestamp.
pub fn env_with_current_time(chain_id: u64) -> EnvResult<Env> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    EnvBuilder::new(chain_id)
        .block_timestamp(now)
        .build()
}

/// Create an environment for testing (fixed timestamp and base fee).
pub fn test_env(chain_id: u64, block_number: u64) -> EnvResult<Env> {
    EnvBuilder::new(chain_id)
        .block_number(block_number)
        .block_timestamp(1_700_000_000)
        .base_fee(10)
        .gas_limit(15_000_000)
        .build()
}

/// Create an environment for a fork simulation.
pub fn fork_env(chain_id: u64, block_number: u64, base_fee: u64) -> EnvResult<Env> {
    EnvBuilder::new(chain_id)
        .block_number(block_number)
        .block_timestamp_now()
        .base_fee(base_fee)
        .build()
}

/// Create an environment with EIP-4844 blob support enabled.
pub fn env_with_blobs(chain_id: u64, block_number: u64, blob_gas_limit: u64) -> EnvResult<Env> {
    EnvBuilder::new(chain_id)
        .block_number(block_number)
        .block_timestamp_now()
        .enable_blob(true)
        .blob_gas_limit(blob_gas_limit)
        .build()
}

/// Create an environment for mainnet default values.
pub fn mainnet_env(chain_id: u64) -> EnvResult<Env> {
    EnvBuilder::new(chain_id)
        .block_number(0)
        .block_timestamp_now()
        .base_fee(DEFAULT_BASE_FEE)
        .gas_limit(DEFAULT_BLOCK_GAS_LIMIT)
        .enable_blob(true)
        .build()
}

// -----------------------------------------------------------------------------
// Default trait implementations
// -----------------------------------------------------------------------------

impl Default for EnvBuilder {
    fn default() -> Self {
        Self {
            chain_id: None,
            block_number: Some(0),
            block_timestamp: Some(0),
            block_coinbase: Some(Address::ZERO),
            block_base_fee: Some(DEFAULT_BASE_FEE),
            block_gas_limit: Some(DEFAULT_BLOCK_GAS_LIMIT),
            block_blob_gas_limit: Some(DEFAULT_BLOB_GAS_LIMIT),
            block_difficulty: Some(U256::ZERO),
            block_prevrandao: None,
            enable_blob: false,
            perf_analyse_bytecode_accesses: true,
            perf_analyse_created_bytecodes: false,
        }
    }
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
        assert_eq!(env.block.basefee, U256::from(DEFAULT_BASE_FEE));
    }

    #[test]
    fn test_default_env_zero_chain_id() {
        let err = default_env(0).unwrap_err();
        assert!(matches!(err, EnvError::ZeroChainId));
    }

    #[test]
    fn test_builder_custom() -> EnvResult<()> {
        let env = EnvBuilder::new(6126151)
            .block_number(1000)
            .block_timestamp(1_700_000_000)
            .base_fee(10)
            .gas_limit(15_000_000)
            .build()?;

        assert_eq!(env.cfg.chain_id, 6126151);
        assert_eq!(env.block.number, U256::from(1000));
        assert_eq!(env.block.timestamp, U256::from(1_700_000_000));
        assert_eq!(env.block.basefee, U256::from(10));
        assert_eq!(env.block.gas_limit, U256::from(15_000_000));
        Ok(())
    }

    #[test]
    fn test_builder_with_blob() -> EnvResult<()> {
        let env = EnvBuilder::new(6126151)
            .enable_blob(true)
            .blob_gas_limit(131_072)
            .build()?;

        assert_eq!(env.block.blob_gas_limit, Some(U256::from(131_072)));
        Ok(())
    }

    #[test]
    fn test_builder_validation_gas_limit_too_high() {
        let builder = EnvBuilder::new(6126151)
            .gas_limit(MAX_BLOCK_GAS_LIMIT + 1);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, EnvError::GasLimitTooHigh(_)));
    }

    #[test]
    fn test_builder_validation_gas_limit_zero() {
        let builder = EnvBuilder::new(6126151)
            .gas_limit(0);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, EnvError::GasLimitZero(0)));
    }

    #[test]
    fn test_builder_validation_base_fee_too_high() {
        let builder = EnvBuilder::new(6126151)
            .base_fee(MAX_BASE_FEE + 1);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, EnvError::BaseFeeTooHigh(_)));
    }

    #[test]
    fn test_builder_validation_base_fee_zero() {
        let builder = EnvBuilder::new(6126151)
            .base_fee(0);
        let err = builder.build().unwrap_err();
        assert!(matches!(err, EnvError::BaseFeeZero(0)));
    }

    #[test]
    fn test_test_env() -> EnvResult<()> {
        let env = test_env(6126151, 500)?;
        assert_eq!(env.block.number, U256::from(500));
        assert_eq!(env.block.basefee, U256::from(10));
        assert_eq!(env.block.gas_limit, U256::from(15_000_000));
        Ok(())
    }

    #[test]
    fn test_fork_env() -> EnvResult<()> {
        let env = fork_env(6126151, 1_000_000, 100)?;
        assert_eq!(env.block.number, U256::from(1_000_000));
        assert_eq!(env.block.basefee, U256::from(100));
        Ok(())
    }

    #[test]
    fn test_default_env_unchecked_deprecated() {
        #[allow(deprecated)]
        let env = default_env_unchecked(42);
        assert_eq!(env.cfg.chain_id, 42);
    }

    #[test]
    fn test_env_with_current_time() -> EnvResult<()> {
        let env = env_with_current_time(6126151)?;
        assert!(env.block.timestamp > U256::from(1_700_000_000));
        Ok(())
    }

    #[test]
    fn test_mainnet_env() -> EnvResult<()> {
        let env = mainnet_env(6126151)?;
        assert_eq!(env.cfg.chain_id, 6126151);
        assert_eq!(env.block.gas_limit, U256::from(DEFAULT_BLOCK_GAS_LIMIT));
        assert_eq!(env.block.basefee, U256::from(DEFAULT_BASE_FEE));
        assert!(env.block.blob_gas_limit.is_some());
        Ok(())
    }

    #[test]
    fn test_env_with_blobs() -> EnvResult<()> {
        let env = env_with_blobs(6126151, 1000, 100_000)?;
        assert_eq!(env.block.number, U256::from(1000));
        assert_eq!(env.block.blob_gas_limit, Some(U256::from(100_000)));
        Ok(())
    }

    #[test]
    fn test_builder_performance_options() -> EnvResult<()> {
        let env = EnvBuilder::new(6126151)
            .analyse_bytecode_accesses(true)
            .analyse_created_bytecodes(true)
            .build()?;
        assert!(env.cfg.perf_analyse_bytecode_accesses);
        assert!(env.cfg.perf_analyse_created_bytecodes);
        Ok(())
    }
}
