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
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Executor Env Module                             │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   constants │    error     │    builder    │        helpers           │
//! │ (constants) │ (EnvError)   │ (EnvBuilder)  │ (default_env, test_env)  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (EnvManager)│ (deprecated) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evm::executor_env::{EnvManager, EnvBuilder, default_env};
//!
//! // Quick default
//! let env = default_env(6126151)?;
//!
//! // Using the manager
//! let manager = EnvManager::default();
//! let env = manager.default_env(6126151)?;
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

#![allow(dead_code)]

use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for the EVM environment.

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
}

pub mod error {
    //! Error types for environment building.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum EnvError {
        #[error("chain ID cannot be zero")]
        ZeroChainId,

        #[error("block number overflow: {0}")]
        BlockNumberOverflow(u64),

        #[error("timestamp overflow: {0}")]
        TimestampOverflow(u64),

        #[error("gas limit {0} exceeds maximum {MAX_BLOCK_GAS_LIMIT}")]
        GasLimitTooHigh(u64),

        #[error("gas limit must be > 0, got {0}")]
        GasLimitZero(u64),

        #[error("base fee {0} exceeds maximum {MAX_BASE_FEE}")]
        BaseFeeTooHigh(u64),

        #[error("base fee must be > 0, got {0}")]
        BaseFeeZero(u64),

        #[error("difficulty overflow: {0}")]
        DifficultyOverflow(u64),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type EnvResult<T> = Result<T, EnvError>;
}

pub mod builder {
    //! Builder for creating custom EVM environments.
    use super::{
        constants::*,
        error::{EnvError, EnvResult},
    };
    use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};
    use core::default::Default;
    use core::fmt;

    /// Builder for creating custom EVM execution environments.
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

            env.cfg = CfgEnv::default();
            env.cfg.chain_id = chain_id;
            env.cfg.perf_analyse_created_bytecodes = self.perf_analyse_created_bytecodes;
            env.cfg.perf_analyse_bytecode_accesses = self.perf_analyse_bytecode_accesses;

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

            env.tx = TxEnv::default();

            Ok(env)
        }

        /// Build with default configuration (chain ID required).
        pub fn build_default(chain_id: u64) -> EnvResult<Env> {
            Self::new(chain_id).build()
        }
    }

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
}

pub mod helpers {
    //! Quick creation helpers for common environments.
    use super::{
        error::EnvResult,
        builder::EnvBuilder,
        constants::DEFAULT_BASE_FEE,
        Constants,
    };
    use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TxEnv, U256};
    use std::time::{SystemTime, UNIX_EPOCH};

    /// Create a default EVM environment with the given chain ID.
    pub fn default_env(chain_id: u64) -> EnvResult<Env> {
        EnvBuilder::new(chain_id).build()
    }

    /// Create an environment with the current block timestamp.
    pub fn env_with_current_time(chain_id: u64) -> EnvResult<Env> {
        EnvBuilder::new(chain_id)
            .block_timestamp_now()
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
            .gas_limit(constants::DEFAULT_BLOCK_GAS_LIMIT)
            .enable_blob(true)
            .build()
    }
}

pub mod manager {
    //! Centralised manager for environment creation.
    use super::{
        error::EnvResult,
        builder::EnvBuilder,
        helpers,
        constants,
    };
    use revm::primitives::Env;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use tracing::{debug, info};

    /// Configuration for the environment manager.
    #[derive(Debug, Clone, Default)]
    pub struct EnvManagerConfig {
        pub default_chain_id: u64,
        pub default_gas_limit: u64,
        pub default_base_fee: u64,
        pub enable_blob_by_default: bool,
        pub collect_metrics: bool,
    }

    /// Metrics for environment creation.
    #[derive(Debug, Default)]
    pub struct EnvManagerMetrics {
        pub total_creations: AtomicU64,
        pub fork_envs: AtomicU64,
        pub test_envs: AtomicU64,
    }

    impl EnvManagerMetrics {
        pub fn inc_total(&self) {
            self.total_creations.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_fork(&self) {
            self.fork_envs.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_test(&self) {
            self.test_envs.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Manager for creating EVM environments.
    pub struct EnvManager {
        config: EnvManagerConfig,
        metrics: Arc<EnvManagerMetrics>,
    }

    impl EnvManager {
        /// Create a new manager with the given configuration.
        pub fn new(config: EnvManagerConfig) -> Self {
            Self {
                config,
                metrics: Arc::new(EnvManagerMetrics::default()),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(EnvManagerConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &EnvManagerMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &EnvManagerConfig {
            &self.config
        }

        /// Create a default environment with the manager's chain ID.
        pub fn default_env(&self) -> EnvResult<Env> {
            self.metrics.inc_total();
            helpers::default_env(self.config.default_chain_id)
        }

        /// Create a default environment with a custom chain ID.
        pub fn env_with_chain_id(&self, chain_id: u64) -> EnvResult<Env> {
            self.metrics.inc_total();
            helpers::default_env(chain_id)
        }

        /// Create a test environment.
        pub fn test_env(&self, block_number: u64) -> EnvResult<Env> {
            self.metrics.inc_total();
            self.metrics.inc_test();
            helpers::test_env(self.config.default_chain_id, block_number)
        }

        /// Create a fork environment.
        pub fn fork_env(&self, block_number: u64, base_fee: u64) -> EnvResult<Env> {
            self.metrics.inc_total();
            self.metrics.inc_fork();
            helpers::fork_env(self.config.default_chain_id, block_number, base_fee)
        }

        /// Create an environment with the current timestamp.
        pub fn env_with_current_time(&self) -> EnvResult<Env> {
            self.metrics.inc_total();
            helpers::env_with_current_time(self.config.default_chain_id)
        }

        /// Build a custom environment using a builder.
        pub fn build(&self, builder: EnvBuilder) -> EnvResult<Env> {
            self.metrics.inc_total();
            builder.build()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::{
    DEFAULT_BLOCK_GAS_LIMIT, DEFAULT_CHAIN_ID, DEFAULT_BASE_FEE, DEFAULT_BLOB_GAS_LIMIT,
    MAX_BLOCK_GAS_LIMIT, MIN_BASE_FEE, MAX_BASE_FEE,
};
pub use error::{EnvError, EnvResult};
pub use builder::EnvBuilder;
pub use helpers::{
    default_env, env_with_current_time, test_env, fork_env, env_with_blobs, mainnet_env,
};
pub use manager::{EnvManager, EnvManagerConfig, EnvManagerMetrics};

// -----------------------------------------------------------------------------
// Legacy deprecated functions (backward compatibility)
// -----------------------------------------------------------------------------

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
    use revm::primitives::U256;

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

    #[test]
    fn test_manager() -> EnvResult<()> {
        let manager = EnvManager::default();
        let env = manager.default_env()?;
        assert_eq!(env.cfg.chain_id, DEFAULT_CHAIN_ID);
        let env2 = manager.test_env(100)?;
        assert_eq!(env2.block.number, U256::from(100));
        let env3 = manager.fork_env(200, 20)?;
        assert_eq!(env3.block.number, U256::from(200));
        assert_eq!(env3.block.basefee, U256::from(20));
        let metrics = manager.metrics();
        assert_eq!(metrics.total_creations.load(Ordering::Relaxed), 3);
        Ok(())
    }
}
