//! Ethereum Virtual Machine (EVM) integration for IONA.
//!
//! This module provides:
//! - `db::MemDb` – in‑memory database for testing and development.
//! - `executor` – REVM transaction executor with full EIP support.
//! - `executor_env` – default execution environment builder.
//! - `kv_state_db` – **unified EVM backend** backed by live `KvState`
//!   (balances, nonces, storage, code).
//! - `types` – EVM transaction types (`EvmTx`, `AccessListItem`).
//!
//! # Features
//! - Legacy, EIP‑2930, and EIP‑1559 transaction support
//! - Full state integration with IONA's `KvState`
//! - Gas metering and fee calculation
//! - Support for contract creation and calls
//! - EVM logs and event emission
//! - Configurable gas limits, prices, and refunds
//! - Metrics collection (success/failure rates, gas usage, timing)
//! - Fork support and state snapshots
//!
//! # Architecture
//!
//! ```text
//!                    ┌─────────────────┐
//!                    │    EvmTx        │
//!                    │ (Legacy/2930/   │
//!                    │  1559)          │
//!                    └────────┬────────┘
//!                             │
//!                             ▼
//!                    ┌─────────────────┐
//!                    │  execute_evm_on │
//!                    │     _state()    │
//!                    └────────┬────────┘
//!                             │
//!              ┌──────────────┼──────────────┐
//!              │              │              │
//!              ▼              ▼              ▼
//!       ┌──────────┐   ┌────────────┐   ┌──────────┐
//!       │ KvStateDb│   │ ExecutorEnv│   │ Executor │
//!       │(unified  │   │  (Env      │   │ (REVM)   │
//!       │ backend) │   │  builder)  │   │          │
//!       └──────────┘   └────────────┘   └──────────┘
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::evm::{EvmManager, EvmConfig, EvmTx};
//!
//! let config = EvmConfig::default();
//! let manager = EvmManager::new(config);
//! let mut state = KvState::default();
//! let tx = EvmTx::Legacy {
//!     from: [0xAB; 20],
//!     to: Some([0xCD; 20]),
//!     nonce: 0,
//!     gas_limit: 100_000,
//!     gas_price: 10,
//!     value: 1_000,
//!     data: vec![],
//!     chain_id: 6126151,
//! };
//! let result = manager.execute_tx(&mut state, tx, 1000, 1700000000)?;
//! if result.success {
//!     println!("Transaction successful, gas used: {}", result.gas_used);
//! }
//! ```
//!
//! # Feature flags
//! - `std` – enables file-system persistence for `MemDb` (disabled by default in kernel).
//! - `tracing` – enables detailed logging of EVM execution (recommended for production).
//! - `metrics` – enables Prometheus metrics collection (enabled by default).

#![allow(dead_code)]

// -----------------------------------------------------------------------------
// Submodule declarations
// -----------------------------------------------------------------------------

pub mod db;
pub mod executor;
pub mod executor_env;
/// Unified EVM executor backed by live KvState.
/// This replaces the isolated `MemDb` with real chain state (balances, nonces, contracts).
pub mod kv_state_db;
pub mod types;

// -----------------------------------------------------------------------------
// Internal modules (embedded)
// -----------------------------------------------------------------------------

mod config {
    //! Configuration for the EVM subsystem.
    use super::{
        executor::EvmExecutorConfig,
        kv_state_db::KvStateDbConfig,
        executor_env::DEFAULT_CHAIN_ID,
        executor_env::DEFAULT_BLOCK_GAS_LIMIT,
        executor_env::DEFAULT_BASE_FEE,
    };
    use serde::{Deserialize, Serialize};
    use crate::evm::error::EvmError;

    /// Combined configuration for the EVM subsystem.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EvmConfig {
        pub executor: EvmExecutorConfig,
        pub db: KvStateDbConfig,
        pub chain_id: u64,
        pub default_gas_limit: u64,
        pub default_base_fee: u64,
    }

    impl Default for EvmConfig {
        fn default() -> Self {
            Self {
                executor: EvmExecutorConfig::default(),
                db: KvStateDbConfig::default(),
                chain_id: DEFAULT_CHAIN_ID,
                default_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
                default_base_fee: DEFAULT_BASE_FEE,
            }
        }
    }

    impl EvmConfig {
        pub fn validate(&self) -> Result<(), EvmError> {
            self.executor.validate().map_err(|e| EvmError::Config(e.to_string()))?;
            self.db.validate().map_err(|e| EvmError::Config(e.into()))?;
            if self.chain_id == 0 {
                return Err(EvmError::Config("chain_id cannot be zero".into()));
            }
            if self.default_gas_limit == 0 {
                return Err(EvmError::Config("default_gas_limit must be > 0".into()));
            }
            if self.default_base_fee == 0 {
                return Err(EvmError::Config("default_base_fee must be > 0".into()));
            }
            Ok(())
        }

        pub fn with_chain_id(mut self, id: u64) -> Self {
            self.chain_id = id;
            self
        }

        pub fn with_gas_limit(mut self, limit: u64) -> Self {
            self.default_gas_limit = limit;
            self
        }

        pub fn with_base_fee(mut self, fee: u64) -> Self {
            self.default_base_fee = fee;
            self
        }
    }
}

mod error {
    //! Unified error types for the EVM module.
    use super::{
        db::MemDbError,
        executor::ExecError,
        kv_state_db::KvStateDbError,
        executor_env::EnvError,
    };
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum EvmError {
        #[error("executor error: {0}")]
        Exec(#[from] ExecError),

        #[error("database error: {0}")]
        Db(#[from] MemDbError),

        #[error("state database error: {0}")]
        KvDb(#[from] KvStateDbError),

        #[error("environment error: {0}")]
        Env(#[from] EnvError),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),

        #[error("serialization error: {0}")]
        Serialization(String),
    }

    pub type EvmResult<T> = Result<T, EvmError>;
}

mod metrics {
    //! Aggregate metrics for the EVM subsystem.
    use std::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct EvmMetrics {
        pub total_txs: AtomicU64,
        pub successful_txs: AtomicU64,
        pub failed_txs: AtomicU64,
        pub reverted_txs: AtomicU64,
        pub total_gas_used: AtomicU64,
        pub total_effective_gas_price: AtomicU64,
        pub total_execution_time_ns: AtomicU64,
    }

    impl EvmMetrics {
        pub fn record_tx(&self, success: bool, reverted: bool, gas_used: u64, effective_gas_price: u64, duration_ns: u64) {
            self.total_txs.fetch_add(1, Ordering::Relaxed);
            if success {
                self.successful_txs.fetch_add(1, Ordering::Relaxed);
            } else if reverted {
                self.reverted_txs.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_txs.fetch_add(1, Ordering::Relaxed);
            }
            self.total_gas_used.fetch_add(gas_used, Ordering::Relaxed);
            self.total_effective_gas_price.fetch_add(effective_gas_price, Ordering::Relaxed);
            self.total_execution_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> EvmMetricsSnapshot {
            EvmMetricsSnapshot {
                total_txs: self.total_txs.load(Ordering::Relaxed),
                successful_txs: self.successful_txs.load(Ordering::Relaxed),
                failed_txs: self.failed_txs.load(Ordering::Relaxed),
                reverted_txs: self.reverted_txs.load(Ordering::Relaxed),
                total_gas_used: self.total_gas_used.load(Ordering::Relaxed),
                total_effective_gas_price: self.total_effective_gas_price.load(Ordering::Relaxed),
                total_execution_time_ns: self.total_execution_time_ns.load(Ordering::Relaxed),
            }
        }

        pub fn reset(&self) {
            self.total_txs.store(0, Ordering::Relaxed);
            self.successful_txs.store(0, Ordering::Relaxed);
            self.failed_txs.store(0, Ordering::Relaxed);
            self.reverted_txs.store(0, Ordering::Relaxed);
            self.total_gas_used.store(0, Ordering::Relaxed);
            self.total_effective_gas_price.store(0, Ordering::Relaxed);
            self.total_execution_time_ns.store(0, Ordering::Relaxed);
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct EvmMetricsSnapshot {
        pub total_txs: u64,
        pub successful_txs: u64,
        pub failed_txs: u64,
        pub reverted_txs: u64,
        pub total_gas_used: u64,
        pub total_effective_gas_price: u64,
        pub total_execution_time_ns: u64,
    }
}

mod manager {
    //! Centralised manager for the EVM subsystem.
    use super::{
        config::EvmConfig,
        error::{EvmError, EvmResult},
        metrics::EvmMetrics,
        kv_state_db::{KvStateDb, execute_evm_on_state, UnifiedEvmResult},
        executor::{EvmExecutor, EvmExecutorConfig},
        executor_env::EnvBuilder,
    };
    use crate::execution::KvState;
    use crate::types::tx_evm::EvmTx;
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info};

    /// Centralised manager for the EVM subsystem.
    #[derive(Clone)]
    pub struct EvmManager {
        config: EvmConfig,
        metrics: Arc<EvmMetrics>,
    }

    impl EvmManager {
        /// Create a new EVM manager with the given configuration.
        pub fn new(config: EvmConfig) -> EvmResult<Self> {
            config.validate()?;
            Ok(Self {
                config,
                metrics: Arc::new(EvmMetrics::default()),
            })
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(EvmConfig::default()).expect("default EVM manager")
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &EvmMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &EvmConfig {
            &self.config
        }

        /// Update the configuration.
        pub fn set_config(&mut self, config: EvmConfig) -> EvmResult<()> {
            config.validate()?;
            self.config = config;
            Ok(())
        }

        /// Create a new `KvStateDb` for the given state, using the manager's config.
        pub fn create_kv_db<'a>(&self, state: &'a mut KvState) -> KvStateDb<'a> {
            KvStateDb::with_config(state, self.config.db.clone())
        }

        /// Create a new `EvmExecutor` using the manager's config.
        pub fn create_executor(&self) -> EvmResult<EvmExecutor> {
            EvmExecutor::new(self.config.executor.clone(), None)
        }

        /// Execute a transaction against the given state, using the manager's config.
        pub fn execute_tx(
            &self,
            state: &mut KvState,
            tx: EvmTx,
            block_number: u64,
            block_timestamp: u64,
        ) -> EvmResult<UnifiedEvmResult> {
            let start = Instant::now();
            let result = execute_evm_on_state(
                state,
                tx,
                block_number,
                block_timestamp,
                self.config.default_base_fee,
                self.config.chain_id,
                Some(self.config.default_gas_limit),
            );
            let duration_ns = start.elapsed().as_nanos() as u64;
            self.metrics.record_tx(
                result.success,
                result.reverted,
                result.gas_used,
                result.effective_gas_price,
                duration_ns,
            );
            Ok(result)
        }

        /// Execute a transaction with custom base fee and gas limit override.
        pub fn execute_tx_with_params(
            &self,
            state: &mut KvState,
            tx: EvmTx,
            block_number: u64,
            block_timestamp: u64,
            base_fee: u64,
            gas_limit: Option<u64>,
        ) -> EvmResult<UnifiedEvmResult> {
            let start = Instant::now();
            let result = execute_evm_on_state(
                state,
                tx,
                block_number,
                block_timestamp,
                base_fee,
                self.config.chain_id,
                gas_limit,
            );
            let duration_ns = start.elapsed().as_nanos() as u64;
            self.metrics.record_tx(
                result.success,
                result.reverted,
                result.gas_used,
                result.effective_gas_price,
                duration_ns,
            );
            Ok(result)
        }

        /// Build an environment using the manager's config.
        pub fn build_env(&self, block_number: u64, block_timestamp: u64, tx: &EvmTx) -> revm::primitives::Env {
            super::kv_state_db::build_evm_env(
                self.config.chain_id,
                block_number,
                block_timestamp,
                self.config.default_base_fee,
                tx,
                Some(self.config.default_gas_limit),
            )
        }

        /// Get a snapshot of the metrics.
        pub fn metrics_snapshot(&self) -> super::metrics::EvmMetricsSnapshot {
            self.metrics.snapshot()
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            self.metrics.reset();
        }
    }
}

// -----------------------------------------------------------------------------
// Re‑exports of all important types and functions
// -----------------------------------------------------------------------------

// Database
pub use db::{MemDb, MemDbConfig, MemDbError, MemDbMetrics};

// Executor
pub use executor::{
    EvmExecutor, EvmExecutorBuilder, EvmExecutorConfig, EvmExecutorMetrics, EvmMetrics as ExecutorMetrics,
    ExecError, ExecOutput, EvmExecOutput, execute_evm_tx,
};

// Environment
pub use executor_env::{
    default_env, default_env_unchecked, env_with_blobs, env_with_current_time, fork_env,
    mainnet_env, test_env, EnvBuilder, EnvError, EnvResult, DEFAULT_BASE_FEE,
    DEFAULT_BLOB_GAS_LIMIT, DEFAULT_BLOCK_GAS_LIMIT, DEFAULT_CHAIN_ID,
};

// Unified state executor (recommended for production)
pub use kv_state_db::{
    build_evm_env, build_tx_env, evm_addr_hex, evm_to_iona_addr,
    execute_evm_on_state, execute_evm_on_state_with_config, iona_addr_hex,
    iona_addr_hex_prefixed, iona_to_evm_addr, parse_evm_addr, parse_iona_addr,
    KvStateDb, KvStateDbConfig, KvStateDbError, KvStateDbMetrics, UnifiedEvmResult,
};

// Transaction types
pub use types::{AccessListItem, EvmTx};

// Unified config and manager
pub use config::EvmConfig;
pub use error::{EvmError, EvmResult};
pub use metrics::{EvmMetrics, EvmMetricsSnapshot};
pub use manager::EvmManager;

// -----------------------------------------------------------------------------
// Global metrics access
// -----------------------------------------------------------------------------

static GLOBAL_METRICS: std::sync::OnceLock<EvmMetrics> = std::sync::OnceLock::new();

/// Initialise global EVM metrics.
pub fn init_metrics() {
    let _ = GLOBAL_METRICS.set(EvmMetrics::default());
    tracing::info!("Global EVM metrics initialised");
}

/// Get global EVM metrics (if initialised).
pub fn metrics() -> Option<&'static EvmMetrics> {
    GLOBAL_METRICS.get()
}

// -----------------------------------------------------------------------------
// Convenience function: execute a transaction with a default manager
// -----------------------------------------------------------------------------

/// Execute a transaction using a default manager and config.
pub fn execute_tx(
    state: &mut KvState,
    tx: EvmTx,
    block_number: u64,
    block_timestamp: u64,
) -> EvmResult<UnifiedEvmResult> {
    let manager = EvmManager::default();
    manager.execute_tx(state, tx, block_number, block_timestamp)
}

/// Execute a transaction with custom base fee and gas limit override.
pub fn execute_tx_with_params(
    state: &mut KvState,
    tx: EvmTx,
    block_number: u64,
    block_timestamp: u64,
    base_fee: u64,
    gas_limit: Option<u64>,
) -> EvmResult<UnifiedEvmResult> {
    let manager = EvmManager::default();
    manager.execute_tx_with_params(state, tx, block_number, block_timestamp, base_fee, gas_limit)
}

// -----------------------------------------------------------------------------
// Version information
// -----------------------------------------------------------------------------

/// Returns the REVM version used by this module.
pub fn revm_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the EVM module version.
pub fn module_version() -> &'static str {
    "2.0.0"
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the EVM module.
pub mod prelude {
    pub use super::{
        // Core execution
        execute_tx, execute_tx_with_params, execute_evm_on_state,
        // Types
        EvmTx, EvmConfig, EvmManager, EvmError, EvmResult,
        // Environment helpers
        build_evm_env, default_env, test_env, fork_env,
        // Database
        KvStateDb, KvStateDbConfig, MemDb, UnifiedEvmResult,
        // Metrics
        init_metrics, metrics,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;
    use crate::types::tx_evm::EvmTx;

    #[test]
    fn test_evm_config_defaults() {
        let config = EvmConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.default_gas_limit, DEFAULT_BLOCK_GAS_LIMIT);
        assert_eq!(config.default_base_fee, DEFAULT_BASE_FEE);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_evm_config_validation() {
        let mut config = EvmConfig::default();
        config.chain_id = 0;
        assert!(config.validate().is_err());
        config.chain_id = 1;
        config.default_gas_limit = 0;
        assert!(config.validate().is_err());
        config.default_gas_limit = 100_000;
        config.default_base_fee = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_evm_manager() -> EvmResult<()> {
        let config = EvmConfig::default();
        let manager = EvmManager::new(config)?;
        assert_eq!(manager.config().chain_id, DEFAULT_CHAIN_ID);

        let mut state = KvState::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        let key = kv_state_db::iona_addr_hex(&from);
        state.balances.insert(key, 10_000_000_000_000_000u64);

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };

        let result = manager.execute_tx(&mut state, tx, 1, 1_700_000_000)?;
        assert!(result.success);
        assert!(result.gas_used > 0);
        Ok(())
    }

    #[test]
    fn test_evm_manager_metrics() -> EvmResult<()> {
        let config = EvmConfig::default();
        let manager = EvmManager::new(config)?;
        let mut state = KvState::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        let key = kv_state_db::iona_addr_hex(&from);
        state.balances.insert(key, 10_000_000_000_000_000u64);

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };

        let _ = manager.execute_tx(&mut state, tx.clone(), 1, 1_700_000_000)?;
        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.total_txs, 1);
        assert_eq!(metrics.successful_txs, 1);

        // Execute a failing transaction (e.g., insufficient balance)
        let from2 = [0xCC; 20];
        let key2 = kv_state_db::iona_addr_hex(&from2);
        state.balances.insert(key2, 0);
        let tx2 = EvmTx::Legacy {
            from: from2,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };
        let _ = manager.execute_tx(&mut state, tx2, 1, 1_700_000_000);
        let metrics2 = manager.metrics_snapshot();
        assert_eq!(metrics2.total_txs, 2);
        assert_eq!(metrics2.failed_txs, 1);

        Ok(())
    }

    #[test]
    fn test_module_version() {
        assert!(!module_version().is_empty());
        assert!(!revm_version().is_empty());
    }

    #[test]
    fn test_global_metrics() {
        init_metrics();
        let metrics = metrics().unwrap();
        assert_eq!(metrics.total_txs.load(Ordering::Relaxed), 0);
        metrics.record_tx(true, false, 100, 10, 1000);
        assert_eq!(metrics.total_txs.load(Ordering::Relaxed), 1);
    }
}
