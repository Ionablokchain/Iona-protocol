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
//! use iona::evm::{execute_evm_on_state, EvmTx};
//!
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
//! let result = execute_evm_on_state(
//!     &mut state,
//!     tx,
//!     1000,           // block_number
//!     1_700_000_000,  // timestamp
//!     10,             // base_fee_per_gas
//!     6126151,        // chain_id
//!     None,           // gas_limit override (optional)
//! );
//! if result.success {
//!     println!("Transaction successful, gas used: {}", result.gas_used);
//! }
//! ```
//!
//! # Feature flags
//! - `std` – enables file-system persistence for `MemDb` (disabled by default in kernel).
//! - `tracing` – enables detailed logging of EVM execution (recommended for production).
//! - `metrics` – enables Prometheus metrics collection (enabled by default).

pub mod db;
pub mod executor;
pub mod executor_env;
/// Unified EVM executor backed by live KvState.
/// This replaces the isolated `MemDb` with real chain state (balances, nonces, contracts).
pub mod kv_state_db;
pub mod types;

// -----------------------------------------------------------------------------
// Re‑exports of all important types and functions
// -----------------------------------------------------------------------------

// Database
pub use db::{MemDb, MemDbConfig, MemDbError, MemDbMetrics};

// Executor
pub use executor::{
    execute_evm_tx, EvmExecOutput, EvmExecutor, EvmExecutorBuilder, EvmExecutorConfig,
    EvmExecutorMetrics, ExecError, ExecOutput, EvmExecutor as Executor,
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

// -----------------------------------------------------------------------------
// Global metrics access
// -----------------------------------------------------------------------------

/// Initialise global EVM executor metrics.
pub fn init_metrics() {
    executor::init_global_metrics();
}

/// Get global EVM executor metrics (if initialised).
pub fn metrics() -> Option<&'static executor::EvmExecutorMetrics> {
    executor::get_global_metrics()
}

// -----------------------------------------------------------------------------
// Unified configuration
// -----------------------------------------------------------------------------

/// Combined configuration for the EVM subsystem.
///
/// Bundles executor and environment settings.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct EvmConfig {
    /// Executor configuration.
    pub executor: EvmExecutorConfig,
    /// Database configuration (for `KvStateDb`).
    pub db: KvStateDbConfig,
    /// Default chain ID.
    pub chain_id: u64,
    /// Default block gas limit.
    pub default_gas_limit: u64,
    /// Default base fee.
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

/// Create a REVM environment from an `EvmConfig` and block/tx details.
#[inline]
pub fn env_from_config(
    config: &EvmConfig,
    block_number: u64,
    block_timestamp: u64,
    tx: &EvmTx,
) -> revm::primitives::Env {
    build_evm_env(
        config.chain_id,
        block_number,
        block_timestamp,
        config.default_base_fee,
        tx,
        Some(config.default_gas_limit),
    )
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
    "1.0.0"
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the EVM module.
///
/// Import this to get access to the most common EVM types and functions.
///
/// # Example
/// ```rust,ignore
/// use iona::evm::prelude::*;
///
/// let mut state = KvState::default();
/// let tx = EvmTx::Legacy { /* ... */ };
/// let result = execute_evm_on_state(&mut state, tx, 0, 0, 1, 1, None);
/// ```
pub mod prelude {
    pub use super::{
        // Core execution
        execute_evm_on_state, execute_evm_on_state_with_config, execute_evm_tx,
        // Types
        EvmExecOutput, EvmExecutor, EvmExecutorConfig, EvmTx, ExecError, ExecOutput,
        // Environment helpers
        build_evm_env, default_env, env_from_config, fork_env, test_env,
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
    use crate::evm::types::{AccessListItem, EvmTx};
    use crate::execution::KvState;

    #[test]
    fn test_evm_config_defaults() {
        let config = EvmConfig::default();
        assert_eq!(config.chain_id, DEFAULT_CHAIN_ID);
        assert_eq!(config.default_gas_limit, DEFAULT_BLOCK_GAS_LIMIT);
        assert_eq!(config.default_base_fee, DEFAULT_BASE_FEE);
    }

    #[test]
    fn test_env_from_config() {
        let config = EvmConfig::default();
        let tx = EvmTx::Legacy {
            from: [0xAB; 20],
            to: Some([0xCD; 20]),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };
        let env = env_from_config(&config, 1000, 1_700_000_000, &tx);
        assert_eq!(env.cfg.chain_id, 6126151);
        assert_eq!(env.block.number, U256::from(1000));
        assert_eq!(env.block.timestamp, U256::from(1_700_000_000));
        assert_eq!(env.block.basefee, U256::from(DEFAULT_BASE_FEE));
        assert_eq!(env.block.gas_limit, U256::from(DEFAULT_BLOCK_GAS_LIMIT));
    }

    #[test]
    fn test_module_version() {
        assert!(!module_version().is_empty());
        assert!(!revm_version().is_empty());
    }
}
