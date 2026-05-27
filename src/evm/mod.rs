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
//! use iona::evm::{execute_evm_on_state, EvmTx, KvStateDb};
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
//! );
//! if result.success {
//!     println!("Transaction successful, gas used: {}", result.gas_used);
//! }
//! ```

pub mod db;
pub mod executor;
pub mod executor_env;
/// Unified EVM executor backed by live KvState.
/// This replaces the isolated `MemDb` with real chain state (balances, nonces, contracts).
pub mod kv_state_db;
pub mod types;

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

// Database
pub use db::MemDb;

// Executor
pub use executor::{execute_evm_tx, EvmExecOutput, EvmExecutorError, EvmExecutorMetrics};

// Environment
pub use executor_env::{
    default_env, default_env_unchecked, EnvBuilder, EnvError, EnvResult,
    fork_env, test_env, DEFAULT_BASE_FEE, DEFAULT_BLOCK_GAS_LIMIT, DEFAULT_CHAIN_ID,
};

// Unified state executor (recommended for production)
pub use kv_state_db::{
    evm_to_iona_addr, execute_evm_on_state, execute_evm_on_state_with_config,
    iona_addr_hex, iona_to_evm_addr, KvStateDb, KvStateDbError, UnifiedEvmResult,
};

// Transaction types
pub use types::{AccessListItem, EvmTx};

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
/// let result = execute_evm_on_state(&mut state, tx, 0, 0, 1, 1);
/// ```
pub mod prelude {
    pub use super::{
        default_env, execute_evm_on_state, execute_evm_on_state_with_config,
        execute_evm_tx, EvmExecOutput, EvmExecutorConfig, EvmExecutorMetrics,
        EvmTx, KvStateDb, MemDb, UnifiedEvmResult,
    };
}

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
