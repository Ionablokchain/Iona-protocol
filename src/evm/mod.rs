//! Ethereum Virtual Machine (EVM) integration for IONA.
//!
//! This module provides:
//! - `db::MemDb` – in‑memory database for testing/dev.
//! - `executor` – REVM transaction executor.
//! - `executor_env` – default execution environment builder.
//! - `kv_state_db` – **unified EVM backend** backed by live `KvState`
//!   (balances, nonces, storage, code).
//! - `types` – EVM transaction types (`EvmTx`, `AccessListItem`).
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::evm::{execute_evm_on_state, EvmTx, KvStateDb};
//!
//! let mut state = KvState::default();
//! let tx = EvmTx::Legacy { /* ... */ };
//! let result = execute_evm_on_state(&mut state, tx, block_number, timestamp, base_fee, chain_id);
//! if result.success {
//!     // state updated
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

pub use db::MemDb;
pub use executor::{execute_evm_tx, EvmExecOutput, EvmExecutorError};
pub use executor_env::{default_env, default_env_unchecked, EnvError, DEFAULT_BLOCK_GAS_LIMIT, DEFAULT_CHAIN_ID};
pub use kv_state_db::{
    evm_to_iona_addr, execute_evm_on_state, iona_addr_hex, iona_to_evm_addr, KvStateDb,
    KvStateDbError, UnifiedEvmResult,
};
pub use types::{AccessListItem, EvmTx};

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Convenience prelude for the EVM module.
pub mod prelude {
    pub use super::{
        default_env, execute_evm_on_state, execute_evm_tx, EvmExecOutput, EvmTx, KvStateDb,
        MemDb, UnifiedEvmResult,
    };
}
