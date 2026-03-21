//! EVM execution engine for IONA.
//!
//! This module integrates the `revm` EVM with IONA's native state (`KvState`),
//! enabling full Ethereum compatibility. It supports:
//! - Legacy, EIP-2930, and EIP-1559 transactions.
//! - In‑memory database for testing (`MemDb`).
//! - Production database that reads/writes directly to `KvState` (`KvStateDb`).
//! - Execution environment builders from Iona block headers.
//!
//! ## Module structure
//!
//! - `db` – In‑memory REVM database for testing and development.
//! - `executor` – Core EVM transaction execution logic (wraps `revm`).
//! - `executor_env` – Helpers to build REVM environments from Iona block headers.
//! - `kv_state_db` – The unification bridge: `revm::Database` backed by `KvState`.
//! - `types` – Re‑exports of EVM transaction types (from `crate::types::tx_evm`).
//!
//! ## Usage
//!
//! To execute an EVM transaction on the current state:
//!
//! ```rust,ignore
//! use iona::evm::{execute_evm_on_state, UnifiedEvmResult};
//! use iona::types::tx_evm::EvmTx;
//!
//! let mut state = KvState::default();
//! let tx = EvmTx::Legacy { ... };
//!
//! let result = execute_evm_on_state(
//!     &mut state, tx,
//!     block_height, block_timestamp, base_fee, gas_limit, coinbase, chain_id,
//! );
//!
//! if result.success {
//!     // State is updated.
//! } else {
//!     println!("Transaction reverted: {:?}", result.error);
//! }
//! ```

// Submodule declarations.
pub mod db;
pub mod executor;
pub mod executor_env;
pub mod kv_state_db;
// `types` is just a re‑export of the EVM transaction types from the types crate.
pub mod types {
    pub use crate::types::tx_evm::*;
}

// Re‑export the most important public items for a convenient top‑level API.
pub use db::MemDb;
pub use executor::execute_evm_tx; // the simpler version (if any)
pub use executor_env::{build_evm_env, default_env, env_from_header};
pub use kv_state_db::{
    evm_to_iona_addr, execute_evm_on_state, iona_addr_hex, iona_to_evm_addr,
    KvStateDb, UnifiedEvmResult,
};
