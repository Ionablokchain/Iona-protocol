//! `KvStateDb` — a `revm::Database` + `DatabaseCommit` implementation backed
//! by IONA's `KvState`.
//!
//! This is the **unification bridge** between IONA's native KV/balance state
//! and the full EVM execution environment provided by `revm`.
//!
//! ## Why this matters
//!
//! Previously IONA had **two separate VM paths**:
//!   1. `src/vm/` — a custom stack machine (arithmetic, SLOAD/SSTORE, LOG*, etc.)
//!   2. `src/evm/` — revm backed by an isolated `MemDb` that knew nothing about
//!      real chain state (balances, nonces, existing contracts).
//!
//! `KvStateDb` closes this gap.  The `evm` module now reads *and writes* to the
//! same `KvState` that the consensus engine commits at end-of-block.  This means:
//!   - EVM transactions see real account balances and nonces.
//!   - EVM-deployed contracts persist across blocks.
//!   - The state root includes EVM storage (already done via `KvState::root()`).
//!   - Tools like MetaMask / Hardhat / cast can interact correctly.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         KvStateDb Module                               │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │       address            │
//! │ (KvDbCfg)   │ (KvDbError)  │ (KvDbMetrics) │ (conversion helpers)     │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   db        │     env      │   executor    │        manager           │
//! │ (KvStateDb) │ (EVN build)  │ (unified exec)│ (KvDbManager)            │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evm::kv_state_db::{KvDbManager, KvStateDbConfig};
//! use iona::execution::KvState;
//!
//! let config = KvStateDbConfig::default();
//! let manager = KvDbManager::new(config);
//! let mut state = KvState::default();
//! let mut db = manager.create(&mut state);
//!
//! // Use db with revm::Evm
//! ```

#![allow(dead_code)]

use crate::execution::KvState;
use revm::primitives::{Account, AccountInfo, Address, Bytecode, B256, KECCAK_EMPTY, U256};
use revm::{Database, DatabaseCommit};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod constants {
    //! Constants for KvStateDb.
    /// Offset for converting 32-byte IONA address to 20-byte EVM address (last 20 bytes).
    pub const ADDRESS_TRUNCATE_OFFSET: usize = 12;

    /// Length of an Ethereum address in bytes.
    pub const EVM_ADDR_LEN: usize = 20;

    /// Default block gas limit for EVM execution (86 million).
    pub const DEFAULT_BLOCK_GAS_LIMIT: u64 = 86_000_000;

    /// Maximum code cache size (number of bytecode entries to keep).
    pub const DEFAULT_MAX_CODE_CACHE: usize = 10_000;

    /// Maximum storage cache size (number of slot entries to keep).
    pub const DEFAULT_MAX_STORAGE_CACHE: usize = 100_000;
}

pub mod error {
    //! Error types for KvStateDb.
    use revm::primitives::{Address, B256, U256};
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum KvStateDbError {
        #[error("code not found for hash 0x{hash:x}")]
        CodeNotFound { hash: B256 },

        #[error("storage slot not found for address 0x{address:x} slot 0x{slot:x}")]
        StorageNotFound { address: Address, slot: U256 },

        #[error("account not found for address 0x{address:x}")]
        AccountNotFound { address: Address },

        #[error("invalid address length: expected {expected}, got {got}")]
        InvalidAddressLength { expected: usize, got: usize },

        #[error("code hash mismatch: expected {expected}, got {got}")]
        CodeHashMismatch { expected: B256, got: B256 },

        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),

        #[error("serialization error: {0}")]
        Serialization(String),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type KvStateDbResult<T> = Result<T, KvStateDbError>;
}

pub mod config {
    //! Configuration for KvStateDb.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for `KvStateDb`.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KvStateDbConfig {
        pub max_code_cache: usize,
        pub max_storage_cache: usize,
        pub enable_code_cache: bool,
        pub enable_storage_cache: bool,
        pub track_metrics: bool,
        pub verify_code_hashes: bool,
        pub default_block_gas_limit: u64,
    }

    impl Default for KvStateDbConfig {
        fn default() -> Self {
            Self {
                max_code_cache: DEFAULT_MAX_CODE_CACHE,
                max_storage_cache: DEFAULT_MAX_STORAGE_CACHE,
                enable_code_cache: true,
                enable_storage_cache: true,
                track_metrics: true,
                verify_code_hashes: true,
                default_block_gas_limit: DEFAULT_BLOCK_GAS_LIMIT,
            }
        }
    }

    impl KvStateDbConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_code_cache == 0 {
                return Err("max_code_cache must be > 0");
            }
            if self.max_storage_cache == 0 {
                return Err("max_storage_cache must be > 0");
            }
            if self.default_block_gas_limit == 0 {
                return Err("default_block_gas_limit must be > 0");
            }
            Ok(())
        }
    }
}

pub mod metrics {
    //! Metrics for KvStateDb operations.
    use std::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct KvStateDbMetrics {
        pub basic_queries: AtomicU64,
        pub basic_hits: AtomicU64,
        pub code_queries: AtomicU64,
        pub code_hits: AtomicU64,
        pub storage_queries: AtomicU64,
        pub storage_hits: AtomicU64,
        pub commits: AtomicU64,
        pub accounts_created: AtomicU64,
        pub accounts_updated: AtomicU64,
        pub accounts_destroyed: AtomicU64,
        pub storage_writes: AtomicU64,
        pub code_writes: AtomicU64,
    }

    impl KvStateDbMetrics {
        pub fn record_basic_query(&self, hit: bool) {
            self.basic_queries.fetch_add(1, Ordering::Relaxed);
            if hit {
                self.basic_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
        pub fn record_code_query(&self, hit: bool) {
            self.code_queries.fetch_add(1, Ordering::Relaxed);
            if hit {
                self.code_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
        pub fn record_storage_query(&self, hit: bool) {
            self.storage_queries.fetch_add(1, Ordering::Relaxed);
            if hit {
                self.storage_hits.fetch_add(1, Ordering::Relaxed);
            }
        }
        pub fn inc_commits(&self) {
            self.commits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_accounts_created(&self, n: u64) {
            self.accounts_created.fetch_add(n, Ordering::Relaxed);
        }
        pub fn inc_accounts_updated(&self, n: u64) {
            self.accounts_updated.fetch_add(n, Ordering::Relaxed);
        }
        pub fn inc_accounts_destroyed(&self, n: u64) {
            self.accounts_destroyed.fetch_add(n, Ordering::Relaxed);
        }
        pub fn inc_storage_writes(&self, n: u64) {
            self.storage_writes.fetch_add(n, Ordering::Relaxed);
        }
        pub fn inc_code_writes(&self, n: u64) {
            self.code_writes.fetch_add(n, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> KvStateDbMetricsSnapshot {
            KvStateDbMetricsSnapshot {
                basic_queries: self.basic_queries.load(Ordering::Relaxed),
                basic_hits: self.basic_hits.load(Ordering::Relaxed),
                code_queries: self.code_queries.load(Ordering::Relaxed),
                code_hits: self.code_hits.load(Ordering::Relaxed),
                storage_queries: self.storage_queries.load(Ordering::Relaxed),
                storage_hits: self.storage_hits.load(Ordering::Relaxed),
                commits: self.commits.load(Ordering::Relaxed),
                accounts_created: self.accounts_created.load(Ordering::Relaxed),
                accounts_updated: self.accounts_updated.load(Ordering::Relaxed),
                accounts_destroyed: self.accounts_destroyed.load(Ordering::Relaxed),
                storage_writes: self.storage_writes.load(Ordering::Relaxed),
                code_writes: self.code_writes.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct KvStateDbMetricsSnapshot {
        pub basic_queries: u64,
        pub basic_hits: u64,
        pub code_queries: u64,
        pub code_hits: u64,
        pub storage_queries: u64,
        pub storage_hits: u64,
        pub commits: u64,
        pub accounts_created: u64,
        pub accounts_updated: u64,
        pub accounts_destroyed: u64,
        pub storage_writes: u64,
        pub code_writes: u64,
    }
}

pub mod address {
    //! Address conversion helpers between IONA (32‑byte) and EVM (20‑byte).
    use super::{
        constants::{ADDRESS_TRUNCATE_OFFSET, EVM_ADDR_LEN},
        error::{KvStateDbError, KvStateDbResult},
    };
    use revm::primitives::Address;
    use core::fmt;

    /// Convert a 32-byte IONA address to a 20-byte EVM address (last 20 bytes).
    #[must_use]
    pub fn iona_to_evm_addr(iona: &[u8; 32]) -> Address {
        Address::from_slice(&iona[ADDRESS_TRUNCATE_OFFSET..])
    }

    /// Convert a 20-byte EVM address back to a 32-byte IONA address (zero-padded).
    #[must_use]
    pub fn evm_to_iona_addr(evm: Address) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[ADDRESS_TRUNCATE_OFFSET..].copy_from_slice(evm.as_slice());
        out
    }

    /// Convert an EVM address to a hex string (with 0x prefix).
    #[must_use]
    pub fn evm_addr_hex(addr: Address) -> String {
        format!("0x{}", hex::encode(addr.as_slice()))
    }

    /// Convert an IONA address to a hex string (without prefix).
    #[must_use]
    pub fn iona_addr_hex(addr: &[u8; 32]) -> String {
        hex::encode(addr)
    }

    /// Convert an IONA address to a hex string with 0x prefix.
    #[must_use]
    pub fn iona_addr_hex_prefixed(addr: &[u8; 32]) -> String {
        format!("0x{}", hex::encode(addr))
    }

    /// Parse a hex string to an IONA address (32 bytes).
    pub fn parse_iona_addr(s: &str) -> KvStateDbResult<[u8; 32]> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|e| KvStateDbError::Serialization(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(KvStateDbError::InvalidAddressLength {
                expected: 32,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }

    /// Parse a hex string to an EVM address (20 bytes).
    pub fn parse_evm_addr(s: &str) -> KvStateDbResult<Address> {
        let s = s.trim_start_matches("0x");
        let bytes = hex::decode(s).map_err(|e| KvStateDbError::Serialization(e.to_string()))?;
        if bytes.len() != 20 {
            return Err(KvStateDbError::InvalidAddressLength {
                expected: 20,
                got: bytes.len(),
            });
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address::new(arr))
    }
}

pub mod db {
    //! Core `KvStateDb` implementation.
    use super::{
        config::KvStateDbConfig,
        error::{KvStateDbError, KvStateDbResult},
        metrics::KvStateDbMetrics,
        address::{iona_to_evm_addr, evm_to_iona_addr, iona_addr_hex},
        constants::{EVM_ADDR_LEN, KECCAK_EMPTY},
    };
    use crate::execution::KvState;
    use revm::primitives::{Account, AccountInfo, Address, Bytecode, B256, U256};
    use revm::{Database, DatabaseCommit};
    use sha3::{Digest, Keccak256};
    use std::collections::HashMap;
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use tracing::{debug, trace};

    /// A `revm::Database` backed by `KvState`.
    pub struct KvStateDb<'a> {
        pub state: &'a mut KvState,
        pending_accounts: HashMap<Address, AccountInfo>,
        pending_storage: HashMap<(Address, U256), U256>,
        pending_code: HashMap<B256, Bytecode>,
        pending_selfdestruct: HashMap<Address, Address>,
        config: Arc<KvStateDbConfig>,
        metrics: Arc<KvStateDbMetrics>,
        code_hash_cache: HashMap<Address, B256>,
        code_lookup: HashMap<B256, [u8; 32]>,
        storage_cache: HashMap<(Address, U256), U256>,
    }

    impl<'a> KvStateDb<'a> {
        /// Create a new `KvStateDb` wrapping the given mutable `KvState`.
        pub fn new(state: &'a mut KvState) -> Self {
            Self::with_config(state, KvStateDbConfig::default())
        }

        /// Create a new `KvStateDb` with the given configuration.
        pub fn with_config(state: &'a mut KvState, config: KvStateDbConfig) -> Self {
            let metrics = Arc::new(KvStateDbMetrics::default());
            Self {
                state,
                pending_accounts: HashMap::new(),
                pending_storage: HashMap::new(),
                pending_code: HashMap::new(),
                pending_selfdestruct: HashMap::new(),
                config: Arc::new(config),
                metrics,
                code_hash_cache: HashMap::new(),
                code_lookup: HashMap::new(),
                storage_cache: HashMap::new(),
            }
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &KvStateDbMetrics {
            &self.metrics
        }

        /// Reset all caches.
        pub fn clear_cache(&mut self) {
            self.code_hash_cache.clear();
            self.code_lookup.clear();
            self.storage_cache.clear();
            debug!("KvStateDb caches cleared");
        }

        /// Read balance for an EVM address from the underlying `KvState`.
        fn read_balance(&self, addr: Address) -> U256 {
            let iona = evm_to_iona_addr(addr);
            let key = iona_addr_hex(&iona);
            let bal = self.state.balances.get(&key).copied().unwrap_or(0);
            U256::from(bal)
        }

        /// Read nonce for an EVM address from the underlying `KvState`.
        fn read_nonce(&self, addr: Address) -> u64 {
            let iona = evm_to_iona_addr(addr);
            let key = iona_addr_hex(&iona);
            self.state.nonces.get(&key).copied().unwrap_or(0)
        }

        /// Read bytecode for an EVM address from the underlying `KvState`.
        fn read_code(&mut self, addr: Address) -> Bytecode {
            let iona = evm_to_iona_addr(addr);
            if let Some(hash) = self.code_hash_cache.get(&addr) {
                if let Some(code) = self.pending_code.get(hash) {
                    return code.clone();
                }
                if let Some(iona_addr) = self.code_lookup.get(hash) {
                    if let Some(code) = self.state.vm.code.get(iona_addr) {
                        return Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(code));
                    }
                }
            }
            let code = self.state.vm.get_code(&iona);
            if code.is_empty() {
                return Bytecode::new();
            }
            let bytecode = Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(&code));
            let hash = bytecode.hash_slow();
            if self.config.enable_code_cache {
                self.code_hash_cache.insert(addr, hash);
                self.code_lookup.insert(hash, iona);
            }
            bytecode
        }

        /// Read storage slot value.
        fn read_storage(&mut self, address: Address, slot: U256) -> U256 {
            if let Some(val) = self.pending_storage.get(&(address, slot)) {
                self.metrics.record_storage_query(true);
                return *val;
            }
            if self.config.enable_storage_cache {
                if let Some(val) = self.storage_cache.get(&(address, slot)) {
                    self.metrics.record_storage_query(true);
                    return *val;
                }
            }
            let iona = evm_to_iona_addr(address);
            let slot_bytes: [u8; 32] = slot.to_be_bytes();
            let val = self
                .state
                .vm
                .storage
                .get(&(iona, slot_bytes))
                .copied()
                .unwrap_or([0u8; 32]);
            let mut be = [0u8; 32];
            be.copy_from_slice(&val);
            let result = U256::from_be_bytes(be);
            if self.config.enable_storage_cache {
                self.storage_cache.insert((address, slot), result);
            }
            self.metrics.record_storage_query(false);
            result
        }

        /// Update the code reverse index when writing bytecode.
        fn update_code_lookup(&mut self, addr: Address, iona: &[u8; 32], code: &Bytecode) {
            if code.is_empty() {
                return;
            }
            let hash = code.hash_slow();
            if self.config.enable_code_cache {
                self.code_hash_cache.insert(addr, hash);
                self.code_lookup.insert(hash, *iona);
            }
        }

        /// Get the number of pending changes.
        pub fn pending_count(&self) -> (usize, usize, usize) {
            (
                self.pending_accounts.len(),
                self.pending_storage.len(),
                self.pending_code.len(),
            )
        }

        /// Revert the current transaction (drop pending changes).
        pub fn revert(&mut self) {
            self.pending_accounts.clear();
            self.pending_storage.clear();
            self.pending_code.clear();
            self.pending_selfdestruct.clear();
            debug!("KvStateDb transaction reverted");
        }
    }

    // -------------------------------------------------------------------------
    // Database impl
    // -------------------------------------------------------------------------

    impl<'a> Database for KvStateDb<'a> {
        type Error = KvStateDbError;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            if let Some(info) = self.pending_accounts.get(&address) {
                self.metrics.record_basic_query(true);
                return Ok(Some(info.clone()));
            }
            let balance = self.read_balance(address);
            let nonce = self.read_nonce(address);
            let code = self.read_code(address);
            let code_hash = if code.is_empty() {
                KECCAK_EMPTY
            } else {
                B256::from_slice(&Keccak256::digest(code.bytecode()).to_vec())
            };
            let exists = balance != U256::ZERO || nonce != 0 || !code.is_empty();
            self.metrics.record_basic_query(false);
            if !exists {
                return Ok(None);
            }
            Ok(Some(AccountInfo {
                balance,
                nonce,
                code_hash,
                code: if code.is_empty() { None } else { Some(code) },
            }))
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            if let Some(code) = self.pending_code.get(&code_hash) {
                self.metrics.record_code_query(true);
                return Ok(code.clone());
            }
            if let Some(iona_addr) = self.code_lookup.get(&code_hash) {
                if let Some(code) = self.state.vm.code.get(iona_addr) {
                    let bytecode = Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(code));
                    self.metrics.record_code_query(true);
                    return Ok(bytecode);
                }
            }
            for (iona, bytecode) in &self.state.vm.code {
                let h = B256::from_slice(&Keccak256::digest(bytecode).to_vec());
                if h == code_hash {
                    if self.config.enable_code_cache {
                        self.code_lookup.insert(h, *iona);
                    }
                    self.metrics.record_code_query(true);
                    return Ok(Bytecode::new_raw(revm::primitives::Bytes::copy_from_slice(
                        bytecode,
                    )));
                }
            }
            self.metrics.record_code_query(false);
            Err(KvStateDbError::CodeNotFound { hash: code_hash })
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            Ok(self.read_storage(address, index))
        }

        fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
            if number == U256::ZERO {
                return Ok(B256::ZERO);
            }
            trace!(block_number = %number, "block_hash lookup not implemented, returning zero");
            Ok(B256::ZERO)
        }
    }

    // -------------------------------------------------------------------------
    // DatabaseCommit impl
    // -------------------------------------------------------------------------

    impl<'a> DatabaseCommit for KvStateDb<'a> {
        fn commit(&mut self, changes: revm::primitives::State) {
            self.metrics.inc_commits();

            let mut accounts_created = 0;
            let mut accounts_updated = 0;
            let mut accounts_destroyed = 0;
            let mut storage_writes = 0;
            let mut code_writes = 0;

            for (evm_addr, account) in changes {
                if !account.is_touched() {
                    continue;
                }
                let iona = evm_to_iona_addr(evm_addr);
                let iona_key = iona_addr_hex(&iona);

                if account.selfdestruct {
                    self.state.vm.code.remove(&iona);
                    let keys: Vec<([u8; 32], [u8; 32])> = self
                        .state
                        .vm
                        .storage
                        .keys()
                        .filter(|(addr, _)| *addr == iona)
                        .copied()
                        .collect();
                    for key in keys {
                        self.state.vm.storage.remove(&key);
                    }
                    self.state.balances.remove(&iona_key);
                    self.state.nonces.remove(&iona_key);
                    accounts_destroyed += 1;
                    continue;
                }

                let bal_u64 = account.info.balance.saturating_to::<u64>();
                if bal_u64 == 0 {
                    self.state.balances.remove(&iona_key);
                } else {
                    self.state.balances.insert(iona_key.clone(), bal_u64);
                }

                if account.info.nonce == 0 {
                    self.state.nonces.remove(&iona_key);
                } else {
                    self.state
                        .nonces
                        .insert(iona_key.clone(), account.info.nonce);
                }

                if let Some(code) = &account.info.code {
                    if !code.is_empty() {
                        let code_bytes = code.bytecode().to_vec();
                        self.state.vm.code.insert(iona, code_bytes);
                        self.update_code_lookup(evm_addr, &iona, code);
                        code_writes += 1;
                    }
                }

                for (slot_u256, slot_val) in &account.storage {
                    let slot_bytes: [u8; 32] = slot_u256.to_be_bytes();
                    let val_bytes: [u8; 32] = slot_val.present_value.to_be_bytes();
                    if slot_val.present_value == U256::ZERO {
                        self.state.vm.storage.remove(&(iona, slot_bytes));
                    } else {
                        self.state
                            .vm
                            .storage
                            .insert((iona, slot_bytes), val_bytes);
                        storage_writes += 1;
                        if self.config.enable_storage_cache {
                            self.storage_cache.insert((evm_addr, *slot_u256), slot_val.present_value);
                        }
                    }
                }

                let old_balance = self.read_balance(evm_addr);
                let old_nonce = self.read_nonce(evm_addr);
                if old_balance == U256::ZERO && old_nonce == 0 {
                    accounts_created += 1;
                } else {
                    accounts_updated += 1;
                }
            }

            self.metrics.inc_accounts_created(accounts_created);
            self.metrics.inc_accounts_updated(accounts_updated);
            self.metrics.inc_accounts_destroyed(accounts_destroyed);
            self.metrics.inc_storage_writes(storage_writes);
            self.metrics.inc_code_writes(code_writes);

            debug!(
                accounts_created,
                accounts_updated,
                accounts_destroyed,
                storage_writes,
                code_writes,
                "KvStateDb commit completed"
            );
        }
    }
}

pub mod env {
    //! Helpers for building REVM environment.
    use super::{
        constants::DEFAULT_BLOCK_GAS_LIMIT,
        address::iona_to_evm_addr,
    };
    use crate::types::tx_evm::EvmTx;
    use revm::primitives::{Address, BlockEnv, CfgEnv, Env, TransactTo, TxEnv, U256};

    /// Build the REVM environment for a transaction.
    pub fn build_evm_env(
        chain_id: u64,
        block_number: u64,
        block_timestamp: u64,
        base_fee: u64,
        tx: &EvmTx,
        gas_limit: Option<u64>,
    ) -> Env {
        let mut env = Env::default();
        env.cfg = CfgEnv::default();
        env.cfg.chain_id = chain_id;

        env.block = BlockEnv {
            number: U256::from(block_number),
            timestamp: U256::from(block_timestamp),
            basefee: U256::from(base_fee),
            gas_limit: U256::from(gas_limit.unwrap_or(DEFAULT_BLOCK_GAS_LIMIT)),
            ..Default::default()
        };

        env.tx = build_tx_env(tx);
        env
    }

    /// Build the transaction environment from an `EvmTx`.
    pub fn build_tx_env(tx: &EvmTx) -> TxEnv {
        let mut env = TxEnv::default();

        match tx {
            EvmTx::Legacy {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                chain_id,
            } => {
                env.caller = iona_to_evm_addr(from);
                env.gas_limit = *gas_limit;
                env.gas_price = U256::from(*gas_price);
                env.value = U256::from(*value);
                env.nonce = Some(*nonce);
                env.chain_id = Some(*chain_id);
                env.transact_to = match to {
                    Some(addr) => TransactTo::Call(iona_to_evm_addr(addr)),
                    None => TransactTo::Create,
                };
                env.data = revm::primitives::Bytes::copy_from_slice(data);
            }
            EvmTx::Eip2930 {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                access_list,
                chain_id,
            } => {
                env.caller = iona_to_evm_addr(from);
                env.gas_limit = *gas_limit;
                env.gas_price = U256::from(*gas_price);
                env.value = U256::from(*value);
                env.nonce = Some(*nonce);
                env.chain_id = Some(*chain_id);
                env.transact_to = match to {
                    Some(addr) => TransactTo::Call(iona_to_evm_addr(addr)),
                    None => TransactTo::Create,
                };
                env.data = revm::primitives::Bytes::copy_from_slice(data);
                env.access_list = access_list
                    .iter()
                    .map(convert_access_list_item)
                    .collect();
            }
            EvmTx::Eip1559 {
                from,
                to,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                value,
                data,
                access_list,
                chain_id,
            } => {
                env.caller = iona_to_evm_addr(from);
                env.gas_limit = *gas_limit;
                env.gas_price = U256::from(*max_fee_per_gas);
                env.gas_priority_fee = Some(U256::from(*max_priority_fee_per_gas));
                env.value = U256::from(*value);
                env.nonce = Some(*nonce);
                env.chain_id = Some(*chain_id);
                env.transact_to = match to {
                    Some(addr) => TransactTo::Call(iona_to_evm_addr(addr)),
                    None => TransactTo::Create,
                };
                env.data = revm::primitives::Bytes::copy_from_slice(data);
                env.access_list = access_list
                    .iter()
                    .map(convert_access_list_item)
                    .collect();
            }
        }

        env
    }

    /// Convert an `AccessListItem` to REVM's access list tuple.
    fn convert_access_list_item(
        item: &crate::types::tx_evm::AccessListItem,
    ) -> (Address, Vec<U256>) {
        (
            iona_to_evm_addr(&item.address),
            item.storage_keys
                .iter()
                .map(|k| U256::from_be_bytes(*k))
                .collect(),
        )
    }
}

pub mod executor {
    //! Unified EVM executor using KvStateDb.
    use super::{
        db::KvStateDb,
        env::build_evm_env,
        address::iona_to_evm_addr,
        constants::EVM_ADDR_LEN,
    };
    use crate::execution::KvState;
    use crate::types::tx_evm::EvmTx;
    use revm::primitives::{CfgEnvWithHandlerCfg, EvmBuilder, Output};
    use std::time::Instant;
    use tracing::{debug, error, info};

    /// Result of executing an EVM transaction via `KvStateDb`.
    #[derive(Debug)]
    pub struct UnifiedEvmResult {
        pub success: bool,
        pub gas_used: u64,
        pub return_data: Vec<u8>,
        pub created_address: Option<[u8; EVM_ADDR_LEN]>,
        pub logs: Vec<revm::primitives::Log>,
        pub error: Option<String>,
        pub effective_gas_price: u64,
    }

    /// Execute an EVM transaction against the live `KvState`.
    ///
    /// On success the state is committed in-place.
    /// On failure the state is left unchanged (revm reverts automatically).
    pub fn execute_evm_on_state(
        kv_state: &mut KvState,
        tx: EvmTx,
        block_number: u64,
        block_timestamp: u64,
        base_fee: u64,
        chain_id: u64,
        gas_limit: Option<u64>,
    ) -> UnifiedEvmResult {
        let start = Instant::now();
        let mut db = KvStateDb::new(kv_state);
        let env = build_evm_env(chain_id, block_number, block_timestamp, base_fee, &tx, gas_limit);

        let mut evm = EvmBuilder::default()
            .with_db(&mut db)
            .with_env(Box::new(env))
            .build();

        match evm.transact_commit() {
            Ok(result) => {
                let (success, gas_used, output, logs) = match &result {
                    revm::primitives::ExecutionResult::Success {
                        gas_used,
                        output,
                        logs,
                        ..
                    } => (true, *gas_used, output.clone(), logs.clone()),
                    revm::primitives::ExecutionResult::Revert { gas_used, output } => (
                        false,
                        *gas_used,
                        Output::Call(output.clone()),
                        vec![],
                    ),
                    revm::primitives::ExecutionResult::Halt { gas_used, .. } => (
                        false,
                        *gas_used,
                        Output::Call(revm::primitives::Bytes::new()),
                        vec![],
                    ),
                };

                let (return_data, created_address) = match output {
                    Output::Call(bytes) => (bytes.to_vec(), None),
                    Output::Create(bytes, addr) => (
                        bytes.to_vec(),
                        addr.map(|a| {
                            let mut arr = [0u8; EVM_ADDR_LEN];
                            arr.copy_from_slice(a.as_slice());
                            arr
                        }),
                    ),
                };

                let effective_gas_price = match tx {
                    EvmTx::Legacy { gas_price, .. } => gas_price,
                    EvmTx::Eip2930 { gas_price, .. } => gas_price,
                    EvmTx::Eip1559 {
                        max_fee_per_gas,
                        max_priority_fee_per_gas,
                        ..
                    } => {
                        let base = base_fee;
                        let priority = u64::min(max_priority_fee_per_gas, max_fee_per_gas.saturating_sub(base));
                        base.saturating_add(priority)
                    }
                };

                let duration = start.elapsed();
                debug!(
                    success,
                    gas_used,
                    effective_gas_price,
                    duration_ms = duration.as_millis(),
                    "EVM transaction executed on KvState"
                );

                UnifiedEvmResult {
                    success,
                    gas_used,
                    return_data,
                    created_address,
                    logs,
                    error: if success { None } else { Some("execution reverted".into()) },
                    effective_gas_price,
                }
            }
            Err(e) => {
                error!(error = ?e, "EVM transaction failed");
                UnifiedEvmResult {
                    success: false,
                    gas_used: 0,
                    return_data: vec![],
                    created_address: None,
                    logs: vec![],
                    error: Some(format!("evm error: {:?}", e)),
                    effective_gas_price: 0,
                }
            }
        }
    }
}

pub mod manager {
    //! Centralised manager for KvStateDb instances.
    use super::{
        config::KvStateDbConfig,
        error::KvStateDbResult,
        db::KvStateDb,
        metrics::KvStateDbMetrics,
    };
    use crate::execution::KvState;
    use std::sync::Arc;

    /// Manager for KvStateDb.
    pub struct KvDbManager {
        config: KvStateDbConfig,
        metrics: Arc<KvStateDbMetrics>,
    }

    impl KvDbManager {
        /// Create a new manager with the given configuration.
        pub fn new(config: KvStateDbConfig) -> Self {
            config.validate().expect("invalid KvStateDbConfig");
            Self {
                config,
                metrics: Arc::new(KvStateDbMetrics::default()),
            }
        }

        /// Create a manager with default configuration.
        pub fn default() -> Self {
            Self::new(KvStateDbConfig::default())
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &KvStateDbMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &KvStateDbConfig {
            &self.config
        }

        /// Create a new `KvStateDb` wrapping the given state.
        pub fn create<'a>(&self, state: &'a mut KvState) -> KvStateDb<'a> {
            KvStateDb::with_config(state, self.config.clone())
        }

        /// Update the configuration (affects future creations).
        pub fn set_config(&mut self, config: KvStateDbConfig) -> KvStateDbResult<()> {
            config.validate().map_err(|e| super::error::KvStateDbError::Config(e.into()))?;
            self.config = config;
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use constants::{ADDRESS_TRUNCATE_OFFSET, EVM_ADDR_LEN, DEFAULT_BLOCK_GAS_LIMIT};
pub use config::KvStateDbConfig;
pub use error::{KvStateDbError, KvStateDbResult};
pub use metrics::{KvStateDbMetrics, KvStateDbMetricsSnapshot};
pub use db::KvStateDb;
pub use address::{
    iona_to_evm_addr, evm_to_iona_addr, evm_addr_hex, iona_addr_hex,
    iona_addr_hex_prefixed, parse_iona_addr, parse_evm_addr,
};
pub use env::{build_evm_env, build_tx_env};
pub use executor::{execute_evm_on_state, UnifiedEvmResult};
pub use manager::KvDbManager;

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Create a new `KvStateDb` with default config (legacy).
pub fn new_kv_state_db(state: &mut KvState) -> KvStateDb {
    KvStateDb::new(state)
}

/// Create a new `KvStateDb` with custom config (legacy).
pub fn new_kv_state_db_with_config(state: &mut KvState, config: KvStateDbConfig) -> KvStateDb {
    KvStateDb::with_config(state, config)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::tx_evm::{AccessListItem, EvmTx};

    #[test]
    fn test_address_conversion_roundtrip() {
        let iona = [0xAA; 32];
        let evm = iona_to_evm_addr(&iona);
        let back = evm_to_iona_addr(evm);
        assert_eq!(back, iona);
    }

    #[test]
    fn test_balance_read_write() {
        let mut state = KvState::default();
        let iona_addr = [0xBB; 32];
        let evm_addr = iona_to_evm_addr(&iona_addr);
        let key = iona_addr_hex(&iona_addr);
        state.balances.insert(key, 1000);

        let mut db = KvStateDb::new(&mut state);
        let info = db.basic(evm_addr).unwrap().unwrap();
        assert_eq!(info.balance, U256::from(1000));
    }

    #[test]
    fn test_storage_read_write() {
        let mut state = KvState::default();
        let iona_addr = [0xCC; 32];
        let evm_addr = iona_to_evm_addr(&iona_addr);
        let slot = U256::from(0x1234u64);
        let value = U256::from(0xDEADBEEFu64);

        let slot_bytes: [u8; 32] = slot.to_be_bytes();
        let val_bytes: [u8; 32] = value.to_be_bytes();
        state.vm.storage.insert((iona_addr, slot_bytes), val_bytes);

        let mut db = KvStateDb::new(&mut state);
        let stored = db.storage(evm_addr, slot).unwrap();
        assert_eq!(stored, value);
    }

    #[test]
    fn test_parse_iona_addr() {
        let addr = [0xAA; 32];
        let hex = iona_addr_hex(&addr);
        let parsed = parse_iona_addr(&hex).unwrap();
        assert_eq!(parsed, addr);
        let hex_prefixed = format!("0x{}", hex);
        let parsed2 = parse_iona_addr(&hex_prefixed).unwrap();
        assert_eq!(parsed2, addr);
    }

    #[test]
    fn test_parse_evm_addr() {
        let addr = Address::new([0xBB; 20]);
        let hex = format!("0x{}", hex::encode(addr.as_slice()));
        let parsed = parse_evm_addr(&hex).unwrap();
        assert_eq!(parsed, addr);
    }

    #[test]
    fn test_code_cache() {
        let mut state = KvState::default();
        let iona_addr = [0xDD; 32];
        let evm_addr = iona_to_evm_addr(&iona_addr);
        let code = vec![0x60, 0x00, 0x00];
        state.vm.code.insert(iona_addr, code.clone());

        let mut db = KvStateDb::new(&mut state);
        let bytecode = db.read_code(evm_addr);
        assert_eq!(bytecode.bytecode().to_vec(), code);

        let hash = bytecode.hash_slow();
        assert!(db.code_hash_cache.contains_key(&evm_addr));
        assert!(db.code_lookup.contains_key(&hash));
    }

    #[test]
    fn test_storage_cache() {
        let mut state = KvState::default();
        let iona_addr = [0xEE; 32];
        let evm_addr = iona_to_evm_addr(&iona_addr);
        let slot = U256::from(0x1234u64);
        let value = U256::from(0xDEADBEEFu64);

        let slot_bytes: [u8; 32] = slot.to_be_bytes();
        let val_bytes: [u8; 32] = value.to_be_bytes();
        state.vm.storage.insert((iona_addr, slot_bytes), val_bytes);

        let mut db = KvStateDb::new(&mut state);
        let stored = db.read_storage(evm_addr, slot);
        assert_eq!(stored, value);
        assert!(db.storage_cache.contains_key(&(evm_addr, slot)));
    }

    #[test]
    fn test_metrics() {
        let mut state = KvState::default();
        let iona_addr = [0xFF; 32];
        let evm_addr = iona_to_evm_addr(&iona_addr);
        let key = iona_addr_hex(&iona_addr);
        state.balances.insert(key, 1000);

        let mut db = KvStateDb::new(&mut state);
        let _ = db.basic(evm_addr).unwrap();
        let _ = db.read_storage(evm_addr, U256::ZERO);

        let metrics = db.metrics();
        assert_eq!(metrics.basic_queries.load(Ordering::Relaxed), 1);
        assert_eq!(metrics.storage_queries.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_execute_evm_on_state_simple_transfer() {
        let mut state = KvState::default();
        let from = [0xAB; 32];
        let to = [0xCD; 32];
        let from_key = iona_addr_hex(&from);
        state.balances.insert(from_key, 10_000_000_000_000_000u64);

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

        let result = execute_evm_on_state(&mut state, tx, 1, 1700000000, 10, 6126151, None);
        assert!(result.success);
        assert!(result.gas_used > 0);
    }

    #[test]
    fn test_manager() {
        let config = KvStateDbConfig::default();
        let manager = KvDbManager::new(config);
        let mut state = KvState::default();
        let _db = manager.create(&mut state);
        assert_eq!(manager.config().max_code_cache, DEFAULT_MAX_CODE_CACHE);
    }
}
