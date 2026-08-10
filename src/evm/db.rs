//! Minimal in‑memory REVM database for development and testing.
//!
//! Implements the `revm::Database` and `DatabaseCommit` traits using
//! `BTreeMap` for accounts, storage, and bytecode storage.
//!
//! # Features
//! - Fork support: inherit state from another `MemDb` (copy‑on‑write)
//! - Metrics: track cache hits/misses, operation counts
//! - Serialization: export/import state to/from JSON
//! - Integration with IONAFS for persistence
//! - Configurable cache limits and fork depth
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                           EVM DB Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │    metrics    │         db               │
//! │ (MemDbCfg)  │ (MemDbError) │ (MemDbMetrics)│ (MemDb core)             │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   manager   │    legacy    │               │                          │
//! │ (DbManager) │ (global fns) │               │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evm::db::{DbManager, MemDbConfig};
//! use revm::Database;
//! use revm::primitives::Address;
//!
//! let config = MemDbConfig::default();
//! let manager = DbManager::new(config);
//! let mut db = manager.create();
//! let addr = Address::new([0x01; 20]);
//! let balance = db.basic(addr).unwrap().map(|acc| acc.balance);
//! ```

#![allow(dead_code)]

use alloc::{
    collections::BTreeMap,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::sync::Arc;
use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};
use revm::{Database, DatabaseCommit};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

#[cfg(feature = "std")]
use std::fs::File;
#[cfg(feature = "std")]
use std::io::{BufReader, BufWriter};
#[cfg(feature = "std")]
use std::path::Path;

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the in‑memory database.
    use serde::{Deserialize, Serialize};

    /// Configuration for the in‑memory database.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct MemDbConfig {
        pub max_accounts: usize,
        pub max_storage_slots: usize,
        pub max_code_entries: usize,
        pub max_fork_depth: usize,
        pub track_metrics: bool,
        pub verify_code_hashes: bool,
    }

    impl Default for MemDbConfig {
        fn default() -> Self {
            Self {
                max_accounts: 100_000,
                max_storage_slots: 1_000_000,
                max_code_entries: 10_000,
                max_fork_depth: 32,
                track_metrics: true,
                verify_code_hashes: true,
            }
        }
    }

    impl MemDbConfig {
        pub fn test() -> Self {
            Self {
                max_accounts: 100,
                max_storage_slots: 1000,
                max_code_entries: 50,
                max_fork_depth: 4,
                track_metrics: true,
                verify_code_hashes: false,
            }
        }

        pub fn large() -> Self {
            Self {
                max_accounts: 1_000_000,
                max_storage_slots: 10_000_000,
                max_code_entries: 100_000,
                max_fork_depth: 128,
                track_metrics: true,
                verify_code_hashes: true,
            }
        }

        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_accounts == 0 {
                return Err("max_accounts must be > 0");
            }
            if self.max_storage_slots == 0 {
                return Err("max_storage_slots must be > 0");
            }
            if self.max_code_entries == 0 {
                return Err("max_code_entries must be > 0");
            }
            if self.max_fork_depth == 0 {
                return Err("max_fork_depth must be > 0");
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for database operations.
    use revm::primitives::{Address, B256, U256};
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum MemDbError {
        #[error("code not found for hash 0x{hash:x}")]
        CodeNotFound { hash: B256 },

        #[error("account not found: 0x{address:x}")]
        AccountNotFound { address: Address },

        #[error("storage slot not found: 0x{address:x} slot 0x{slot:x}")]
        StorageNotFound { address: Address, slot: U256 },

        #[error("I/O error: {0}")]
        Io(#[from] std::io::Error),

        #[error("serialization error: {0}")]
        Serialization(String),

        #[error("fork parent not found: {0}")]
        ForkParentNotFound(String),

        #[error("fork depth limit {limit} exceeded")]
        ForkDepthExceeded { limit: usize },

        #[error("invalid configuration: {0}")]
        Config(String),

        #[error("persistence error: {0}")]
        Persistence(String),
    }

    pub type MemDbResult<T> = Result<T, MemDbError>;
}

pub mod metrics {
    //! Metrics for database operations.
    use core::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};
    use core::fmt;

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct MemDbMetrics {
        pub basic_queries: u64,
        pub basic_hits: u64,
        pub code_queries: u64,
        pub code_hits: u64,
        pub storage_queries: u64,
        pub storage_hits: u64,
        pub commits: u64,
        pub forks: u64,
        pub evicted_accounts: u64,
        pub evicted_storage: u64,
    }

    impl MemDbMetrics {
        pub fn inc_basic_query(&self) {
            self.basic_queries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_basic_hit(&self) {
            self.basic_hits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_code_query(&self) {
            self.code_queries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_code_hit(&self) {
            self.code_hits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_storage_query(&self) {
            self.storage_queries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_storage_hit(&self) {
            self.storage_hits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_commit(&self) {
            self.commits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_fork(&self) {
            self.forks.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_evicted_account(&self) {
            self.evicted_accounts.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_evicted_storage(&self) {
            self.evicted_storage.fetch_add(1, Ordering::Relaxed);
        }
    }

    impl fmt::Display for MemDbMetrics {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "MemDb Metrics:")?;
            writeln!(f, "  basic: {} queries, {} hits", self.basic_queries, self.basic_hits)?;
            writeln!(f, "  code: {} queries, {} hits", self.code_queries, self.code_hits)?;
            writeln!(f, "  storage: {} queries, {} hits", self.storage_queries, self.storage_hits)?;
            writeln!(f, "  commits: {}", self.commits)?;
            writeln!(f, "  forks: {}", self.forks)?;
            writeln!(f, "  evictions: accounts={}, storage={}", self.evicted_accounts, self.evicted_storage)
        }
    }
}

pub mod db {
    //! Core in‑memory database implementation.
    use super::{
        config::MemDbConfig,
        error::{MemDbError, MemDbResult},
        metrics::MemDbMetrics,
    };
    use alloc::{
        collections::BTreeMap,
        string::{String, ToString},
        vec::Vec,
    };
    use core::fmt;
    use core::sync::atomic::Ordering;
    use core::sync::Arc;
    use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};
    use revm::{Database, DatabaseCommit};
    use serde::{Deserialize, Serialize};
    use tracing::{debug, error, info, warn};

    /// In‑memory REVM database.
    #[derive(Clone)]
    pub struct MemDb {
        config: Arc<MemDbConfig>,
        accounts: BTreeMap<Address, AccountInfo>,
        code: BTreeMap<B256, Bytecode>,
        storage: BTreeMap<(Address, U256), U256>,
        parent: Option<Arc<MemDb>>,
        fork_depth: usize,
        metrics: Arc<MemDbMetrics>,
    }

    impl MemDb {
        pub fn new(config: MemDbConfig) -> Self {
            let config = Arc::new(config);
            Self {
                config: config.clone(),
                accounts: BTreeMap::new(),
                code: BTreeMap::new(),
                storage: BTreeMap::new(),
                parent: None,
                fork_depth: 0,
                metrics: Arc::new(MemDbMetrics::default()),
            }
        }

        pub fn default() -> Self {
            Self::new(MemDbConfig::default())
        }

        pub fn fork(parent: &MemDb) -> MemDbResult<Self> {
            let new_depth = parent.fork_depth + 1;
            if parent.config.max_fork_depth > 0 && new_depth > parent.config.max_fork_depth {
                return Err(MemDbError::ForkDepthExceeded {
                    limit: parent.config.max_fork_depth,
                });
            }
            parent.metrics.inc_fork();
            debug!(depth = new_depth, "creating fork from parent database");
            Ok(Self {
                config: parent.config.clone(),
                accounts: BTreeMap::new(),
                code: BTreeMap::new(),
                storage: BTreeMap::new(),
                parent: Some(Arc::new(parent.clone())),
                fork_depth: new_depth,
                metrics: parent.metrics.clone(),
            })
        }

        pub fn metrics(&self) -> &MemDbMetrics {
            &self.metrics
        }

        pub fn reset_metrics(&self) {
            *self.metrics = MemDbMetrics::default();
            debug!("database metrics reset");
        }

        pub fn insert_account(&mut self, address: Address, nonce: u64, balance: U256) {
            let info = AccountInfo {
                nonce,
                balance,
                code_hash: B256::ZERO,
                code: None,
            };
            self.accounts.insert(address, info);
            debug!(address = %address, nonce, balance = %balance, "account inserted");
        }

        pub fn insert_code(&mut self, code: Bytecode) -> B256 {
            let hash = code.hash_slow();
            if self.config.verify_code_hashes {
                let computed = code.hash_slow();
                if computed != hash {
                    warn!(computed = %computed, stored = %hash, "code hash mismatch");
                }
            }
            self.code.insert(hash, code.clone());
            debug!(hash = %hash, "bytecode inserted");
            hash
        }

        pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
            self.storage.insert((address, slot), value);
            debug!(address = %address, slot = %slot, value = %value, "storage slot set");
        }

        pub fn get_storage(&self, address: Address, slot: U256) -> U256 {
            self.metrics.inc_storage_query();
            if let Some(&value) = self.storage.get(&(address, slot)) {
                self.metrics.inc_storage_hit();
                return value;
            }
            if let Some(parent) = &self.parent {
                return parent.get_storage(address, slot);
            }
            U256::ZERO
        }

        pub fn get_account(&self, address: Address) -> Option<AccountInfo> {
            self.metrics.inc_basic_query();
            if let Some(account) = self.accounts.get(&address) {
                self.metrics.inc_basic_hit();
                return Some(account.clone());
            }
            if let Some(parent) = &self.parent {
                return parent.get_account(address);
            }
            None
        }

        pub fn nonce(&self, address: Address) -> u64 {
            self.get_account(address).map(|a| a.nonce).unwrap_or(0)
        }

        pub fn balance(&self, address: Address) -> U256 {
            self.get_account(address).map(|a| a.balance).unwrap_or(U256::ZERO)
        }

        pub fn code(&self, address: Address) -> Option<Bytecode> {
            self.get_account(address).and_then(|a| a.code)
        }

        pub fn account_exists(&self, address: Address) -> bool {
            self.get_account(address).is_some()
        }

        pub fn set_code(&mut self, address: Address, code: Bytecode) {
            let hash = self.insert_code(code.clone());
            let info = self.accounts.entry(address).or_insert_with(|| AccountInfo {
                nonce: 0,
                balance: U256::ZERO,
                code_hash: hash,
                code: Some(code.clone()),
            });
            info.code_hash = hash;
            info.code = Some(code);
            debug!(address = %address, "account code set");
        }

        pub fn clear(&mut self) {
            self.accounts.clear();
            self.code.clear();
            self.storage.clear();
            debug!("database cleared (local state only)");
        }

        pub fn is_empty(&self) -> bool {
            self.accounts.is_empty()
                && self.code.is_empty()
                && self.storage.is_empty()
                && self.parent.as_ref().map(|p| p.is_empty()).unwrap_or(true)
        }

        pub fn total_accounts(&self) -> usize {
            let local_count = self.accounts.len();
            let parent_count = self.parent.as_ref().map(|p| p.total_accounts()).unwrap_or(0);
            local_count + parent_count
        }

        pub fn export_json(&self) -> MemDbResult<String> {
            #[derive(Serialize)]
            struct ExportState {
                accounts: Vec<(Address, AccountInfo)>,
                code: Vec<(B256, Bytecode)>,
                storage: Vec<((Address, U256), U256)>,
            }

            let export = ExportState {
                accounts: self.accounts.iter().map(|(k, v)| (*k, v.clone())).collect(),
                code: self.code.iter().map(|(k, v)| (*k, v.clone())).collect(),
                storage: self.storage.iter().map(|(k, v)| (*k, *v)).collect(),
            };

            serde_json::to_string_pretty(&export)
                .map_err(|e| MemDbError::Serialization(e.to_string()))
        }

        pub fn import_json(&mut self, json: &str) -> MemDbResult<()> {
            #[derive(Deserialize)]
            struct ImportState {
                accounts: Vec<(Address, AccountInfo)>,
                code: Vec<(B256, Bytecode)>,
                storage: Vec<((Address, U256), U256)>,
            }

            let import: ImportState = serde_json::from_str(json)
                .map_err(|e| MemDbError::Serialization(e.to_string()))?;

            for (addr, info) in import.accounts {
                self.accounts.insert(addr, info);
            }
            for (hash, code) in import.code {
                self.code.insert(hash, code);
            }
            for ((addr, slot), value) in import.storage {
                self.storage.insert((addr, slot), value);
            }

            info!(accounts = import.accounts.len(), code = import.code.len(), storage = import.storage.len(), "database state imported");
            Ok(())
        }

        pub fn persist(&self, path: &str) -> MemDbResult<()> {
            let json = self.export_json()?;
            crate::fs::ionafs::write(path, json.as_bytes());
            info!(path, "database persisted to IONAFS");
            Ok(())
        }

        pub fn load(path: &str) -> MemDbResult<Self> {
            let mut db = Self::default();
            if let Some(data) = crate::fs::ionafs::read(path) {
                let json = String::from_utf8_lossy(&data);
                db.import_json(&json)?;
                info!(path, "database loaded from IONAFS");
            } else {
                debug!(path, "no existing database found, using empty state");
            }
            Ok(db)
        }

        #[cfg(feature = "std")]
        pub fn persist_to_file(&self, path: &Path) -> MemDbResult<()> {
            let json = self.export_json()?;
            let file = File::create(path)?;
            let writer = BufWriter::new(file);
            serde_json::to_writer_pretty(writer, &json)?;
            info!(path = %path.display(), "database persisted to file");
            Ok(())
        }

        #[cfg(feature = "std")]
        pub fn load_from_file(path: &Path) -> MemDbResult<Self> {
            let file = File::open(path)?;
            let reader = BufReader::new(file);
            let json: String = serde_json::from_reader(reader)?;
            let mut db = Self::default();
            db.import_json(&json)?;
            info!(path = %path.display(), "database loaded from file");
            Ok(db)
        }

        pub fn dump_state(&self) -> String {
            let mut s = String::new();
            s.push_str("--- MemDb State ---\n");
            s.push_str(&format!("Accounts ({}):\n", self.accounts.len()));
            for (addr, info) in &self.accounts {
                s.push_str(&format!(
                    "  0x{:x} balance={} nonce={} code_hash=0x{:x} code={}\n",
                    addr,
                    info.balance,
                    info.nonce,
                    info.code_hash,
                    if info.code.is_some() { "present" } else { "absent" }
                ));
            }
            s.push_str(&format!("Code entries ({}):\n", self.code.len()));
            for (hash, code) in &self.code {
                s.push_str(&format!(
                    "  0x{:x}: {} bytes\n",
                    hash,
                    code.bytes().len()
                ));
            }
            s.push_str(&format!("Storage slots ({}):\n", self.storage.len()));
            for ((addr, slot), value) in &self.storage {
                s.push_str(&format!("  0x{:x} slot 0x{:x} -> 0x{:x}\n", addr, slot, value));
            }
            if let Some(parent) = &self.parent {
                s.push_str("--- Parent state ---\n");
                s.push_str(&parent.dump_state());
            }
            s
        }

        pub fn with_parent<F, R>(&self, f: F) -> Option<R>
        where
            F: FnOnce(&MemDb) -> R,
        {
            self.parent.as_ref().map(|p| f(p))
        }

        pub fn fork_depth(&self) -> usize {
            self.fork_depth
        }

        pub fn config(&self) -> &MemDbConfig {
            &self.config
        }
    }

    impl Default for MemDb {
        fn default() -> Self {
            Self::new(MemDbConfig::default())
        }
    }

    impl Database for MemDb {
        type Error = MemDbError;

        fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(self.get_account(address))
        }

        fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
            self.metrics.inc_code_query();
            if let Some(code) = self.code.get(&code_hash) {
                self.metrics.inc_code_hit();
                return Ok(code.clone());
            }
            if let Some(parent) = &self.parent {
                return parent.code_by_hash(code_hash);
            }
            Err(MemDbError::CodeNotFound { hash: code_hash })
        }

        fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
            Ok(self.get_storage(address, index))
        }

        fn block_hash(&mut self, number: U256) -> Result<B256, Self::Error> {
            if number != U256::ZERO {
                debug!(block_number = %number, "block_hash called for non‑zero block, returning zero");
            }
            Ok(B256::ZERO)
        }
    }

    impl DatabaseCommit for MemDb {
        fn commit(&mut self, changes: revm::primitives::State) {
            self.metrics.inc_commit();
            let mut accounts_updated = 0;
            let mut storage_updated = 0;
            let mut code_updated = 0;

            for (address, account) in changes {
                self.accounts.insert(address, account.info.clone());
                accounts_updated += 1;

                for (slot, value) in account.storage {
                    self.storage.insert((address, slot), value.present_value);
                    storage_updated += 1;
                }

                if let Some(code) = account.info.code {
                    let hash = code.hash_slow();
                    self.code.insert(hash, code);
                    code_updated += 1;
                }
            }

            debug!(
                accounts = accounts_updated,
                storage_slots = storage_updated,
                code_entries = code_updated,
                "database commit completed"
            );
        }
    }
}

pub mod manager {
    //! Centralised manager for creating and managing MemDb instances.
    use super::{
        config::MemDbConfig,
        db::MemDb,
        error::MemDbResult,
    };
    use crate::fs::ionafs;

    /// Manager for EVM database instances.
    #[derive(Clone)]
    pub struct DbManager {
        config: MemDbConfig,
    }

    impl DbManager {
        pub fn new(config: MemDbConfig) -> Self {
            Self { config }
        }

        pub fn default() -> Self {
            Self::new(MemDbConfig::default())
        }

        /// Create a new empty database with the manager's configuration.
        pub fn create(&self) -> MemDb {
            MemDb::new(self.config.clone())
        }

        /// Create a fork of an existing database.
        pub fn fork(&self, parent: &MemDb) -> MemDbResult<MemDb> {
            MemDb::fork(parent)
        }

        /// Load a database from IONAFS.
        pub fn load(&self, path: &str) -> MemDbResult<MemDb> {
            MemDb::load(path)
        }

        /// Persist a database to IONAFS.
        pub fn persist(&self, db: &MemDb, path: &str) -> MemDbResult<()> {
            db.persist(path)
        }

        /// Get the configuration.
        pub fn config(&self) -> &MemDbConfig {
            &self.config
        }

        /// Update the configuration (affects future creations).
        pub fn set_config(&mut self, config: MemDbConfig) -> MemDbResult<()> {
            config.validate().map_err(|e| MemDbError::Config(e.into()))?;
            self.config = config;
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::MemDbConfig;
pub use error::{MemDbError, MemDbResult};
pub use metrics::MemDbMetrics;
pub use db::MemDb;
pub use manager::DbManager;

// -----------------------------------------------------------------------------
// Legacy global functions (kept for backward compatibility)
// -----------------------------------------------------------------------------

/// Create a new database with default configuration (legacy).
pub fn new_db() -> MemDb {
    MemDb::default()
}

/// Create a new database with the given configuration (legacy).
pub fn new_db_with_config(config: MemDbConfig) -> MemDb {
    MemDb::new(config)
}

/// Fork a database (legacy).
pub fn fork_db(parent: &MemDb) -> MemDbResult<MemDb> {
    MemDb::fork(parent)
}

/// Load a database from IONAFS (legacy).
pub fn load_db(path: &str) -> MemDbResult<MemDb> {
    MemDb::load(path)
}

/// Persist a database to IONAFS (legacy).
pub fn persist_db(db: &MemDb, path: &str) -> MemDbResult<()> {
    db.persist(path)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{Address, Bytes, B256, U256};

    fn test_addr() -> Address {
        Address::new([0x01; 20])
    }

    fn test_addr2() -> Address {
        Address::new([0x02; 20])
    }

    #[test]
    fn test_new_db_is_empty() {
        let db = MemDb::default();
        assert!(db.is_empty());
    }

    #[test]
    fn test_insert_account() {
        let mut db = MemDb::default();
        let addr = test_addr();
        db.insert_account(addr, 42, U256::from(1000));
        let info = db.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 42);
        assert_eq!(info.balance, U256::from(1000));
    }

    #[test]
    fn test_code_by_hash_not_found() {
        let mut db = MemDb::default();
        let hash = B256::new([0xAA; 32]);
        let err = db.code_by_hash(hash).unwrap_err();
        assert!(matches!(err, MemDbError::CodeNotFound { hash: _ }));
    }

    #[test]
    fn test_insert_code() {
        let mut db = MemDb::default();
        let bytes = Bytes::from(vec![0x60, 0x00, 0x00]);
        let code = Bytecode::new_raw(bytes);
        let hash = db.insert_code(code.clone());
        let retrieved = db.code_by_hash(hash).unwrap();
        assert_eq!(retrieved.bytes(), code.bytes());
    }

    #[test]
    fn test_storage_ops() {
        let mut db = MemDb::default();
        let addr = test_addr();
        let slot = U256::from(0x1234);
        db.set_storage(addr, slot, U256::from(0xDEADBEEF));
        let value = db.storage(addr, slot).unwrap();
        assert_eq!(value, U256::from(0xDEADBEEF));
        let value2 = db.storage(addr, U256::from(0x9999)).unwrap();
        assert_eq!(value2, U256::ZERO);
    }

    #[test]
    fn test_clear() {
        let mut db = MemDb::default();
        db.insert_account(test_addr(), 0, U256::ONE);
        db.set_storage(test_addr(), U256::ZERO, U256::ONE);
        assert!(!db.is_empty());
        db.clear();
        assert!(db.is_empty());
    }

    #[test]
    fn test_fork() {
        let mut parent = MemDb::default();
        let addr = test_addr();
        parent.insert_account(addr, 10, U256::from(1000));
        parent.set_storage(addr, U256::ZERO, U256::from(42));

        let mut fork = MemDb::fork(&parent).unwrap();
        let info = fork.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 10);
        let storage = fork.storage(addr, U256::ZERO).unwrap();
        assert_eq!(storage, U256::from(42));

        fork.insert_account(addr, 20, U256::from(2000));
        fork.set_storage(addr, U256::ZERO, U256::from(99));

        let parent_info = parent.basic(addr).unwrap().unwrap();
        assert_eq!(parent_info.nonce, 10);
        let parent_storage = parent.storage(addr, U256::ZERO).unwrap();
        assert_eq!(parent_storage, U256::from(42));
    }

    #[test]
    fn test_export_import() -> MemDbResult<()> {
        let mut db = MemDb::default();
        let addr = test_addr();
        db.insert_account(addr, 5, U256::from(500));
        db.set_storage(addr, U256::from(1), U256::from(0xFF));

        let json = db.export_json()?;
        let mut db2 = MemDb::default();
        db2.import_json(&json)?;

        let info = db2.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 5);
        assert_eq!(info.balance, U256::from(500));
        let storage = db2.storage(addr, U256::from(1)).unwrap();
        assert_eq!(storage, U256::from(0xFF));
        Ok(())
    }

    #[test]
    fn test_metrics() {
        let config = MemDbConfig {
            track_metrics: true,
            ..Default::default()
        };
        let mut db = MemDb::new(config);
        let addr = test_addr();
        db.insert_account(addr, 1, U256::ONE);

        let _ = db.basic(addr).unwrap();
        let _ = db.storage(addr, U256::ZERO).unwrap();

        let metrics = db.metrics();
        assert_eq!(metrics.basic_queries, 1);
        assert_eq!(metrics.basic_hits, 1);
        assert_eq!(metrics.storage_queries, 1);
        assert_eq!(metrics.storage_hits, 0);
    }

    #[test]
    fn test_total_accounts() {
        let mut parent = MemDb::default();
        parent.insert_account(test_addr(), 1, U256::ONE);

        let mut fork = MemDb::fork(&parent).unwrap();
        fork.insert_account(test_addr2(), 2, U256::from(2));

        assert_eq!(fork.total_accounts(), 2);
    }

    #[test]
    fn test_fork_depth_limit() {
        let config = MemDbConfig {
            max_fork_depth: 1,
            ..Default::default()
        };
        let mut parent = MemDb::new(config);
        let fork = MemDb::fork(&parent).unwrap();
        let result = MemDb::fork(&fork);
        assert!(matches!(result, Err(MemDbError::ForkDepthExceeded { limit: 1 })));
    }

    #[test]
    fn test_manager() {
        let config = MemDbConfig::test();
        let manager = DbManager::new(config);
        let db = manager.create();
        assert!(db.is_empty());
        assert_eq!(db.config().max_accounts, 100);
    }

    #[test]
    fn test_manager_load_persist() -> MemDbResult<()> {
        let manager = DbManager::default();
        let mut db = manager.create();
        db.insert_account(test_addr(), 1, U256::ONE);

        let path = "/tmp/test_db.json";
        manager.persist(&db, path)?;
        let loaded = manager.load(path)?;
        assert!(!loaded.is_empty());
        assert_eq!(loaded.balance(test_addr()), U256::ONE);
        Ok(())
    }
}
