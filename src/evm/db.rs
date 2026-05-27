//! Minimal in‑memory REVM database for development and testing.
//!
//! Implements the `revm::Database` and `DatabaseCommit` traits using
//! `HashMap` for accounts, storage, and bytecode storage.
//!
//! # Features
//! - Fork support: inherit state from another `MemDb` (copy‑on‑write)
//! - Metrics: track cache hits/misses, operation counts
//! - Serialization: export/import state to/from JSON
//! - Integration with IONAFS for persistence
//!
//! # Example
//!
//! ```
//! use iona::evm::db::MemDb;
//! use revm::Database;
//! use revm::primitives::{Address, U256};
//!
//! let mut db = MemDb::new();
//! let addr = Address::new([0x01; 20]);
//! let balance = db.basic(addr).unwrap().map(|acc| acc.balance);
//! assert_eq!(balance, Some(U256::ZERO));
//! ```

use revm::primitives::{AccountInfo, Address, Bytecode, B256, U256};
use revm::{Database, DatabaseCommit};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during database operations.
#[derive(Debug, Error)]
pub enum MemDbError {
    /// Bytecode not found for the given hash.
    #[error("code not found for hash 0x{hash:x}")]
    CodeNotFound { hash: B256 },

    /// Account not found at the given address.
    #[error("account not found: 0x{address:x}")]
    AccountNotFound { address: Address },

    /// I/O error during serialisation or persistence.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialisation error (JSON).
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Fork parent database is not available.
    #[error("fork parent not found: {0}")]
    ForkParentNotFound(String),
}

/// Result type for `MemDb` operations.
pub type MemDbResult<T> = Result<T, MemDbError>;

// -----------------------------------------------------------------------------
// Database metrics
// -----------------------------------------------------------------------------

/// Metrics for database operations.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemDbMetrics {
    /// Number of `basic` (account) queries.
    pub basic_queries: u64,
    /// Number of `basic` cache hits.
    pub basic_hits: u64,
    /// Number of `code_by_hash` queries.
    pub code_queries: u64,
    /// Number of `code` cache hits.
    pub code_hits: u64,
    /// Number of `storage` queries.
    pub storage_queries: u64,
    /// Number of `storage` cache hits.
    pub storage_hits: u64,
    /// Number of commits.
    pub commits: u64,
}

impl std::fmt::Display for MemDbMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "MemDb Metrics:")?;
        writeln!(f, "  basic: {} queries, {} hits", self.basic_queries, self.basic_hits)?;
        writeln!(f, "  code: {} queries, {} hits", self.code_queries, self.code_hits)?;
        writeln!(f, "  storage: {} queries, {} hits", self.storage_queries, self.storage_hits)?;
        writeln!(f, "  commits: {}", self.commits)
    }
}

// -----------------------------------------------------------------------------
// MemDb
// -----------------------------------------------------------------------------

/// In‑memory REVM database for development, testing, and lightweight execution.
///
/// Supports:
/// - Forking from another `MemDb` (copy‑on‑write)
/// - Metrics collection
/// - Serialisation to/from JSON
/// - Persistence to IONAFS
#[derive(Default, Clone)]
pub struct MemDb {
    /// Account state (nonce, balance, code hash, etc.)
    pub accounts: HashMap<Address, AccountInfo>,
    /// Bytecode indexed by code hash.
    pub code: HashMap<B256, Bytecode>,
    /// Storage slots: (address, slot) → value.
    pub storage: HashMap<(Address, U256), U256>,
    /// Optional parent database for forking (read‑only fallback).
    parent: Option<Arc<MemDb>>,
    /// Metrics (shared across clones).
    metrics: Arc<MemDbMetrics>,
}

impl MemDb {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new database with metrics enabled.
    pub fn with_metrics() -> Self {
        Self {
            accounts: HashMap::new(),
            code: HashMap::new(),
            storage: HashMap::new(),
            parent: None,
            metrics: Arc::new(MemDbMetrics::default()),
        }
    }

    /// Create a fork of an existing database.
    /// The new database inherits all state from the parent but records writes
    /// locally (copy‑on‑write). This is useful for simulating contract calls
    /// without affecting the original state.
    pub fn fork(parent: &MemDb) -> Self {
        info!("creating fork from parent database");
        Self {
            accounts: HashMap::new(),
            code: HashMap::new(),
            storage: HashMap::new(),
            parent: Some(Arc::new(parent.clone())),
            metrics: parent.metrics.clone(),
        }
    }

    /// Get metrics for this database.
    pub fn metrics(&self) -> &MemDbMetrics {
        &self.metrics
    }

    /// Reset metrics counters.
    pub fn reset_metrics(&self) {
        self.metrics.basic_queries = 0;
        self.metrics.basic_hits = 0;
        self.metrics.code_queries = 0;
        self.metrics.code_hits = 0;
        self.metrics.storage_queries = 0;
        self.metrics.storage_hits = 0;
        self.metrics.commits = 0;
        debug!("database metrics reset");
    }

    /// Insert an account with the given nonce and balance.
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

    /// Insert bytecode for a contract.
    /// Returns the code hash.
    pub fn insert_code(&mut self, code: Bytecode) -> B256 {
        let hash = code.hash_slow();
        self.code.insert(hash, code.clone());
        debug!(hash = %hash, "bytecode inserted");
        hash
    }

    /// Set a storage slot for a given address.
    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.storage.insert((address, slot), value);
        debug!(address = %address, slot = %slot, value = %value, "storage slot set");
    }

    /// Get a storage slot value (falling back to parent if present).
    pub fn get_storage(&self, address: Address, slot: U256) -> U256 {
        self.metrics.storage_queries.fetch_add(1, Ordering::Relaxed);
        if let Some(&value) = self.storage.get(&(address, slot)) {
            self.metrics.storage_hits.fetch_add(1, Ordering::Relaxed);
            return value;
        }
        if let Some(parent) = &self.parent {
            return parent.get_storage(address, slot);
        }
        U256::ZERO
    }

    /// Get account info (falling back to parent if present).
    pub fn get_account(&self, address: Address) -> Option<AccountInfo> {
        self.metrics.basic_queries.fetch_add(1, Ordering::Relaxed);
        if let Some(account) = self.accounts.get(&address) {
            self.metrics.basic_hits.fetch_add(1, Ordering::Relaxed);
            return Some(account.clone());
        }
        if let Some(parent) = &self.parent {
            return parent.get_account(address);
        }
        None
    }

    /// Clear all local state (does not affect parent).
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.code.clear();
        self.storage.clear();
        debug!("database cleared (local state only)");
    }

    /// Check if the database (including parent) is empty.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty()
            && self.code.is_empty()
            && self.storage.is_empty()
            && self.parent.as_ref().map(|p| p.is_empty()).unwrap_or(true)
    }

    /// Get the total number of accounts (including parent).
    pub fn total_accounts(&self) -> usize {
        let local_count = self.accounts.len();
        let parent_count = self.parent.as_ref().map(|p| p.total_accounts()).unwrap_or(0);
        local_count + parent_count
    }

    /// Export the database state to JSON.
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

    /// Import database state from JSON.
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

    /// Persist the database to IONAFS.
    pub fn persist(&self, path: &str) -> MemDbResult<()> {
        let json = self.export_json()?;
        crate::fs::ionafs::write(path, json.as_bytes());
        info!(path, "database persisted to IONAFS");
        Ok(())
    }

    /// Load a database from IONAFS.
    pub fn load(path: &str) -> MemDbResult<Self> {
        let mut db = Self::new();
        if let Some(data) = crate::fs::ionafs::read(path) {
            let json = String::from_utf8_lossy(&data);
            db.import_json(&json)?;
            info!(path, "database loaded from IONAFS");
        } else {
            debug!(path, "no existing database found, using empty state");
        }
        Ok(db)
    }
}

// -----------------------------------------------------------------------------
// Database trait implementation
// -----------------------------------------------------------------------------

impl Database for MemDb {
    type Error = MemDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.get_account(address))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.metrics.code_queries.fetch_add(1, Ordering::Relaxed);
        if let Some(code) = self.code.get(&code_hash) {
            self.metrics.code_hits.fetch_add(1, Ordering::Relaxed);
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
        // In production, this would return the actual block hash from chain state.
        // For in‑memory DB, we return zero with a warning if it's not the genesis block.
        if number != U256::ZERO {
            debug!(block_number = %number, "block_hash called for non‑zero block, returning zero");
        }
        Ok(B256::ZERO)
    }
}

// -----------------------------------------------------------------------------
// DatabaseCommit trait implementation
// -----------------------------------------------------------------------------

impl DatabaseCommit for MemDb {
    fn commit(&mut self, changes: revm::primitives::State) {
        self.metrics.commits.fetch_add(1, Ordering::Relaxed);
        let mut accounts_updated = 0;
        let mut storage_updated = 0;
        let mut code_updated = 0;

        for (address, account) in changes {
            // Update account info
            self.accounts.insert(address, account.info.clone());
            accounts_updated += 1;

            // Commit storage changes
            for (slot, value) in account.storage {
                self.storage.insert((address, slot), value.present_value);
                storage_updated += 1;
            }

            // Store code if present
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
        let db = MemDb::new();
        assert!(db.is_empty());
    }

    #[test]
    fn test_insert_account() {
        let mut db = MemDb::new();
        let addr = test_addr();
        db.insert_account(addr, 42, U256::from(1000));
        let info = db.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 42);
        assert_eq!(info.balance, U256::from(1000));
    }

    #[test]
    fn test_code_by_hash_not_found() {
        let mut db = MemDb::new();
        let hash = B256::new([0xAA; 32]);
        let err = db.code_by_hash(hash).unwrap_err();
        assert!(matches!(err, MemDbError::CodeNotFound { hash: _ }));
    }

    #[test]
    fn test_insert_code() {
        let mut db = MemDb::new();
        let bytes = Bytes::from(vec![0x60, 0x00, 0x00]);
        let code = Bytecode::new_raw(bytes);
        let hash = db.insert_code(code.clone());
        let retrieved = db.code_by_hash(hash).unwrap();
        assert_eq!(retrieved.bytes(), code.bytes());
    }

    #[test]
    fn test_storage_ops() {
        let mut db = MemDb::new();
        let addr = test_addr();
        let slot = U256::from(0x1234);
        db.set_storage(addr, slot, U256::from(0xDEADBEEF));
        let value = db.storage(addr, slot).unwrap();
        assert_eq!(value, U256::from(0xDEADBEEF));
        // Non‑existent slot returns zero
        let value2 = db.storage(addr, U256::from(0x9999)).unwrap();
        assert_eq!(value2, U256::ZERO);
    }

    #[test]
    fn test_clear() {
        let mut db = MemDb::new();
        db.insert_account(test_addr(), 0, U256::ONE);
        db.set_storage(test_addr(), U256::ZERO, U256::ONE);
        assert!(!db.is_empty());
        db.clear();
        assert!(db.is_empty());
    }

    #[test]
    fn test_fork() {
        let mut parent = MemDb::new();
        let addr = test_addr();
        parent.insert_account(addr, 10, U256::from(1000));
        parent.set_storage(addr, U256::ZERO, U256::from(42));

        let mut fork = MemDb::fork(&parent);
        // Fork should see parent's data
        let info = fork.basic(addr).unwrap().unwrap();
        assert_eq!(info.nonce, 10);
        let storage = fork.storage(addr, U256::ZERO).unwrap();
        assert_eq!(storage, U256::from(42));

        // Modify fork locally
        fork.insert_account(addr, 20, U256::from(2000));
        fork.set_storage(addr, U256::ZERO, U256::from(99));

        // Parent unchanged
        let parent_info = parent.basic(addr).unwrap().unwrap();
        assert_eq!(parent_info.nonce, 10);
        let parent_storage = parent.storage(addr, U256::ZERO).unwrap();
        assert_eq!(parent_storage, U256::from(42));
    }

    #[test]
    fn test_export_import() -> MemDbResult<()> {
        let mut db = MemDb::new();
        let addr = test_addr();
        db.insert_account(addr, 5, U256::from(500));
        db.set_storage(addr, U256::from(1), U256::from(0xFF));

        let json = db.export_json()?;
        let mut db2 = MemDb::new();
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
        let mut db = MemDb::with_metrics();
        let addr = test_addr();
        db.insert_account(addr, 1, U256::ONE);

        let _ = db.basic(addr).unwrap();
        let _ = db.storage(addr, U256::ZERO).unwrap();

        let metrics = db.metrics();
        assert_eq!(metrics.basic_queries, 1);
        assert_eq!(metrics.basic_hits, 1);
        assert_eq!(metrics.storage_queries, 1);
        assert_eq!(metrics.storage_hits, 0); // not found
    }

    #[test]
    fn test_total_accounts() {
        let mut parent = MemDb::new();
        parent.insert_account(test_addr(), 1, U256::ONE);

        let mut fork = MemDb::fork(&parent);
        fork.insert_account(test_addr2(), 2, U256::from(2));

        assert_eq!(fork.total_accounts(), 2);
    }
}
