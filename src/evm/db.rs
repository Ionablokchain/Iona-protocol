//! Minimal in-memory REVM database for development and testing.
//!
//! Implements the `revm::Database` and `DatabaseCommit` traits using
//! `HashMap` for accounts, storage, and bytecode storage.
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
use std::collections::HashMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during database operations.
#[derive(Debug, Error)]
pub enum MemDbError {
    #[error("code not found for hash 0x{hash:x}")]
    CodeNotFound { hash: B256 },

    #[error("account not found: 0x{address:x}")]
    AccountNotFound { address: Address },
}

pub type MemDbResult<T> = Result<T, MemDbError>;

// -----------------------------------------------------------------------------
// MemDb
// -----------------------------------------------------------------------------

/// Minimal in-memory REVM DB for dev/testing.
/// For production, implement `Database` backed by your chain state.
#[derive(Default)]
pub struct MemDb {
    /// Account state (nonce, balance, code hash, etc.)
    pub accounts: HashMap<Address, AccountInfo>,
    /// Bytecode indexed by code hash.
    pub code: HashMap<B256, Bytecode>,
    /// Storage slots: (address, slot) → value.
    pub storage: HashMap<(Address, U256), U256>,
}

impl MemDb {
    /// Create a new empty database.
    pub fn new() -> Self {
        Self::default()
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
    }

    /// Insert bytecode for a contract.
    pub fn insert_code(&mut self, code: Bytecode) -> B256 {
        let hash = code.hash_slow();
        self.code.insert(hash, code);
        hash
    }

    /// Set a storage slot for a given address.
    pub fn set_storage(&mut self, address: Address, slot: U256, value: U256) {
        self.storage.insert((address, slot), value);
    }

    /// Clear all state (accounts, storage, code).
    pub fn clear(&mut self) {
        self.accounts.clear();
        self.code.clear();
        self.storage.clear();
    }

    /// Check if the database is empty.
    pub fn is_empty(&self) -> bool {
        self.accounts.is_empty() && self.code.is_empty() && self.storage.is_empty()
    }
}

// -----------------------------------------------------------------------------
// Database trait implementation
// -----------------------------------------------------------------------------

impl Database for MemDb {
    type Error = MemDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        Ok(self.accounts.get(&address).cloned())
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.code
            .get(&code_hash)
            .cloned()
            .ok_or(MemDbError::CodeNotFound { hash: code_hash })
    }

    fn storage(&mut self, address: Address, index: U256) -> Result<U256, Self::Error> {
        Ok(*self.storage.get(&(address, index)).unwrap_or(&U256::ZERO))
    }

    fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
        // In a real database this would return the actual block hash.
        // For testing, returning zero is sufficient.
        Ok(B256::ZERO)
    }
}

// -----------------------------------------------------------------------------
// DatabaseCommit trait implementation
// -----------------------------------------------------------------------------

impl DatabaseCommit for MemDb {
    fn commit(&mut self, changes: revm::primitives::State) {
        for (address, account) in changes {
            // Update account info if present (REVM v9 uses `AccountInfo` directly,
            // not `Option<AccountInfo>`). We assume the `info` field is accessible.
            self.accounts.insert(address, account.info.clone());

            // Commit storage changes
            for (slot, value) in account.storage {
                self.storage.insert((address, slot), value.present_value);
            }

            // Store code if present
            if let Some(code) = account.info.code {
                let hash = code.hash_slow();
                self.code.insert(hash, code);
            }
        }
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
        // Non-existent slot returns zero
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
}
