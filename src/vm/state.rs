//! VM state interface and concrete implementation over KvState.
//!
//! The VM needs:
//!   - Contract storage (sload/sstore): 32‑byte key → 32‑byte value per contract
//!   - Contract code storage: address → bytecode
//!   - Memory: linear byte array, grows on demand
//!   - Event log: emitted LOG0..LOG4 entries
//!
//! This module provides the `VmState` trait that abstracts the state,
//! a concrete in‑memory `VmStorage` that integrates with `KvState`,
//! and a `Memory` structure for managing execution‑time linear memory.
//!
//! # Example
//!
//! ```
//! use iona::vm::state::{VmState, VmStorage};
//!
//! let mut storage = VmStorage::default();
//! let contract = [0xAA; 32];
//! let key = [0x01; 32];
//! let value = [0xDE; 32];
//!
//! storage.sstore(&contract, &key, value).unwrap();
//! let loaded = storage.sload(&contract, &key).unwrap();
//! assert_eq!(loaded, value);
//! ```

use crate::vm::errors::VmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// VmState trait
// -----------------------------------------------------------------------------

/// Abstract state interface for the VM interpreter.
///
/// All operations are deterministic and must be implemented by the state backend
/// (e.g., `KvState` which includes `VmStorage`). The trait separates the VM
/// from the underlying storage, allowing for testing with mock states.
pub trait VmState {
    /// Read a 32‑byte value from the contract's storage at the given key.
    /// Returns `Ok([0u8; 32])` if the key has never been written.
    fn sload(&self, contract: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 32], VmError>;

    /// Write a 32‑byte value to the contract's storage at the given key.
    /// If the value is all zeros, the entry is deleted (to save space).
    fn sstore(
        &mut self,
        contract: &[u8; 32],
        key: &[u8; 32],
        value: [u8; 32],
    ) -> Result<(), VmError>;

    /// Retrieve the bytecode of a contract. Returns an empty vector if no code exists.
    fn get_code(&self, contract: &[u8; 32]) -> Vec<u8>;

    /// Set the bytecode of a contract. Passing an empty vector removes the code.
    fn set_code(&mut self, contract: &[u8; 32], code: Vec<u8>);

    /// Emit a log entry. The `topics` list can contain 0–4 32‑byte values.
    fn emit_log(&mut self, contract: &[u8; 32], topics: Vec<[u8; 32]>, data: Vec<u8>);
}

// -----------------------------------------------------------------------------
// VmLog
// -----------------------------------------------------------------------------

/// A log entry emitted by a contract during execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLog {
    /// Contract address that emitted the log.
    pub contract: [u8; 32],
    /// List of topics (each 32 bytes). Usually used for indexed search.
    pub topics: Vec<[u8; 32]>,
    /// Arbitrary data associated with the log.
    pub data: Vec<u8>,
}

// -----------------------------------------------------------------------------
// VmStorage
// -----------------------------------------------------------------------------

/// In‑memory VM state backed by `BTreeMap`.
/// This is integrated into `KvState` for persistence across blocks.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStorage {
    /// Contract storage: (contract_addr, slot) → value.
    /// Stored as (32‑byte contract address, 32‑byte slot) → 32‑byte value.
    pub storage: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    /// Contract bytecode: contract_addr → bytecode.
    pub code: BTreeMap<[u8; 32], Vec<u8>>,
    /// Nonce per contract address (for sub‑call address derivation).
    pub nonces: BTreeMap<[u8; 32], u64>,
    /// Emitted logs during the current block. Cleared after block execution.
    #[serde(skip)]
    pub logs: Vec<VmLog>,
}

impl VmStorage {
    /// Clear all logs (call at the start of a new block).
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Get the number of logs stored.
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// Check if there are any logs.
    pub fn has_logs(&self) -> bool {
        !self.logs.is_empty()
    }
}

impl VmState for VmStorage {
    fn sload(&self, contract: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 32], VmError> {
        Ok(self
            .storage
            .get(&(*contract, *key))
            .copied()
            .unwrap_or([0u8; 32]))
    }

    fn sstore(
        &mut self,
        contract: &[u8; 32],
        key: &[u8; 32],
        value: [u8; 32],
    ) -> Result<(), VmError> {
        if value == [0u8; 32] {
            self.storage.remove(&(*contract, *key));
        } else {
            self.storage.insert((*contract, *key), value);
        }
        Ok(())
    }

    fn get_code(&self, contract: &[u8; 32]) -> Vec<u8> {
        self.code.get(contract).cloned().unwrap_or_default()
    }

    fn set_code(&mut self, contract: &[u8; 32], code: Vec<u8>) {
        if code.is_empty() {
            self.code.remove(contract);
        } else {
            self.code.insert(*contract, code);
        }
    }

    fn emit_log(&mut self, contract: &[u8; 32], topics: Vec<[u8; 32]>, data: Vec<u8>) {
        self.logs.push(VmLog {
            contract: *contract,
            topics,
            data,
        });
    }
}

// -----------------------------------------------------------------------------
// Memory
// -----------------------------------------------------------------------------

/// Linear memory used during a single contract execution.
/// Grows in 32‑byte word chunks. Maximum size is 4 MiB to prevent DoS.
#[derive(Debug, Clone)]
pub struct Memory {
    data: Vec<u8>,
}

const MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

impl Memory {
    /// Create a new empty memory.
    #[must_use]
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    /// Current size of memory in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Ensure memory is at least `offset + size` bytes, growing as needed.
    /// Returns gas cost for the expansion (3 gas per new 32‑byte word).
    pub fn ensure(&mut self, offset: usize, size: usize) -> Result<u64, VmError> {
        if size == 0 {
            return Ok(0);
        }
        let new_end = offset
            .checked_add(size)
            .ok_or(VmError::MemoryLimit)?;
        if new_end > MAX_MEMORY_BYTES {
            return Err(VmError::MemoryLimit);
        }
        if new_end > self.data.len() {
            let old_words = (self.data.len() + 31) / 32;
            let new_words = (new_end + 31) / 32;
            self.data.resize(new_words * 32, 0);
            let gas = ((new_words - old_words) as u64) * 3;
            return Ok(gas);
        }
        Ok(0)
    }

    /// Read 32 bytes at `offset`.
    pub fn load32(&mut self, offset: usize) -> Result<[u8; 32], VmError> {
        self.ensure(offset, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offset..offset + 32]);
        Ok(out)
    }

    /// Write 32 bytes at `offset`.
    pub fn store32(&mut self, offset: usize, value: &[u8; 32]) -> Result<u64, VmError> {
        let gas = self.ensure(offset, 32)?;
        self.data[offset..offset + 32].copy_from_slice(value);
        Ok(gas)
    }

    /// Write a single byte at `offset`.
    pub fn store8(&mut self, offset: usize, byte: u8) -> Result<u64, VmError> {
        let gas = self.ensure(offset, 1)?;
        self.data[offset] = byte;
        Ok(gas)
    }

    /// Read `size` bytes at `offset`.
    pub fn read_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 {
            return Ok(vec![]);
        }
        self.ensure(offset, size)?;
        Ok(self.data[offset..offset + size].to_vec())
    }

    /// Write a slice of bytes at `offset`.
    pub fn write_range(&mut self, offset: usize, data: &[u8]) -> Result<u64, VmError> {
        if data.is_empty() {
            return Ok(0);
        }
        let gas = self.ensure(offset, data.len())?;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(gas)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_storage_basic() {
        let mut storage = VmStorage::default();
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];

        // Initially storage should be zero.
        assert_eq!(
            storage.sload(&contract, &key).unwrap(),
            [0u8; 32]
        );

        // Store a value.
        storage.sstore(&contract, &key, value).unwrap();
        assert_eq!(
            storage.sload(&contract, &key).unwrap(),
            value
        );

        // Delete by storing zero.
        storage.sstore(&contract, &key, [0u8; 32]).unwrap();
        assert_eq!(
            storage.sload(&contract, &key).unwrap(),
            [0u8; 32]
        );
    }

    #[test]
    fn test_vm_storage_code() {
        let mut storage = VmStorage::default();
        let contract = [0xBB; 32];
        let code = vec![0x60, 0x00, 0x60, 0x00, 0xf3];

        storage.set_code(&contract, code.clone());
        assert_eq!(storage.get_code(&contract), code);

        // Setting empty code removes it.
        storage.set_code(&contract, vec![]);
        assert_eq!(storage.get_code(&contract), vec![]);
    }

    #[test]
    fn test_vm_storage_logs() {
        let mut storage = VmStorage::default();
        let contract = [0xCC; 32];
        let topics = vec![[0x01; 32], [0x02; 32]];
        let data = b"hello".to_vec();

        storage.emit_log(&contract, topics.clone(), data.clone());
        assert_eq!(storage.log_count(), 1);
        let log = &storage.logs[0];
        assert_eq!(log.contract, contract);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);

        storage.clear_logs();
        assert_eq!(storage.log_count(), 0);
        assert!(!storage.has_logs());
    }

    #[test]
    fn test_memory_growth() {
        let mut mem = Memory::new();
        assert_eq!(mem.size(), 0);

        // Write at offset 100, size 32 → should grow to at least 132 bytes.
        let gas = mem.store32(100, &[0xAA; 32]).unwrap();
        assert!(gas > 0);
        assert!(mem.size() >= 132);

        // Writing again at same offset should not grow further.
        let gas2 = mem.store32(100, &[0xBB; 32]).unwrap();
        assert_eq!(gas2, 0);
    }

    #[test]
    fn test_memory_read_write() {
        let mut mem = Memory::new();
        let value = [
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00,
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        ];

        mem.store32(0, &value).unwrap();
        let loaded = mem.load32(0).unwrap();
        assert_eq!(loaded, value);

        // Write a single byte
        mem.store8(0, 0x00).unwrap();
        let mut expected = value;
        expected[0] = 0x00;
        assert_eq!(mem.load32(0).unwrap(), expected);
    }

    #[test]
    fn test_memory_range() {
        let mut mem = Memory::new();
        let data = b"hello world".to_vec();

        mem.write_range(0, &data).unwrap();
        let read_back = mem.read_range(0, data.len()).unwrap();
        assert_eq!(read_back, data);

        // Read empty range
        let empty = mem.read_range(0, 0).unwrap();
        assert!(empty.is_empty());
    }

    #[test]
    fn test_memory_limit() {
        let mut mem = Memory::new();
        // Try to write beyond 4 MiB
        let result = mem.ensure(MAX_MEMORY_BYTES, 1);
        assert!(matches!(result, Err(VmError::MemoryLimit)));
    }

    #[test]
    fn test_vm_state_trait() {
        let mut storage = VmStorage::default();
        let contract = [0xDD; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];

        // Use trait methods
        <VmStorage as VmState>::sstore(&mut storage, &contract, &key, value).unwrap();
        let loaded = <VmStorage as VmState>::sload(&storage, &contract, &key).unwrap();
        assert_eq!(loaded, value);

        let code = vec![0x00, 0x01];
        <VmStorage as VmState>::set_code(&mut storage, &contract, code.clone());
        let fetched = <VmStorage as VmState>::get_code(&storage, &contract);
        assert_eq!(fetched, code);
    }
}
