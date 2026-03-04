//! VM state interface and concrete implementation over KvState.
//!
//! The VM needs:
//!   - Contract storage (sload/sstore): 32-byte key → 32-byte value per contract
//!   - Contract code storage: address → bytecode
//!   - Memory: linear byte array, grows on demand
//!   - Event log: emitted LOG0..LOG4 entries

use crate::vm::errors::VmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Abstract state interface for the VM interpreter.
pub trait VmState {
    fn sload(&self, contract: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 32], VmError>;
    fn sstore(&mut self, contract: &[u8; 32], key: &[u8; 32], value: [u8; 32]) -> Result<(), VmError>;
    fn get_code(&self, contract: &[u8; 32]) -> Vec<u8>;
    fn set_code(&mut self, contract: &[u8; 32], code: Vec<u8>);
    fn emit_log(&mut self, contract: &[u8; 32], topics: Vec<[u8; 32]>, data: Vec<u8>);
}

/// A log entry emitted by a contract.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLog {
    pub contract: [u8; 32],
    pub topics:   Vec<[u8; 32]>,
    pub data:     Vec<u8>,
}

/// In-memory VM state backed by BTreeMaps.
/// This is integrated into KvState for persistence.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStorage {
    /// Contract storage: (contract_addr, slot) → value
    pub storage: BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    /// Contract bytecode: contract_addr → bytecode
    pub code: BTreeMap<[u8; 32], Vec<u8>>,
    /// Nonce per contract address (for sub-call address derivation)
    pub nonces: BTreeMap<[u8; 32], u64>,
    /// Emitted logs (cleared per block, indexed separately)
    #[serde(skip)]
    pub logs: Vec<VmLog>,
}

impl VmState for VmStorage {
    fn sload(&self, contract: &[u8; 32], key: &[u8; 32]) -> Result<[u8; 32], VmError> {
        Ok(self.storage.get(&(*contract, *key)).copied().unwrap_or([0u8; 32]))
    }

    fn sstore(&mut self, contract: &[u8; 32], key: &[u8; 32], value: [u8; 32]) -> Result<(), VmError> {
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
        self.logs.push(VmLog { contract: *contract, topics, data });
    }
}

/// Linear memory used during a single contract execution.
/// Grows in 32-byte word chunks. Max 4 MiB to prevent DoS.
pub struct Memory {
    data: Vec<u8>,
}

const MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

impl Memory {
    pub fn new() -> Self { Self { data: Vec::new() } }

    pub fn size(&self) -> usize { self.data.len() }

    /// Ensure memory is at least `offset + size` bytes, growing as needed.
    /// Returns gas cost for the expansion (3 gas per new 32-byte word).
    pub fn ensure(&mut self, offset: usize, size: usize) -> Result<u64, VmError> {
        if size == 0 { return Ok(0); }
        let new_end = offset.checked_add(size).ok_or(VmError::MemoryLimit)?;
        if new_end > MAX_MEMORY_BYTES { return Err(VmError::MemoryLimit); }
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

    /// Write 1 byte at `offset`.
    pub fn store8(&mut self, offset: usize, byte: u8) -> Result<u64, VmError> {
        let gas = self.ensure(offset, 1)?;
        self.data[offset] = byte;
        Ok(gas)
    }

    /// Read `size` bytes at `offset`.
    pub fn read_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 { return Ok(vec![]); }
        self.ensure(offset, size)?;
        Ok(self.data[offset..offset + size].to_vec())
    }

    /// Write slice at `offset`.
    pub fn write_range(&mut self, offset: usize, data: &[u8]) -> Result<u64, VmError> {
        if data.is_empty() { return Ok(0); }
        let gas = self.ensure(offset, data.len())?;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(gas)
    }
}
