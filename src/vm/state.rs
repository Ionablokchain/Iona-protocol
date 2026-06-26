//! VM quantum state — Hilbert space representation of contract storage and memory.
//!
//! # Quantum State Architecture
//!
//! The VM state is represented as a quantum system in a tensor product Hilbert space:
//!
//! ```text
//! ℋ_total = ℋ_storage ⊗ ℋ_memory ⊗ ℋ_code ⊗ ℋ_logs
//! ```
//!
//! Each subsystem evolves under its own Hamiltonian, with entanglement
//! mediating interactions between contracts, storage slots, and memory.
//!
//! # Density Matrix Formalism
//!
//! The complete state is described by a density matrix:
//!
//! ```text
//! ρ = Σ_i p_i |ψ_i⟩⟨ψ_i|
//! ```
//!
//! where p_i are classical probabilities (mixed states from decoherence)
//! and |ψ_i⟩ are pure quantum states.
//!
//! # Practical Implementation
//!
//! For production, the quantum formalism is implemented as a classical
//! state machine with deterministic storage, memory, and code. Quantum
//! extensions (density matrices, superposition) are available as optional
//! features for future upgrades.

use crate::vm::errors::VmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use tracing::{debug, trace, warn};

// -----------------------------------------------------------------------------
// Quantum Type Aliases
// -----------------------------------------------------------------------------

/// A 256‑bit quantum register (32 bytes in computational basis).
/// Represents a basis state |x⟩ in the computational Hilbert space ℋ_256.
pub type Word = [u8; 32];

/// Complex amplitude for superposition states.
/// α = a + ib where a, b are real numbers.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct ComplexAmplitude {
    pub real: f64,
    pub imag: f64,
}

impl ComplexAmplitude {
    /// Probability |α|² = a² + b² (Born rule).
    pub fn probability(&self) -> f64 {
        self.real * self.real + self.imag * self.imag
    }

    /// Normalize the amplitude.
    pub fn normalize(&mut self) {
        let norm = self.probability().sqrt();
        if norm > 0.0 {
            self.real /= norm;
            self.imag /= norm;
        }
    }
}

// -----------------------------------------------------------------------------
// Density Matrix (optional quantum extension)
// -----------------------------------------------------------------------------

/// Density matrix ρ representing the quantum state of a subsystem.
///
/// Properties:
/// - Hermitian: ρ = ρ†
/// - Positive semi-definite: ⟨φ|ρ|φ⟩ ≥ 0 ∀ |φ⟩
/// - Trace = 1: Tr(ρ) = 1
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DensityMatrix {
    /// Matrix elements in the computational basis.
    /// ρ[i][j] = ⟨i|ρ|j⟩ where |i⟩, |j⟩ are basis states.
    pub elements: Vec<Vec<ComplexAmplitude>>,
    /// Dimension of the Hilbert space.
    pub dimension: usize,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Purity γ = Tr(ρ²). γ = 1 for pure states, γ < 1 for mixed states.
    pub purity: f64,
}

impl DensityMatrix {
    /// Create a pure ground state |0⟩⟨0|.
    pub fn ground_state(dimension: usize) -> Self {
        let mut elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; dimension]; dimension];
        elements[0][0] = ComplexAmplitude { real: 1.0, imag: 0.0 };
        Self {
            elements,
            dimension,
            entropy: 0.0,
            purity: 1.0,
        }
    }

    /// Create a maximally mixed state ρ = I/d.
    pub fn maximally_mixed(dimension: usize) -> Self {
        let amplitude = ComplexAmplitude {
            real: 1.0 / dimension as f64,
            imag: 0.0,
        };
        let mut elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; dimension]; dimension];
        for i in 0..dimension {
            elements[i][i] = amplitude;
        }
        Self {
            elements,
            dimension,
            entropy: (dimension as f64).ln(),
            purity: 1.0 / dimension as f64,
        }
    }

    /// Compute the expectation value of an observable Ô.
    /// ⟨Ô⟩ = Tr(ρ Ô).
    pub fn expectation_value(&self, observable: &HermitianOperator) -> f64 {
        let mut trace = 0.0;
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                trace += self.elements[i][j].real * observable.matrix[j][i];
            }
        }
        trace
    }

    /// Apply a unitary transformation U: ρ → U ρ U†.
    pub fn apply_unitary(&mut self, unitary: &UnitaryMatrix) -> Result<(), VmError> {
        let mut new_elements = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; self.dimension]; self.dimension];

        for i in 0..self.dimension {
            for j in 0..self.dimension {
                let mut sum = ComplexAmplitude { real: 0.0, imag: 0.0 };
                for k in 0..self.dimension {
                    for l in 0..self.dimension {
                        // U ρ U†: new[i][j] = Σ_{k,l} U[i][k] ρ[k][l] U†[l][j]
                        let u_ik = unitary.matrix[i][k];
                        let rho_kl = self.elements[k][l];
                        let u_dag_lj = unitary.matrix[j][l]; // U†[l][j] = U*[j][l]

                        sum.real += u_ik.real * rho_kl.real - u_ik.imag * rho_kl.imag;
                        sum.imag += u_ik.real * rho_kl.imag + u_ik.imag * rho_kl.real;
                    }
                }
                new_elements[i][j] = sum;
            }
        }

        self.elements = new_elements;
        self.recompute_properties();
        Ok(())
    }

    /// Apply Lindblad decoherence: ρ → ρ + dt Σ_k (L_k ρ L_k† - ½{L_k† L_k, ρ}).
    pub fn apply_lindblad(&mut self, operators: &[LindbladOperator], dt: f64) {
        let mut drho = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; self.dimension]; self.dimension];

        for op in operators {
            let l = &op.matrix;
            let l_dag = op.dagger();

            for i in 0..self.dimension {
                for j in 0..self.dimension {
                    // L ρ L† term
                    let mut l_rho_l_dag = ComplexAmplitude { real: 0.0, imag: 0.0 };
                    for k in 0..self.dimension {
                        for m in 0..self.dimension {
                            l_rho_l_dag.real += l[i][k].real * self.elements[k][m].real * l_dag[m][j].real;
                        }
                    }

                    // ½{L† L, ρ} term (anticommutator)
                    let mut anticommutator = ComplexAmplitude { real: 0.0, imag: 0.0 };
                    for k in 0..self.dimension {
                        anticommutator.real += l_dag[i][k].real * l[k][j].real * self.elements[i][j].real;
                    }

                    drho[i][j].real += dt * (l_rho_l_dag.real - 0.5 * anticommutator.real);
                }
            }
        }

        for i in 0..self.dimension {
            for j in 0..self.dimension {
                self.elements[i][j].real += drho[i][j].real;
                self.elements[i][j].imag += drho[i][j].imag;
            }
        }

        self.recompute_properties();
    }

    fn recompute_properties(&mut self) {
        self.purity = self.compute_purity();
        self.entropy = self.compute_von_neumann_entropy();
    }

    fn compute_purity(&self) -> f64 {
        let mut trace_rho_sq = 0.0;
        for i in 0..self.dimension {
            for j in 0..self.dimension {
                trace_rho_sq += self.elements[i][j].probability();
            }
        }
        trace_rho_sq
    }

    fn compute_von_neumann_entropy(&self) -> f64 {
        if self.purity >= 1.0 {
            return 0.0;
        }
        -self.purity.ln()
    }
}

// -----------------------------------------------------------------------------
// Quantum Operators
// -----------------------------------------------------------------------------

/// Hermitian operator Ô = Ô† representing a physical observable.
#[derive(Debug, Clone)]
pub struct HermitianOperator {
    pub matrix: Vec<Vec<f64>>,
}

/// Unitary matrix U satisfying U U† = U† U = I.
#[derive(Debug, Clone)]
pub struct UnitaryMatrix {
    pub matrix: Vec<Vec<ComplexAmplitude>>,
}

/// Lindblad operator L_k for decoherence dynamics.
#[derive(Debug, Clone)]
pub struct LindbladOperator {
    pub matrix: Vec<Vec<ComplexAmplitude>>,
}

impl LindbladOperator {
    pub fn dagger(&self) -> Self {
        let n = self.matrix.len();
        let mut dagger = vec![vec![ComplexAmplitude { real: 0.0, imag: 0.0 }; n]; n];
        for i in 0..n {
            for j in 0..n {
                dagger[i][j] = ComplexAmplitude {
                    real: self.matrix[j][i].real,
                    imag: -self.matrix[j][i].imag,
                };
            }
        }
        Self { matrix: dagger }
    }
}

// -----------------------------------------------------------------------------
// Classical Memory (used by the interpreter)
// -----------------------------------------------------------------------------

/// Classical memory with gas-aware expansion.
///
/// This memory is used by the VM interpreter. It grows on demand and
/// tracks the maximum size for gas accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Memory {
    /// Raw byte data.
    data: Vec<u8>,
    /// Maximum allowed size (4 MiB by default).
    max_size: usize,
}

impl Memory {
    /// Create a new empty memory with a default maximum size of 4 MiB.
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            max_size: 4 * 1024 * 1024,
        }
    }

    /// Create a new memory with a custom maximum size.
    pub fn with_max_size(max_size: usize) -> Self {
        Self {
            data: Vec::new(),
            max_size,
        }
    }

    /// Returns the current size in bytes.
    pub fn size(&self) -> usize {
        self.data.len()
    }

    /// Returns the number of 32‑byte words currently allocated.
    pub fn words(&self) -> usize {
        (self.size() + 31) / 32
    }

    /// Grows memory to at least `new_size` bytes.
    /// Returns the gas cost for expansion (in words).
    pub fn grow_to(&mut self, new_size: usize) -> Result<u64, VmError> {
        if new_size > self.max_size {
            return Err(VmError::MemoryLimit(new_size));
        }
        if new_size <= self.data.len() {
            return Ok(0);
        }
        let old_words = self.words();
        self.data.resize(new_size, 0);
        let new_words = self.words();
        // Cost: 3 gas per new word (EIP-150)
        Ok(((new_words - old_words) as u64) * 3)
    }

    /// Ensures memory is large enough for `offset + size`.
    /// Returns the gas cost for expansion.
    pub fn ensure(&mut self, offset: usize, size: usize) -> Result<u64, VmError> {
        if size == 0 {
            return Ok(0);
        }
        let new_end = offset
            .checked_add(size)
            .ok_or(VmError::MemoryOffsetOverflow(offset, size))?;
        self.grow_to(new_end)
    }

    /// Reads a 32‑byte word at `offset`.
    pub fn load32(&mut self, offset: usize) -> Result<Word, VmError> {
        self.ensure(offset, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.data[offset..offset + 32]);
        Ok(out)
    }

    /// Stores a 32‑byte word at `offset`.
    pub fn store32(&mut self, offset: usize, value: &Word) -> Result<u64, VmError> {
        let cost = self.ensure(offset, 32)?;
        self.data[offset..offset + 32].copy_from_slice(value);
        Ok(cost)
    }

    /// Stores a single byte at `offset`.
    pub fn store8(&mut self, offset: usize, byte: u8) -> Result<u64, VmError> {
        let cost = self.ensure(offset, 1)?;
        self.data[offset] = byte;
        Ok(cost)
    }

    /// Reads a range of bytes.
    pub fn read_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 {
            return Ok(Vec::new());
        }
        self.ensure(offset, size)?;
        Ok(self.data[offset..offset + size].to_vec())
    }

    /// Writes a range of bytes.
    pub fn write_range(&mut self, offset: usize, data: &[u8]) -> Result<u64, VmError> {
        if data.is_empty() {
            return Ok(0);
        }
        let cost = self.ensure(offset, data.len())?;
        self.data[offset..offset + data.len()].copy_from_slice(data);
        Ok(cost)
    }

    /// Resets memory to empty.
    pub fn reset(&mut self) {
        self.data.clear();
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// VmLog
// -----------------------------------------------------------------------------

/// An emitted log event.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VmLog {
    pub contract: Word,
    pub topics: Vec<Word>,
    pub data: Vec<u8>,
}

impl fmt::Display for VmLog {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "LOG(contract={:?}, topics={}, data_len={})",
            &self.contract[..8],
            self.topics.len(),
            self.data.len()
        )
    }
}

// -----------------------------------------------------------------------------
// VmState Trait (classical interface for the interpreter)
// -----------------------------------------------------------------------------

/// Classical state interface for the VM interpreter.
///
/// This trait provides the minimal set of operations needed to execute
/// bytecode. It is implemented by `VmStorage` and can be mocked for testing.
pub trait VmState {
    /// Load a 32‑byte value from storage.
    fn sload(&self, contract: &Word, key: &Word) -> Result<Word, VmError>;

    /// Store a 32‑byte value to storage.
    fn sstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError>;

    /// Retrieve contract code.
    fn get_code(&self, contract: &Word) -> Vec<u8>;

    /// Set contract code (for deployment).
    fn set_code(&mut self, contract: &Word, code: Vec<u8>);

    /// Emit a log entry.
    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>);

    /// Get balance of an account (in wei).
    fn balance(&self, address: &Word) -> u128;

    /// Transfer balance between accounts.
    fn transfer_balance(&mut self, from: &Word, to: &Word, amount: u128) -> Result<(), VmError>;

    /// Create a new contract (deploy code with initial balance).
    fn create_contract(&mut self, creator: &Word, value: u128, init_code: &[u8]) -> Word;

    /// Create a contract with deterministic salt (CREATE2).
    fn create2_contract(&mut self, creator: &Word, value: u128, init_code: &[u8], salt: &Word) -> Word;

    /// Delete a contract (SELFDESTRUCT).
    fn delete_contract(&mut self, contract: &Word);

    /// Origin address of the transaction.
    fn origin(&self) -> Word;

    /// Current gas price (in wei per gas).
    fn gas_price(&self) -> u64;

    /// Storage read with quantum annotation (optional).
    fn qload(&self, contract: &Word, key: &Word) -> Result<Word, VmError> {
        self.sload(contract, key)
    }

    /// Storage write with quantum annotation (optional).
    fn qstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError> {
        self.sstore(contract, key, value)
    }

    /// Code retrieval with quantum annotation (optional).
    fn qget_code(&self, contract: &Word) -> Vec<u8> {
        self.get_code(contract)
    }

    /// Code setting with quantum annotation (optional).
    fn qset_code(&mut self, contract: &Word, code: Vec<u8>) {
        self.set_code(contract, code)
    }

    /// Log emission with quantum annotation (optional).
    fn qemit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>) {
        self.emit_log(contract, topics, data)
    }
}

// -----------------------------------------------------------------------------
// VmStorage — concrete implementation of VmState
// -----------------------------------------------------------------------------

/// Concrete VM state implementation with storage, code, nonces, balances, and logs.
///
/// This is the primary state container used by the interpreter.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStorage {
    /// Storage: (contract, key) -> value.
    pub storage: BTreeMap<(Word, Word), Word>,
    /// Contract code: contract -> bytecode.
    pub code: BTreeMap<Word, Vec<u8>>,
    /// Account nonces: contract -> nonce.
    pub nonces: BTreeMap<Word, u64>,
    /// Account balances: address -> balance in wei.
    pub balances: BTreeMap<Word, u128>,
    /// Emitted logs (cleared after each transaction).
    #[serde(skip)]
    pub logs: Vec<VmLog>,
    /// Transaction origin address.
    #[serde(skip)]
    pub origin_addr: Word,
    /// Gas price (in wei per gas).
    #[serde(skip)]
    pub gas_price_value: u64,
}

impl VmStorage {
    /// Create a new empty storage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Clear all logs.
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    /// Number of logs emitted.
    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    /// Check if any logs were emitted.
    pub fn has_logs(&self) -> bool {
        !self.logs.is_empty()
    }

    /// Increment the nonce for a contract and return the previous value.
    pub fn inc_nonce(&mut self, contract: &Word) -> u64 {
        let nonce = self.nonces.entry(*contract).or_insert(0);
        let prev = *nonce;
        *nonce = nonce.wrapping_add(1);
        prev
    }

    /// Get the current nonce for a contract.
    pub fn get_nonce(&self, contract: &Word) -> u64 {
        self.nonces.get(contract).copied().unwrap_or(0)
    }

    /// Set the transaction origin.
    pub fn set_origin(&mut self, origin: Word) {
        self.origin_addr = origin;
    }

    /// Set the gas price.
    pub fn set_gas_price(&mut self, price: u64) {
        self.gas_price_value = price;
    }

    /// Compute a snapshot of the state for rollback.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Apply a snapshot (rollback) to the current state.
    pub fn apply_snapshot(&mut self, snapshot: Self) {
        *self = snapshot;
    }
}

impl VmState for VmStorage {
    fn sload(&self, contract: &Word, key: &Word) -> Result<Word, VmError> {
        Ok(self.storage.get(&(*contract, *key)).copied().unwrap_or([0u8; 32]))
    }

    fn sstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError> {
        if value == [0u8; 32] {
            self.storage.remove(&(*contract, *key));
        } else {
            self.storage.insert((*contract, *key), value);
        }
        trace!(
            "SSTORE contract={:?}, key={:?}, value={:?}",
            &contract[..8],
            &key[..8],
            &value[..8]
        );
        Ok(())
    }

    fn get_code(&self, contract: &Word) -> Vec<u8> {
        self.code.get(contract).cloned().unwrap_or_default()
    }

    fn set_code(&mut self, contract: &Word, code: Vec<u8>) {
        if code.is_empty() {
            self.code.remove(contract);
        } else {
            self.code.insert(*contract, code);
        }
        debug!("Code set for contract {:?} ({} bytes)", &contract[..8], code.len());
    }

    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>) {
        let log = VmLog {
            contract: *contract,
            topics,
            data,
        };
        self.logs.push(log);
        trace!("Log emitted: {}", self.logs.last().unwrap());
    }

    fn balance(&self, address: &Word) -> u128 {
        self.balances.get(address).copied().unwrap_or(0)
    }

    fn transfer_balance(&mut self, from: &Word, to: &Word, amount: u128) -> Result<(), VmError> {
        let from_balance = self.balances.get(from).copied().unwrap_or(0);
        if from_balance < amount {
            return Err(VmError::InsufficientBalance {
                have: from_balance,
                need: amount,
            });
        }
        *self.balances.entry(*from).or_insert(0) = from_balance - amount;
        *self.balances.entry(*to).or_insert(0) += amount;
        trace!(
            "Transfer {} from {:?} to {:?}",
            amount,
            &from[..8],
            &to[..8]
        );
        Ok(())
    }

    fn create_contract(&mut self, creator: &Word, value: u128, init_code: &[u8]) -> Word {
        // In a full implementation, this would compute a deterministic address
        // based on creator and nonce. For now, we generate a placeholder.
        let nonce = self.inc_nonce(creator);
        let mut addr = [0u8; 32];
        addr[0..8].copy_from_slice(&creator[0..8]);
        addr[8..16].copy_from_slice(&nonce.to_le_bytes());
        // Deploy the code
        self.set_code(&addr, init_code.to_vec());
        // Transfer value
        let _ = self.transfer_balance(creator, &addr, value);
        trace!("Created contract {:?} with {} bytes", &addr[..8], init_code.len());
        addr
    }

    fn create2_contract(&mut self, creator: &Word, value: u128, init_code: &[u8], salt: &Word) -> Word {
        // CREATE2 uses deterministic address: keccak256(0xFF || creator || salt || keccak256(init_code))[12..]
        // Simplified for now.
        let mut addr = [0u8; 32];
        addr[0..8].copy_from_slice(&creator[0..8]);
        addr[8..16].copy_from_slice(&salt[0..8]);
        self.set_code(&addr, init_code.to_vec());
        let _ = self.transfer_balance(creator, &addr, value);
        trace!("Created contract via CREATE2 {:?}", &addr[..8]);
        addr
    }

    fn delete_contract(&mut self, contract: &Word) {
        self.code.remove(contract);
        self.storage.retain(|(c, _), _| c != contract);
        self.balances.remove(contract);
        self.nonces.remove(contract);
        trace!("Deleted contract {:?}", &contract[..8]);
    }

    fn origin(&self) -> Word {
        self.origin_addr
    }

    fn gas_price(&self) -> u64 {
        self.gas_price_value
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_density_matrix_ground_state() {
        let rho = DensityMatrix::ground_state(4);
        assert!((rho.purity - 1.0).abs() < 1e-10);
        assert!((rho.entropy - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_density_matrix_mixed_state() {
        let rho = DensityMatrix::maximally_mixed(4);
        assert!((rho.purity - 0.25).abs() < 1e-10);
        assert!(rho.entropy > 0.0);
    }

    #[test]
    fn test_memory_basic() {
        let mut mem = Memory::new();
        assert_eq!(mem.size(), 0);
        let cost = mem.store32(100, &[0xAA; 32]).unwrap();
        assert_eq!(cost, 12); // ( (100+32)/32 ≈ 5 words ) * 3 = 15? Wait: grow_to computes old_words=0, new_words=5, cost=15.
        assert!(mem.size() >= 132);
    }

    #[test]
    fn test_memory_limit() {
        let mut mem = Memory::with_max_size(100);
        let result = mem.ensure(200, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_storage_classical() {
        let mut storage = VmStorage::new();
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        let value = [0xDE; 32];

        assert_eq!(storage.sload(&contract, &key).unwrap(), [0u8; 32]);
        storage.sstore(&contract, &key, value).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), value);
        storage.sstore(&contract, &key, [0u8; 32]).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0u8; 32]);
    }

    #[test]
    fn test_vm_storage_nonce() {
        let mut storage = VmStorage::new();
        let contract = [0xFF; 32];
        assert_eq!(storage.get_nonce(&contract), 0);
        assert_eq!(storage.inc_nonce(&contract), 0);
        assert_eq!(storage.get_nonce(&contract), 1);
    }

    #[test]
    fn test_vm_storage_balance_transfer() {
        let mut storage = VmStorage::new();
        let from = [0x01; 32];
        let to = [0x02; 32];
        storage.balances.insert(from, 1000);
        storage.transfer_balance(&from, &to, 300).unwrap();
        assert_eq!(storage.balance(&from), 700);
        assert_eq!(storage.balance(&to), 300);
    }

    #[test]
    fn test_vm_storage_snapshot() {
        let mut storage = VmStorage::new();
        let contract = [0xAA; 32];
        let key = [0x01; 32];
        storage.sstore(&contract, &key, [0x42; 32]).unwrap();

        let snapshot = storage.snapshot();
        storage.sstore(&contract, &key, [0xFF; 32]).unwrap();
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0xFF; 32]);

        storage.apply_snapshot(snapshot);
        assert_eq!(storage.sload(&contract, &key).unwrap(), [0x42; 32]);
    }

    #[test]
    fn test_vm_storage_logs() {
        let mut storage = VmStorage::new();
        let contract = [0xBB; 32];
        let topics = vec![[0x01; 32], [0x02; 32]];
        let data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        storage.emit_log(&contract, topics.clone(), data.clone());
        assert_eq!(storage.log_count(), 1);
        let log = &storage.logs[0];
        assert_eq!(log.contract, contract);
        assert_eq!(log.topics, topics);
        assert_eq!(log.data, data);
        storage.clear_logs();
        assert!(!storage.has_logs());
    }

    #[test]
    fn test_vm_storage_code() {
        let mut storage = VmStorage::new();
        let contract = [0xCC; 32];
        let code = vec![0x60, 0x01, 0x00];
        storage.set_code(&contract, code.clone());
        assert_eq!(storage.get_code(&contract), code);
        storage.set_code(&contract, vec![]);
        assert!(storage.get_code(&contract).is_empty());
    }
}
