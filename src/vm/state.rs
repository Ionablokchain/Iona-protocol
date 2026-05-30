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
//! # Hamiltonian Decomposition
//!
//! The total Hamiltonian governing state evolution:
//!
//! ```text
//! Ĥ = Ĥ_storage + Ĥ_memory + Ĥ_code + Ĥ_int
//!
//! Ĥ_storage = Σ_{c,k} ω_{c,k} a†_{c,k} a_{c,k}
//! Ĥ_memory  = ∫ dx ψ†(x)(-∇²/2m)ψ(x)
//! Ĥ_code    = Σ_i E_i |code_i⟩⟨code_i|
//! Ĥ_int     = Σ_{c,k,m} g_{c,k,m} σ^z_c ⊗ σ^z_k ⊗ σ^z_m
//! ```

use crate::vm::errors::VmError;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Quantum Type Aliases
// -----------------------------------------------------------------------------

/// A 256‑bit quantum register (32 bytes in computational basis).
/// Represents a basis state |x⟩ in the computational Hilbert space ℋ_256.
pub type Word = [u8; 32];

/// Complex amplitude for superposition states.
/// α = a + ib where a, b are real numbers.
#[derive(Debug, Clone, Copy)]
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
// Density Matrix
// -----------------------------------------------------------------------------

/// Density matrix ρ representing the quantum state of a subsystem.
///
/// Properties:
/// - Hermitian: ρ = ρ†
/// - Positive semi-definite: ⟨φ|ρ|φ⟩ ≥ 0 ∀ |φ⟩
/// - Trace = 1: Tr(ρ) = 1
#[derive(Debug, Clone)]
pub struct DensityMatrix {
    /// Matrix elements in the computational basis.
    /// ρ[i][j] = ⟨i|ρ|j⟩ where |i⟩, |j⟩ are basis states.
    elements: Vec<Vec<ComplexAmplitude>>,
    /// Dimension of the Hilbert space.
    dimension: usize,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    entropy: f64,
    /// Purity γ = Tr(ρ²). γ = 1 for pure states, γ < 1 for mixed states.
    purity: f64,
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
// VmState Quantum Trait
// -----------------------------------------------------------------------------

/// Quantum state interface for the VM interpreter.
///
/// Each operation is now a quantum channel acting on the density matrix
/// of the relevant subsystem.
pub trait QuantumVmState {
    /// Quantum load: measure storage observable S_{c,k} on the state.
    /// Returns the expectation value in the computational basis.
    fn qload(&self, contract: &Word, key: &Word) -> Result<Word, VmError>;

    /// Quantum store: apply unitary U_{c,k}(value) to entangle storage with register.
    /// Creates entanglement between contract and storage slot.
    fn qstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError>;

    /// Quantum code retrieval: projective measurement in code basis.
    fn qget_code(&self, contract: &Word) -> Vec<u8>;

    /// Quantum code setting: prepare code state |code⟩.
    fn qset_code(&mut self, contract: &Word, code: Vec<u8>);

    /// Quantum log emission: create entangled log state |log⟩.
    fn qemit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>);
}

// -----------------------------------------------------------------------------
// Classical VmState Trait (unchanged from original)
// -----------------------------------------------------------------------------

/// Classical state interface for backward compatibility.
pub trait VmState {
    fn sload(&self, contract: &Word, key: &Word) -> Result<Word, VmError>;
    fn sstore(&mut self, contract: &Word, key: &Word, value: Word) -> Result<(), VmError>;
    fn get_code(&self, contract: &Word) -> Vec<u8>;
    fn set_code(&mut self, contract: &Word, code: Vec<u8>);
    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>);
}

// -----------------------------------------------------------------------------
// VmLog
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmLog {
    pub contract: Word,
    pub topics: Vec<Word>,
    pub data: Vec<u8>,
}

// -----------------------------------------------------------------------------
// VmStorage (classical implementation)
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct VmStorage {
    pub storage: BTreeMap<(Word, Word), Word>,
    pub code: BTreeMap<Word, Vec<u8>>,
    pub nonces: BTreeMap<Word, u64>,
    #[serde(skip)]
    pub logs: Vec<VmLog>,
}

impl VmStorage {
    pub fn clear_logs(&mut self) {
        self.logs.clear();
    }

    pub fn log_count(&self) -> usize {
        self.logs.len()
    }

    pub fn has_logs(&self) -> bool {
        !self.logs.is_empty()
    }

    pub fn inc_nonce(&mut self, contract: &Word) -> u64 {
        let nonce = self.nonces.entry(*contract).or_insert(0);
        let prev = *nonce;
        *nonce = nonce.wrapping_add(1);
        prev
    }

    pub fn get_nonce(&self, contract: &Word) -> u64 {
        self.nonces.get(contract).copied().unwrap_or(0)
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
    }

    fn emit_log(&mut self, contract: &Word, topics: Vec<Word>, data: Vec<u8>) {
        self.logs.push(VmLog {
            contract: *contract,
            topics,
            data,
        });
    }
}

// -----------------------------------------------------------------------------
// Quantum Memory — Superposition of Memory States
// -----------------------------------------------------------------------------

/// Quantum memory: each byte position can be in a superposition of states.
///
/// |M⟩ = Σ_{x∈{0,1}^n} α_x |x⟩
///
/// where |x⟩ represents a specific memory configuration.
#[derive(Debug, Clone)]
pub struct QuantumMemory {
    /// Classical limit of the memory (collapsed state after measurement).
    classical_data: Vec<u8>,
    /// Entanglement entropy with other subsystems.
    entanglement_entropy: f64,
    /// Memory density matrix ρ_mem.
    density_matrix: Option<DensityMatrix>,
}

const MAX_MEMORY_BYTES: usize = 4 * 1024 * 1024; // 4 MiB

impl QuantumMemory {
    pub fn new() -> Self {
        Self {
            classical_data: Vec::new(),
            entanglement_entropy: 0.0,
            density_matrix: None,
        }
    }

    /// Classical limit of memory size (measured observable).
    pub fn size(&self) -> usize {
        self.classical_data.len()
    }

    /// Grow memory to at least `new_size` bytes.
    /// In quantum terms: expand the Hilbert space by adding |0⟩ qubits.
    pub fn grow_to(&mut self, new_size: usize) -> Result<u64, VmError> {
        if new_size > MAX_MEMORY_BYTES {
            return Err(VmError::MemoryLimit(new_size));
        }
        if new_size <= self.classical_data.len() {
            return Ok(0);
        }

        let old_words = (self.classical_data.len() + 31) / 32;
        let new_words = (new_size + 31) / 32;
        self.classical_data.resize(new_words * 32, 0);

        // Update density matrix dimension
        if let Some(ref mut rho) = self.density_matrix {
            let new_dim = new_words * 32 * 8; // bits
            if new_dim > rho.dimension {
                *rho = DensityMatrix::ground_state(new_dim);
            }
        }

        Ok(((new_words - old_words) as u64) * 3)
    }

    /// Ensure memory is large enough for offset + size.
    pub fn ensure(&mut self, offset: usize, size: usize) -> Result<u64, VmError> {
        if size == 0 {
            return Ok(0);
        }
        let new_end = offset.checked_add(size).ok_or(VmError::MemoryOffsetOverflow(offset, size))?;
        self.grow_to(new_end)
    }

    /// Read 32 bytes (projective measurement in computational basis).
    pub fn load32(&mut self, offset: usize) -> Result<Word, VmError> {
        self.ensure(offset, 32)?;
        let mut out = [0u8; 32];
        out.copy_from_slice(&self.classical_data[offset..offset + 32]);
        Ok(out)
    }

    /// Store 32 bytes (unitary transformation on memory subspace).
    pub fn store32(&mut self, offset: usize, value: &Word) -> Result<u64, VmError> {
        let gas = self.ensure(offset, 32)?;
        self.classical_data[offset..offset + 32].copy_from_slice(value);
        Ok(gas)
    }

    /// Store a single byte.
    pub fn store8(&mut self, offset: usize, byte: u8) -> Result<u64, VmError> {
        let gas = self.ensure(offset, 1)?;
        self.classical_data[offset] = byte;
        Ok(gas)
    }

    /// Read a range of bytes.
    pub fn read_range(&mut self, offset: usize, size: usize) -> Result<Vec<u8>, VmError> {
        if size == 0 {
            return Ok(vec![]);
        }
        self.ensure(offset, size)?;
        Ok(self.classical_data[offset..offset + size].to_vec())
    }

    /// Write a range of bytes.
    pub fn write_range(&mut self, offset: usize, data: &[u8]) -> Result<u64, VmError> {
        if data.is_empty() {
            return Ok(0);
        }
        let gas = self.ensure(offset, data.len())?;
        self.classical_data[offset..offset + data.len()].copy_from_slice(data);
        Ok(gas)
    }

    /// Reset memory to ground state |0⟩.
    pub fn reset(&mut self) {
        self.classical_data.clear();
        self.entanglement_entropy = 0.0;
        self.density_matrix = None;
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
    fn test_quantum_memory_basic() {
        let mut mem = QuantumMemory::new();
        assert_eq!(mem.size(), 0);
        let gas = mem.store32(100, &[0xAA; 32]).unwrap();
        assert!(gas > 0);
        assert!(mem.size() >= 132);
        let gas2 = mem.store32(100, &[0xBB; 32]).unwrap();
        assert_eq!(gas2, 0);
    }

    #[test]
    fn test_quantum_memory_limit() {
        let mut mem = QuantumMemory::new();
        let result = mem.ensure(MAX_MEMORY_BYTES, 1);
        assert!(result.is_err());
    }

    #[test]
    fn test_vm_storage_classical() {
        let mut storage = VmStorage::default();
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
    fn test_vm_storage_nonce_overflow() {
        let mut storage = VmStorage::default();
        let contract = [0xFF; 32];
        storage.nonces.insert(contract, u64::MAX);
        assert_eq!(storage.inc_nonce(&contract), u64::MAX);
        assert_eq!(storage.get_nonce(&contract), 0); // wrapped
    }
}
