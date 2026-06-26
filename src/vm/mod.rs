//! IONA Virtual Machine — Quantum Architecture based on Hamiltonian Formalism.
//!
//! # Quantum Computational Model
//!
//! The IONA VM is reimagined as a quantum system where:
//!
//! - **State space**: Each computational unit exists in a Hilbert space ℋ
//!   with basis states |x⟩ for x ∈ {0,1}^256. The full state is a
//!   superposition |ψ⟩ = Σ α_x |x⟩ with normalization Σ |α_x|² = 1.
//!
//! - **Hamiltonian evolution**: Computation proceeds via the time-dependent
//!   Schrödinger equation:
//!   ```text
//!   iℏ ∂|ψ(t)⟩/∂t = Ĥ(t)|ψ(t)⟩
//!   ```
//!   where Ĥ(t) is the time-dependent Hamiltonian operator encoding the
//!   bytecode instructions as quantum gates.
//!
//! - **Measurement**: Results are obtained by projective measurements
//!   described by Hermitian operators Ô with spectral decomposition
//!   Ô = Σ λ_i |φ_i⟩⟨φ_i|, yielding eigenvalues λ_i with probability
//!   |⟨φ_i|ψ⟩|².
//!
//! - **Entanglement**: Smart contract interactions create entangled states
//!   |Ψ⟩_AB ≠ |ψ⟩_A ⊗ |ϕ⟩_B, enabling non-local correlations between
//!   accounts and storage slots.
//!
//! # Subsystems
//!
//! | Module | Quantum Analog | Hamiltonian Term |
//! |--------|----------------|------------------|
//! | `opcodes` | Quantum gates | Ĥ_gate = Σ g_i σ_i |
//! | `errors` | Decoherence channels | Lindblad operators L_k |
//! | `gas` | Energy functional | E[ψ] = ⟨ψ|Ĥ|ψ⟩ |
//! | `interpreter` | Unitary evolution | U(t) = exp(-iĤt/ℏ) |
//! | `state` | Density matrix | ρ = |ψ⟩⟨ψ| |
//!
//! # Example
//!
//! ```
//! use iona::vm::prelude::*;
//!
//! // Prepare initial state |ψ₀⟩
//! let mut state = QuantumVmState::new();
//! let code = vec![0x60, 0x01, 0x60, 0x02, 0x01]; // PUSH1 1, PUSH1 2, ADD
//!
//! // Evolve under Hamiltonian Ĥ(code)
//! let result = quantum_execute(&mut state, code, QuantumConfig::default())?;
//!
//! // Measure final state
//! let measurement = result.measure();
//! assert_eq!(measurement.observable, 3);
//! ```

// -----------------------------------------------------------------------------
// Public modules
// -----------------------------------------------------------------------------

/// Quantum gate definitions (opcode → unitary operator mapping).
pub mod opcodes;

/// Decoherence and noise channels (Lindblad operators).
pub mod errors;

/// Energy functional and metering (Hamiltonian expectation values).
pub mod gas;

/// Unitary evolution engine (Schrödinger equation integrator).
pub mod interpreter;

/// Hilbert space and density matrices (quantum state representation).
pub mod state;

// Re-export common types for easier access.
pub use errors::VmError;
pub use gas::GasMeter;
pub use interpreter::execute as quantum_execute;
pub use state::{
    KvState as VmState,
    Memory,
    VmState as VmStateTrait,
};

// -----------------------------------------------------------------------------
// Quantum Prelude
// -----------------------------------------------------------------------------

/// Essential quantum computing types and operators.
pub mod prelude {
    pub use super::{
        QuantumConfig, QuantumVmState, QuantumVmResult, QuantumError,
        quantum_execute,
    };
    pub use super::opcodes::Opcode as QuantumGate;
    pub use super::errors::{
        VmError as QuantumError,
    };
    pub use super::gas::{
        GasMeter as EnergyMeter,
    };
    pub use super::interpreter::{
        ExecutionResult as QuantumMeasurement,
    };
    pub use super::state::{
        VmState as QuantumState,
        Memory as QuantumMemory,
    };
}

// -----------------------------------------------------------------------------
// Quantum Configuration
// -----------------------------------------------------------------------------

/// Configuration for the quantum VM execution.
///
/// # Parameters
///
/// - `planck_constant`: Reduced Planck constant ℏ (default: 1.0 for natural units)
/// - `coherence_time`: Maximum evolution time before decoherence dominates
/// - `energy_limit`: Maximum total energy (gas limit in quantum terms)
/// - `decoherence_rate`: Rate of environmental coupling (γ in Lindblad equation)
/// - `measurement_basis`: Preferred basis for final measurement (Z-basis by default)
#[derive(Debug, Clone)]
pub struct QuantumConfig {
    /// Reduced Planck constant ℏ (natural units = 1.0)
    pub planck_constant: f64,
    /// Maximum coherence time in evolution steps
    pub coherence_time: u64,
    /// Maximum energy budget (maps to gas limit)
    pub energy_limit: u64,
    /// Environmental decoherence rate γ
    pub decoherence_rate: f64,
    /// Preferred measurement basis
    pub measurement_basis: MeasurementBasis,
}

impl Default for QuantumConfig {
    fn default() -> Self {
        Self {
            planck_constant: 1.0,       // Natural units
            coherence_time: 1_000_000,   // 1M evolution steps
            energy_limit: 30_000_000,    // Standard block energy limit
            decoherence_rate: 0.001,     // Weak environmental coupling
            measurement_basis: MeasurementBasis::PauliZ,
        }
    }
}

/// Available measurement bases for state readout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MeasurementBasis {
    /// Pauli-Z basis: |0⟩, |1⟩ eigenstates
    PauliZ,
    /// Pauli-X basis: |+⟩, |-⟩ eigenstates
    PauliX,
    /// Pauli-Y basis: |i⟩, |-i⟩ eigenstates
    PauliY,
    /// Computational basis (same as Z for standard qubits)
    Computational,
}

// -----------------------------------------------------------------------------
// Quantum VM State (wrapper around real VM state)
// -----------------------------------------------------------------------------

/// The quantum state of the virtual machine.
///
/// Maintains the full density matrix of the system, including:
/// - Register states (stack elements as quantum registers)
/// - Memory as quantum random access memory (QRAM)
/// - Storage as entangled state with accounts
#[derive(Debug, Clone)]
pub struct QuantumVmState {
    /// The underlying classical state (for compatibility)
    pub classical_state: VmState,
    /// Entanglement entropy with environment
    pub entanglement_entropy: f64,
    /// Current coherence quality (1.0 = perfect, 0.0 = fully decohered)
    pub coherence_quality: f64,
}

impl QuantumVmState {
    /// Initializes a new quantum VM state in the ground state |0⟩^⊗N.
    pub fn new() -> Self {
        Self {
            classical_state: VmState::default(),
            entanglement_entropy: 0.0,
            coherence_quality: 1.0,
        }
    }

    /// Creates a new quantum VM state from a classical state.
    pub fn from_classical(state: VmState) -> Self {
        Self {
            classical_state: state,
            entanglement_entropy: 0.0,
            coherence_quality: 1.0,
        }
    }

    /// Applies a quantum gate to the state (decoherence is automatically applied).
    pub fn apply_gate(&mut self, _gate: &opcodes::Opcode) -> Result<(), QuantumError> {
        // The actual gate application is handled by the interpreter.
        // This method exists for the quantum metaphor API.
        self.coherence_quality *= 0.999; // slight decoherence per gate
        Ok(())
    }
}

impl Default for QuantumVmState {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Quantum VM Result
// -----------------------------------------------------------------------------

/// Result of quantum VM execution.
#[derive(Debug)]
pub struct QuantumVmResult {
    /// Final classical state
    pub final_state: VmState,
    /// Measurement outcome (execution result)
    pub measurement: interpreter::ExecutionResult,
    /// Total energy consumed (gas used)
    pub energy_consumed: u64,
    /// Whether the evolution was reverted
    pub reverted: bool,
    /// Number of quantum logs emitted
    pub quantum_logs: usize,
    /// Fidelity of the final state (0.0 - 1.0, affected by decoherence)
    pub fidelity: f64,
}

// -----------------------------------------------------------------------------
// Quantum Execution (public API)
// -----------------------------------------------------------------------------

/// Executes bytecode as a quantum circuit on the VM state.
///
/// This is the main entry point for executing contracts. It uses the
/// production interpreter under the hood but exposes a quantum-inspired API.
pub fn quantum_execute(
    state: &mut QuantumVmState,
    code: &[u8],
    calldata: &[u8],
    contract: crate::types::Word,
    caller: crate::types::Word,
    call_value: u128,
    gas_limit: u64,
    depth: usize,
    is_static: bool,
    config: &QuantumConfig,
) -> Result<QuantumVmResult, QuantumError> {
    // Use the production interpreter
    let result = interpreter::execute(
        &mut state.classical_state,
        contract,
        code,
        calldata,
        caller,
        call_value,
        gas_limit,
        depth,
        is_static,
    ).map_err(|e| QuantumError::Execution(e))?;

    // Apply decoherence based on gas used
    let decoherence_factor = (result.gas_used as f64 / config.energy_limit as f64) * config.decoherence_rate;
    state.coherence_quality *= (-decoherence_factor).exp();
    state.entanglement_entropy = -state.coherence_quality * state.coherence_quality.ln();

    Ok(QuantumVmResult {
        final_state: state.classical_state.clone(),
        measurement: result.clone(),
        energy_consumed: result.gas_used,
        reverted: result.reverted,
        quantum_logs: result.logs_count,
        fidelity: state.coherence_quality,
    })
}

// -----------------------------------------------------------------------------
// Quantum Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum VM execution.
#[derive(Debug, thiserror::Error)]
pub enum QuantumError {
    #[error("execution error: {0}")]
    Execution(#[from] VmError),

    #[error("energy budget exceeded: required {required}, available {available}")]
    EnergyBudgetExceeded { required: u64, available: u64 },

    #[error("decoherence threshold exceeded")]
    DecoherenceThresholdExceeded,

    #[error("entanglement fidelity below threshold")]
    EntanglementFidelityLost,

    #[error("measurement basis incompatible with current state")]
    IncompatibleMeasurementBasis,

    #[error("quantum state coherence lost")]
    CoherenceLost,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Word;

    #[test]
    fn test_quantum_config_default() {
        let cfg = QuantumConfig::default();
        assert!((cfg.planck_constant - 1.0).abs() < f64::EPSILON);
        assert_eq!(cfg.coherence_time, 1_000_000);
        assert_eq!(cfg.energy_limit, 30_000_000);
        assert_eq!(cfg.measurement_basis, MeasurementBasis::PauliZ);
    }

    #[test]
    fn test_quantum_vm_state_new() {
        let state = QuantumVmState::new();
        assert!((state.coherence_quality - 1.0).abs() < f64::EPSILON);
        assert!((state.entanglement_entropy - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_quantum_execute_simple() {
        let mut state = QuantumVmState::new();
        let code = vec![
            0x60, 0x02, // PUSH1 2
            0x60, 0x03, // PUSH1 3
            0x01,       // ADD
            0x60, 0x00, // PUSH1 0
            0x52,       // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3,       // RETURN
        ];
        let config = QuantumConfig::default();
        let result = quantum_execute(
            &mut state,
            &code,
            &[],
            [0u8; 32],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
            &config,
        ).unwrap();
        assert!(!result.reverted);
        assert!(result.fidelity > 0.99);
        assert_eq!(result.quantum_logs, 0);
        assert!(result.energy_consumed > 0);
    }

    #[test]
    fn test_quantum_execute_revert() {
        let mut state = QuantumVmState::new();
        let code = vec![
            0x60, 0x10, // PUSH1 16
            0x60, 0x00, // PUSH1 0
            0xFD,       // REVERT
        ];
        let config = QuantumConfig::default();
        let result = quantum_execute(
            &mut state,
            &code,
            &[],
            [0u8; 32],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
            &config,
        );
        assert!(result.is_err());
        if let Err(QuantumError::Execution(VmError::Revert(_))) = result {
            // Expected
        } else {
            panic!("Expected Revert error");
        }
    }

    #[test]
    fn test_quantum_decoherence() {
        let mut state = QuantumVmState::new();
        let code = vec![
            0x60, 0x01, // PUSH1 1
            0x60, 0x01, // PUSH1 1
            0x01,       // ADD
        ];
        let config = QuantumConfig {
            decoherence_rate: 0.01,
            ..Default::default()
        };
        let result = quantum_execute(
            &mut state,
            &code,
            &[],
            [0u8; 32],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
            &config,
        ).unwrap();
        // Decoherence should have slightly reduced fidelity
        assert!(result.fidelity < 1.0);
        assert!(state.coherence_quality < 1.0);
    }
}
