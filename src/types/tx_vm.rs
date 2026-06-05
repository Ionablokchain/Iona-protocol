//! VM transaction types for the IONA custom VM — Quantum-Ready.
//!
//! # Quantum VM Transaction Model
//!
//! Each VM transaction (Deploy/Call) is modelled as a **quantum state**
//! that evolves through validation. The transaction type determines the
//! **subspace** in the VM execution Hilbert space.
//!
//! # Mathematical Formalism
//!
//! ## Transaction State
//! ```text
//! |Tx⟩ = |type⟩ ⊗ |sender⟩ ⊗ |gas⟩ ⊗ |payload⟩
//! ```
//!
//! ## Hamiltonian for VM Validation
//! ```text
//! Ĥ_validate = Ĥ_gas + Ĥ_sender + Ĥ_payload
//!
//! Ĥ_gas     = Σ_g ω_g a†_g a_g                      (gas oscillator)
//! Ĥ_sender  = Σ_s E_s |sender_s⟩⟨sender_s|          (identity projector)
//! Ĥ_payload = Σ_p λ_p |valid_payload_p⟩⟨valid_payload_p|
//! ```
//!
//! ## Validation as Projective Measurement
//! ```text
//! Π_valid = Π_gas ⊗ Π_sender ⊗ Π_payload
//! P(valid) = ⟨Tx| Π_valid |Tx⟩ ∈ {0, 1}
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for VM transaction state.
const DEFAULT_VM_TX_COHERENCE: f64 = 1.0;

/// Decoherence rate per validation check.
const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per validation failure (stronger).
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum coherence threshold for valid transaction.
const MIN_VM_TX_COHERENCE: f64 = 0.99;

/// Kraus rank for VM transaction quantum channels.
const VM_TX_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Type aliases
// -----------------------------------------------------------------------------

/// 32‑byte contract address (derived from sender + nonce via Blake3).
/// This is a **quantum fingerprint** of the contract's identity.
pub type ContractAddr = [u8; 32];

// -----------------------------------------------------------------------------
// Quantum VM Transaction State
// -----------------------------------------------------------------------------

/// Quantum state of a VM transaction.
///
/// Tracks the density matrix properties during validation and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumVmTxState {
    /// Purity γ = Tr(ρ²) of the transaction state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the validation subsystem.
    pub validation_coherence: f64,
    /// Coherence of the payload (init_code/calldata).
    pub payload_coherence: f64,
    /// Number of validation checks performed.
    pub total_checks: u64,
    /// Number of validation failures.
    pub checks_failed: u64,
    /// Whether the transaction state is valid.
    pub is_valid: bool,
}

impl Default for QuantumVmTxState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_VM_TX_COHERENCE,
            entropy: 0.0,
            validation_coherence: DEFAULT_VM_TX_COHERENCE,
            payload_coherence: DEFAULT_VM_TX_COHERENCE,
            total_checks: 0,
            checks_failed: 0,
            is_valid: true,
        }
    }
}

impl QuantumVmTxState {
    /// Create a new quantum VM transaction state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a passed validation check — minor decoherence.
    pub fn record_pass(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a failed validation check — strong decoherence.
    pub fn record_failure(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        self.checks_failed = self.checks_failed.wrapping_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply payload-related decoherence (for size/complexity).
    pub fn apply_payload_decoherence(&mut self, payload_size: usize) {
        let decay = (-VALIDATION_DECOHERENCE_RATE * payload_size as f64).exp();
        self.payload_coherence = (self.payload_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for VM transaction operations.
    pub fn apply_vm_tx_channel(&mut self) {
        let kraus_factor = (1.0 / VM_TX_KRAUS_RANK as f64).sqrt();
        self.validation_coherence = (self.validation_coherence * kraus_factor).clamp(0.0, 1.0);
        self.payload_coherence = (self.payload_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.validation_coherence * self.payload_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_VM_TX_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating a VM transaction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VmTxError {
    #[error("gas limit must be > 0, got {0}")]
    ZeroGasLimit(u64),

    #[error("init code cannot be empty for deployment")]
    EmptyInitCode,

    #[error("sender address cannot be empty")]
    EmptySender,

    #[error("contract address cannot be all zeroes")]
    ZeroContractAddress,

    #[error("quantum decoherence: vm tx coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type VmTxResult<T> = Result<T, VmTxError>;

// -----------------------------------------------------------------------------
// VM transaction enum
// -----------------------------------------------------------------------------

/// VM transaction types.
///
/// Each variant is a **quantum state** in the VM execution Hilbert space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VmTx {
    /// Deploy a new contract — creation operator a†.
    Deploy {
        /// Sender address (derived from public key, hex string).
        sender: String,
        /// Initialisation bytecode (constructor).
        init_code: Vec<u8>,
        /// Gas limit for the deployment.
        gas_limit: u64,
        /// Quantum coherence of this transaction.
        #[serde(default = "default_coherence")]
        coherence: f64,
    },
    /// Call an existing contract — measurement operator.
    Call {
        /// Sender address.
        sender: String,
        /// Contract address (32 bytes).
        contract: ContractAddr,
        /// Calldata (ABI‑encoded arguments).
        calldata: Vec<u8>,
        /// Gas limit for the call.
        gas_limit: u64,
        /// Quantum coherence of this transaction.
        #[serde(default = "default_coherence")]
        coherence: f64,
    },
}

fn default_coherence() -> f64 {
    DEFAULT_VM_TX_COHERENCE
}

impl VmTx {
    /// Returns the sender address.
    pub fn sender(&self) -> &str {
        match self {
            VmTx::Deploy { sender, .. } => sender,
            VmTx::Call { sender, .. } => sender,
        }
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            VmTx::Deploy { gas_limit, .. } => *gas_limit,
            VmTx::Call { gas_limit, .. } => *gas_limit,
        }
    }

    /// Returns the quantum coherence of this transaction.
    pub fn coherence(&self) -> f64 {
        match self {
            VmTx::Deploy { coherence, .. } => *coherence,
            VmTx::Call { coherence, .. } => *coherence,
        }
    }

    /// Returns `true` if this is a deployment transaction.
    pub fn is_deploy(&self) -> bool {
        matches!(self, VmTx::Deploy { .. })
    }

    /// Returns `true` if this is a call transaction.
    pub fn is_call(&self) -> bool {
        matches!(self, VmTx::Call { .. })
    }

    /// For deploy transactions: returns the init code.
    pub fn init_code(&self) -> Option<&[u8]> {
        match self {
            VmTx::Deploy { init_code, .. } => Some(init_code),
            VmTx::Call { .. } => None,
        }
    }

    /// For call transactions: returns the contract address.
    pub fn contract(&self) -> Option<&ContractAddr> {
        match self {
            VmTx::Call { contract, .. } => Some(contract),
            VmTx::Deploy { .. } => None,
        }
    }

    /// For call transactions: returns the calldata.
    pub fn calldata(&self) -> Option<&[u8]> {
        match self {
            VmTx::Call { calldata, .. } => Some(calldata),
            VmTx::Deploy { .. } => None,
        }
    }

    /// Validate the transaction.
    ///
    /// Performs a **projective measurement** that collapses the transaction
    /// state to either |valid⟩ or |invalid⟩.
    ///
    /// Checks:
    /// - Gas limit > 0
    /// - Sender not empty
    /// - For deploy: init code not empty
    /// - For call: contract address not all zeroes
    pub fn validate(&self) -> VmTxResult<()> {
        let mut qstate = QuantumVmTxState::new();

        // Gas limit check — oscillator ground state
        if self.gas_limit() == 0 {
            qstate.record_failure();
            return Err(VmTxError::ZeroGasLimit(self.gas_limit()));
        }
        qstate.record_pass();

        // Sender check — identity projector
        if self.sender().is_empty() {
            qstate.record_failure();
            return Err(VmTxError::EmptySender);
        }
        qstate.record_pass();

        // Payload checks — subspace projectors
        match self {
            VmTx::Deploy { init_code, .. } => {
                if init_code.is_empty() {
                    qstate.record_failure();
                    return Err(VmTxError::EmptyInitCode);
                }
                qstate.record_pass();
                qstate.apply_payload_decoherence(init_code.len());
            }
            VmTx::Call { contract, calldata, .. } => {
                if contract.iter().all(|&b| b == 0) {
                    qstate.record_failure();
                    return Err(VmTxError::ZeroContractAddress);
                }
                qstate.record_pass();
                qstate.apply_payload_decoherence(calldata.len());
            }
        }

        qstate.apply_vm_tx_channel();
        Ok(())
    }

    /// Validate with quantum state tracking returned.
    ///
    /// Returns both the validation result and the quantum state after
    /// all checks have been performed.
    pub fn validate_quantum(&self) -> (VmTxResult<()>, QuantumVmTxState) {
        let result = self.validate();
        let mut qstate = QuantumVmTxState::new();

        match &result {
            Ok(_) => {
                // Simulate the validation path
                qstate.record_pass(); // gas
                qstate.record_pass(); // sender
                qstate.record_pass(); // payload
                match self {
                    VmTx::Deploy { init_code, .. } => {
                        qstate.apply_payload_decoherence(init_code.len());
                    }
                    VmTx::Call { calldata, .. } => {
                        qstate.apply_payload_decoherence(calldata.len());
                    }
                }
            }
            Err(_) => {
                qstate.record_failure();
            }
        }
        qstate.apply_vm_tx_channel();

        (result, qstate)
    }

    /// Compute the payload size for decoherence estimation.
    pub fn payload_size(&self) -> usize {
        match self {
            VmTx::Deploy { init_code, .. } => init_code.len(),
            VmTx::Call { calldata, .. } => calldata.len(),
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Fidelity
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two VM transaction states.
///
/// ```text
/// F = |⟨tx_a|tx_b⟩|²
/// ```
/// For deterministic comparison: F = 1.0 if structurally identical, 0.0 otherwise.
pub fn vm_tx_fidelity(a: &VmTx, b: &VmTx) -> f64 {
    if a.sender() == b.sender()
        && a.gas_limit() == b.gas_limit()
        && a.is_deploy() == b.is_deploy()
    {
        match (a, b) {
            (VmTx::Deploy { init_code: ic_a, .. }, VmTx::Deploy { init_code: ic_b, .. }) => {
                if ic_a == ic_b {
                    1.0
                } else {
                    0.0
                }
            }
            (VmTx::Call {
                contract: ct_a,
                calldata: cd_a,
                ..
            }, VmTx::Call {
                contract: ct_b,
                calldata: cd_b,
                ..
            }) => {
                if ct_a == ct_b && cd_a == cd_b {
                    1.0
                } else {
                    0.0
                }
            }
            _ => 0.0,
        }
    } else {
        0.0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_deploy() -> VmTx {
        VmTx::Deploy {
            sender: "alice".into(),
            init_code: vec![0x60, 0x00, 0x00],
            gas_limit: 100_000,
            coherence: 1.0,
        }
    }

    fn valid_call() -> VmTx {
        VmTx::Call {
            sender: "bob".into(),
            contract: [1u8; 32],
            calldata: vec![0x01, 0x02],
            gas_limit: 200_000,
            coherence: 1.0,
        }
    }

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_validate_ok() {
        assert!(valid_deploy().validate().is_ok());
        assert!(valid_call().validate().is_ok());
    }

    #[test]
    fn test_zero_gas_limit() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { gas_limit, .. } = &mut tx {
            *gas_limit = 0;
        }
        assert!(matches!(tx.validate(), Err(VmTxError::ZeroGasLimit(0))));
    }

    #[test]
    fn test_empty_sender() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { sender, .. } = &mut tx {
            sender.clear();
        }
        assert!(matches!(tx.validate(), Err(VmTxError::EmptySender)));
    }

    #[test]
    fn test_empty_init_code() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        assert!(matches!(tx.validate(), Err(VmTxError::EmptyInitCode)));
    }

    #[test]
    fn test_zero_contract_address() {
        let mut tx = valid_call();
        if let VmTx::Call { contract, .. } = &mut tx {
            *contract = [0u8; 32];
        }
        assert!(matches!(tx.validate(), Err(VmTxError::ZeroContractAddress)));
    }

    #[test]
    fn test_accessors() {
        let deploy = valid_deploy();
        assert_eq!(deploy.sender(), "alice");
        assert_eq!(deploy.gas_limit(), 100_000);
        assert!(deploy.is_deploy());
        assert!(!deploy.is_call());
        assert_eq!(deploy.init_code(), Some(&[0x60, 0x00, 0x00][..]));
        assert!(deploy.contract().is_none());
        assert!(deploy.calldata().is_none());
        assert!((deploy.coherence() - 1.0).abs() < 1e-10);

        let call = valid_call();
        assert_eq!(call.sender(), "bob");
        assert_eq!(call.gas_limit(), 200_000);
        assert!(call.is_call());
        assert!(!call.is_deploy());
        assert_eq!(call.contract(), Some(&[1u8; 32]));
        assert_eq!(call.calldata(), Some(&[0x01, 0x02][..]));
        assert!(call.init_code().is_none());
        assert!((call.coherence() - 1.0).abs() < 1e-10);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumVmTxState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_record_pass_decoheres() {
        let mut state = QuantumVmTxState::new();
        let initial_purity = state.purity;

        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_checks, 1);
    }

    #[test]
    fn test_record_failure_stronger_decoherence() {
        let mut state1 = QuantumVmTxState::new();
        let mut state2 = QuantumVmTxState::new();

        state1.record_pass();
        state2.record_failure();

        assert!(state2.purity < state1.purity);
        assert_eq!(state2.checks_failed, 1);
    }

    #[test]
    fn test_payload_decoherence() {
        let mut state = QuantumVmTxState::new();
        let initial_payload_coh = state.payload_coherence;

        state.apply_payload_decoherence(1000);
        assert!(state.payload_coherence < initial_payload_coh);
    }

    #[test]
    fn test_vm_tx_channel() {
        let mut state = QuantumVmTxState::new();
        let initial_val_coh = state.validation_coherence;

        state.apply_vm_tx_channel();
        assert!(state.validation_coherence < initial_val_coh);
    }

    #[test]
    fn test_validate_quantum_ok() {
        let tx = valid_deploy();
        let (result, qstate) = tx.validate_quantum();
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
        assert!(qstate.purity < 1.0);
    }

    #[test]
    fn test_validate_quantum_failure() {
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        let (result, qstate) = tx.validate_quantum();
        assert!(result.is_err());
        assert!(qstate.checks_failed > 0);
        assert!(qstate.purity < 1.0);
    }

    #[test]
    fn test_vm_tx_fidelity_identical() {
        let tx1 = valid_deploy();
        let tx2 = valid_deploy();
        assert!((vm_tx_fidelity(&tx1, &tx2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_vm_tx_fidelity_different() {
        let tx1 = valid_deploy();
        let mut tx2 = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx2 {
            *init_code = vec![0xFF];
        }
        assert!((vm_tx_fidelity(&tx1, &tx2) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_vm_tx_fidelity_different_types() {
        let deploy = valid_deploy();
        let call = valid_call();
        assert!((vm_tx_fidelity(&deploy, &call) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_payload_size() {
        let deploy = valid_deploy();
        assert_eq!(deploy.payload_size(), 3);

        let call = valid_call();
        assert_eq!(call.payload_size(), 2);
    }

    #[test]
    fn test_health_after_many_failures() {
        let mut state = QuantumVmTxState::new();
        assert!(state.is_valid);

        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumVmTxState::new();
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }
}
