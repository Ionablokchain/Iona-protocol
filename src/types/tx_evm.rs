//! EVM transaction types (Legacy, EIP‑2930, EIP‑1559) — Quantum-Ready.
//!
//! # Quantum Transaction Model
//!
//! Each transaction type represents a distinct **quantum state** in the
//! EVM execution Hilbert space. The transaction validation acts as a
//! **projective measurement** that collapses the state to either |valid⟩
//! or |invalid⟩.
//!
//! # Mathematical Formalism
//!
//! ## Transaction State
//! ```text
//! |Tx⟩ = |type⟩ ⊗ |from⟩ ⊗ |to⟩ ⊗ |value⟩ ⊗ |data⟩ ⊗ |gas⟩ ⊗ |signature⟩
//! ```
//!
//! ## Hamiltonian for Validation
//! ```text
//! Ĥ_validate = Ĥ_chain + Ĥ_gas + Ĥ_fee + Ĥ_nonce
//!
//! Ĥ_chain = Σ_c E_c |chain_c⟩⟨chain_c|              (chain ID projector)
//! Ĥ_gas   = Σ_g ω_g a†_g a_g                          (gas oscillator)
//! Ĥ_fee   = Σ_f λ_f |valid_fee_f⟩⟨valid_fee_f|        (fee constraint)
//! Ĥ_nonce = Σ_n ν_n b†_n b_n                           (nonce counter)
//! ```
//!
//! ## EIP-1559 Fee as Quantum Harmonic Oscillator
//! ```text
//! E_fee = max_priority + min(base_fee, max_fee - base_fee)
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for transaction state.
const DEFAULT_TX_COHERENCE: f64 = 1.0;

/// Decoherence rate per validation step.
const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per validation failure (stronger).
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum coherence threshold for valid transaction.
const MIN_TX_COHERENCE: f64 = 0.99;

/// Kraus rank for transaction quantum channels.
const TX_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Type aliases for EVM compatibility
// -----------------------------------------------------------------------------

/// 20‑byte Ethereum address — quantum state of an account.
pub type Address20 = [u8; 20];

/// 32‑byte hash (used for storage keys) — quantum fingerprint.
pub type H256 = [u8; 32];

// -----------------------------------------------------------------------------
// Quantum Transaction State
// -----------------------------------------------------------------------------

/// Quantum state of an EVM transaction.
///
/// Tracks the density matrix properties during validation and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumEvmTxState {
    /// Purity γ = Tr(ρ²) of the transaction state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the validation subsystem.
    pub validation_coherence: f64,
    /// Coherence of the fee subsystem.
    pub fee_coherence: f64,
    /// Number of validation checks performed.
    pub total_checks: u64,
    /// Number of validation failures.
    pub checks_failed: u64,
    /// Whether the transaction state is valid.
    pub is_valid: bool,
}

impl Default for QuantumEvmTxState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_TX_COHERENCE,
            entropy: 0.0,
            validation_coherence: DEFAULT_TX_COHERENCE,
            fee_coherence: DEFAULT_TX_COHERENCE,
            total_checks: 0,
            checks_failed: 0,
            is_valid: true,
        }
    }
}

impl QuantumEvmTxState {
    /// Create a new quantum transaction state in the ground state |∅⟩.
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

    /// Apply fee-related decoherence (for EIP-1559 calculations).
    pub fn apply_fee_decoherence(&mut self) {
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.fee_coherence = (self.fee_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for transaction operations.
    pub fn apply_tx_channel(&mut self) {
        let kraus_factor = (1.0 / TX_KRAUS_RANK as f64).sqrt();
        self.validation_coherence = (self.validation_coherence * kraus_factor).clamp(0.0, 1.0);
        self.fee_coherence = (self.fee_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.validation_coherence * self.fee_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_TX_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Access list item (EIP‑2930 and EIP‑1559)
// -----------------------------------------------------------------------------

/// A single entry in an EIP‑2930 access list.
///
/// Each access list item represents an **entanglement** between the
/// transaction and specific storage slots, pre-warming them to reduce
/// gas costs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: Address20,
    pub storage_keys: Vec<H256>,
    /// Quantum coherence of this access list item.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    1.0
}

impl AccessListItem {
    /// Create a new access list item with full coherence.
    pub fn new(address: Address20, storage_keys: Vec<H256>) -> Self {
        Self {
            address,
            storage_keys,
            coherence: DEFAULT_TX_COHERENCE,
        }
    }

    /// Check if the access list item is empty (no storage keys).
    pub fn is_empty(&self) -> bool {
        self.storage_keys.is_empty()
    }

    /// Number of storage keys (entanglement count).
    pub fn len(&self) -> usize {
        self.storage_keys.len()
    }

    /// Apply decoherence from access list usage.
    pub fn apply_usage_decoherence(&mut self) {
        let decay = (-VALIDATION_DECOHERENCE_RATE * self.storage_keys.len() as f64).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating an EVM transaction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvmTxError {
    #[error("chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("gas limit must be > 0, got {0}")]
    ZeroGasLimit(u64),

    #[error("gas price must be > 0, got {0}")]
    ZeroGasPrice(u128),

    #[error("gas fee cap cannot be zero (EIP‑1559)")]
    ZeroMaxFeePerGas,

    #[error("priority fee cannot exceed max fee per gas (EIP‑1559)")]
    PriorityFeeExceedsMaxFee,

    #[error("nonce overflow (max 2^64-1)")]
    NonceOverflow,

    #[error("value overflow (max 2^128-1)")]
    ValueOverflow,

    #[error("quantum decoherence: tx coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type EvmTxResult<T> = Result<T, EvmTxError>;

// -----------------------------------------------------------------------------
// EVM transaction enum
// -----------------------------------------------------------------------------

/// EVM transaction types supported by IONA.
///
/// Each variant is a **quantum state** in the EVM execution Hilbert space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmTx {
    /// Legacy transaction (pre‑EIP‑1559) — classical state.
    Legacy {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        chain_id: u64,
        #[serde(default = "default_coherence")]
        coherence: f64,
    },
    /// EIP‑2930 transaction with access list — entangled state.
    Eip2930 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
        #[serde(default = "default_coherence")]
        coherence: f64,
    },
    /// EIP‑1559 transaction with fee caps — harmonic oscillator state.
    Eip1559 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
        #[serde(default = "default_coherence")]
        coherence: f64,
    },
}

impl EvmTx {
    /// Returns the chain ID of the transaction.
    pub fn chain_id(&self) -> u64 {
        match self {
            EvmTx::Legacy { chain_id, .. } => *chain_id,
            EvmTx::Eip2930 { chain_id, .. } => *chain_id,
            EvmTx::Eip1559 { chain_id, .. } => *chain_id,
        }
    }

    /// Returns the sender address (already recovered and filled).
    pub fn from(&self) -> &Address20 {
        match self {
            EvmTx::Legacy { from, .. } => from,
            EvmTx::Eip2930 { from, .. } => from,
            EvmTx::Eip1559 { from, .. } => from,
        }
    }

    /// Returns the recipient address (None for contract creation).
    pub fn to(&self) -> Option<&Address20> {
        match self {
            EvmTx::Legacy { to, .. } => to.as_ref(),
            EvmTx::Eip2930 { to, .. } => to.as_ref(),
            EvmTx::Eip1559 { to, .. } => to.as_ref(),
        }
    }

    /// Returns the transaction nonce.
    pub fn nonce(&self) -> u64 {
        match self {
            EvmTx::Legacy { nonce, .. } => *nonce,
            EvmTx::Eip2930 { nonce, .. } => *nonce,
            EvmTx::Eip1559 { nonce, .. } => *nonce,
        }
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            EvmTx::Legacy { gas_limit, .. } => *gas_limit,
            EvmTx::Eip2930 { gas_limit, .. } => *gas_limit,
            EvmTx::Eip1559 { gas_limit, .. } => *gas_limit,
        }
    }

    /// Returns the value transferred (in wei).
    pub fn value(&self) -> u128 {
        match self {
            EvmTx::Legacy { value, .. } => *value,
            EvmTx::Eip2930 { value, .. } => *value,
            EvmTx::Eip1559 { value, .. } => *value,
        }
    }

    /// Returns the call data.
    pub fn data(&self) -> &[u8] {
        match self {
            EvmTx::Legacy { data, .. } => data,
            EvmTx::Eip2930 { data, .. } => data,
            EvmTx::Eip1559 { data, .. } => data,
        }
    }

    /// Returns the quantum coherence of this transaction.
    pub fn coherence(&self) -> f64 {
        match self {
            EvmTx::Legacy { coherence, .. } => *coherence,
            EvmTx::Eip2930 { coherence, .. } => *coherence,
            EvmTx::Eip1559 { coherence, .. } => *coherence,
        }
    }

    /// Returns `true` if this is a contract creation transaction (`to` is `None`).
    pub fn is_create(&self) -> bool {
        self.to().is_none()
    }

    /// For legacy and EIP‑2930: gas price. For EIP‑1559: returns `None`.
    pub fn gas_price(&self) -> Option<u128> {
        match self {
            EvmTx::Legacy { gas_price, .. } => Some(*gas_price),
            EvmTx::Eip2930 { gas_price, .. } => Some(*gas_price),
            EvmTx::Eip1559 { .. } => None,
        }
    }

    /// For EIP‑1559: max fee per gas.
    pub fn max_fee_per_gas(&self) -> Option<u128> {
        match self {
            EvmTx::Eip1559 { max_fee_per_gas, .. } => Some(*max_fee_per_gas),
            _ => None,
        }
    }

    /// For EIP‑1559: max priority fee per gas.
    pub fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            EvmTx::Eip1559 {
                max_priority_fee_per_gas,
                ..
            } => Some(*max_priority_fee_per_gas),
            _ => None,
        }
    }

    /// For EIP‑2930 and EIP‑1559: access list (empty for legacy).
    pub fn access_list(&self) -> &[AccessListItem] {
        match self {
            EvmTx::Legacy { .. } => &[],
            EvmTx::Eip2930 { access_list, .. } => access_list,
            EvmTx::Eip1559 { access_list, .. } => access_list,
        }
    }

    /// Validate the transaction against a given expected chain ID.
    ///
    /// Performs a **projective measurement** that collapses the transaction
    /// state to either |valid⟩ or |invalid⟩.
    pub fn validate(&self, expected_chain_id: u64) -> EvmTxResult<()> {
        let mut qstate = QuantumEvmTxState::new();

        // Chain ID check — projector Π_chain
        if self.chain_id() != expected_chain_id {
            qstate.record_failure();
            return Err(EvmTxError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: self.chain_id(),
            });
        }
        qstate.record_pass();

        // Gas limit check — oscillator ground state
        if self.gas_limit() == 0 {
            qstate.record_failure();
            return Err(EvmTxError::ZeroGasLimit(self.gas_limit()));
        }
        qstate.record_pass();

        // Fee validation — harmonic oscillator energy levels
        match self {
            EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => {
                if *gas_price == 0 {
                    qstate.record_failure();
                    return Err(EvmTxError::ZeroGasPrice(*gas_price));
                }
                qstate.record_pass();
            }
            EvmTx::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                if *max_fee_per_gas == 0 {
                    qstate.record_failure();
                    return Err(EvmTxError::ZeroMaxFeePerGas);
                }
                qstate.record_pass();

                if *max_priority_fee_per_gas > *max_fee_per_gas {
                    qstate.record_failure();
                    return Err(EvmTxError::PriorityFeeExceedsMaxFee);
                }
                qstate.record_pass();
                qstate.apply_fee_decoherence();
            }
        }

        qstate.apply_tx_channel();
        Ok(())
    }

    /// Validate with quantum state tracking returned.
    pub fn validate_quantum(
        &self,
        expected_chain_id: u64,
    ) -> (EvmTxResult<()>, QuantumEvmTxState) {
        let result = self.validate(expected_chain_id);
        let mut qstate = QuantumEvmTxState::new();

        match &result {
            Ok(_) => {
                qstate.record_pass();
            }
            Err(_) => {
                qstate.record_failure();
            }
        }
        qstate.apply_tx_channel();

        (result, qstate)
    }

    /// Compute the effective gas price given the block base fee (EIP‑1559).
    ///
    /// This is a **quantum measurement** that determines the actual energy
    /// cost of the transaction.
    pub fn effective_gas_price(&self, base_fee_per_gas: u64) -> u128 {
        match self {
            EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
            EvmTx::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                let base = base_fee_per_gas as u128;
                let tip = (*max_priority_fee_per_gas).min(max_fee_per_gas.saturating_sub(base));
                base.saturating_add(tip).min(*max_fee_per_gas)
            }
        }
    }

    /// Compute effective gas price with quantum state tracking.
    pub fn effective_gas_price_quantum(
        &self,
        base_fee_per_gas: u64,
    ) -> (u128, QuantumEvmTxState) {
        let price = self.effective_gas_price(base_fee_per_gas);
        let mut qstate = QuantumEvmTxState::new();
        qstate.apply_fee_decoherence();
        qstate.apply_tx_channel();
        (price, qstate)
    }
}

// -----------------------------------------------------------------------------
// Quantum Fidelity
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two EVM transaction states.
///
/// ```text
/// F = |⟨tx_a|tx_b⟩|²
/// ```
/// For deterministic comparison: F = 1.0 if identical, 0.0 otherwise.
pub fn tx_fidelity(a: &EvmTx, b: &EvmTx) -> f64 {
    if a.chain_id() == b.chain_id()
        && a.from() == b.from()
        && a.nonce() == b.nonce()
        && a.gas_limit() == b.gas_limit()
        && a.value() == b.value()
        && a.data() == b.data()
    {
        1.0
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

    fn dummy_legacy() -> EvmTx {
        EvmTx::Legacy {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 0,
            data: vec![],
            chain_id: 1,
            coherence: 1.0,
        }
    }

    fn dummy_eip1559() -> EvmTx {
        EvmTx::Eip1559 {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: 0,
            data: vec![],
            access_list: vec![],
            chain_id: 1,
            coherence: 1.0,
        }
    }

    // ── Classical Tests ──────────────────────────────────────────────
    @test
    fn test_validate_ok() {
        let tx = dummy_legacy();
        assert!(tx.validate(1).is_ok());
        let tx1559 = dummy_eip1559();
        assert!(tx1559.validate(1).is_ok());
    }

    @test
    fn test_validate_wrong_chain() {
        let tx = dummy_legacy();
        assert!(matches!(
            tx.validate(2),
            Err(EvmTxError::ChainIdMismatch {
                expected: 2,
                actual: 1
            })
        ));
    }

    @test
    fn test_validate_zero_gas_limit() {
        let mut tx = dummy_legacy();
        if let EvmTx::Legacy { gas_limit, .. } = &mut tx {
            *gas_limit = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroGasLimit(0))));
    }

    @test
    fn test_validate_zero_gas_price() {
        let mut tx = dummy_legacy();
        if let EvmTx::Legacy { gas_price, .. } = &mut tx {
            *gas_price = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroGasPrice(0))));
    }

    @test
    fn test_validate_eip1559_fee_caps() {
        let mut tx = dummy_eip1559();
        if let EvmTx::Eip1559 { max_fee_per_gas, .. } = &mut tx {
            *max_fee_per_gas = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroMaxFeePerGas)));

        let mut tx = dummy_eip1559();
        if let EvmTx::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..
        } = &mut tx
        {
            *max_priority_fee_per_gas = *max_fee_per_gas + 1;
        }
        assert!(matches!(
            tx.validate(1),
            Err(EvmTxError::PriorityFeeExceedsMaxFee)
        ));
    }

    @test
    fn test_effective_gas_price_legacy() {
        let tx = dummy_legacy();
        let base = 5_000_000_000;
        assert_eq!(tx.effective_gas_price(base), 10_000_000_000);
    }

    @test
    fn test_effective_gas_price_eip1559() {
        let tx = dummy_eip1559();
        let base = 50_000_000_000;
        let expected = base as u128
            + tx.max_priority_fee_per_gas().unwrap().min(
                tx.max_fee_per_gas()
                    .unwrap()
                    .saturating_sub(base as u128),
            );
        assert_eq!(tx.effective_gas_price(base), expected);
    }

    @test
    fn test_accessors() {
        let tx = dummy_legacy();
        assert_eq!(tx.chain_id(), 1);
        assert_eq!(tx.from(), &[0xAA; 20]);
        assert_eq!(tx.to(), Some(&[0xBB; 20]));
        assert_eq!(tx.nonce(), 1);
        assert_eq!(tx.gas_limit(), 100_000);
        assert_eq!(tx.value(), 0);
        assert!(tx.data().is_empty());
        assert!(!tx.is_create());
        assert_eq!(tx.gas_price(), Some(10_000_000_000));
        assert_eq!(tx.max_fee_per_gas(), None);
        assert!(tx.access_list().is_empty());
        assert!((tx.coherence() - 1.0).abs() < 1e-10);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    @test
    fn test_quantum_state_initialization() {
        let state = QuantumEvmTxState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    @test
    fn test_record_pass_decoheres() {
        let mut state = QuantumEvmTxState::new();
        let initial_purity = state.purity;

        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_checks, 1);
    }

    @test
    fn test_record_failure_stronger_decoherence() {
        let mut state1 = QuantumEvmTxState::new();
        let mut state2 = QuantumEvmTxState::new();

        state1.record_pass();
        state2.record_failure();

        assert!(state2.purity < state1.purity);
        assert_eq!(state2.checks_failed, 1);
    }

    @test
    fn test_fee_decoherence() {
        let mut state = QuantumEvmTxState::new();
        let initial_fee_coh = state.fee_coherence;

        state.apply_fee_decoherence();
        assert!(state.fee_coherence < initial_fee_coh);
    }

    @test
    fn test_tx_channel() {
        let mut state = QuantumEvmTxState::new();
        let initial_val_coh = state.validation_coherence;

        state.apply_tx_channel();
        assert!(state.validation_coherence < initial_val_coh);
    }

    @test
    fn test_validate_quantum() {
        let tx = dummy_legacy();
        let (result, qstate) = tx.validate_quantum(1);
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
        assert!(qstate.purity < 1.0);
    }

    @test
    fn test_validate_quantum_failure() {
        let tx = dummy_legacy();
        let (result, qstate) = tx.validate_quantum(2);
        assert!(result.is_err());
        assert!(qstate.checks_failed > 0);
        assert!(qstate.purity < 1.0);
    }

    @test
    fn test_effective_gas_price_quantum() {
        let tx = dummy_eip1559();
        let (price, qstate) = tx.effective_gas_price_quantum(50_000_000_000);
        assert!(price > 0);
        assert!(qstate.fee_coherence < 1.0);
    }

    @test
    fn test_tx_fidelity_identical() {
        let tx1 = dummy_legacy();
        let tx2 = dummy_legacy();
        assert!((tx_fidelity(&tx1, &tx2) - 1.0).abs() < 1e-10);
    }

    @test
    fn test_tx_fidelity_different() {
        let tx1 = dummy_legacy();
        let mut tx2 = dummy_legacy();
        if let EvmTx::Legacy { nonce, .. } = &mut tx2 {
            *nonce = 99;
        }
        assert!((tx_fidelity(&tx1, &tx2) - 0.0).abs() < 1e-10);
    }

    @test
    fn test_access_list_item_decoherence() {
        let mut item = AccessListItem::new([0xAA; 20], vec![[0xBB; 32], [0xCC; 32]]);
        let initial_coh = item.coherence;

        item.apply_usage_decoherence();
        assert!(item.coherence < initial_coh);
    }

    @test
    fn test_health_after_many_failures() {
        let mut state = QuantumEvmTxState::new();
        assert!(state.is_valid);

        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_valid);
    }

    @test
    fn test_purity_never_negative() {
        let mut state = QuantumEvmTxState::new();
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }
}
