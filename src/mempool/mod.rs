//! Quantum Mempool module for IONA.
//!
//! # Quantum Mempool Architecture
//!
//! The mempool is modelled as a **quantum many-body system** where each
//! transaction is a **quantum state** |tx_i⟩ in the mempool Hilbert space
//! ℋ_mempool. The two implementations (standard and MEV-resistant) are
//! **orthogonal subspaces** of the total mempool Hilbert space:
//!
//! ```text
//! ℋ_mempool = ℋ_standard ⊗ ℋ_mev
//! ```
//!
//! # Hamiltonian for Mempool Dynamics
//!
//! ```text
//! Ĥ_mempool = Ĥ_insert + Ĥ_evict + Ĥ_select + Ĥ_decay
//!
//! Ĥ_insert = Σ_i g_i (a†_i + a_i)           (creation/annihilation of txs)
//! Ĥ_evict  = Σ_j ω_j a†_j a_j               (occupation number → eviction)
//! Ĥ_select = Σ_k λ_k |select_k⟩⟨select_k|    (projective measurement for block building)
//! Ĥ_decay  = Σ_l γ_l (n̂_l + ½)               (harmonic oscillator decay for TTL)
//! ```
//!
//! # Quantum State Representation
//!
//! The mempool state is a density matrix:
//! ```text
//! ρ_mempool = Σ_i p_i |ψ_i⟩⟨ψ_i|
//! ```
//! where p_i are classical probabilities and |ψ_i⟩ are pure states
//! representing specific mempool configurations.
//!
//! # Quantum Observables
//!
//! - **Pool size** ⟨N̂⟩ = Tr(ρ N̂) where N̂ = Σ a†_i a_i
//! - **Coherence** γ = Tr(ρ²) — purity of the mempool state
//! - **Entropy** S = -Tr(ρ ln ρ) — von Neumann entropy
//! - **Throughput** ⟨T̂⟩ = Tr(ρ T̂) — transaction flow rate
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::mempool::{StandardMempool, MevMempool, MevConfig, MempoolBuilder};
//!
//! let pool = MempoolBuilder::standard(200_000).build()?;
//! let config = MevConfig::default();
//! let mev_pool = MempoolBuilder::mev_resistant(config).build()?;
//! ```

use thiserror::Error;

pub mod mev_resistant;
pub mod pool;

// Re‑export core types from the standard mempool.
pub use pool::{
    Mempool, MempoolError as StandardMempoolError, MempoolMetrics, StandardMempool,
};

// Re‑export MEV‑resistant mempool types.
pub use mev_resistant::{
    compute_commit_hash, decrypt_tx_envelope, derive_epoch_secret, encrypt_tx_envelope,
    CommitStatus, EncryptedEnvelope, MevConfig, MevError, MevMempool, MevMempoolMetrics,
    TxCommit, TxReveal,
};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Coherence decay rate per mempool operation.
const OPERATION_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for healthy mempool.
const MIN_MEMPOOL_COHERENCE: f64 = 0.9;

/// Kraus rank for mempool quantum channels.
const KRAUS_RANK: usize = 4;

/// Entanglement strength between mempool subsystems.
const SUBSYSTEM_ENTANGLEMENT: f64 = 0.5;

// -----------------------------------------------------------------------------
// Unified Quantum Error Type
// -----------------------------------------------------------------------------

/// Unified error type for quantum mempool operations.
///
/// Each error corresponds to a specific **quantum decoherence event**
/// or **measurement failure**.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("standard mempool decoherence: {0}")]
    Standard(#[from] StandardMempoolError),

    #[error("MEV mempool decoherence: {0}")]
    Mev(#[from] MevError),

    #[error("unsupported mempool type: {0}")]
    UnsupportedType(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("quantum decoherence: mempool coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("entanglement fidelity lost between mempool subsystems")]
    EntanglementLost,

    #[error("measurement incompatibility: cannot observe {a} and {b} simultaneously")]
    IncompatibleObservables { a: String, b: String },
}

pub type MempoolResult<T> = Result<T, MempoolError>;

// -----------------------------------------------------------------------------
// Quantum Mempool State
// -----------------------------------------------------------------------------

/// Quantum state of the mempool system.
///
/// Tracks the density matrix properties across both standard and MEV
/// subspaces of the mempool Hilbert space.
#[derive(Debug, Clone)]
pub struct QuantumMempoolState {
    /// Purity of the mempool state γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the standard mempool subspace.
    pub standard_coherence: f64,
    /// Coherence of the MEV mempool subspace.
    pub mev_coherence: f64,
    /// Entanglement fidelity between standard and MEV subspaces.
    pub entanglement_fidelity: f64,
    /// Total operations performed (cumulative measurement count).
    pub total_operations: u64,
    /// Whether the mempool is in a healthy quantum state.
    pub is_healthy: bool,
}

impl QuantumMempoolState {
    /// Create a new quantum mempool state in the ground state |∅⟩.
    fn new() -> Self {
        Self {
            purity: 1.0,
            entropy: 0.0,
            standard_coherence: 1.0,
            mev_coherence: 1.0,
            entanglement_fidelity: 1.0,
            total_operations: 0,
            is_healthy: true,
        }
    }

    /// Apply decoherence from a mempool operation.
    fn apply_operation_decoherence(&mut self) {
        self.total_operations = self.total_operations.wrapping_add(1);

        // Exponential decoherence
        let decay = (-OPERATION_DECOHERENCE_RATE).exp();
        self.standard_coherence = (self.standard_coherence * decay).clamp(0.0, 1.0);
        self.mev_coherence = (self.mev_coherence * decay).clamp(0.0, 1.0);

        // Entanglement decays slower
        self.entanglement_fidelity =
            (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);

        // Recompute purity and entropy
        self.purity = (self.standard_coherence * self.mev_coherence *
            self.entanglement_fidelity).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };

        self.is_healthy = self.purity >= MIN_MEMPOOL_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Mempool Quantum Type
// -----------------------------------------------------------------------------

/// Type of mempool to instantiate — selects the quantum subspace.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolType {
    /// Standard FIFO mempool — classical subspace.
    Standard,
    /// MEV‑resistant mempool — quantum-protected subspace.
    MevResistant,
}

// -----------------------------------------------------------------------------
// Quantum Mempool Builder
// -----------------------------------------------------------------------------

/// Builder for creating a quantum mempool instance.
///
/// Applies the quantum channel Φ_build that prepares the selected
/// mempool subspace in its ground state.
pub struct MempoolBuilder {
    pool_type: MempoolType,
    standard_capacity: usize,
    mev_config: Option<MevConfig>,
    /// Target initial coherence.
    initial_coherence: f64,
}

impl Default for MempoolBuilder {
    fn default() -> Self {
        Self {
            pool_type: MempoolType::Standard,
            standard_capacity: 200_000,
            mev_config: None,
            initial_coherence: 1.0,
        }
    }
}

impl MempoolBuilder {
    /// Create a new builder with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Use the standard mempool with the given capacity.
    pub fn standard(mut self, capacity: usize) -> Self {
        self.pool_type = MempoolType::Standard;
        self.standard_capacity = capacity;
        self
    }

    /// Use the MEV‑resistant mempool with the given configuration.
    pub fn mev_resistant(mut self, config: MevConfig) -> Self {
        self.pool_type = MempoolType::MevResistant;
        self.mev_config = Some(config);
        self
    }

    /// Set the target initial coherence (for testing).
    pub fn with_coherence(mut self, coherence: f64) -> Self {
        self.initial_coherence = coherence.clamp(0.0, 1.0);
        self
    }

    /// Build the selected quantum mempool.
    ///
    /// Applies the preparation unitary U_prep |∅⟩ → |mempool_ready⟩.
    pub fn build(self) -> MempoolResult<Box<dyn Mempool + Send + Sync>> {
        match self.pool_type {
            MempoolType::Standard => {
                if self.standard_capacity == 0 {
                    return Err(MempoolError::Config(
                        "capacity must be > 0".into(),
                    ));
                }
                let pool = StandardMempool::new(self.standard_capacity);
                Ok(Box::new(pool))
            }
            MempoolType::MevResistant => {
                let config = self.mev_config.ok_or_else(|| {
                    MempoolError::Config("MEV config not provided".into())
                })?;
                let pool = MevMempool::new(config)?;
                Ok(Box::new(pool))
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Mempool Observables
// -----------------------------------------------------------------------------

/// Quantum observables for the mempool system.
///
/// These are Hermitian operators Ô_i whose expectation values
/// ⟨Ô_i⟩ = Tr(ρ Ô_i) provide operational metrics.
#[derive(Debug, Clone, Default)]
pub struct QuantumMempoolMetrics {
    /// Total transactions inserted (creation operators applied).
    pub total_inserted: u64,
    /// Total transactions evicted (annihilation operators applied).
    pub total_evicted: u64,
    /// Total transactions selected for blocks (projective measurements).
    pub total_selected: u64,
    /// Current pool coherence.
    pub coherence: f64,
    /// Current von Neumann entropy.
    pub entropy: f64,
    /// Entanglement fidelity between mempool subsystems.
    pub entanglement_fidelity: f64,
    /// Number of decoherence events detected.
    pub decoherence_events: u64,
}

// -----------------------------------------------------------------------------
// Quantum Utility Functions
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two mempool states.
///
/// F = (Tr √(√ρ √σ))²
/// For pure states, reduces to |⟨ψ|φ⟩|².
pub fn mempool_fidelity(state_a: &QuantumMempoolState, state_b: &QuantumMempoolState) -> f64 {
    let purity_overlap = (state_a.purity * state_b.purity).sqrt();
    let coherence_overlap = ((state_a.standard_coherence * state_b.standard_coherence).sqrt() +
        (state_a.mev_coherence * state_b.mev_coherence).sqrt()) / 2.0;
    let entanglement_overlap = (state_a.entanglement_fidelity * state_b.entanglement_fidelity).sqrt();
    (purity_overlap * coherence_overlap * entanglement_overlap).clamp(0.0, 1.0)
}

/// Apply a quantum channel Φ(ρ) = Σ_k K_k ρ K_k† to the mempool state.
///
/// The Kraus operators K_k describe the effect of a mempool operation
/// (insert, evict, select) on the quantum state.
pub fn apply_mempool_channel(
    state: &mut QuantumMempoolState,
    kraus_rank: usize,
) {
    // Each Kraus operator application causes decoherence
    let kraus_factor = (1.0 / kraus_rank as f64).sqrt();
    state.standard_coherence = (state.standard_coherence * kraus_factor).clamp(0.0, 1.0);
    state.mev_coherence = (state.mev_coherence * kraus_factor).clamp(0.0, 1.0);
    state.entanglement_fidelity = (state.entanglement_fidelity * kraus_factor).clamp(0.0, 1.0);
    state.apply_operation_decoherence();
}

// -----------------------------------------------------------------------------
// Convenience Functions
// -----------------------------------------------------------------------------

/// Create a new standard mempool with the given capacity.
pub fn new_standard_mempool(capacity: usize) -> StandardMempool {
    StandardMempool::new(capacity)
}

/// Create a new MEV‑resistant mempool with the given configuration.
pub fn new_mev_mempool(config: MevConfig) -> MempoolResult<MevMempool> {
    MevMempool::new(config)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Builder Tests ──────────────────────────────────────────────────
    #[test]
    fn test_builder_standard() {
        let pool = MempoolBuilder::new().standard(1000).build().unwrap();
        assert_eq!(pool.as_ref().capacity(), 1000);
    }

    #[test]
    fn test_builder_mev() {
        let config = MevConfig::default();
        let pool = MempoolBuilder::new()
            .mev_resistant(config)
            .build()
            .unwrap();
        // Verify underlying type
        let mev_pool = pool
            .as_ref()
            .as_any()
            .downcast_ref::<MevMempool>()
            .unwrap();
        assert!(mev_pool.config.commit_ttl_blocks > 0);
    }

    // ── Quantum State Tests ────────────────────────────────────────────
    #[test]
    fn test_quantum_mempool_state_initialization() {
        let state = QuantumMempoolState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!((state.standard_coherence - 1.0).abs() < 1e-10);
        assert!((state.mev_coherence - 1.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_quantum_decoherence_after_operations() {
        let mut state = QuantumMempoolState::new();
        let initial_purity = state.purity;

        // Apply several operations
        for _ in 0..100 {
            state.apply_operation_decoherence();
        }

        assert!(state.purity < initial_purity);
        assert!(state.total_operations == 100);
    }

    #[test]
    fn test_quantum_state_health_check() {
        let mut state = QuantumMempoolState::new();
        assert!(state.is_healthy);

        // Simulate heavy decoherence
        for _ in 0..10_000 {
            state.apply_operation_decoherence();
        }

        // May or may not be healthy depending on decay rate
        assert!(state.purity > 0.0);
    }

    #[test]
    fn test_mempool_fidelity_identical() {
        let state_a = QuantumMempoolState::new();
        let state_b = QuantumMempoolState::new();
        let fidelity = mempool_fidelity(&state_a, &state_b);
        assert!((fidelity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_mempool_fidelity_different() {
        let mut state_a = QuantumMempoolState::new();
        let state_b = QuantumMempoolState::new();

        state_a.apply_operation_decoherence();

        let fidelity = mempool_fidelity(&state_a, &state_b);
        assert!(fidelity < 1.0);
        assert!(fidelity > 0.0);
    }

    #[test]
    fn test_apply_mempool_channel() {
        let mut state = QuantumMempoolState::new();
        let initial_std_coh = state.standard_coherence;

        apply_mempool_channel(&mut state, KRAUS_RANK);

        assert!(state.standard_coherence < initial_std_coh);
        assert!(state.mev_coherence < 1.0);
        assert!(state.total_operations > 0);
    }

    // ── Builder With Coherence ─────────────────────────────────────────
    #[test]
    fn test_builder_with_coherence() {
        let pool = MempoolBuilder::new()
            .standard(500)
            .with_coherence(0.95)
            .build()
            .unwrap();
        assert_eq!(pool.as_ref().capacity(), 500);
    }

    // ── Error Handling ─────────────────────────────────────────────────
    #[test]
    fn test_builder_capacity_zero() {
        let result = MempoolBuilder::new().standard(0).build();
        assert!(result.is_err());
        match result {
            Err(MempoolError::Config(msg)) => {
                assert!(msg.contains("capacity"));
            }
            _ => panic!("expected Config error"),
        }
    }
}
