//! IONA consensus engine and supporting modules — Quantum Architecture.
//!
//! # Quantum Consensus Model
//!
//! The consensus engine is modeled as an **open quantum system** where
//! each validator exists in a superposition of voting states and the
//! collective decision emerges from entanglement-based measurements.
//!
//! # Mathematical Formalism
//!
//! ## State Representation
//! ```text
//! |Ψ_consensus⟩ = |height⟩ ⊗ |round⟩ ⊗ (⊗_i |validator_i⟩) ⊗ |proposal⟩
//! ```
//!
//! ## Hamiltonian
//! ```text
//! Ĥ = Ĥ_propose + Ĥ_prevote + Ĥ_precommit + Ĥ_commit + Ĥ_timeout
//! ```
//!
//! ## Evolution
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_k γ_k (L_k ρ L_k† - ½{L_k† L_k, ρ})
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::{Engine, Config, ValidatorSet};
//!
//! let config = Config::default();
//! let vset = ValidatorSet::default();
//! let engine = Engine::new(config, vset, 1, Hash32::zero(), …);
//! ```

pub mod block_producer;
pub mod debug_trace;
pub mod diagnostic;
pub mod double_sign;
pub mod engine;
pub mod fast_finality;
pub mod genesis;
pub mod messages;
pub mod quorum;
pub mod quorum_diag;
pub mod validator_set;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
pub const HBAR: f64 = 1.0;

/// Default quantum coherence for consensus states.
pub const DEFAULT_COHERENCE: f64 = 1.0;

/// Decoherence rate per consensus step.
pub const STEP_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for healthy consensus.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

// -----------------------------------------------------------------------------
// Quantum Consensus State (shared across modules)
// -----------------------------------------------------------------------------

/// Quantum state tracker for consensus operations.
///
/// Provides purity, entropy, and coherence metrics that are updated
/// by the engine and supporting modules.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumConsensusState {
    /// Purity γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Step coherence (propose/prevote/precommit/commit).
    pub step_coherence: f64,
    /// Entanglement fidelity with validator set.
    pub validator_entanglement: f64,
    /// Total step transitions.
    pub total_transitions: u64,
    /// Total quorum measurements.
    pub total_quorums: u64,
    /// Total timeouts.
    pub total_timeouts: u64,
    /// Whether consensus is healthy.
    pub is_healthy: bool,
}

impl Default for QuantumConsensusState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_COHERENCE,
            entropy: 0.0,
            step_coherence: DEFAULT_COHERENCE,
            validator_entanglement: DEFAULT_COHERENCE,
            total_transitions: 0,
            total_quorums: 0,
            total_timeouts: 0,
            is_healthy: true,
        }
    }
}

impl QuantumConsensusState {
    /// Create a new quantum state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a step transition.
    pub fn apply_step_decoherence(&mut self) {
        self.total_transitions = self.total_transitions.wrapping_add(1);
        let decay = (-STEP_DECOHERENCE_RATE).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.validator_entanglement = (self.validator_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a timeout.
    pub fn apply_timeout_decoherence(&mut self) {
        self.total_timeouts = self.total_timeouts.wrapping_add(1);
        let decay = (-STEP_DECOHERENCE_RATE * 5.0).exp();
        self.step_coherence = (self.step_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a quorum measurement.
    pub fn apply_quorum_decoherence(&mut self) {
        self.total_quorums = self.total_quorums.wrapping_add(1);
        let kraus_factor = 0.5f64.sqrt();
        self.step_coherence = (self.step_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.step_coherence * self.validator_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_CONSENSUS_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Re‑exports – core consensus types
// -----------------------------------------------------------------------------

pub use block_producer::*;
pub use diagnostic::*;
pub use double_sign::*;
pub use engine::*;
pub use fast_finality::*;
pub use messages::*;
pub use quorum::*;
pub use validator_set::*;

// -----------------------------------------------------------------------------
// Prelude – convenient import of common consensus items
// -----------------------------------------------------------------------------

/// Prelude for the consensus module.
pub mod prelude {
    pub use super::{
        Config, ConsensusMsg, Engine, Proposal, QuorumCalculator, Validator, ValidatorSet, Vote,
        VoteType,
    };
    pub use super::diagnostic::{diagnose, ConsensusDiagnostic, StallReason};
    pub use super::double_sign::{vote_guard_key, DoubleSignGuard};
    pub use super::fast_finality::{FinalityStats, FinalityTracker, PipelineState};
    pub use super::QuantumConsensusState;
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quantum_consensus_state_initialization() {
        let state = QuantumConsensusState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_step_decoherence() {
        let mut state = QuantumConsensusState::new();
        let initial_purity = state.purity;

        state.apply_step_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_transitions, 1);
    }

    #[test]
    fn test_timeout_decoherence_stronger() {
        let mut state = QuantumConsensusState::new();
        state.apply_step_decoherence();
        let after_step = state.purity;

        let mut state2 = QuantumConsensusState::new();
        state2.apply_timeout_decoherence();
        assert!(state2.purity < after_step);
        assert_eq!(state2.total_timeouts, 1);
    }

    #[test]
    fn test_quorum_decoherence() {
        let mut state = QuantumConsensusState::new();
        let initial_purity = state.purity;

        state.apply_quorum_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_quorums, 1);
    }

    #[test]
    fn test_health_check() {
        let mut state = QuantumConsensusState::new();
        assert!(state.is_healthy);

        // Apply many decoherence events
        for _ in 0..1000 {
            state.apply_step_decoherence();
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumConsensusState::new();
        for _ in 0..10000 {
            state.apply_timeout_decoherence();
        }
        assert!(state.purity >= 0.0);
    }
}
