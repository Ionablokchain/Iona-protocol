//! IONA consensus engine and supporting modules — Production‑Grade.
//!
//! This module implements a Tendermint‑style BFT consensus engine with:
//! - Round‑robin proposer selection
//! - Prevote / Precommit voting
//! - Double‑sign protection (persistent guard)
//! - Fast finality (optimistic single‑round commit)
//! - Quorum calculators and diagnostics
//! - Validator set management
//! - Quantum state tracking across all consensus phases
//!
//! # Quantum Consensus Architecture
//!
//! The consensus engine is modelled as an **open quantum system** where
//! each validator's state exists in a superposition of vote intentions.
//! The BFT algorithm is a **quantum error correction code** that projects
//! the system onto the |committed⟩ eigenstate when 2/3+ validators agree.
//!
//! # Mathematical Formalism
//!
//! ## Hamiltonian for BFT Consensus
//! ```text
//! Ĥ = Ĥ_propose + Ĥ_prevote + Ĥ_precommit + Ĥ_commit + Ĥ_timeout + Ĥ_evidence
//!
//! Ĥ_propose   = ω_p a†_p a_p
//! Ĥ_prevote   = Σ_i g_i (|prevoted_i⟩⟨nil_i| + h.c.)
//! Ĥ_precommit = Σ_j h_j (|precommitted_j⟩⟨nil_j| + h.c.)
//! Ĥ_commit    = E_c |committed⟩⟨committed|
//! Ĥ_timeout   = Σ_k γ_k (n̂_k + ½)
//! Ĥ_evidence  = Σ_e λ_e |equivocation_e⟩⟨equivocation_e|
//! ```
//!
//! ## Lindblad Master Equation
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_l γ_l (L_l ρ L_l† - ½{L_l† L_l, ρ})
//! ```
//! where L_l are Lindblad operators for network decoherence, timeouts,
//! and double‑sign detection.
//!
//! # Module Overview
//!
//! | Module | Purpose | Quantum Analog |
//! |--------|---------|----------------|
//! | `engine` | BFT state machine | Hamiltonian evolution |
//! | `messages` | Proposal/Vote types | Quantum states |
//! | `double_sign` | Equivocation protection | Entanglement witness |
//! | `fast_finality` | Sub‑second commits | Projective measurement |
//! | `quorum` | Vote counting | Expectation value ⟨Q̂⟩ |
//! | `diagnostic` | Stall detection | Quantum state tomography |
//! | `validator_set` | Validator management | Basis state enumeration |
//! | `block_producer` | Block creation | State preparation |
//! | `debug_trace` | Event tracing | Measurement record |
//! | `genesis` | Chain initialisation | Ground state |∅⟩ |
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
// Re‑exports – core consensus types
// -----------------------------------------------------------------------------

pub use block_producer::*;
pub use debug_trace::*;
pub use diagnostic::*;
pub use double_sign::*;
pub use engine::*;
pub use fast_finality::*;
pub use genesis::*;
pub use messages::*;
pub use quorum::*;
pub use quorum_diag::*;
pub use validator_set::*;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Minimum quorum threshold (2/3).
pub const QUORUM_NUMERATOR: u64 = 2;
pub const QUORUM_DENOMINATOR: u64 = 3;

/// Minimum coherence for healthy consensus.
pub const MIN_CONSENSUS_COHERENCE: f64 = 0.9;

/// Kraus rank for consensus quantum channels.
pub const KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Consensus Statistics
// -----------------------------------------------------------------------------

/// Aggregated statistics across all consensus components.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ConsensusStats {
    /// Total blocks committed.
    pub blocks_committed: u64,
    /// Total rounds advanced.
    pub rounds_advanced: u64,
    /// Total proposals made (by this node).
    pub proposals_made: u64,
    /// Total proposals received.
    pub proposals_received: u64,
    /// Total prevotes cast (by this node).
    pub prevotes_cast: u64,
    /// Total prevotes received.
    pub prevotes_received: u64,
    /// Total precommits cast (by this node).
    pub precommits_cast: u64,
    /// Total precommits received.
    pub precommits_received: u64,
    /// Total timeouts experienced.
    pub timeouts: u64,
    /// Total double‑sign detections.
    pub double_sign_detections: u64,
    /// Total evidence messages processed.
    pub evidence_processed: u64,
    /// Current consensus quantum purity.
    pub quantum_purity: f64,
    /// Current consensus entropy.
    pub quantum_entropy: f64,
    /// Whether consensus is in a healthy quantum state.
    pub is_quantum_healthy: bool,
}

// -----------------------------------------------------------------------------
// Prelude – convenient import of common consensus items
// -----------------------------------------------------------------------------

/// Prelude for the consensus module.
pub mod prelude {
    pub use super::block_producer::{ProducerConfig, SimpleBlockProducer};
    pub use super::debug_trace::{ConsensusEvent, ConsensusTracer, StateRootLog, StateRootLogEntry};
    pub use super::diagnostic::{
        diagnose, ConsensusDiagnostic, DiagnosticConfig, DiagnosticStats, StallReason,
    };
    pub use super::double_sign::{vote_guard_key, DoubleSignGuard, GuardStats};
    pub use super::engine::{BlockStore, CommitCertificate, Config, ConsensusState, Engine, Outbox, Step};
    pub use super::fast_finality::{FinalityCertificate, FinalityStats, FinalityTracker, PipelineState};
    pub use super::messages::{
        proposal_sign_bytes, vote_sign_bytes, sign_bytes_fidelity,
        ConsensusMsg, MessageStats, Proposal, Vote, VoteType,
    };
    pub use super::quorum::{quorum_threshold, QuorumCalculator, VoteTally};
    pub use super::quorum_diag::QuorumDiagnostic;
    pub use super::validator_set::{Validator, ValidatorSet};
    pub use super::{ConsensusStats, QUORUM_NUMERATOR, QUORUM_DENOMINATOR, MIN_CONSENSUS_COHERENCE};
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Compute the quorum threshold (2/3 + 1) for a given total voting power.
///
/// This is the projective measurement threshold:
/// ```text
/// Q = ⌊total × 2 / 3⌋ + 1
/// ```
#[must_use]
pub fn quorum_threshold(total_power: u64) -> u64 {
    if total_power == 0 {
        return 1;
    }
    (total_power * QUORUM_NUMERATOR / QUORUM_DENOMINATOR) + 1
}

/// Check if a given voting power meets the quorum threshold.
#[must_use]
pub fn has_quorum(voting_power: u64, total_power: u64) -> bool {
    voting_power >= quorum_threshold(total_power)
}

/// Compute the quantum purity from a set of vote coherences.
///
/// ```text
/// γ = (1/N) Σ_i coherence_i
/// ```
#[must_use]
pub fn compute_consensus_purity(coherences: &[f64]) -> f64 {
    if coherences.is_empty() {
        return 1.0;
    }
    let avg: f64 = coherences.iter().sum::<f64>() / coherences.len() as f64;
    avg.clamp(0.0, 1.0)
}

/// Compute the von Neumann entropy from purity.
///
/// ```text
/// S = -γ ln γ - (1-γ) ln(1-γ)
/// ```
#[must_use]
pub fn compute_consensus_entropy(purity: f64) -> f64 {
    if purity >= 1.0 || purity <= 0.0 {
        return 0.0;
    }
    -purity * purity.ln() - (1.0 - purity) * (1.0 - purity).ln()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quorum_threshold() {
        assert_eq!(quorum_threshold(0), 1);
        assert_eq!(quorum_threshold(1), 1);
        assert_eq!(quorum_threshold(3), 3); // 2 + 1
        assert_eq!(quorum_threshold(4), 3); // 2 + 1
        assert_eq!(quorum_threshold(100), 67); // 66 + 1
    }

    #[test]
    fn test_has_quorum() {
        assert!(!has_quorum(2, 4)); // need 3
        assert!(has_quorum(3, 4)); // exactly 3
        assert!(has_quorum(4, 4)); // all
    }

    #[test]
    fn test_compute_consensus_purity() {
        let coherences = vec![0.99, 0.98, 0.97];
        let purity = compute_consensus_purity(&coherences);
        assert!(purity > 0.9);
        assert!(purity <= 1.0);

        assert!((compute_consensus_purity(&[]) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_compute_consensus_entropy() {
        let entropy_pure = compute_consensus_entropy(1.0);
        assert!((entropy_pure - 0.0).abs() < 1e-10);

        let entropy_mixed = compute_consensus_entropy(0.5);
        assert!(entropy_mixed > 0.0);

        let entropy_zero = compute_consensus_entropy(0.0);
        assert!((entropy_zero - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_consensus_stats_default() {
        let stats = ConsensusStats::default();
        assert_eq!(stats.blocks_committed, 0);
        assert!((stats.quantum_purity - 0.0).abs() < 1e-10);
        assert!(!stats.is_quantum_healthy);
    }
}
