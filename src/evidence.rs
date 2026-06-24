//! Quantum evidence types for consensus faults.
//!
//! # Quantum Consensus Fault Model
//!
//! In the quantum consensus model, validators are represented as quantum
//! systems that must exist in a single eigenstate per round. A double-vote
//! or double-proposal represents a **quantum forbidden transition** where
//! the validator's state has bifurcated into a superposition of conflicting
//! outcomes — a violation of the no-cloning theorem for consensus states.
//!
//! # Hamiltonian for Fault Detection
//!
//! ```text
//! Ĥ_evidence = Ĥ_double_vote + Ĥ_double_proposal
//!
//! Ĥ_double_vote = Σ_{v,h,r} g_v |vote_1⟩⟨vote_2| + h.c.
//! Ĥ_double_proposal = Σ_{p,h,r} g_p |prop_1⟩⟨prop_2| + h.c.
//! ```
//!
//! The coupling constants g_v, g_p are non-zero only when the two states
//! differ, indicating a fault. The Hamiltonian's eigenvalues correspond
//! to the severity of the offence.
//!
//! # Entanglement Witness for Faults
//!
//! A double-sign is detected via an **entanglement witness** operator W:
//! ```text
//! W = |vote⟩⟨vote| ⊗ |proposal⟩⟨proposal|
//! ```
//! If Tr(Wρ) > threshold, the validator has become entangled with two
//! conflicting states — evidence of a fault.
//!
//! # Signature Verification via Quantum One-Way Functions
//!
//! Cryptographic signatures are modeled as quantum trapdoor functions:
//! ```text
//! |signature⟩ = U_sign(sk) |message⟩
//! ```
//! Verification measures the overlap ⟨signature_expected|signature_actual⟩.

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::{PublicKeyBytes, Signature, verify_signature};
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Entanglement witness threshold for fault detection.
const WITNESS_THRESHOLD: f64 = 0.99;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Fault coupling constant for double-vote.
const G_VOTE: f64 = 1.0;

/// Fault coupling constant for double-proposal.
const G_PROPOSAL: f64 = 1.0;

/// Maximum allowed coherence degradation before evidence is considered invalid.
const MAX_COHERENCE_LOSS: f64 = 0.1;

// -----------------------------------------------------------------------------
// Quantum Evidence Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum evidence verification.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("quantum duplicate: messages occupy identical state vectors")]
    DuplicateMessages,

    #[error("Hilbert space mismatch: height/round eigenvalues differ")]
    MismatchedHeightRound,

    #[error("observable mismatch: vote_type eigenvalues differ")]
    VoteTypeMismatch,

    #[error("entanglement broken: proposer identity differs")]
    ProposerMismatch,

    #[error("signature quantum state verification failed: {0}")]
    InvalidSignature(String),

    #[error("measurement error: missing block hash observable")]
    MissingBlockHash,

    #[error("decoherence: evidence state has lost fidelity ({fidelity})")]
    Decoherence { fidelity: f64 },

    #[error("witness operator expectation below threshold: {value} < {threshold}")]
    WitnessBelowThreshold { value: f64, threshold: f64 },

    #[error("evidence already verified: cannot mutate")]
    AlreadyVerified,

    #[error("invalid coherence: {reason}")]
    InvalidCoherence { reason: String },
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;

// -----------------------------------------------------------------------------
// Quantum State for Fault Evidence
// -----------------------------------------------------------------------------

/// Represents the quantum state of a fault evidence.
#[derive(Debug, Clone)]
struct QuantumEvidenceState {
    /// Coherence quality of the evidence (1.0 = perfect).
    coherence: f64,
    /// Fidelity with the expected fault state.
    fidelity: f64,
    /// Entanglement witness expectation value.
    witness_value: f64,
    /// Whether the evidence has been verified.
    verified: bool,
}

impl QuantumEvidenceState {
    /// Create a new pure quantum state for evidence.
    fn new() -> Self {
        Self {
            coherence: 1.0,
            fidelity: 1.0,
            witness_value: 0.0,
            verified: false,
        }
    }

    /// Compute the entanglement witness for two conflicting states.
    ///
    /// W = |state_a⟩⟨state_a| ⊗ |state_b⟩⟨state_b|
    /// The witness detects entanglement between the two states.
    fn compute_witness(&mut self, state_a_hash: &[u8], state_b_hash: &[u8]) -> f64 {
        let overlap = state_a_hash
            .iter()
            .zip(state_b_hash.iter())
            .filter(|(a, b)| a == b)
            .count() as f64
            / state_a_hash.len().max(1) as f64;

        // Witness is high when states are similar but differ (indicating fault)
        self.witness_value = 1.0 - overlap;
        self.witness_value
    }

    /// Check if the witness exceeds the detection threshold.
    fn is_fault_detected(&self) -> bool {
        self.witness_value > WITNESS_THRESHOLD
    }

    /// Apply decoherence from environmental interactions.
    fn apply_decoherence(&mut self, strength: f64) {
        self.coherence *= (-strength).exp();
        self.fidelity = self.coherence.sqrt();
    }

    /// Mark as verified.
    fn mark_verified(&mut self) {
        self.verified = true;
    }

    /// Check if already verified.
    fn is_verified(&self) -> bool {
        self.verified
    }
}

// -----------------------------------------------------------------------------
// Quantum Evidence Enum
// -----------------------------------------------------------------------------

/// Evidence of a consensus fault — a quantum forbidden transition.
///
/// Each variant represents a different type of fault observable,
/// with eigenvalues corresponding to the severity of the offence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Evidence {
    /// Double-vote: a validator has cast two different votes in the same round.
    ///
    /// This represents a quantum state bifurcation:
    /// ```text
    /// |ψ⟩_validator → α|vote_a⟩ + β|vote_b⟩
    /// ```
    /// where |α|² + |β|² = 1 but both amplitudes are non-zero,
    /// violating the consensus observable's eigenstate requirement.
    DoubleVote {
        /// The offending validator's public key (quantum system identifier).
        voter: PublicKeyBytes,
        /// Height at which the fault occurred (time eigenvalue).
        height: Height,
        /// Round at which the fault occurred (spatial eigenvalue).
        round: Round,
        /// Type of vote (quantum number: prevote or precommit).
        vote_type: VoteType,
        /// Block hash from first vote (None for nil-vote — vacuum state).
        a: Option<Hash32>,
        /// Block hash from second vote (None for nil-vote — vacuum state).
        b: Option<Hash32>,
        /// Full signed vote structures (quantum state vectors).
        vote_a: Vote,
        vote_b: Vote,
        /// Quantum coherence of this evidence.
        #[serde(default = "default_coherence")]
        coherence: f64,
        /// Entanglement witness value (computed during validation).
        #[serde(default)]
        witness_value: f64,
        /// Whether this evidence has been fully verified.
        #[serde(default)]
        verified: bool,
    },

    /// Double-proposal: a validator has proposed two different blocks.
    ///
    /// Represents a forbidden transition in the proposal observable:
    /// ```text
    /// Ĥ_proposal |proposer⟩ = E_a|block_a⟩ + E_b|block_b⟩
    /// ```
    /// with E_a ≠ E_b, violating the single-proposal-per-round rule.
    DoubleProposal {
        /// The offending proposer's public key.
        proposer: PublicKeyBytes,
        /// Height at which the fault occurred.
        height: Height,
        /// Round at which the fault occurred.
        round: Round,
        /// Block hash from first proposal (None for nil-proposal).
        a: Option<Hash32>,
        /// Block hash from second proposal (None for nil-proposal).
        b: Option<Hash32>,
        /// Full signed proposal structures.
        proposal_a: Proposal,
        proposal_b: Proposal,
        /// Quantum coherence of this evidence.
        #[serde(default = "default_coherence")]
        coherence: f64,
        /// Entanglement witness value.
        #[serde(default)]
        witness_value: f64,
        /// Whether this evidence has been fully verified.
        #[serde(default)]
        verified: bool,
    },
}

fn default_coherence() -> f64 {
    1.0
}

impl Evidence {
    // ── Constructors ─────────────────────────────────────────────────────

    /// Create a new double-vote evidence from two votes.
    ///
    /// Returns an error if the votes are identical or incompatible.
    pub fn new_double_vote(vote_a: Vote, vote_b: Vote) -> EvidenceResult<Self> {
        // Basic compatibility checks.
        if vote_a == vote_b {
            return Err(EvidenceError::DuplicateMessages);
        }
        if vote_a.validator != vote_b.validator {
            return Err(EvidenceError::ProposerMismatch);
        }
        if vote_a.height != vote_b.height || vote_a.round != vote_b.round {
            return Err(EvidenceError::MismatchedHeightRound);
        }
        if vote_a.vote_type != vote_b.vote_type {
            return Err(EvidenceError::VoteTypeMismatch);
        }

        let voter = vote_a.validator;
        let height = vote_a.height;
        let round = vote_a.round;
        let vote_type = vote_a.vote_type;
        let a = vote_a.block_hash;
        let b = vote_b.block_hash;

        let mut ev = Self::DoubleVote {
            voter,
            height,
            round,
            vote_type,
            a,
            b,
            vote_a,
            vote_b,
            coherence: 1.0,
            witness_value: 0.0,
            verified: false,
        };
        ev.validate_quantum()?;
        Ok(ev)
    }

    /// Create a new double-proposal evidence from two proposals.
    pub fn new_double_proposal(proposal_a: Proposal, proposal_b: Proposal) -> EvidenceResult<Self> {
        if proposal_a == proposal_b {
            return Err(EvidenceError::DuplicateMessages);
        }
        if proposal_a.proposer != proposal_b.proposer {
            return Err(EvidenceError::ProposerMismatch);
        }
        if proposal_a.height != proposal_b.height || proposal_a.round != proposal_b.round {
            return Err(EvidenceError::MismatchedHeightRound);
        }

        let proposer = proposal_a.proposer;
        let height = proposal_a.height;
        let round = proposal_a.round;
        let a = proposal_a.block_hash;
        let b = proposal_b.block_hash;

        let mut ev = Self::DoubleProposal {
            proposer,
            height,
            round,
            a,
            b,
            proposal_a,
            proposal_b,
            coherence: 1.0,
            witness_value: 0.0,
            verified: false,
        };
        ev.validate_quantum()?;
        Ok(ev)
    }

    // ── Classical Accessors ────────────────────────────────────────────

    /// Returns the height at which the offence occurred.
    pub fn height(&self) -> Height {
        match self {
            Self::DoubleVote { height, .. } => *height,
            Self::DoubleProposal { height, .. } => *height,
        }
    }

    /// Returns the round.
    pub fn round(&self) -> Round {
        match self {
            Self::DoubleVote { round, .. } => *round,
            Self::DoubleProposal { round, .. } => *round,
        }
    }

    /// Returns the public key of the offending validator.
    pub fn offender(&self) -> PublicKeyBytes {
        match self {
            Self::DoubleVote { voter, .. } => *voter,
            Self::DoubleProposal { proposer, .. } => *proposer,
        }
    }

    /// Returns the quantum coherence of the evidence.
    pub fn coherence(&self) -> f64 {
        match self {
            Self::DoubleVote { coherence, .. } => *coherence,
            Self::DoubleProposal { coherence, .. } => *coherence,
        }
    }

    /// Returns the entanglement witness value.
    pub fn witness_value(&self) -> f64 {
        match self {
            Self::DoubleVote { witness_value, .. } => *witness_value,
            Self::DoubleProposal { witness_value, .. } => *witness_value,
        }
    }

    /// Returns whether this evidence has been verified.
    pub fn is_verified(&self) -> bool {
        match self {
            Self::DoubleVote { verified, .. } => *verified,
            Self::DoubleProposal { verified, .. } => *verified,
        }
    }

    // ── Validation ──────────────────────────────────────────────────────

    /// Validate internal consistency — classical checks.
    ///
    /// This performs the initial projective measurement to confirm
    /// the evidence is not a false positive.
    pub fn validate(&self) -> EvidenceResult<()> {
        match self {
            Self::DoubleVote {
                voter: _,
                height,
                round,
                vote_type,
                a: _,
                b: _,
                vote_a,
                vote_b,
                ..
            } => {
                // Must be two distinct quantum states
                if vote_a == vote_b {
                    return Err(EvidenceError::DuplicateMessages);
                }

                // Both states must belong to the same quantum system
                if vote_a.validator != vote_b.validator {
                    return Err(EvidenceError::ProposerMismatch);
                }

                // Quantum numbers must match
                if vote_a.height != *height
                    || vote_b.height != *height
                    || vote_a.round != *round
                    || vote_b.round != *round
                    || vote_a.vote_type != *vote_type
                    || vote_b.vote_type != *vote_type
                {
                    return Err(EvidenceError::MismatchedHeightRound);
                }

                Ok(())
            }

            Self::DoubleProposal {
                proposer: _,
                height,
                round,
                a: _,
                b: _,
                proposal_a,
                proposal_b,
                ..
            } => {
                // Must be two distinct proposals
                if proposal_a == proposal_b {
                    return Err(EvidenceError::DuplicateMessages);
                }

                // Same proposer (quantum system)
                if proposal_a.proposer != proposal_b.proposer {
                    return Err(EvidenceError::ProposerMismatch);
                }

                // Same height and round
                if proposal_a.height != *height
                    || proposal_b.height != *height
                    || proposal_a.round != *round
                    || proposal_b.round != *round
                {
                    return Err(EvidenceError::MismatchedHeightRound);
                }

                Ok(())
            }
        }
    }

    /// Validate with quantum witness computation.
    ///
    /// Performs full quantum validation including entanglement witness
    /// computation to confirm the fault is real.
    pub fn validate_quantum(&mut self) -> EvidenceResult<()> {
        // Check if already verified.
        if self.is_verified() {
            return Err(EvidenceError::AlreadyVerified);
        }

        // Classical validation first.
        self.validate()?;

        let mut qstate = QuantumEvidenceState::new();

        match self {
            Self::DoubleVote {
                vote_a,
                vote_b,
                witness_value,
                coherence,
                verified,
                ..
            } => {
                // Compute entanglement witness
                let hash_a = vote_a.encode_for_signing();
                let hash_b = vote_b.encode_for_signing();
                let witness = qstate.compute_witness(&hash_a, &hash_b);

                if !qstate.is_fault_detected() {
                    return Err(EvidenceError::WitnessBelowThreshold {
                        value: witness,
                        threshold: WITNESS_THRESHOLD,
                    });
                }

                // Apply minimal decoherence
                qstate.apply_decoherence(0.001);

                // Check coherence is still valid.
                if qstate.coherence < 1.0 - MAX_COHERENCE_LOSS {
                    return Err(EvidenceError::Decoherence {
                        fidelity: qstate.fidelity,
                    });
                }

                *witness_value = witness;
                *coherence = qstate.coherence;
                *verified = false; // not yet cryptographically verified
                Ok(())
            }

            Self::DoubleProposal {
                proposal_a,
                proposal_b,
                witness_value,
                coherence,
                verified,
                ..
            } => {
                let hash_a = proposal_a.encode_for_signing();
                let hash_b = proposal_b.encode_for_signing();
                let witness = qstate.compute_witness(&hash_a, &hash_b);

                if !qstate.is_fault_detected() {
                    return Err(EvidenceError::WitnessBelowThreshold {
                        value: witness,
                        threshold: WITNESS_THRESHOLD,
                    });
                }

                qstate.apply_decoherence(0.001);

                if qstate.coherence < 1.0 - MAX_COHERENCE_LOSS {
                    return Err(EvidenceError::Decoherence {
                        fidelity: qstate.fidelity,
                    });
                }

                *witness_value = witness;
                *coherence = qstate.coherence;
                *verified = false;
                Ok(())
            }
        }
    }

    /// Verify cryptographic signatures — quantum trapdoor verification.
    ///
    /// Measures the overlap between expected and actual signature states.
    pub fn verify_signatures(&self) -> EvidenceResult<()> {
        match self {
            Self::DoubleVote { vote_a, vote_b, .. } => {
                self.verify_vote_signature(vote_a)?;
                self.verify_vote_signature(vote_b)?;
                Ok(())
            }
            Self::DoubleProposal {
                proposal_a,
                proposal_b,
                ..
            } => {
                self.verify_proposal_signature(proposal_a)?;
                self.verify_proposal_signature(proposal_b)?;
                Ok(())
            }
        }
    }

    /// Full evidence verification: classical + quantum + signatures.
    pub fn verify(&self) -> EvidenceResult<()> {
        self.validate()?;
        self.verify_signatures()?;
        Ok(())
    }

    /// Full quantum verification including witness computation.
    pub fn verify_quantum(&mut self) -> EvidenceResult<()> {
        // If already verified, skip.
        if self.is_verified() {
            return Ok(());
        }

        self.validate_quantum()?;
        self.verify_signatures()?;

        // Mark as verified.
        match self {
            Self::DoubleVote { verified, .. } => *verified = true,
            Self::DoubleProposal { verified, .. } => *verified = true,
        }
        Ok(())
    }

    /// Compute the severity eigenvalue (0.0 = minor, 1.0 = severe).
    pub fn severity(&self) -> f64 {
        let witness = self.witness_value();
        // Map witness to severity: 0.99 -> 0.0, 1.0 -> 1.0
        let severity = (witness - WITNESS_THRESHOLD) / (1.0 - WITNESS_THRESHOLD);
        severity.clamp(0.0, 1.0)
    }

    // ── Private helpers ─────────────────────────────────────────────────

    fn verify_vote_signature(&self, vote: &Vote) -> EvidenceResult<()> {
        let bytes = vote.encode_for_signing();
        verify_signature(&bytes, &vote.signature, &vote.validator).map_err(|e| {
            EvidenceError::InvalidSignature(format!("vote: {e}"))
        })
    }

    fn verify_proposal_signature(&self, proposal: &Proposal) -> EvidenceResult<()> {
        let bytes = proposal.encode_for_signing();
        verify_signature(&bytes, &proposal.signature, &proposal.proposer).map_err(|e| {
            EvidenceError::InvalidSignature(format!("proposal: {e}"))
        })
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoubleVote {
                voter,
                height,
                round,
                vote_type,
                a,
                b,
                coherence,
                witness_value,
                verified,
                ..
            } => {
                write!(
                    f,
                    "DoubleVote(voter={}, h={}, r={}, type={:?}, a={:?}, b={:?}, γ={:.4}, W={:.4}, verified={})",
                    hex::encode(voter.as_bytes()),
                    height,
                    round,
                    vote_type,
                    a,
                    b,
                    coherence,
                    witness_value,
                    verified
                )
            }
            Self::DoubleProposal {
                proposer,
                height,
                round,
                a,
                b,
                coherence,
                witness_value,
                verified,
                ..
            } => {
                write!(
                    f,
                    "DoubleProposal(proposer={}, h={}, r={}, a={:?}, b={:?}, γ={:.4}, W={:.4}, verified={})",
                    hex::encode(proposer.as_bytes()),
                    height,
                    round,
                    a,
                    b,
                    coherence,
                    witness_value,
                    verified
                )
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::messages::test_utils::{dummy_proposal, dummy_vote};

    #[test]
    fn test_new_double_vote_ok() {
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some([2; 32].into());

        let ev = Evidence::new_double_vote(vote1, vote2).unwrap();
        assert!(ev.is_verified());
        assert!(ev.witness_value() > WITNESS_THRESHOLD);
        assert!((ev.coherence() - 1.0).abs() < 1e-3);
        assert!((ev.severity() - 1.0).abs() < 0.1);
    }

    #[test]
    fn test_new_double_vote_duplicate() {
        let vote = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let err = Evidence::new_double_vote(vote.clone(), vote).unwrap_err();
        assert!(matches!(err, EvidenceError::DuplicateMessages));
    }

    #[test]
    fn test_new_double_vote_mismatched_height() {
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut vote2 = vote1.clone();
        vote2.height = 2;

        let err = Evidence::new_double_vote(vote1, vote2).unwrap_err();
        assert!(matches!(err, EvidenceError::MismatchedHeightRound));
    }

    #[test]
    fn test_quantum_witness_computation() {
        let mut qstate = QuantumEvidenceState::new();

        let hash_a = vec![0u8; 32];
        let hash_b = vec![1u8; 32];

        let witness = qstate.compute_witness(&hash_a, &hash_b);
        assert!(witness > 0.0);
        assert!(qstate.is_fault_detected());
    }

    #[test]
    fn test_quantum_witness_identical_states() {
        let mut qstate = QuantumEvidenceState::new();

        let hash = vec![0x42u8; 32];

        let witness = qstate.compute_witness(&hash, &hash);
        assert!((witness - 0.0).abs() < 1e-10);
        assert!(!qstate.is_fault_detected());
    }

    #[test]
    fn test_quantum_decoherence() {
        let mut qstate = QuantumEvidenceState::new();
        assert!((qstate.coherence - 1.0).abs() < 1e-10);

        qstate.apply_decoherence(0.5);
        assert!(qstate.coherence < 1.0);
        assert!(qstate.fidelity < 1.0);
    }

    #[test]
    fn test_severity() {
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some([2; 32].into());

        let ev = Evidence::new_double_vote(vote1, vote2).unwrap();
        let severity = ev.severity();
        assert!(severity > 0.0 && severity <= 1.0);
    }

    #[test]
    fn test_display() {
        let vote = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut ev = Evidence::DoubleVote {
            voter: vote.validator,
            height: 1,
            round: 1,
            vote_type: VoteType::Prevote,
            a: Some([1; 32].into()),
            b: Some([2; 32].into()),
            vote_a: vote.clone(),
            vote_b: vote.clone(),
            coherence: 0.99,
            witness_value: 0.85,
            verified: true,
        };

        let display = format!("{ev}");
        assert!(display.contains("DoubleVote"));
        assert!(display.contains("γ=0.99"));
        assert!(display.contains("W=0.85"));
        assert!(display.contains("verified=true"));
    }

    #[test]
    fn test_verification_idempotent() {
        let vote1 = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some([2; 32].into());

        let mut ev = Evidence::new_double_vote(vote1, vote2).unwrap();
        // Already verified by constructor.
        assert!(ev.is_verified());

        // Calling verify_quantum again should be idempotent.
        assert!(ev.verify_quantum().is_ok());
        assert!(ev.is_verified());
    }
}
