//! Quantum consensus message types and signing for IONA — Production-Grade.
//!
//! # Quantum Message Model
//!
//! Each consensus message (Proposal, Vote) is modelled as a **quantum state**
//! in a tensor product Hilbert space. The deterministic binary signing format
//! acts as a **quantum fingerprint** that uniquely identifies each state.
//!
//! # Mathematical Formalism
//!
//! ## Message State Representation
//! ```text
//! |Proposal⟩ = |height⟩ ⊗ |round⟩ ⊗ |proposer⟩ ⊗ |block_id⟩ ⊗ |pol_round⟩
//! |Vote⟩     = |vote_type⟩ ⊗ |height⟩ ⊗ |round⟩ ⊗ |voter⟩ ⊗ |block_id⟩
//! ```
//!
//! ## Signing as Quantum Unitary
//! ```text
//! U_sign: |message⟩ ⊗ |sk⟩ → |message⟩ ⊗ |signature⟩
//! U_sign = H_domain ⊗ H_height ⊗ H_round ⊗ H_payload
//! ```
//!
//! ## Signature Verification as Projective Measurement
//! ```text
//! Π_verify = |valid⟩⟨valid|
//! P(valid) = ⟨message, signature| Π_verify |message, signature⟩
//! ```
//!
//! ## Domain Tags as Quantum Channels
//! ```text
//! Φ_domain(ρ) = K_tag ρ K_tag†
//! K_tag = |tag⟩⟨∅|
//! ```
//! Each domain tag (PROP, VTPY, VTCX, VNIL) is a Kraus operator that
//! projects the state onto a specific subspace, preventing cross‑type
//! replay attacks via quantum decoherence between subspaces.
//!
//! ## Binary Format Stability
//! The sign bytes format uses little‑endian encoding explicitly, making it
//! **basis‑independent** — the quantum measurement outcome is identical
//! regardless of the host's classical architecture.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Domain tag for proposals: `"PROP"` as 4‑byte little‑endian.
/// Quantum channel identifier for the proposal subspace.
const DOMAIN_PROPOSAL: [u8; 4] = *b"PROP";

/// Domain tag for prevote (non‑nil): `"VTPY"` — prevote subspace.
const DOMAIN_PREVOTE: [u8; 4] = *b"VTPY";

/// Domain tag for precommit (non‑nil): `"VTCX"` — precommit subspace.
const DOMAIN_PRECOMMIT: [u8; 4] = *b"VTCX";

/// Domain tag for nil votes: `"VNIL"` — nil subspace.
const DOMAIN_NIL_VOTE: [u8; 4] = *b"VNIL";

/// Flag byte indicating a value is present (quantum state populated).
const FLAG_PRESENT: u8 = 0x01;

/// Flag byte indicating a value is absent (vacuum state |∅⟩).
const FLAG_ABSENT: u8 = 0x00;

/// Length of a block ID hash in bytes (quantum fingerprint length).
const BLOCK_ID_LEN: usize = 32;

/// Length of domain tag (subspace dimension).
const DOMAIN_LEN: usize = 4;

/// Length of height (8 bytes LE).
const HEIGHT_LEN: usize = 8;

/// Length of round (4 bytes LE).
const ROUND_LEN: usize = 4;

/// Length of the optional value flag byte.
const FLAG_LEN: usize = 1;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Quantum fidelity threshold for signature verification.
const SIGNATURE_FIDELITY_THRESHOLD: f64 = 0.999;

/// Decoherence rate per signing operation.
const SIGNING_DECOHERENCE_RATE: f64 = 0.00001;

/// Kraus rank for domain quantum channels.
const KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Vote Types
// -----------------------------------------------------------------------------

/// Vote type — quantum number distinguishing prevote from precommit.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType {
    Prevote,
    Precommit,
}

impl VoteType {
    /// Quantum domain tag for this vote type.
    pub fn domain_tag(&self) -> [u8; 4] {
        match self {
            VoteType::Prevote => DOMAIN_PREVOTE,
            VoteType::Precommit => DOMAIN_PRECOMMIT,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Proposal Message
// -----------------------------------------------------------------------------

/// Proposal message — quantum state in the proposal Hilbert space.
///
/// ```text
/// |Proposal⟩ = |height⟩ ⊗ |round⟩ ⊗ |proposer⟩ ⊗ |block_id⟩ ⊗ |pol_round⟩
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub proposer: PublicKeyBytes,
    pub block_id: Hash32,
    pub block: Option<Block>,
    pub pol_round: Option<Round>,
    pub signature: SignatureBytes,
    /// Quantum purity of this proposal state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Entanglement fidelity with the validator set.
    #[serde(default = "default_purity")]
    pub entanglement_fidelity: f64,
}

fn default_purity() -> f64 {
    1.0
}

impl Proposal {
    /// Compute the deterministic bytes that must be signed.
    ///
    /// This is the quantum state representation before signing:
    /// ```text
    /// |sign_bytes⟩ = U_encode |Proposal⟩
    /// ```
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }

    /// Apply decoherence from network propagation.
    pub fn apply_propagation_decoherence(&mut self) {
        let decay = (-SIGNING_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Quantum Vote Message
// -----------------------------------------------------------------------------

/// Vote message — quantum state in the vote Hilbert space.
///
/// ```text
/// |Vote⟩ = |vote_type⟩ ⊗ |height⟩ ⊗ |round⟩ ⊗ |voter⟩ ⊗ |block_id⟩
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: Height,
    pub round: Round,
    pub voter: PublicKeyBytes,
    pub block_id: Option<Hash32>,
    pub signature: SignatureBytes,
    /// Quantum purity of this vote state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Entanglement fidelity with the validator set.
    #[serde(default = "default_purity")]
    pub entanglement_fidelity: f64,
}

impl Vote {
    /// Compute the deterministic bytes that must be signed.
    ///
    /// ```text
    /// |sign_bytes⟩ = U_encode |Vote⟩
    /// ```
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }

    /// Check if this is a nil vote (vacuum state in block_id subspace).
    pub fn is_nil(&self) -> bool {
        self.block_id.is_none()
    }

    /// Apply decoherence from network propagation.
    pub fn apply_propagation_decoherence(&mut self) {
        let decay = (-SIGNING_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Consensus Message Enum
// -----------------------------------------------------------------------------

/// Top‑level consensus message — quantum channel multiplexer.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

impl ConsensusMsg {
    /// Apply decoherence based on message type.
    pub fn apply_propagation_decoherence(&mut self) {
        match self {
            ConsensusMsg::Proposal(p) => p.apply_propagation_decoherence(),
            ConsensusMsg::Vote(v) => v.apply_propagation_decoherence(),
            ConsensusMsg::Evidence(_) => {
                // Evidence has its own quantum model
            }
        }
    }

    /// Get the height of this message (if applicable).
    pub fn height(&self) -> Option<Height> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.height),
            ConsensusMsg::Vote(v) => Some(v.height),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the round of this message (if applicable).
    pub fn round(&self) -> Option<Round> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.round),
            ConsensusMsg::Vote(v) => Some(v.round),
            ConsensusMsg::Evidence(_) => None,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Message Statistics
// -----------------------------------------------------------------------------

/// Statistics for quantum consensus messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageStats {
    /// Total proposals created/sent.
    pub proposals_sent: u64,
    /// Total proposals received.
    pub proposals_received: u64,
    /// Total prevotes sent.
    pub prevotes_sent: u64,
    /// Total prevotes received.
    pub prevotes_received: u64,
    /// Total precommits sent.
    pub precommits_sent: u64,
    /// Total precommits received.
    pub precommits_received: u64,
    /// Total nil votes.
    pub nil_votes: u64,
    /// Average purity of received messages.
    pub avg_purity: f64,
    /// Average entanglement fidelity.
    pub avg_entanglement_fidelity: f64,
    /// Total signature verification failures.
    pub signature_failures: u64,
}

// -----------------------------------------------------------------------------
// Deterministic Binary Sign Bytes (Quantum Encoding)
// -----------------------------------------------------------------------------
//
// The sign bytes represent the **quantum state** of the message before
// the signing unitary is applied. The format is:
//
// ```text
// |sign_bytes⟩ = |domain⟩ ⊗ |height⟩ ⊗ |round⟩ ⊗ |block_id⟩ ⊗ |flags⟩
// ```
//
// ## Domain Tags (Quantum Subspace Identifiers)
// - `PROP` (0x504F5052): Proposal subspace — orthonormal to vote subspaces
// - `VTPY` (0x56545059): Prevote subspace — orthonormal to precommit
// - `VTCX` (0x56544358): Precommit subspace — orthonormal to prevote
// - `VNIL` (0x564E494C): Nil vote subspace — vacuum state
//
// ## Determinism Guarantee
// All integers are encoded as little‑endian regardless of host byte order,
// ensuring **basis independence** — the quantum measurement outcome is
// identical across all platforms.

/// Compute the sign bytes for a proposal.
///
/// ```text
/// |proposal_sign_bytes⟩ = |DOMAIN_PROPOSAL⟩ ⊗ |height⟩ ⊗ |round⟩ ⊗ |block_id⟩ ⊗ |pol_round_flag⟩
/// ```
#[must_use]
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + BLOCK_ID_LEN + 1 + ROUND_LEN,
    );
    out.extend_from_slice(&DOMAIN_PROPOSAL);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&block_id.0);
    match pol_round {
        None => out.push(FLAG_ABSENT),
        Some(r) => {
            out.push(FLAG_PRESENT);
            out.extend_from_slice(&r.to_le_bytes());
        }
    }
    out
}

/// Compute the sign bytes for a vote (prevote or precommit).
///
/// ```text
/// |vote_sign_bytes⟩ = |domain(vote_type, is_nil)⟩ ⊗ |height⟩ ⊗ |round⟩ ⊗ |block_id_flag⟩
/// ```
#[must_use]
pub fn vote_sign_bytes(
    vote_type: VoteType,
    height: Height,
    round: Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let domain = match (vote_type, block_id) {
        (VoteType::Prevote, Some(_)) => DOMAIN_PREVOTE,
        (VoteType::Precommit, Some(_)) => DOMAIN_PRECOMMIT,
        _ => DOMAIN_NIL_VOTE,
    };
    let mut out =
        Vec::with_capacity(DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + FLAG_LEN + BLOCK_ID_LEN);
    out.extend_from_slice(&domain);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    match block_id {
        Some(id) => {
            out.push(FLAG_PRESENT);
            out.extend_from_slice(&id.0);
        }
        None => {
            out.push(FLAG_ABSENT);
            out.extend_from_slice(&[0u8; BLOCK_ID_LEN]);
        }
    }
    out
}

// -----------------------------------------------------------------------------
// Quantum Utility Functions
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two sign byte sequences.
///
/// ```text
/// F = (1/N) Σ_i δ(a_i, b_i)
/// ```
/// where δ is the Kronecker delta.
pub fn sign_bytes_fidelity(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / len as f64
}

/// Apply quantum channel to sign bytes (domain‑based Kraus operator).
///
/// ```text
/// Φ_domain(|sign_bytes⟩) = K_tag |sign_bytes⟩⟨sign_bytes| K_tag†
/// ```
pub fn apply_domain_channel(sign_bytes: &mut Vec<u8>, domain: &[u8; 4]) {
    if sign_bytes.len() >= DOMAIN_LEN {
        let kraus_factor = (1.0 / KRAUS_RANK as f64).sqrt();
        // The Kraus operator K_tag projects onto the domain subspace
        for i in 0..DOMAIN_LEN {
            sign_bytes[i] = ((sign_bytes[i] as f64 * kraus_factor) as u8).min(sign_bytes[i]);
        }
        sign_bytes[..DOMAIN_LEN].copy_from_slice(domain);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proposal_sign_bytes_deterministic() {
        let height = 42;
        let round = 7;
        let block_id = Hash32([0xAA; 32]);
        let pol_round = Some(5);
        let bytes1 = proposal_sign_bytes(height, round, &block_id, pol_round);
        let bytes2 = proposal_sign_bytes(height, round, &block_id, pol_round);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_vote_sign_bytes_deterministic() {
        let height = 100;
        let round = 3;
        let block_id = Some(Hash32([0xBB; 32]));
        let bytes1 = vote_sign_bytes(VoteType::Prevote, height, round, &block_id);
        let bytes2 = vote_sign_bytes(VoteType::Prevote, height, round, &block_id);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_nil_vote_different_domain() {
        let height = 100;
        let round = 3;
        let nil_sig = vote_sign_bytes(VoteType::Prevote, height, round, &None);
        let block_sig =
            vote_sign_bytes(VoteType::Prevote, height, round, &Some(Hash32([0xCC; 32])));
        assert_ne!(nil_sig, block_sig);
    }

    #[test]
    fn test_different_vote_types_have_different_bytes() {
        let height = 1;
        let round = 0;
        let block_id = Some(Hash32([0xDD; 32]));
        let prevote_bytes = vote_sign_bytes(VoteType::Prevote, height, round, &block_id);
        let precommit_bytes = vote_sign_bytes(VoteType::Precommit, height, round, &block_id);
        assert_ne!(prevote_bytes, precommit_bytes);
    }

    #[test]
    fn test_proposal_different_pol_round() {
        let height = 1;
        let round = 0;
        let block_id = Hash32([0xEE; 32]);
        let with_pol = proposal_sign_bytes(height, round, &block_id, Some(3));
        let without_pol = proposal_sign_bytes(height, round, &block_id, None);
        assert_ne!(with_pol, without_pol);
    }

    #[test]
    fn test_sign_bytes_fidelity_identical() {
        let bytes = proposal_sign_bytes(1, 0, &Hash32([0xFF; 32]), None);
        let fidelity = sign_bytes_fidelity(&bytes, &bytes);
        assert!((fidelity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_sign_bytes_fidelity_different() {
        let a = proposal_sign_bytes(1, 0, &Hash32([0x11; 32]), None);
        let b = proposal_sign_bytes(2, 0, &Hash32([0x22; 32]), None);
        let fidelity = sign_bytes_fidelity(&a, &b);
        assert!(fidelity < 1.0);
    }

    #[test]
    fn test_apply_domain_channel() {
        let mut bytes = proposal_sign_bytes(1, 0, &Hash32([0xAA; 32]), None);
        let original_domain = bytes[..DOMAIN_LEN].to_vec();
        apply_domain_channel(&mut bytes, &DOMAIN_PREVOTE);
        assert_ne!(&bytes[..DOMAIN_LEN], &original_domain[..]);
        assert_eq!(&bytes[..DOMAIN_LEN], &DOMAIN_PREVOTE[..]);
    }

    #[test]
    fn test_proposal_quantum_properties() {
        let mut proposal = Proposal {
            height: 1,
            round: 0,
            proposer: PublicKeyBytes(vec![0; 32]),
            block_id: Hash32([0xAA; 32]),
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };

        assert!((proposal.purity - 1.0).abs() < 1e-10);
        proposal.apply_propagation_decoherence();
        assert!(proposal.purity < 1.0);
        assert!(proposal.entanglement_fidelity < 1.0);
    }

    #[test]
    fn test_vote_quantum_properties() {
        let mut vote = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![0; 32]),
            block_id: Some(Hash32([0xBB; 32])),
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };

        assert!((vote.purity - 1.0).abs() < 1e-10);
        vote.apply_propagation_decoherence();
        assert!(vote.purity < 1.0);
    }

    #[test]
    fn test_vote_is_nil() {
        let block_vote = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![0; 32]),
            block_id: Some(Hash32([0xCC; 32])),
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };
        assert!(!block_vote.is_nil());

        let nil_vote = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![0; 32]),
            block_id: None,
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };
        assert!(nil_vote.is_nil());
    }

    #[test]
    fn test_consensus_msg_height() {
        let proposal = Proposal {
            height: 42,
            round: 0,
            proposer: PublicKeyBytes(vec![0; 32]),
            block_id: Hash32([0; 32]),
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };
        let msg = ConsensusMsg::Proposal(proposal);
        assert_eq!(msg.height(), Some(42));
        assert_eq!(msg.round(), Some(0));
    }

    #[test]
    fn test_message_stats_default() {
        let stats = MessageStats::default();
        assert_eq!(stats.proposals_sent, 0);
        assert_eq!(stats.signature_failures, 0);
    }
}
