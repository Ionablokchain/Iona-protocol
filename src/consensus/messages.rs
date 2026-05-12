//! Consensus message types and signing for IONA v21.
//!
//! Sign bytes format: all signing uses a deterministic binary format, NOT serde_json.
//! Format: domain_tag (4 bytes LE) || fixed fields as little‑endian u64/u32 || raw bytes.
//! This is stable across serde versions and JSON whitespace changes.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use serde::{Deserialize, Serialize};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Domain tag for proposals: `"PROP"` as 4‑byte little‑endian.
const DOMAIN_PROPOSAL: [u8; 4] = *b"PROP";

/// Domain tag for prevote (non‑nil): `"VTPY"`.
const DOMAIN_PREVOTE: [u8; 4] = *b"VTPY";

/// Domain tag for precommit (non‑nil): `"VTCX"`.
const DOMAIN_PRECOMMIT: [u8; 4] = *b"VTCX";

/// Domain tag for nil votes (prevote or precommit): `"VNIL"`.
const DOMAIN_NIL_VOTE: [u8; 4] = *b"VNIL";

/// Flag byte indicating that a value is present (e.g., block_id or pol_round).
const FLAG_PRESENT: u8 = 0x01;

/// Flag byte indicating that a value is absent (None).
const FLAG_ABSENT: u8 = 0x00;

/// Length of a block ID hash in bytes.
const BLOCK_ID_LEN: usize = 32;

/// Length of domain tag.
const DOMAIN_LEN: usize = 4;

/// Length of height (8 bytes LE).
const HEIGHT_LEN: usize = 8;

/// Length of round (4 bytes LE).
const ROUND_LEN: usize = 4;

/// Length of the optional value flag byte.
const FLAG_LEN: usize = 1;

// -----------------------------------------------------------------------------
// Vote Types
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType {
    Prevote,
    Precommit,
}

// -----------------------------------------------------------------------------
// Proposal Message
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub proposer: PublicKeyBytes,
    pub block_id: Hash32,
    pub block: Option<Block>,
    pub pol_round: Option<Round>,
    pub signature: SignatureBytes,
}

impl Proposal {
    /// Compute the deterministic bytes that must be signed to produce a valid signature.
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }
}

// -----------------------------------------------------------------------------
// Vote Message
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: Height,
    pub round: Round,
    pub voter: PublicKeyBytes,
    pub block_id: Option<Hash32>,
    pub signature: SignatureBytes,
}

impl Vote {
    /// Compute the deterministic bytes that must be signed to produce a valid signature.
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }
}

// -----------------------------------------------------------------------------
// Consensus Message Enum
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

// -----------------------------------------------------------------------------
// Deterministic Binary Sign Bytes (low‑level)
// -----------------------------------------------------------------------------
//
// Format for all signing:
//   [domain: 4 bytes] [height: 8 bytes LE] [round: 4 bytes LE] [block_id: 32 bytes or 32×0] [flags: 1 byte]
//
// Domain tags prevent cross‑type replay:
//   - `0x504F5052` = "PROP" (proposal)
//   - `0x56545059` = "VTPY" (prevote)
//   - `0x56544358` = "VTCX" (precommit)
//   - `0x564E494C` = "VNIL" (nil vote)
//
// This format is stable across Rust versions, serde versions, and OS byte order
// because we explicitly write little‑endian regardless of host byte order.

/// Compute the sign bytes for a proposal.
#[must_use]
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + BLOCK_ID_LEN + 1 + ROUND_LEN);
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
    let mut out = Vec::with_capacity(DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + FLAG_LEN + BLOCK_ID_LEN);
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
        let block_sig = vote_sign_bytes(VoteType::Prevote, height, round, &Some(Hash32([0xCC; 32])));
        assert_ne!(nil_sig, block_sig);
    }
}
