//! Consensus message types and signing for IONA v28.
//!
//! Sign bytes format: all signing uses a deterministic binary format, NOT serde_json.
//! Format:
//!   [domain: 4 bytes] [height: 8 bytes LE] [round: 4 bytes LE] [block_id: 32 bytes or 32x0] [flags: variable]
//!
//! Domain tags (prevent cross‑type replay):
//!   - `b"PROP"` (proposal)
//!   - `b"VTPY"` (prevote)
//!   - `b"VTCX"` (precommit)
//!   - `b"VNIL"` (nil vote)
//!
//! This format is stable across Rust versions, serde versions, and host byte order
//! because we explicitly write little‑endian regardless of platform.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::fmt;

// -----------------------------------------------------------------------------
// VoteType
// -----------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType {
    Prevote,
    Precommit,
}

impl fmt::Display for VoteType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VoteType::Prevote => write!(f, "Prevote"),
            VoteType::Precommit => write!(f, "Precommit"),
        }
    }
}

// -----------------------------------------------------------------------------
// Proposal
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
    /// Returns the deterministic signing bytes for this proposal.
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }

    /// Returns a unique hash for this proposal (for deduplication, not consensus).
    pub fn hash(&self) -> Hash32 {
        use crate::types::hash_bytes;
        let mut buf = Vec::new();
        buf.extend_from_slice(b"PROP");
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        buf.extend_from_slice(&self.block_id.0);
        if let Some(r) = self.pol_round {
            buf.extend_from_slice(&r.to_le_bytes());
        }
        hash_bytes(&buf)
    }
}

impl fmt::Display for Proposal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Proposal(h={}, r={}, proposer={}, block={})",
            self.height,
            self.round,
            hex::encode(&self.proposer.0[..4]),
            hex::encode(&self.block_id.0[..8])
        )
    }
}

// -----------------------------------------------------------------------------
// Vote
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
    /// Returns the deterministic signing bytes for this vote.
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }

    /// Returns a unique hash for this vote (for deduplication).
    pub fn hash(&self) -> Hash32 {
        use crate::types::hash_bytes;
        let mut buf = Vec::new();
        match (self.vote_type, &self.block_id) {
            (VoteType::Prevote, Some(id)) => buf.extend_from_slice(b"PREV"),
            (VoteType::Precommit, Some(id)) => buf.extend_from_slice(b"PREC"),
            _ => buf.extend_from_slice(b"NILV"),
        }
        buf.extend_from_slice(&self.height.to_le_bytes());
        buf.extend_from_slice(&self.round.to_le_bytes());
        if let Some(id) = &self.block_id {
            buf.extend_from_slice(&id.0);
        } else {
            buf.extend_from_slice(&[0u8; 32]);
        }
        hash_bytes(&buf)
    }
}

impl fmt::Display for Vote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let block = match &self.block_id {
            Some(id) => format!("0x{}", hex::encode(&id.0[..8])),
            None => "nil".to_string(),
        };
        write!(
            f,
            "Vote({}, h={}, r={}, voter={}, block={})",
            self.vote_type,
            self.height,
            self.round,
            hex::encode(&self.voter.0[..4]),
            block
        )
    }
}

// -----------------------------------------------------------------------------
// ConsensusMsg
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

impl fmt::Display for ConsensusMsg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConsensusMsg::Proposal(p) => write!(f, "{}", p),
            ConsensusMsg::Vote(v) => write!(f, "{}", v),
            ConsensusMsg::Evidence(e) => write!(f, "Evidence({:?})", e),
        }
    }
}

// -----------------------------------------------------------------------------
// Domain constants
// -----------------------------------------------------------------------------

const DOMAIN_PROPOSAL: [u8; 4] = *b"PROP";
const DOMAIN_PREVOTE: [u8; 4] = *b"VTPY";
const DOMAIN_PRECOMMIT: [u8; 4] = *b"VTCX";
const DOMAIN_NIL_VOTE: [u8; 4] = *b"VNIL";

// -----------------------------------------------------------------------------
// Signing helpers
// -----------------------------------------------------------------------------

/// Deterministic signing bytes for a proposal.
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 4 + 32 + 5);
    out.extend_from_slice(&DOMAIN_PROPOSAL);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&block_id.0);
    // pol_round: 0x00 = None, 0x01 || u32 = Some(r)
    match pol_round {
        None => out.push(0x00),
        Some(r) => {
            out.push(0x01);
            out.extend_from_slice(&r.to_le_bytes());
        }
    }
    out
}

/// Deterministic signing bytes for a vote.
pub fn vote_sign_bytes(
    vt: VoteType,
    height: Height,
    round: Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 4 + 33);
    let domain = match (vt, block_id) {
        (VoteType::Prevote, Some(_)) => DOMAIN_PREVOTE,
        (VoteType::Precommit, Some(_)) => DOMAIN_PRECOMMIT,
        _ => DOMAIN_NIL_VOTE,
    };
    out.extend_from_slice(&domain);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    match block_id {
        Some(id) => {
            out.push(0x01);
            out.extend_from_slice(&id.0);
        }
        None => {
            out.push(0x00);
            out.extend_from_slice(&[0u8; 32]);
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
        let h = 123;
        let r = 5;
        let id = Hash32([0xAA; 32]);
        let pol = Some(2);

        let b1 = proposal_sign_bytes(h, r, &id, pol);
        let b2 = proposal_sign_bytes(h, r, &id, pol);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_vote_sign_bytes_deterministic() {
        let h = 123;
        let r = 5;
        let id = Some(Hash32([0xAA; 32]));

        let b1 = vote_sign_bytes(VoteType::Prevote, h, r, &id);
        let b2 = vote_sign_bytes(VoteType::Prevote, h, r, &id);
        assert_eq!(b1, b2);
    }

    #[test]
    fn test_nil_vote_domain() {
        let h = 123;
        let r = 5;
        let nil: Option<Hash32> = None;
        let b = vote_sign_bytes(VoteType::Prevote, h, r, &nil);
        assert_eq!(&b[0..4], &DOMAIN_NIL_VOTE);
    }

    #[test]
    fn test_proposal_hash_deterministic() {
        let prop = Proposal {
            height: 100,
            round: 0,
            proposer: PublicKeyBytes(vec![1u8; 32]),
            block_id: Hash32([0xAA; 32]),
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![]),
        };
        let h1 = prop.hash();
        let h2 = prop.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_vote_hash_deterministic() {
        let vote = Vote {
            vote_type: VoteType::Prevote,
            height: 100,
            round: 0,
            voter: PublicKeyBytes(vec![1u8; 32]),
            block_id: Some(Hash32([0xAA; 32])),
            signature: SignatureBytes(vec![]),
        };
        let h1 = vote.hash();
        let h2 = vote.hash();
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_display_does_not_panic() {
        let prop = Proposal {
            height: 100,
            round: 0,
            proposer: PublicKeyBytes(vec![1u8; 32]),
            block_id: Hash32([0xAA; 32]),
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![]),
        };
        let vote = Vote {
            vote_type: VoteType::Prevote,
            height: 100,
            round: 0,
            voter: PublicKeyBytes(vec![1u8; 32]),
            block_id: Some(Hash32([0xAA; 32])),
            signature: SignatureBytes(vec![]),
        };
        let _ = format!("{}", prop);
        let _ = format!("{}", vote);
        let _ = format!("{}", ConsensusMsg::Proposal(prop));
    }
}
