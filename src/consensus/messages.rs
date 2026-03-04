//! Consensus message types and signing for IONA v21.
//!
//! Sign bytes format: all signing uses a deterministic binary format, NOT serde_json.
//! Format: domain_tag (4 bytes LE) || fixed fields as little-endian u64/u32 || raw bytes.
//! This is stable across serde versions and JSON whitespace changes.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType { Prevote, Precommit }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height:    Height,
    pub round:     Round,
    pub proposer:  PublicKeyBytes,
    pub block_id:  Hash32,
    pub block:     Option<Block>,
    pub pol_round: Option<Round>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height:    Height,
    pub round:     Round,
    pub voter:     PublicKeyBytes,
    pub block_id:  Option<Hash32>,
    pub signature: SignatureBytes,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

// ── Deterministic binary sign bytes ──────────────────────────────────────
//
// Format for all signing:
//   [domain: 4 bytes] [height: 8 bytes LE] [round: 4 bytes LE] [block_id: 32 bytes or 32x0] [flags: 1 byte]
//
// domain tags (prevent cross-type replay):
//   0x504F5052 = "PROP" (proposal)
//   0x56545059 = "VTPY" (prevote)
//   0x56544358 = "VTCX" (precommit)
//
// This format is stable across Rust versions, serde versions, and OS byte order
// because we explicitly write little-endian regardless of host byte order.

const DOMAIN_PROPOSAL:   [u8; 4] = *b"PROP";
const DOMAIN_PREVOTE:    [u8; 4] = *b"VTPY";
const DOMAIN_PRECOMMIT:  [u8; 4] = *b"VTCX";
const DOMAIN_NIL_VOTE:   [u8; 4] = *b"VNIL";

pub fn proposal_sign_bytes(
    height:    Height,
    round:     Round,
    block_id:  &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 4 + 32 + 5);
    out.extend_from_slice(&DOMAIN_PROPOSAL);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&block_id.0);
    // pol_round: 0x00 = None, 0x01 || u32 = Some(r)
    match pol_round {
        None    => out.push(0x00),
        Some(r) => { out.push(0x01); out.extend_from_slice(&r.to_le_bytes()); }
    }
    out
}

pub fn vote_sign_bytes(
    vt:       VoteType,
    height:   Height,
    round:    Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + 8 + 4 + 33);
    let domain = match (vt, block_id) {
        (VoteType::Prevote,   Some(_)) => DOMAIN_PREVOTE,
        (VoteType::Precommit, Some(_)) => DOMAIN_PRECOMMIT,
        _                              => DOMAIN_NIL_VOTE,
    };
    out.extend_from_slice(&domain);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    match block_id {
        Some(id) => { out.push(0x01); out.extend_from_slice(&id.0); }
        None     => { out.push(0x00); out.extend_from_slice(&[0u8; 32]); }
    }
    out
}
