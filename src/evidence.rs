use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Evidence {
    DoubleVote {
        voter: PublicKeyBytes,
        height: Height,
        round: Round,
        vote_type: VoteType,
        a: Option<Hash32>,
        b: Option<Hash32>,
        // raw signed votes (for auditability)
        vote_a: Vote,
        vote_b: Vote,
    },

    DoubleProposal {
        proposer: PublicKeyBytes,
        height: Height,
        round: Round,
        a: Option<Hash32>,
        b: Option<Hash32>,
        proposal_a: Proposal,
        proposal_b: Proposal,
    },
}
