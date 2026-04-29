//! Evidence types for consensus faults (double-vote, double-proposal).
//!
//! Each evidence variant includes both raw signed messages and metadata
//! needed for external verification by slashable offence handlers.

use crate::consensus::messages::{Proposal, Vote, VoteType};
use crate::crypto::{PublicKeyBytes, Signature, verify_signature};
use crate::types::{Hash32, Height, Round};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvidenceError {
    #[error("invalid evidence: duplicate messages (identical content)")]
    DuplicateMessages,
    #[error("invalid evidence: messages are from different height/round")]
    MismatchedHeightRound,
    #[error("invalid evidence: vote_type mismatch between the two votes")]
    VoteTypeMismatch,
    #[error("invalid evidence: proposer mismatch between proposals")]
    ProposerMismatch,
    #[error("signature verification failed: {0}")]
    InvalidSignature(String),
    #[error("missing block hash in vote/proposal")]
    MissingBlockHash,
}

pub type EvidenceResult<T> = Result<T, EvidenceError>;

// -----------------------------------------------------------------------------
// Evidence enum
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum Evidence {
    /// Two distinct votes from the same validator at the same (height, round, vote_type).
    DoubleVote {
        voter: PublicKeyBytes,
        height: Height,
        round: Round,
        vote_type: VoteType,
        /// Block hash from first vote (None for nil-vote)
        a: Option<Hash32>,
        /// Block hash from second vote (None for nil-vote)
        b: Option<Hash32>,
        /// The full signed vote structures (for audit and replay verification)
        vote_a: Vote,
        vote_b: Vote,
    },
    /// Two distinct proposals from the same validator at the same (height, round).
    DoubleProposal {
        proposer: PublicKeyBytes,
        height: Height,
        round: Round,
        /// Block hash from first proposal (None for nil-proposal)
        a: Option<Hash32>,
        /// Block hash from second proposal (None for nil-proposal)
        b: Option<Hash32>,
        proposal_a: Proposal,
        proposal_b: Proposal,
    },
}

impl Evidence {
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

    /// Validate internal consistency – does not verify cryptographic signatures.
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
            } => {
                // Must be two distinct votes.
                if vote_a == vote_b {
                    return Err(EvidenceError::DuplicateMessages);
                }
                // Both votes must belong to the same validator.
                if vote_a.validator != vote_b.validator {
                    return Err(EvidenceError::ProposerMismatch);
                }
                // Height, round, vote_type must match the evidence fields.
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
            } => {
                if proposal_a == proposal_b {
                    return Err(EvidenceError::DuplicateMessages);
                }
                if proposal_a.proposer != proposal_b.proposer {
                    return Err(EvidenceError::ProposerMismatch);
                }
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

    /// Verify cryptographic signatures of both included messages.
    /// Requires access to the validator's public key (already present in the evidence).
    pub fn verify_signatures(&self) -> EvidenceResult<()> {
        match self {
            Self::DoubleVote { vote_a, vote_b, .. } => {
                self.verify_vote_signature(vote_a)?;
                self.verify_vote_signature(vote_b)?;
                Ok(())
            }
            Self::DoubleProposal { proposal_a, proposal_b, .. } => {
                self.verify_proposal_signature(proposal_a)?;
                self.verify_proposal_signature(proposal_b)?;
                Ok(())
            }
        }
    }

    fn verify_vote_signature(&self, vote: &Vote) -> EvidenceResult<()> {
        let bytes = vote.encode_for_signing(); // assume method exists
        verify_signature(&bytes, &vote.signature, &vote.validator)
            .map_err(|e| EvidenceError::InvalidSignature(format!("vote: {}", e)))
    }

    fn verify_proposal_signature(&self, proposal: &Proposal) -> EvidenceResult<()> {
        let bytes = proposal.encode_for_signing(); // assume method exists
        verify_signature(&bytes, &proposal.signature, &proposal.proposer)
            .map_err(|e| EvidenceError::InvalidSignature(format!("proposal: {}", e)))
    }

    /// Full evidence verification: internal consistency + signatures.
    pub fn verify(&self) -> EvidenceResult<()> {
        self.validate()?;
        self.verify_signatures()?;
        Ok(())
    }
}

impl fmt::Display for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DoubleVote { voter, height, round, vote_type, a, b, .. } => {
                write!(
                    f,
                    "DoubleVote(voter={}, height={}, round={}, type={:?}, a={:?}, b={:?})",
                    hex::encode(voter.as_bytes()), height, round, vote_type, a, b
                )
            }
            Self::DoubleProposal { proposer, height, round, a, b, .. } => {
                write!(
                    f,
                    "DoubleProposal(proposer={}, height={}, round={}, a={:?}, b={:?})",
                    hex::encode(proposer.as_bytes()), height, round, a, b
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
    fn test_double_vote_validation_ok() {
        let mut vote1 = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let mut vote2 = vote1.clone();
        vote2.block_hash = Some([2; 32].into()); // different hash
        let ev = Evidence::DoubleVote {
            voter: vote1.validator,
            height: 1,
            round: 1,
            vote_type: VoteType::Prevote,
            a: Some([1; 32].into()),
            b: Some([2; 32].into()),
            vote_a: vote1.clone(),
            vote_b: vote2.clone(),
        };
        assert!(ev.validate().is_ok());
    }

    #[test]
    fn test_double_vote_duplicate_messages() {
        let vote = dummy_vote(1, 1, VoteType::Prevote, Some([1; 32].into()));
        let ev = Evidence::DoubleVote {
            voter: vote.validator,
            height: 1,
            round: 1,
            vote_type: VoteType::Prevote,
            a: Some([1; 32].into()),
            b: Some([1; 32].into()),
            vote_a: vote.clone(),
            vote_b: vote.clone(),
        };
        assert!(matches!(
            ev.validate(),
            Err(EvidenceError::DuplicateMessages)
        ));
    }
}
