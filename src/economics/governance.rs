//! On‑chain governance for IONA.
//!
//! Provides proposal submission, voting, and tallying for parameter changes
//! and protocol upgrades. Proposals are active for a fixed number of epochs.
//!
//! # Example
//!
//! ```
//! use iona::governance::{GovernanceState, ProposalKind, GovernanceError};
//!
//! let mut gov = GovernanceState::new();
//! let id = gov.submit(ProposalKind::ParamChange { key: "min_gas_price".into(), value: "1".into() }, 1000, 10, 5)?;
//! gov.vote(id, "validator1".into(), true)?;
//! let (yes, no) = gov.tally(id);
//! assert_eq!(yes, 1);
//! # Ok::<(), GovernanceError>(())
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during governance operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovernanceError {
    #[error("deposit must be > 0, got {0}")]
    ZeroDeposit(u128),
    #[error("voting epochs must be > 0, got {0}")]
    ZeroVotingEpochs(u64),
    #[error("proposal {0} not found")]
    ProposalNotFound(u64),
    #[error("proposal {0} is not active (ended at epoch {end_epoch})")]
    ProposalInactive { id: u64, end_epoch: u64 },
    #[error("proposal {0} already executed")]
    AlreadyExecuted(u64),
}

pub type GovernanceResult<T> = Result<T, GovernanceError>;

// -----------------------------------------------------------------------------
// Proposal types
// -----------------------------------------------------------------------------

/// Type of governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Change a configuration parameter.
    ParamChange { key: String, value: String },
    /// Upgrade the protocol to a new version.
    Upgrade { target_version: String },
}

/// A governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub kind: ProposalKind,
    pub deposit: u128,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub executed: bool,
}

impl Proposal {
    /// Check if the proposal is active at the given epoch.
    pub fn is_active(&self, epoch: u64) -> bool {
        !self.executed && epoch >= self.start_epoch && epoch < self.end_epoch
    }
}

// -----------------------------------------------------------------------------
// Governance state
// -----------------------------------------------------------------------------

/// In‑memory governance state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub next_id: u64,
    pub proposals: BTreeMap<u64, Proposal>,
    pub votes: BTreeMap<(u64, String), bool>, // (proposal_id, voter) -> yes/no
}

impl GovernanceState {
    /// Create a new governance state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Submit a new proposal.
    ///
    /// `deposit` must be > 0 (burned if proposal fails).
    /// `start_epoch` is the epoch when voting begins.
    /// `voting_epochs` must be > 0; the proposal ends at `start_epoch + voting_epochs`.
    pub fn submit(
        &mut self,
        kind: ProposalKind,
        deposit: u128,
        start_epoch: u64,
        voting_epochs: u64,
    ) -> GovernanceResult<u64> {
        if deposit == 0 {
            return Err(GovernanceError::ZeroDeposit(deposit));
        }
        if voting_epochs == 0 {
            return Err(GovernanceError::ZeroVotingEpochs(voting_epochs));
        }
        let id = self.next_id;
        self.next_id += 1;
        let proposal = Proposal {
            id,
            kind,
            deposit,
            start_epoch,
            end_epoch: start_epoch.saturating_add(voting_epochs),
            executed: false,
        };
        self.proposals.insert(id, proposal);
        Ok(id)
    }

    /// Cast a vote on a proposal.
    ///
    /// The proposal must be active at the current epoch.
    pub fn vote(&mut self, proposal_id: u64, voter: String, yes: bool, current_epoch: u64) -> GovernanceResult<()> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        if !proposal.is_active(current_epoch) {
            return Err(GovernanceError::ProposalInactive {
                id: proposal_id,
                end_epoch: proposal.end_epoch,
            });
        }
        self.votes.insert((proposal_id, voter), yes);
        Ok(())
    }

    /// Mark a proposal as executed (e.g., after quorum is reached).
    pub fn execute(&mut self, proposal_id: u64) -> GovernanceResult<()> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;
        if proposal.executed {
            return Err(GovernanceError::AlreadyExecuted(proposal_id));
        }
        proposal.executed = true;
        Ok(())
    }

    /// Tally votes for a proposal.
    ///
    /// Returns `(yes_count, no_count)`.
    pub fn tally(&self, proposal_id: u64) -> (u64, u64) {
        let mut yes = 0;
        let mut no = 0;
        for ((pid, _), &v) in self.votes.iter() {
            if *pid == proposal_id {
                if v {
                    yes += 1;
                } else {
                    no += 1;
                }
            }
        }
        (yes, no)
    }

    /// Get a proposal by ID.
    pub fn get_proposal(&self, id: u64) -> Option<&Proposal> {
        self.proposals.get(&id)
    }

    /// Get all active proposals at the given epoch.
    pub fn active_proposals(&self, epoch: u64) -> Vec<&Proposal> {
        self.proposals
            .values()
            .filter(|p| p.is_active(epoch))
            .collect()
    }

    /// Remove expired proposals (optional cleanup).
    pub fn prune_expired(&mut self, epoch: u64) -> usize {
        let expired: Vec<u64> = self
            .proposals
            .iter()
            .filter(|(_, p)| p.end_epoch <= epoch || p.executed)
            .map(|(&id, _)| id)
            .collect();
        let count = expired.len();
        for id in expired {
            self.proposals.remove(&id);
            // Also remove votes for this proposal to keep state clean.
            let votes_to_remove: Vec<(u64, String)> = self
                .votes
                .keys()
                .filter(|(pid, _)| *pid == id)
                .cloned()
                .collect();
            for key in votes_to_remove {
                self.votes.remove(&key);
            }
        }
        count
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_submit_and_vote() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let kind = ProposalKind::ParamChange {
            key: "max_block_gas".into(),
            value: "30000000".into(),
        };
        let id = gov.submit(kind, 1000, 10, 5)?;
        assert_eq!(id, 0);
        let proposal = gov.get_proposal(id).unwrap();
        assert!(!proposal.executed);
        assert_eq!(proposal.start_epoch, 10);
        assert_eq!(proposal.end_epoch, 15);

        // Vote at epoch 12 (active)
        gov.vote(id, "alice".into(), true, 12)?;
        gov.vote(id, "bob".into(), false, 13)?;
        let (yes, no) = gov.tally(id);
        assert_eq!(yes, 1);
        assert_eq!(no, 1);

        // Vote after end epoch should fail
        let err = gov.vote(id, "carol".into(), true, 15);
        assert!(matches!(err, Err(GovernanceError::ProposalInactive { id: 0, end_epoch: 15 })));
        Ok(())
    }

    #[test]
    fn test_submit_invalid() {
        let mut gov = GovernanceState::new();
        let kind = ProposalKind::Upgrade { target_version: "2.0".into() };
        let err = gov.submit(kind.clone(), 0, 10, 5).unwrap_err();
        assert!(matches!(err, GovernanceError::ZeroDeposit(0)));

        let err = gov.submit(kind, 1000, 10, 0).unwrap_err();
        assert!(matches!(err, GovernanceError::ZeroVotingEpochs(0)));
    }

    #[test]
    fn test_execute() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let id = gov.submit(ProposalKind::ParamChange { key: "a".into(), value: "b".into() }, 1000, 1, 5)?;
        gov.execute(id)?;
        let prop = gov.get_proposal(id).unwrap();
        assert!(prop.executed);
        let err = gov.execute(id).unwrap_err();
        assert!(matches!(err, GovernanceError::AlreadyExecuted(0)));
        Ok(())
    }

    #[test]
    fn test_active_proposals() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        gov.submit(ProposalKind::ParamChange { key: "p1".into(), value: "v1".into() }, 1000, 5, 10)?;
        gov.submit(ProposalKind::ParamChange { key: "p2".into(), value: "v2".into() }, 1000, 20, 10)?;
        let active_at_epoch_10 = gov.active_proposals(10);
        assert_eq!(active_at_epoch_10.len(), 1);
        let active_at_epoch_25 = gov.active_proposals(25);
        assert_eq!(active_at_epoch_25.len(), 1);
        Ok(())
    }

    #[test]
    fn test_prune_expired() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        gov.submit(ProposalKind::ParamChange { key: "p1".into(), value: "v1".into() }, 1000, 10, 5)?;
        gov.submit(ProposalKind::ParamChange { key: "p2".into(), value: "v2".into() }, 1000, 20, 10)?;
        // p1 ends at 15, p2 ends at 30
        let count = gov.prune_expired(16);
        assert_eq!(count, 1);
        assert!(gov.get_proposal(0).is_none());
        assert!(gov.get_proposal(1).is_some());
        Ok(())
    }
}
