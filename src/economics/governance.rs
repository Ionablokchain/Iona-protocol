use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Proposal kind
// -----------------------------------------------------------------------------

/// The type of action to be executed if the proposal passes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Change a configuration parameter.
    ParamChange { key: String, value: String },
    /// Schedule a protocol upgrade.
    Upgrade { target_version: String },
}

// -----------------------------------------------------------------------------
// Proposal
// -----------------------------------------------------------------------------

/// A governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub kind: ProposalKind,
    /// Amount of tokens deposited by the proposer.
    pub deposit: u128,
    /// Epoch when voting starts.
    pub start_epoch: u64,
    /// Epoch when voting ends.
    pub end_epoch: u64,
    /// Whether the proposal has been processed (passed or rejected).
    pub processed: bool,
    /// The final result, if processed.
    pub result: Option<ProposalResult>,
}

/// The outcome of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalResult {
    Passed,
    Rejected,
    Expired,   // did not meet quorum
}

// -----------------------------------------------------------------------------
// Governance state
// -----------------------------------------------------------------------------

/// Configuration parameters for the governance module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Minimum deposit required to submit a proposal.
    pub min_deposit: u128,
    /// Number of epochs the voting period lasts.
    pub voting_period_epochs: u64,
    /// Fraction of total stake that must vote (quorum). Expressed in basis points (1 = 0.01%).
    pub quorum_bps: u64,
    /// Fraction of votes (yes / total) needed to pass. Expressed in basis points.
    pub threshold_bps: u64,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_deposit: 1_000_000,          // 1 M tokens
            voting_period_epochs: 100,        // 100 epochs
            quorum_bps: 3340,                 // 33.4% of total stake must vote
            threshold_bps: 5000,              // 50% of votes must be yes
        }
    }
}

/// The main governance state, persisted in the chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub params: GovernanceParams,
    pub next_id: u64,
    pub proposals: BTreeMap<u64, Proposal>,
    /// Votes: (proposal_id, voter) -> yes/no
    pub votes: BTreeMap<(u64, String), bool>,
}

impl GovernanceState {
    /// Submits a new proposal.
    /// Returns the proposal ID, or `None` if deposit is insufficient.
    pub fn submit(
        &mut self,
        kind: ProposalKind,
        deposit: u128,
        current_epoch: u64,
    ) -> Option<u64> {
        if deposit < self.params.min_deposit {
            return None;
        }
        let id = self.next_id;
        self.next_id += 1;
        let proposal = Proposal {
            id,
            kind,
            deposit,
            start_epoch: current_epoch,
            end_epoch: current_epoch.saturating_add(self.params.voting_period_epochs),
            processed: false,
            result: None,
        };
        self.proposals.insert(id, proposal);
        Some(id)
    }

    /// Records a vote. If the voter has already voted, the vote is overwritten.
    pub fn vote(&mut self, proposal_id: u64, voter: String, yes: bool) {
        self.votes.insert((proposal_id, voter), yes);
    }

    /// Tally votes for a proposal, using the current total stake (passed as argument).
    /// Returns `(yes_stake, no_stake)`.
    pub fn tally(&self, proposal_id: u64, total_stake: u128, stake_of: impl Fn(&str) -> u128) -> (u128, u128) {
        let mut yes = 0u128;
        let mut no = 0u128;
        for ((pid, voter), &vote) in &self.votes {
            if *pid != proposal_id {
                continue;
            }
            let stake = stake_of(voter);
            if vote {
                yes = yes.saturating_add(stake);
            } else {
                no = no.saturating_add(stake);
            }
        }
        (yes, no)
    }

    /// Determines the outcome of a proposal based on stake votes and quorum.
    /// Returns `Some(ProposalResult)` if the proposal can be finalized.
    pub fn evaluate(&self, proposal_id: u64, total_stake: u128, stake_of: impl Fn(&str) -> u128) -> Option<ProposalResult> {
        let proposal = self.proposals.get(&proposal_id)?;
        if proposal.processed {
            return proposal.result;
        }

        let (yes, no) = self.tally(proposal_id, total_stake, stake_of);
        let voted_stake = yes + no;
        let quorum_needed = total_stake * self.params.quorum_bps as u128 / 10_000;

        if voted_stake < quorum_needed {
            // Not enough participation yet → cannot finalize.
            return None;
        }

        let threshold = voted_stake * self.params.threshold_bps as u128 / 10_000;
        let result = if yes >= threshold {
            ProposalResult::Passed
        } else {
            ProposalResult::Rejected
        };
        Some(result)
    }

    /// Finalize a proposal if its voting period has ended and it meets quorum.
    /// Returns `Ok(Some(ProposalResult))` if the proposal was processed, `Ok(None)` if
    /// it is still active, or `Err` if the proposal does not exist.
    pub fn try_finalize(
        &mut self,
        proposal_id: u64,
        current_epoch: u64,
        total_stake: u128,
        stake_of: impl Fn(&str) -> u128,
    ) -> Result<Option<ProposalResult>, &'static str> {
        let proposal = self.proposals.get_mut(&proposal_id).ok_or("Proposal not found")?;
        if proposal.processed {
            return Ok(proposal.result);
        }
        if current_epoch < proposal.end_epoch {
            return Ok(None);
        }

        // Determine result (may be None if quorum not met even after end_epoch)
        let result = self.evaluate(proposal_id, total_stake, stake_of).unwrap_or(ProposalResult::Expired);
        proposal.result = Some(result);
        proposal.processed = true;

        // Handle deposit: if proposal passed or expired (no quorum), return deposit to proposer.
        // In a real implementation, you would transfer tokens back to the proposer's account.
        // For a pure model, we just return the result.
        // If rejected, the deposit is burned (or sent to treasury).
        Ok(Some(result))
    }

    /// Execute a passed proposal. This should be called after finalization, e.g., at the next block.
    /// Returns `Ok(())` if execution was successful, `Err` otherwise.
    pub fn execute(&self, proposal_id: u64, executor: impl FnOnce(&ProposalKind) -> Result<(), String>) -> Result<(), String> {
        let proposal = self.proposals.get(&proposal_id).ok_or("Proposal not found")?;
        if !proposal.processed {
            return Err("Proposal not yet processed".into());
        }
        if proposal.result != Some(ProposalResult::Passed) {
            return Err("Proposal did not pass".into());
        }
        executor(&proposal.kind)
    }

    /// Process all proposals that have reached their end epoch.
    pub fn process_expired_proposals(
        &mut self,
        current_epoch: u64,
        total_stake: u128,
        stake_of: impl Fn(&str) -> u128,
    ) -> Vec<(u64, ProposalResult)> {
        let ids: Vec<u64> = self.proposals.keys().copied().collect();
        let mut results = Vec::new();
        for id in ids {
            if let Ok(Some(res)) = self.try_finalize(id, current_epoch, total_stake, &stake_of) {
                results.push((id, res));
            }
        }
        results
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stake_of(addr: &str) -> u128 {
        match addr {
            "alice" => 500_000,
            "bob"   => 300_000,
            "carol" => 200_000,
            _ => 0,
        }
    }

    fn total_stake() -> u128 {
        500_000 + 300_000 + 200_000
    }

    #[test]
    fn test_proposal_lifecycle() {
        let mut gov = GovernanceState::default();
        let params = GovernanceParams::default();
        gov.params = params;

        let epoch = 0;
        let id = gov.submit(ProposalKind::ParamChange { key: "foo".into(), value: "bar".into() }, 1_000_000, epoch).unwrap();

        // Vote
        gov.vote(id, "alice".into(), true);
        gov.vote(id, "bob".into(), false);
        gov.vote(id, "carol".into(), true);

        // Not yet final (epoch still inside voting period)
        let res = gov.try_finalize(id, epoch + 50, total_stake(), stake_of).unwrap();
        assert!(res.is_none());

        // After voting period ends
        let res = gov.try_finalize(id, epoch + 101, total_stake(), stake_of).unwrap();
        assert_eq!(res, Some(ProposalResult::Passed));

        // Execute
        let executed = std::cell::RefCell::new(false);
        let executor = |kind: &ProposalKind| {
            if let ProposalKind::ParamChange { key, value } = kind {
                assert_eq!(key, "foo");
                assert_eq!(value, "bar");
                *executed.borrow_mut() = true;
                Ok(())
            } else {
                Err("unexpected kind".into())
            }
        };
        gov.execute(id, executor).unwrap();
        assert!(*executed.borrow());
    }

    #[test]
    fn test_quorum_failure() {
        let mut gov = GovernanceState::default();
        let mut params = GovernanceParams::default();
        params.quorum_bps = 5000; // 50% of total stake must vote
        gov.params = params;

        let id = gov.submit(ProposalKind::ParamChange { key: "x".into(), value: "y".into() }, 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true); // 500 000 stake votes, but total = 1 000 000, quorum = 500 000, ok

        // Let it expire
        let res = gov.try_finalize(id, 101, total_stake(), stake_of).unwrap();
        assert_eq!(res, Some(ProposalResult::Passed)); // passed because yes stake >= threshold

        // Now test no quorum: reduce total stake but keep same votes
        let id2 = gov.submit(ProposalKind::ParamChange { key: "x".into(), value: "y".into() }, 1_000_000, 0).unwrap();
        gov.vote(id2, "alice".into(), true);
        // Pretend total stake is 2 000 000, quorum needs 1 000 000, but alice only has 500 000
        let huge_total = 2_000_000;
        let res = gov.try_finalize(id2, 101, huge_total, stake_of).unwrap();
        assert_eq!(res, Some(ProposalResult::Expired));
    }
}
