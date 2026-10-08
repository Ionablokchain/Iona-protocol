//! Governance module: proposals, voting, tallying, and execution.
//!
//! # Lifecycle
//!
//! Each proposal goes through three phases:
//!
//! 1. **Submit** — proposer locks a deposit and opens a voting window
//!    of `voting_period_epochs`.
//! 2. **Vote** — staked voters cast yes/no votes inside the window.
//! 3. **Finalize** — once the window closes, [`GovernanceState::try_finalize`]
//!    computes the outcome and marks the proposal processed.
//!
//! A passed proposal is then **executed at most once** via
//! [`GovernanceState::execute`].
//!
//! # Quorum and threshold
//!
//! Both are expressed in basis points (1 bp = 0.01%):
//!
//! ```text
//! quorum:    voted_stake / total_stake  >= quorum_bps / 10_000
//! threshold: yes_stake   / voted_stake  >= threshold_bps / 10_000
//! ```
//!
//! Ratios are compared as `f64` fractions. `u128` amounts above 2^53 lose
//! precision when converted, but for realistic token totals the leading
//! digits determine the comparison.
//!
//! # Invariants
//!
//! - [`GovernanceParams`] must pass [`GovernanceParams::validate`] before
//!   use; otherwise the tally logic may produce nonsensical results.
//! - A vote is only valid while `start_epoch <= current_epoch < end_epoch`
//!   and before the proposal is processed.
//! - A passed proposal executes at most once.
//! - `try_finalize` is idempotent for processed proposals: it returns the
//!   stored result without recomputing (and therefore is safe to call
//!   after [`GovernanceState::prune_finalized_votes`]).
//!
//! # Storage
//!
//! Votes are stored as `proposal_id -> {voter -> yes/no}`, so per-proposal
//! tallies are O(votes on that proposal) rather than O(all votes ever).
//! Call [`GovernanceState::prune_finalized_votes`] periodically to bound
//! memory on long-running chains.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────

/// Basis-points denominator: 10,000 bp = 100%.
const BPS_DENOMINATOR: u64 = 10_000;

// ── Proposal kind ─────────────────────────────────────────────────────────

/// The action a proposal will execute if it passes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalKind {
    /// Change a configuration parameter.
    ParamChange { key: String, value: String },
    /// Schedule a protocol upgrade.
    Upgrade { target_version: String },
}

// ── Proposal result ───────────────────────────────────────────────────────

/// Final outcome of a proposal.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProposalResult {
    /// Voting ended, quorum met, threshold met.
    Passed,
    /// Voting ended, quorum met, threshold not met.
    Rejected,
    /// Voting ended without reaching quorum.
    Expired,
}

// ── Proposal ──────────────────────────────────────────────────────────────

/// A governance proposal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Proposal {
    pub id: u64,
    pub kind: ProposalKind,
    /// Amount of tokens locked by the proposer.
    pub deposit: u128,
    /// Epoch when voting opens (inclusive).
    pub start_epoch: u64,
    /// Epoch when voting closes (exclusive).
    pub end_epoch: u64,
    /// Whether the proposal has been finalized.
    pub processed: bool,
    /// Final result, set together with `processed`.
    pub result: Option<ProposalResult>,
    /// Whether a passed proposal has been executed.
    ///
    /// `#[serde(default)]` keeps older serialized proposals loadable.
    #[serde(default)]
    pub executed: bool,
}

impl Proposal {
    /// Whether voting is open at `current_epoch`.
    #[must_use]
    pub fn is_voting_open(&self, current_epoch: u64) -> bool {
        !self.processed
            && current_epoch >= self.start_epoch
            && current_epoch < self.end_epoch
    }
}

// ── Governance parameters ─────────────────────────────────────────────────

/// Configuration parameters for the governance module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GovernanceParams {
    /// Minimum deposit required to submit a proposal.
    pub min_deposit: u128,
    /// Number of epochs the voting period lasts.
    pub voting_period_epochs: u64,
    /// Fraction of total stake that must vote (quorum), in basis points.
    pub quorum_bps: u64,
    /// Fraction of votes (yes / voted) needed to pass, in basis points.
    pub threshold_bps: u64,
}

impl Default for GovernanceParams {
    fn default() -> Self {
        Self {
            min_deposit: 1_000_000,     // 1 M tokens
            voting_period_epochs: 100,  // 100 epochs
            quorum_bps: 3_340,          // 33.40%
            threshold_bps: 5_000,       // 50.00%
        }
    }
}

impl GovernanceParams {
    /// Validate the parameter set.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.min_deposit == 0 {
            return Err("min_deposit must be > 0");
        }
        if self.voting_period_epochs == 0 {
            return Err("voting_period_epochs must be > 0");
        }
        if self.quorum_bps == 0 || self.quorum_bps > BPS_DENOMINATOR {
            return Err("quorum_bps must be in (0, 10_000]");
        }
        if self.threshold_bps == 0 || self.threshold_bps > BPS_DENOMINATOR {
            return Err("threshold_bps must be in (0, 10_000]");
        }
        Ok(())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors from [`GovernanceState::submit`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum SubmitError {
    #[error("insufficient deposit: required {required}, provided {provided}")]
    InsufficientDeposit { required: u128, provided: u128 },
    #[error("invalid governance parameters: {0}")]
    InvalidParams(&'static str),
}

/// Errors from [`GovernanceState::vote`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum VoteError {
    #[error("proposal {proposal_id} not found")]
    ProposalNotFound { proposal_id: u64 },
    #[error("proposal {proposal_id} has already been processed")]
    AlreadyProcessed { proposal_id: u64 },
    #[error(
        "voting for proposal {proposal_id} is not yet open \
         (opens at epoch {start_epoch}, now {current_epoch})"
    )]
    VotingNotOpen {
        proposal_id: u64,
        start_epoch: u64,
        current_epoch: u64,
    },
    #[error(
        "voting for proposal {proposal_id} is closed \
         (closed at epoch {end_epoch}, now {current_epoch})"
    )]
    VotingClosed {
        proposal_id: u64,
        end_epoch: u64,
        current_epoch: u64,
    },
}

/// Errors from [`GovernanceState::try_finalize`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum FinalizeError {
    #[error("proposal {proposal_id} not found")]
    ProposalNotFound { proposal_id: u64 },
}

/// Errors from [`GovernanceState::execute`].
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ExecuteError {
    #[error("proposal {proposal_id} not found")]
    ProposalNotFound { proposal_id: u64 },
    #[error("proposal {proposal_id} has not been processed")]
    NotProcessed { proposal_id: u64 },
    #[error("proposal {proposal_id} did not pass (result={result:?})")]
    DidNotPass {
        proposal_id: u64,
        result: Option<ProposalResult>,
    },
    #[error("proposal {proposal_id} has already been executed")]
    AlreadyExecuted { proposal_id: u64 },
    #[error("executor failed for proposal {proposal_id}: {reason}")]
    ExecutorFailed { proposal_id: u64, reason: String },
}

// ── Governance state ──────────────────────────────────────────────────────

/// Persisted governance state.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub params: GovernanceParams,
    pub next_id: u64,
    pub proposals: BTreeMap<u64, Proposal>,
    /// Votes: `proposal_id -> (voter -> yes/no)`.
    ///
    /// Nested rather than a tuple key so per-proposal tallies only visit
    /// the relevant slice.
    pub votes: BTreeMap<u64, BTreeMap<String, bool>>,
}

impl GovernanceState {
    /// Create a state with the given parameters.
    ///
    /// The parameters are **not** validated here; call
    /// [`GovernanceParams::validate`] first (or use [`Self::try_with_params`]).
    #[must_use]
    pub fn with_params(params: GovernanceParams) -> Self {
        Self {
            params,
            ..Default::default()
        }
    }

    /// Create a state with the given parameters, validating them first.
    pub fn try_with_params(params: GovernanceParams) -> Result<Self, SubmitError> {
        params
            .validate()
            .map_err(SubmitError::InvalidParams)?;
        Ok(Self::with_params(params))
    }

    /// Submit a new proposal.
    ///
    /// Returns the assigned proposal ID on success.
    pub fn submit(
        &mut self,
        kind: ProposalKind,
        deposit: u128,
        current_epoch: u64,
    ) -> Result<u64, SubmitError> {
        self.params
            .validate()
            .map_err(SubmitError::InvalidParams)?;

        if deposit < self.params.min_deposit {
            return Err(SubmitError::InsufficientDeposit {
                required: self.params.min_deposit,
                provided: deposit,
            });
        }

        let id = self.next_id;
        self.next_id = self.next_id.saturating_add(1);

        let proposal = Proposal {
            id,
            kind,
            deposit,
            start_epoch: current_epoch,
            end_epoch: current_epoch.saturating_add(self.params.voting_period_epochs),
            processed: false,
            result: None,
            executed: false,
        };
        self.proposals.insert(id, proposal);
        Ok(id)
    }

    /// Record a vote from `voter` on `proposal_id` at `current_epoch`.
    ///
    /// A second vote by the same voter on the same proposal **overwrites**
    /// the previous one. Voting is only accepted while the proposal is
    /// unprocessed and `current_epoch ∈ [start_epoch, end_epoch)`.
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: String,
        yes: bool,
        current_epoch: u64,
    ) -> Result<(), VoteError> {
        let proposal = self
            .proposals
            .get(&proposal_id)
            .ok_or(VoteError::ProposalNotFound { proposal_id })?;

        if proposal.processed {
            return Err(VoteError::AlreadyProcessed { proposal_id });
        }
        if current_epoch < proposal.start_epoch {
            return Err(VoteError::VotingNotOpen {
                proposal_id,
                start_epoch: proposal.start_epoch,
                current_epoch,
            });
        }
        if current_epoch >= proposal.end_epoch {
            return Err(VoteError::VotingClosed {
                proposal_id,
                end_epoch: proposal.end_epoch,
                current_epoch,
            });
        }

        self.votes
            .entry(proposal_id)
            .or_default()
            .insert(voter, yes);
        Ok(())
    }

    /// Sum yes/no stake for a proposal.
    ///
    /// Returns `(yes_stake, no_stake)`. Callers supply `stake_of` to look
    /// up a voter's stake.
    #[must_use]
    pub fn tally(
        &self,
        proposal_id: u64,
        stake_of: impl Fn(&str) -> u128,
    ) -> (u128, u128) {
        let Some(votes) = self.votes.get(&proposal_id) else {
            return (0, 0);
        };
        let mut yes: u128 = 0;
        let mut no: u128 = 0;
        for (voter, &approved) in votes {
            let stake = stake_of(voter.as_str());
            if approved {
                yes = yes.saturating_add(stake);
            } else {
                no = no.saturating_add(stake);
            }
        }
        (yes, no)
    }

    /// Projected outcome if voting ended **now**.
    ///
    /// This is a pure function of the current votes and `total_stake`. It
    /// does **not** check the current epoch — the caller is responsible
    /// for verifying that voting has ended (see [`Self::try_finalize`]).
    ///
    /// Returns:
    /// - `None` if quorum is not met;
    /// - `Some(Passed)` / `Some(Rejected)` otherwise.
    ///
    /// If the proposal has already been processed, returns the stored
    /// result verbatim.
    #[must_use]
    pub fn evaluate(
        &self,
        proposal_id: u64,
        total_stake: u128,
        stake_of: impl Fn(&str) -> u128,
    ) -> Option<ProposalResult> {
        let proposal = self.proposals.get(&proposal_id)?;
        if proposal.processed {
            return proposal.result;
        }
        if total_stake == 0 {
            // No stake → quorum can never be met.
            return None;
        }

        let (yes, no) = self.tally(proposal_id, stake_of);
        let voted = yes.saturating_add(no);

        if !meets_ratio(voted, total_stake, self.params.quorum_bps) {
            return None;
        }
        if meets_ratio(yes, voted, self.params.threshold_bps) {
            Some(ProposalResult::Passed)
        } else {
            Some(ProposalResult::Rejected)
        }
    }

    /// Finalize a proposal once voting has closed.
    ///
    /// - `Ok(Some(result))` — the proposal was finalized (this call, or a
    ///   previous one), and `result` is its outcome.
    /// - `Ok(None)` — the proposal exists but its voting window is still
    ///   open.
    /// - `Err(_)` — the proposal does not exist.
    ///
    /// Idempotent: subsequent calls for a processed proposal return the
    /// stored result without recomputing (safe after pruning votes).
    pub fn try_finalize(
        &mut self,
        proposal_id: u64,
        current_epoch: u64,
        total_stake: u128,
        stake_of: impl Fn(&str) -> u128,
    ) -> Result<Option<ProposalResult>, FinalizeError> {
        // Peek (immutable borrow, released at end of block).
        let (processed, end_epoch, existing) = {
            let p = self
                .proposals
                .get(&proposal_id)
                .ok_or(FinalizeError::ProposalNotFound { proposal_id })?;
            (p.processed, p.end_epoch, p.result)
        };

        if processed {
            return Ok(existing);
        }
        if current_epoch < end_epoch {
            return Ok(None);
        }

        // Compute (immutable borrow of `self`).
        let result = self
            .evaluate(proposal_id, total_stake, stake_of)
            .unwrap_or(ProposalResult::Expired);

        // Apply (mutable borrow).
        let p = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(FinalizeError::ProposalNotFound { proposal_id })?;
        p.result = Some(result);
        p.processed = true;

        Ok(Some(result))
    }

    /// Execute a passed proposal at most once.
    ///
    /// The executor is invoked **before** the `executed` flag is set, so a
    /// failed execution leaves the proposal retryable. Note that an
    /// executor that has already applied a partial effect cannot be rolled
    /// back by this module — executors should be idempotent or atomic.
    pub fn execute(
        &mut self,
        proposal_id: u64,
        executor: impl FnOnce(&ProposalKind) -> Result<(), String>,
    ) -> Result<(), ExecuteError> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(ExecuteError::ProposalNotFound { proposal_id })?;

        if !proposal.processed {
            return Err(ExecuteError::NotProcessed { proposal_id });
        }
        if proposal.result != Some(ProposalResult::Passed) {
            return Err(ExecuteError::DidNotPass {
                proposal_id,
                result: proposal.result,
            });
        }
        if proposal.executed {
            return Err(ExecuteError::AlreadyExecuted { proposal_id });
        }

        executor(&proposal.kind).map_err(|reason| ExecuteError::ExecutorFailed {
            proposal_id,
            reason,
        })?;

        proposal.executed = true;
        Ok(())
    }

    /// Finalize every proposal whose voting window has closed but which is
    /// still unprocessed.
    ///
    /// Returns `(proposal_id, result)` pairs for proposals processed by
    /// this call (proposals finalized in a previous call are not returned).
    pub fn process_expired_proposals(
        &mut self,
        current_epoch: u64,
        total_stake: u128,
        stake_of: impl Fn(&str) -> u128,
    ) -> Vec<(u64, ProposalResult)> {
        let ids: Vec<u64> = self
            .proposals
            .iter()
            .filter(|(_, p)| !p.processed && p.end_epoch <= current_epoch)
            .map(|(&id, _)| id)
            .collect();

        let mut out = Vec::with_capacity(ids.len());
        for id in ids {
            match self.try_finalize(id, current_epoch, total_stake, &stake_of) {
                Ok(Some(res)) => out.push((id, res)),
                Ok(None) => {} // still open — impossible by the filter
                Err(_) => {}   // proposal disappeared — impossible
            }
        }
        out
    }

    /// Remove per-proposal vote maps for every processed proposal.
    ///
    /// Safe to call at any time: `try_finalize` and `evaluate` return the
    /// stored result for processed proposals without touching votes.
    ///
    /// Returns the number of proposals whose votes were dropped.
    pub fn prune_finalized_votes(&mut self) -> usize {
        let ids: Vec<u64> = self
            .proposals
            .iter()
            .filter(|(_, p)| p.processed)
            .map(|(&id, _)| id)
            .collect();

        let mut removed = 0;
        for id in ids {
            if self.votes.remove(&id).is_some() {
                removed += 1;
            }
        }
        removed
    }
}

// ── Ratio helper ──────────────────────────────────────────────────────────

/// True if `num / denom >= bps / 10_000`.
///
/// - `denom == 0` → `false`.
/// - Uses `f64` to avoid overflowing `num * 10_000` and `denom * bps`.
///   For realistic token totals the leading digits decide correctly; the
///   comparison is only near-exact at `u128` extremes.
#[inline]
fn meets_ratio(num: u128, denom: u128, bps: u64) -> bool {
    if denom == 0 {
        return false;
    }
    debug_assert!(bps <= BPS_DENOMINATOR);
    (num as f64) / (denom as f64) >= (bps as f64) / (BPS_DENOMINATOR as f64)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn stake_of(addr: &str) -> u128 {
        match addr {
            "alice" => 500_000,
            "bob" => 300_000,
            "carol" => 200_000,
            _ => 0,
        }
    }

    fn total_stake() -> u128 {
        1_000_000
    }

    fn gov() -> GovernanceState {
        GovernanceState::with_params(GovernanceParams::default())
    }

    fn param_change() -> ProposalKind {
        ProposalKind::ParamChange {
            key: "foo".into(),
            value: "bar".into(),
        }
    }

    // ── Config validation ───────────────────────────────────────────────

    #[test]
    fn config_default_is_valid() {
        assert!(GovernanceParams::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_values() {
        assert!(GovernanceParams { min_deposit: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(GovernanceParams { voting_period_epochs: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(GovernanceParams { quorum_bps: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(GovernanceParams { threshold_bps: 0, ..Default::default() }
            .validate()
            .is_err());
    }

    #[test]
    fn config_rejects_bps_above_100_percent() {
        assert!(GovernanceParams { quorum_bps: 10_001, ..Default::default() }
            .validate()
            .is_err());
        assert!(GovernanceParams { threshold_bps: 10_001, ..Default::default() }
            .validate()
            .is_err());
    }

    #[test]
    fn try_with_params_rejects_invalid() {
        let bad = GovernanceParams { quorum_bps: 0, ..Default::default() };
        assert!(GovernanceState::try_with_params(bad).is_err());
        assert!(GovernanceState::try_with_params(GovernanceParams::default()).is_ok());
    }

    // ── Submit ──────────────────────────────────────────────────────────

    #[test]
    fn submit_rejects_insufficient_deposit() {
        let mut gov = gov();
        let err = gov
            .submit(param_change(), 100, 0)
            .expect_err("deposit too low");
        assert!(matches!(err, SubmitError::InsufficientDeposit { .. }));
    }

    #[test]
    fn submit_assigns_monotonic_ids() {
        let mut gov = gov();
        let a = gov.submit(param_change(), 1_000_000, 0).unwrap();
        let b = gov.submit(param_change(), 1_000_000, 0).unwrap();
        assert_eq!(b, a + 1);
    }

    // ── Vote validation ─────────────────────────────────────────────────

    #[test]
    fn vote_on_missing_proposal_fails() {
        let mut gov = gov();
        let err = gov.vote(42, "alice".into(), true, 0).unwrap_err();
        assert!(matches!(err, VoteError::ProposalNotFound { proposal_id: 42 }));
    }

    #[test]
    fn vote_before_window_fails() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 10).unwrap();
        let err = gov.vote(id, "alice".into(), true, 5).unwrap_err();
        assert!(matches!(err, VoteError::VotingNotOpen { .. }));
    }

    #[test]
    fn vote_after_window_fails() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        let err = gov.vote(id, "alice".into(), true, 200).unwrap_err();
        assert!(matches!(err, VoteError::VotingClosed { .. }));
    }

    #[test]
    fn vote_on_processed_proposal_fails() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        gov.try_finalize(id, 101, total_stake(), stake_of).unwrap();
        let err = gov.vote(id, "bob".into(), false, 0).unwrap_err();
        assert!(matches!(err, VoteError::AlreadyProcessed { .. }));
    }

    #[test]
    fn revote_overwrites_previous() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        gov.vote(id, "alice".into(), false, 0).unwrap();
        let (yes, no) = gov.tally(id, stake_of);
        assert_eq!(yes, 0);
        assert_eq!(no, 500_000);
    }

    // ── Tally ───────────────────────────────────────────────────────────

    #[test]
    fn tally_ignores_other_proposals() {
        let mut gov = gov();
        let a = gov.submit(param_change(), 1_000_000, 0).unwrap();
        let b = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(a, "alice".into(), true, 0).unwrap();
        gov.vote(b, "bob".into(), false, 0).unwrap();

        let (yes_a, no_a) = gov.tally(a, stake_of);
        assert_eq!((yes_a, no_a), (500_000, 0));

        let (yes_b, no_b) = gov.tally(b, stake_of);
        assert_eq!((yes_b, no_b), (0, 300_000));
    }

    // ── Evaluate / finalize ─────────────────────────────────────────────

    #[test]
    fn evaluate_returns_none_without_quorum() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap(); // 500k of 1M = 50%
        // Default quorum is 33.4% — met. Raise the bar.
        let strict = GovernanceParams {
            quorum_bps: 8_000,
            ..Default::default()
        };
        gov.params = strict;
        assert!(gov.evaluate(id, total_stake(), stake_of).is_none());
    }

    #[test]
    fn evaluate_returns_none_on_zero_total_stake() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        assert!(gov.evaluate(id, 0, stake_of).is_none());
    }

    #[test]
    fn try_finalize_returns_none_while_window_open() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        let res = gov.try_finalize(id, 50, total_stake(), stake_of).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn try_finalize_unknown_proposal_fails() {
        let mut gov = gov();
        assert!(matches!(
            gov.try_finalize(42, 999, total_stake(), stake_of),
            Err(FinalizeError::ProposalNotFound { .. })
        ));
    }

    #[test]
    fn try_finalize_is_idempotent_after_pruning() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        let first = gov.try_finalize(id, 101, total_stake(), stake_of).unwrap();
        assert_eq!(first, Some(ProposalResult::Passed));

        gov.prune_finalized_votes();

        let second = gov.try_finalize(id, 999, total_stake(), stake_of).unwrap();
        assert_eq!(first, second);
    }

    // ── Lifecycle ───────────────────────────────────────────────────────

    #[test]
    fn lifecycle_passes_then_executes_once() {
        let mut gov = gov();
        let epoch = 0u64;
        let id = gov
            .submit(param_change(), 1_000_000, epoch)
            .unwrap();

        gov.vote(id, "alice".into(), true, epoch).unwrap();
        gov.vote(id, "bob".into(), false, epoch).unwrap();
        gov.vote(id, "carol".into(), true, epoch).unwrap();

        // Still inside the voting period.
        assert!(gov
            .try_finalize(id, epoch + 50, total_stake(), stake_of)
            .unwrap()
            .is_none());

        // After the period.
        let res = gov
            .try_finalize(id, epoch + 101, total_stake(), stake_of)
            .unwrap();
        assert_eq!(res, Some(ProposalResult::Passed));

        // Execute once.
        let executed = std::cell::Cell::new(false);
        gov.execute(id, |kind| {
            if let ProposalKind::ParamChange { key, value } = kind {
                assert_eq!(key, "foo");
                assert_eq!(value, "bar");
            } else {
                return Err("unexpected kind".into());
            }
            executed.set(true);
            Ok(())
        })
        .unwrap();
        assert!(executed.get());

        // Execute again → rejected.
        let err = gov.execute(id, |_| Ok(())).unwrap_err();
        assert!(matches!(err, ExecuteError::AlreadyExecuted { .. }));
    }

    #[test]
    fn execute_rejects_unprocessed() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        let err = gov.execute(id, |_| Ok(())).unwrap_err();
        assert!(matches!(err, ExecuteError::NotProcessed { .. }));
    }

    #[test]
    fn execute_rejects_rejected_proposals() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "bob".into(), false, 0).unwrap();
        gov.vote(id, "carol".into(), false, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        let _ = gov
            .try_finalize(id, 101, total_stake(), stake_of)
            .unwrap()
            .unwrap();
        let err = gov.execute(id, |_| Ok(())).unwrap_err();
        assert!(matches!(err, ExecuteError::DidNotPass { .. }));
    }

    #[test]
    fn execute_leaves_proposal_retryable_on_failure() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        gov.vote(id, "carol".into(), true, 0).unwrap();
        let _ = gov.try_finalize(id, 101, total_stake(), stake_of).unwrap();

        // First attempt fails.
        let err = gov
            .execute(id, |_| Err("transient failure".into()))
            .unwrap_err();
        assert!(matches!(err, ExecuteError::ExecutorFailed { .. }));

        // Retry succeeds.
        gov.execute(id, |_| Ok(())).unwrap();
    }

    // ── Expired handling ────────────────────────────────────────────────

    #[test]
    fn expired_when_quorum_misses() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(id, "alice".into(), true, 0).unwrap();
        // Pretend total stake is 2M → quorum needs 668k, only 500k voted.
        let res = gov
            .try_finalize(id, 101, 2_000_000, stake_of)
            .unwrap();
        assert_eq!(res, Some(ProposalResult::Expired));
    }

    // ── Bulk finalization ───────────────────────────────────────────────

    #[test]
    fn process_expired_processes_only_closed_proposals() {
        let mut gov = gov();
        let a = gov.submit(param_change(), 1_000_000, 0).unwrap();  // closes at 100
        let b = gov.submit(param_change(), 1_000_000, 0).unwrap();  // closes at 100
        let c = gov.submit(param_change(), 1_000_000, 200).unwrap(); // closes at 300

        gov.vote(a, "alice".into(), true, 0).unwrap();
        gov.vote(b, "bob".into(), false, 0).unwrap();
        gov.vote(c, "carol".into(), true, 200).unwrap();

        let processed = gov.process_expired_proposals(150, total_stake(), stake_of);
        assert_eq!(processed.len(), 2);
        let ids: Vec<u64> = processed.iter().map(|(id, _)| *id).collect();
        assert!(ids.contains(&a) && ids.contains(&b));
        assert!(!ids.contains(&c));

        // Second call at the same epoch processes nothing new.
        let processed2 = gov.process_expired_proposals(150, total_stake(), stake_of);
        assert!(processed2.is_empty());

        // At 350, c is now closed.
        let processed3 = gov.process_expired_proposals(350, total_stake(), stake_of);
        assert_eq!(processed3.len(), 1);
        assert_eq!(processed3[0].0, c);
    }

    // ── Pruning ─────────────────────────────────────────────────────────

    #[test]
    fn prune_removes_only_finalized_votes() {
        let mut gov = gov();
        let a = gov.submit(param_change(), 1_000_000, 0).unwrap();
        let b = gov.submit(param_change(), 1_000_000, 0).unwrap();
        gov.vote(a, "alice".into(), true, 0).unwrap();
        gov.vote(b, "bob".into(), false, 0).unwrap();

        let _ = gov.try_finalize(a, 101, total_stake(), stake_of);
        let removed = gov.prune_finalized_votes();
        assert_eq!(removed, 1);
        assert!(!gov.votes.contains_key(&a));
        assert!(gov.votes.contains_key(&b));
    }

    // ── Overflow ────────────────────────────────────────────────────────

    #[test]
    fn tallies_saturate_on_overflow() {
        let mut gov = gov();
        let id = gov.submit(param_change(), 1_000_000, 0).unwrap();
        // Register two voters with huge stake.
        let huge_stake = |_: &str| u128::MAX;
        gov.vote(id, "a".into(), true, 0).unwrap();
        gov.vote(id, "b".into(), true, 0).unwrap();
        let (yes, no) = gov.tally(id, huge_stake);
        assert_eq!(yes, u128::MAX);
        assert_eq!(no, 0);
    }
}
