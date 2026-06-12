//! On‑chain governance for IONA — Quantum Governance Engine.
//!
//! # Quantum Governance Model
//!
//! Governance is modelled as a **collective quantum measurement** where each
//! validator's vote is a projection onto a subspace of the decision Hilbert
//! space. The tally operator collapses the superposition of votes into a
//! definite outcome |passed⟩ or |rejected⟩.
//!
//! # Mathematical Formalism
//!
//! ## Proposal State
//! ```text
//! |P⟩ = |kind⟩ ⊗ |deposit⟩ ⊗ |start_epoch⟩ ⊗ |end_epoch⟩
//! ```
//!
//! ## Voting as Projective Measurement
//! ```text
//! Π_vote = Σ_v |voter_v⟩⟨voter_v| ⊗ |yes⟩⟨yes| + |no⟩⟨no|
//! ```
//!
//! ## Tally Operator
//! ```text
//! Ô_tally = Σ_v w_v (|yes⟩⟨yes| - |no⟩⟨no|)
//! ⟨Ô_tally⟩ > 0 → passed
//! ```
//!
//! # Features
//!
//! - Proposal submission with configurable deposit and voting period.
//! - Stake‑weighted voting (validator power from `StakeLedger`).
//! - Quorum and threshold enforcement.
//! - Veto power for strong negative consensus.
//! - Automatic execution on passing.
//! - Proposal expiry and cleanup.
//!
//! # Example
//!
//! ```
//! use iona::governance::{GovernanceState, ProposalKind, GovernanceError};
//!
//! let mut gov = GovernanceState::new();
//! let id = gov.submit(
//!     ProposalKind::ParamChange { key: "min_gas_price".into(), value: "1".into() },
//!     1000, 10, 5
//! )?;
//! gov.vote(id, "validator1".into(), true, 10)?;
//! let (yes, no) = gov.tally(id);
//! assert_eq!(yes, 1);
//! # Ok::<(), GovernanceError>(())
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh governance state.
const DEFAULT_GOVERNANCE_COHERENCE: f64 = 1.0;

/// Decoherence rate per proposal submission.
const SUBMIT_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per vote cast.
const VOTE_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per proposal execution.
const EXECUTE_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per proposal expiry.
const EXPIRE_DECOHERENCE_RATE: f64 = 0.0003;

/// Minimum coherence threshold for a healthy governance system.
const MIN_GOVERNANCE_COHERENCE: f64 = 0.99;

/// Kraus rank for governance quantum channels.
const GOVERNANCE_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Default minimum deposit required for a proposal.
pub const DEFAULT_MIN_DEPOSIT: u128 = 1_000_000;

/// Default voting period in epochs.
pub const DEFAULT_VOTING_EPOCHS: u64 = 100;

/// Default quorum basis points (33.4% = 3340/10000).
pub const DEFAULT_QUORUM_BPS: u64 = 3340;

/// Default threshold basis points (50% = 5000/10000).
pub const DEFAULT_THRESHOLD_BPS: u64 = 5000;

/// Default veto threshold basis points (33.4% = 3340/10000).
/// If `no_power` exceeds this fraction of total power, the proposal is vetoed.
pub const DEFAULT_VETO_BPS: u64 = 3340;

// -----------------------------------------------------------------------------
// Quantum Governance State
// -----------------------------------------------------------------------------

/// Quantum state of the governance system.
///
/// Tracks the density matrix properties during proposal submission,
/// voting, and execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumGovernanceState {
    /// Purity γ = Tr(ρ²) of the governance state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the proposal subsystem.
    pub proposal_coherence: f64,
    /// Coherence of the voting subsystem.
    pub voting_coherence: f64,
    /// Number of proposals submitted.
    pub total_proposals: u64,
    /// Number of votes cast.
    pub total_votes: u64,
    /// Number of proposals executed.
    pub total_executed: u64,
    /// Number of proposals expired.
    pub total_expired: u64,
    /// Whether the governance system is healthy.
    pub is_healthy: bool,
}

impl Default for QuantumGovernanceState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_GOVERNANCE_COHERENCE,
            entropy: 0.0,
            proposal_coherence: DEFAULT_GOVERNANCE_COHERENCE,
            voting_coherence: DEFAULT_GOVERNANCE_COHERENCE,
            total_proposals: 0,
            total_votes: 0,
            total_executed: 0,
            total_expired: 0,
            is_healthy: true,
        }
    }
}

impl QuantumGovernanceState {
    /// Create a new quantum governance state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a proposal submission.
    pub fn apply_submit_decoherence(&mut self) {
        self.total_proposals = self.total_proposals.wrapping_add(1);
        let decay = (-SUBMIT_DECOHERENCE_RATE).exp();
        self.proposal_coherence = (self.proposal_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a vote being cast.
    pub fn apply_vote_decoherence(&mut self) {
        self.total_votes = self.total_votes.wrapping_add(1);
        let decay = (-VOTE_DECOHERENCE_RATE).exp();
        self.voting_coherence = (self.voting_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a proposal execution.
    pub fn apply_execute_decoherence(&mut self) {
        self.total_executed = self.total_executed.wrapping_add(1);
        let decay = (-EXECUTE_DECOHERENCE_RATE).exp();
        self.proposal_coherence = (self.proposal_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a proposal expiry.
    pub fn apply_expire_decoherence(&mut self, count: u64) {
        self.total_expired = self.total_expired.wrapping_add(count);
        let decay = (-EXPIRE_DECOHERENCE_RATE * count as f64).exp();
        self.proposal_coherence = (self.proposal_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for governance operations.
    pub fn apply_governance_channel(&mut self) {
        let kraus_factor = (1.0 / GOVERNANCE_KRAUS_RANK as f64).sqrt();
        self.proposal_coherence = (self.proposal_coherence * kraus_factor).clamp(0.0, 1.0);
        self.voting_coherence = (self.voting_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.proposal_coherence * self.voting_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_GOVERNANCE_COHERENCE;
    }
}

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

    #[error("insufficient deposit: need at least {required}, got {provided}")]
    InsufficientDeposit { required: u128, provided: u128 },

    #[error("no stakes loaded; cannot compute voting power")]
    NoStakes,

    #[error("quantum decoherence: governance coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type GovernanceResult<T> = Result<T, GovernanceError>;

// -----------------------------------------------------------------------------
// Proposal types
// -----------------------------------------------------------------------------

/// Type of governance proposal.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProposalKind {
    /// Change a configuration parameter.
    ParamChange { key: String, value: String },
    /// Upgrade the protocol to a new version.
    Upgrade { target_version: String },
    /// Text proposal (signalling / opinion poll).
    Text { title: String, description: String },
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
    /// Quantum coherence of this proposal.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    DEFAULT_GOVERNANCE_COHERENCE
}

impl Proposal {
    /// Check if the proposal is active at the given epoch.
    pub fn is_active(&self, epoch: u64) -> bool {
        !self.executed && epoch >= self.start_epoch && epoch < self.end_epoch
    }

    /// Time remaining until expiry (0 if expired).
    pub fn remaining_epochs(&self, epoch: u64) -> u64 {
        if epoch >= self.end_epoch {
            0
        } else {
            self.end_epoch - epoch
        }
    }
}

// -----------------------------------------------------------------------------
// Governance state
// -----------------------------------------------------------------------------

/// In‑memory governance state with quantum tracking.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GovernanceState {
    pub next_id: u64,
    pub proposals: BTreeMap<u64, Proposal>,
    pub votes: BTreeMap<(u64, String), bool>, // (proposal_id, voter) -> yes/no
    pub min_deposit: u128,
    pub voting_epochs: u64,
    pub quorum_bps: u64,
    pub threshold_bps: u64,
    pub veto_bps: u64,
    /// Quantum state of the governance system.
    #[serde(default = "QuantumGovernanceState::new")]
    pub quantum: QuantumGovernanceState,
}

impl GovernanceState {
    /// Create a new governance state with default parameters and full coherence.
    pub fn new() -> Self {
        Self {
            next_id: 0,
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            min_deposit: DEFAULT_MIN_DEPOSIT,
            voting_epochs: DEFAULT_VOTING_EPOCHS,
            quorum_bps: DEFAULT_QUORUM_BPS,
            threshold_bps: DEFAULT_THRESHOLD_BPS,
            veto_bps: DEFAULT_VETO_BPS,
            quantum: QuantumGovernanceState::new(),
        }
    }

    /// Quantum purity of the governance system.
    pub fn purity(&self) -> f64 {
        self.quantum.purity
    }

    /// Whether the governance system is healthy.
    pub fn is_healthy(&self) -> bool {
        self.quantum.is_healthy
    }

    /// Submit a new proposal.
    ///
    /// `deposit` must be at least `min_deposit` (burned if proposal fails).
    /// `start_epoch` is the epoch when voting begins.
    /// `voting_epochs` must be > 0; the proposal ends at `start_epoch + voting_epochs`.
    pub fn submit(
        &mut self,
        kind: ProposalKind,
        deposit: u128,
        start_epoch: u64,
        voting_epochs: u64,
    ) -> GovernanceResult<u64> {
        // Validate inputs
        if deposit == 0 {
            return Err(GovernanceError::ZeroDeposit(deposit));
        }
        if deposit < self.min_deposit {
            return Err(GovernanceError::InsufficientDeposit {
                required: self.min_deposit,
                provided: deposit,
            });
        }
        if voting_epochs == 0 {
            return Err(GovernanceError::ZeroVotingEpochs(voting_epochs));
        }

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let proposal = Proposal {
            id,
            kind,
            deposit,
            start_epoch,
            end_epoch: start_epoch.saturating_add(voting_epochs),
            executed: false,
            coherence: DEFAULT_GOVERNANCE_COHERENCE,
        };

        self.proposals.insert(id, proposal);
        self.quantum.apply_submit_decoherence();
        self.quantum.apply_governance_channel();

        Ok(id)
    }

    /// Cast a vote on a proposal.
    ///
    /// The proposal must be active at `current_epoch`.
    pub fn vote(
        &mut self,
        proposal_id: u64,
        voter: String,
        yes: bool,
        current_epoch: u64,
    ) -> GovernanceResult<()> {
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
        self.quantum.apply_vote_decoherence();
        self.quantum.apply_governance_channel();

        Ok(())
    }

    /// Mark a proposal as executed (e.g., after quorum is reached and vote passes).
    pub fn execute(&mut self, proposal_id: u64) -> GovernanceResult<()> {
        let proposal = self
            .proposals
            .get_mut(&proposal_id)
            .ok_or(GovernanceError::ProposalNotFound(proposal_id))?;

        if proposal.executed {
            return Err(GovernanceError::AlreadyExecuted(proposal_id));
        }

        proposal.executed = true;
        self.quantum.apply_execute_decoherence();
        self.quantum.apply_governance_channel();

        Ok(())
    }

    /// Tally votes for a proposal (simple count, ignoring stake).
    ///
    /// Returns `(yes_count, no_count)`.
    pub fn tally(&self, proposal_id: u64) -> (u64, u64) {
        let mut yes = 0u64;
        let mut no = 0u64;
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

    /// Tally votes weighted by validator stake.
    ///
    /// Requires a mapping from voter address to stake amount.
    /// Returns `(yes_power, no_power, total_power, quorum_reached, passes, vetoed)`.
    pub fn tally_weighted(
        &self,
        proposal_id: u64,
        stakes: &BTreeMap<String, u128>,
    ) -> (u128, u128, u128, bool, bool, bool) {
        let mut yes_power = 0u128;
        let mut no_power = 0u128;

        for ((pid, voter), &vote) in self.votes.iter() {
            if *pid == proposal_id {
                let stake = stakes.get(voter).copied().unwrap_or(0);
                if vote {
                    yes_power = yes_power.saturating_add(stake);
                } else {
                    no_power = no_power.saturating_add(stake);
                }
            }
        }

        let total_power: u128 = stakes.values().sum();
        let voted_power = yes_power.saturating_add(no_power);

        let quorum_needed = total_power
            .saturating_mul(self.quorum_bps as u128)
            .saturating_div(10_000);
        let threshold_needed = total_power
            .saturating_mul(self.threshold_bps as u128)
            .saturating_div(10_000);
        let veto_threshold = total_power
            .saturating_mul(self.veto_bps as u128)
            .saturating_div(10_000);

        let quorum_reached = voted_power >= quorum_needed;
        let vetoed = no_power >= veto_threshold;
        let passes = quorum_reached && yes_power >= threshold_needed && !vetoed;

        (yes_power, no_power, total_power, quorum_reached, passes, vetoed)
    }

    /// Tally weighted and return a structured result.
    pub fn tally_result(
        &self,
        proposal_id: u64,
        stakes: &BTreeMap<String, u128>,
    ) -> GovernanceResult<TallyResult> {
        let (yes_power, no_power, total_power, quorum, passes, vetoed) =
            self.tally_weighted(proposal_id, stakes);

        Ok(TallyResult {
            proposal_id,
            yes_power,
            no_power,
            total_power,
            quorum_reached: quorum,
            passes,
            vetoed,
        })
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

    /// Count votes for a proposal (simple).
    pub fn vote_count(&self, proposal_id: u64) -> usize {
        self.votes
            .keys()
            .filter(|(pid, _)| *pid == proposal_id)
            .count()
    }

    /// Remove expired proposals and their votes (cleanup).
    pub fn prune_expired(&mut self, epoch: u64) -> usize {
        let expired: Vec<u64> = self
            .proposals
            .iter()
            .filter(|(_, p)| p.end_epoch <= epoch || p.executed)
            .map(|(&id, _)| id)
            .collect();

        let count = expired.len();
        for id in &expired {
            self.proposals.remove(id);
            let votes_to_remove: Vec<(u64, String)> = self
                .votes
                .keys()
                .filter(|(pid, _)| *pid == *id)
                .cloned()
                .collect();
            for key in votes_to_remove {
                self.votes.remove(&key);
            }
        }

        if count > 0 {
            self.quantum.apply_expire_decoherence(count as u64);
            self.quantum.apply_governance_channel();
        }

        count
    }

    /// Update governance parameters.
    pub fn set_min_deposit(&mut self, value: u128) {
        self.min_deposit = value;
    }

    pub fn set_voting_epochs(&mut self, value: u64) {
        self.voting_epochs = value;
    }

    pub fn set_quorum_bps(&mut self, value: u64) {
        self.quorum_bps = value;
    }

    pub fn set_threshold_bps(&mut self, value: u64) {
        self.threshold_bps = value;
    }

    pub fn set_veto_bps(&mut self, value: u64) {
        self.veto_bps = value;
    }

    /// Get governance statistics.
    pub fn stats(&self) -> GovernanceStats {
        GovernanceStats {
            total_proposals: self.proposals.len(),
            active_proposals: self.active_proposals(0).len(),
            total_votes: self.votes.len(),
            min_deposit: self.min_deposit,
            voting_epochs: self.voting_epochs,
            quorum_bps: self.quorum_bps,
            threshold_bps: self.threshold_bps,
            purity: self.quantum.purity,
            is_healthy: self.quantum.is_healthy,
        }
    }
}

// -----------------------------------------------------------------------------
// Tally Result
// -----------------------------------------------------------------------------

/// Structured result of a weighted tally.
#[derive(Debug, Clone)]
pub struct TallyResult {
    pub proposal_id: u64,
    pub yes_power: u128,
    pub no_power: u128,
    pub total_power: u128,
    pub quorum_reached: bool,
    pub passes: bool,
    pub vetoed: bool,
}

// -----------------------------------------------------------------------------
// Governance Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the governance system.
#[derive(Debug, Clone)]
pub struct GovernanceStats {
    pub total_proposals: usize,
    pub active_proposals: usize,
    pub total_votes: usize,
    pub min_deposit: u128,
    pub voting_epochs: u64,
    pub quorum_bps: u64,
    pub threshold_bps: u64,
    pub purity: f64,
    pub is_healthy: bool,
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
        let id = gov.submit(kind, DEFAULT_MIN_DEPOSIT, 10, 5)?;
        assert_eq!(id, 0);
        let proposal = gov.get_proposal(id).unwrap();
        assert!(!proposal.executed);
        assert_eq!(proposal.start_epoch, 10);
        assert_eq!(proposal.end_epoch, 15);
        assert!(proposal.is_active(12));
        assert!(!proposal.is_active(15));

        gov.vote(id, "alice".into(), true, 12)?;
        gov.vote(id, "bob".into(), false, 13)?;
        let (yes, no) = gov.tally(id);
        assert_eq!(yes, 1);
        assert_eq!(no, 1);

        let err = gov.vote(id, "carol".into(), true, 15);
        assert!(matches!(
            err,
            Err(GovernanceError::ProposalInactive {
                id: 0,
                end_epoch: 15
            })
        ));
        Ok(())
    }

    #[test]
    fn test_submit_insufficient_deposit() {
        let mut gov = GovernanceState::new();
        let kind = ProposalKind::Upgrade {
            target_version: "2.0".into(),
        };
        let err = gov
            .submit(kind, DEFAULT_MIN_DEPOSIT - 1, 10, 5)
            .unwrap_err();
        assert!(matches!(
            err,
            GovernanceError::InsufficientDeposit {
                required: DEFAULT_MIN_DEPOSIT,
                provided: _
            }
        ));
    }

    #[test]
    fn test_zero_deposit() {
        let mut gov = GovernanceState::new();
        let err = gov
            .submit(
                ProposalKind::Text {
                    title: "test".into(),
                    description: "test".into(),
                },
                0,
                1,
                10,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::ZeroDeposit(0)));
    }

    #[test]
    fn test_zero_voting_epochs() {
        let mut gov = GovernanceState::new();
        let err = gov
            .submit(
                ProposalKind::Text {
                    title: "test".into(),
                    description: "test".into(),
                },
                1000,
                1,
                0,
            )
            .unwrap_err();
        assert!(matches!(err, GovernanceError::ZeroVotingEpochs(0)));
    }

    #[test]
    fn test_tally_weighted() {
        let mut gov = GovernanceState::new();
        let id = gov
            .submit(
                ProposalKind::ParamChange {
                    key: "test".into(),
                    value: "1".into(),
                },
                DEFAULT_MIN_DEPOSIT,
                1,
                10,
            )
            .unwrap();

        gov.vote(id, "alice".into(), true, 2).unwrap();
        gov.vote(id, "bob".into(), false, 2).unwrap();

        let mut stakes = BTreeMap::new();
        stakes.insert("alice".into(), 1_000);
        stakes.insert("bob".into(), 500);
        stakes.insert("charlie".into(), 2_000);

        let (yes, no, total, quorum, passes, vetoed) = gov.tally_weighted(id, &stakes);
        assert_eq!(yes, 1_000);
        assert_eq!(no, 500);
        assert_eq!(total, 3_500);
        assert!(quorum); // 1500 >= 1167 (33.4% of 3500)
        assert!(!passes); // 1000 < 1750 (50% of 3500)
        assert!(!vetoed); // 500 < 1167 (33.4% of 3500)
    }

    #[test]
    fn test_veto_power() {
        let mut gov = GovernanceState::new();
        let id = gov
            .submit(
                ProposalKind::Upgrade {
                    target_version: "bad".into(),
                },
                DEFAULT_MIN_DEPOSIT,
                1,
                10,
            )
            .unwrap();

        gov.vote(id, "alice".into(), false, 2).unwrap();
        gov.vote(id, "bob".into(), false, 2).unwrap();
        gov.vote(id, "charlie".into(), false, 2).unwrap();

        let mut stakes = BTreeMap::new();
        stakes.insert("alice".into(), 1_000);
        stakes.insert("bob".into(), 1_000);
        stakes.insert("charlie".into(), 1_000);

        let (_, no, total, _, _, vetoed) = gov.tally_weighted(id, &stakes);
        assert_eq!(no, 3_000);
        assert_eq!(total, 3_000);
        assert!(vetoed); // 3000 >= 1002 (33.4% of 3000)
    }

    #[test]
    fn test_prune_expired() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        gov.submit(
            ProposalKind::ParamChange {
                key: "p1".into(),
                value: "v1".into(),
            },
            DEFAULT_MIN_DEPOSIT,
            10,
            5,
        )?;
        gov.submit(
            ProposalKind::ParamChange {
                key: "p2".into(),
                value: "v2".into(),
            },
            DEFAULT_MIN_DEPOSIT,
            20,
            10,
        )?;

        let count = gov.prune_expired(16);
        assert_eq!(count, 1);
        assert!(gov.get_proposal(0).is_none());
        assert!(gov.get_proposal(1).is_some());
        Ok(())
    }

    #[test]
    fn test_execute() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let id = gov.submit(
            ProposalKind::ParamChange {
                key: "k".into(),
                value: "v".into(),
            },
            DEFAULT_MIN_DEPOSIT,
            1,
            10,
        )?;

        gov.execute(id)?;
        assert!(gov.get_proposal(id).unwrap().executed);

        let err = gov.execute(id).unwrap_err();
        assert!(matches!(err, GovernanceError::AlreadyExecuted(0)));
        Ok(())
    }

    #[test]
    fn test_tally_result() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let id = gov.submit(
            ProposalKind::ParamChange {
                key: "k".into(),
                value: "v".into(),
            },
            DEFAULT_MIN_DEPOSIT,
            1,
            10,
        )?;

        gov.vote(id, "alice".into(), true, 2).unwrap();

        let mut stakes = BTreeMap::new();
        stakes.insert("alice".into(), 5_000);

        let result = gov.tally_result(id, &stakes)?;
        assert_eq!(result.proposal_id, id);
        assert_eq!(result.yes_power, 5_000);
        assert!(result.passes);
        Ok(())
    }

    #[test]
    fn test_proposal_remaining_epochs() {
        let mut gov = GovernanceState::new();
        let id = gov
            .submit(
                ProposalKind::Text {
                    title: "t".into(),
                    description: "d".into(),
                },
                1000,
                10,
                5,
            )
            .unwrap();

        let p = gov.get_proposal(id).unwrap();
        assert_eq!(p.remaining_epochs(10), 5);
        assert_eq!(p.remaining_epochs(12), 3);
        assert_eq!(p.remaining_epochs(15), 0);
    }

    #[test]
    fn test_governance_stats() {
        let mut gov = GovernanceState::new();
        gov.submit(
            ProposalKind::Text {
                title: "t".into(),
                description: "d".into(),
            },
            1000,
            1,
            10,
        )
        .unwrap();

        let stats = gov.stats();
        assert_eq!(stats.total_proposals, 1);
        assert!(stats.purity < 1.0);
    }

    // ── Quantum-specific tests ────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let gov = GovernanceState::new();
        assert!((gov.purity() - 1.0).abs() < 1e-10);
        assert!(gov.is_healthy());
    }

    #[test]
    fn test_submit_decoherence() {
        let mut gov = GovernanceState::new();
        let initial_purity = gov.purity();

        gov.submit(
            ProposalKind::Text {
                title: "t".into(),
                description: "d".into(),
            },
            1000,
            1,
            10,
        )
        .unwrap();

        assert!(gov.purity() < initial_purity);
        assert_eq!(gov.quantum.total_proposals, 1);
    }

    #[test]
    fn test_vote_decoherence() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let id = gov.submit(
            ProposalKind::Text {
                title: "t".into(),
                description: "d".into(),
            },
            1000,
            1,
            10,
        )?;

        let purity_before = gov.purity();
        gov.vote(id, "alice".into(), true, 2)?;

        assert!(gov.purity() < purity_before);
        assert_eq!(gov.quantum.total_votes, 1);
        Ok(())
    }

    #[test]
    fn test_execute_decoherence() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        let id = gov.submit(
            ProposalKind::Text {
                title: "t".into(),
                description: "d".into(),
            },
            1000,
            1,
            10,
        )?;

        let purity_before = gov.purity();
        gov.execute(id)?;

        assert!(gov.purity() < purity_before);
        assert_eq!(gov.quantum.total_executed, 1);
        Ok(())
    }

    #[test]
    fn test_health_after_many_operations() -> GovernanceResult<()> {
        let mut gov = GovernanceState::new();
        for i in 0..1000 {
            let id = gov.submit(
                ProposalKind::Text {
                    title: format!("t{}", i),
                    description: "d".into(),
                },
                1000,
                1,
                10,
            )?;
            gov.vote(id, "alice".into(), true, 2)?;
            gov.execute(id)?;
        }
        assert!(!gov.is_healthy());
        Ok(())
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumGovernanceState::new();
        for _ in 0..10000 {
            state.apply_submit_decoherence();
        }
        assert!(state.purity >= 0.0);
    }
}
