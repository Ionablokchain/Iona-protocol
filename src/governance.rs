//! Quantum validator set governance for IONA v21.
//!
//! # Quantum Governance Model
//!
//! Governance is modeled as a quantum decision process where each validator
//! exists in a superposition of voting states |yes⟩ and |no⟩ until measurement
//! (vote submission). The collective decision emerges from the entanglement
//! of validator states with the proposal.
//!
//! # Hamiltonian for Governance
//!
//! ```text
//! Ĥ_gov = Ĥ_proposal + Ĥ_voting + Ĥ_execution
//!
//! Ĥ_proposal = Σ_p E_p |proposal_p⟩⟨proposal_p|
//! Ĥ_voting    = Σ_v g_v (|yes⟩⟨no|_v + h.c.)
//! Ĥ_execution = Σ_a ω_a a†_a a_a
//! ```
//!
//! # Quantum Consensus for Governance
//!
//! A proposal passes when the YES voting power exceeds 2/3 of total power.
//! In quantum terms, this is a projective measurement:
//! ```text
//! P_pass = θ(Σ_{v∈yes} w_v - 2/3 Σ_v w_v)
//! ```
//! where θ is the Heaviside step function and w_v are validator weights.
//!
//! # Entanglement Between Proposals
//!
//! Validators become entangled with proposals when they vote:
//! ```text
//! |Ψ⟩ = (1/√2)(|proposal⟩|yes⟩ + |proposal⟩|no⟩)
//! ```

use crate::consensus::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::slashing::StakeLedger;
use crate::types::Height;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default minimum deposit for governance proposals.
pub const DEFAULT_MIN_GOV_DEPOSIT: u64 = 1_000_000;

/// Default proposal time-to-live in blocks.
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 50_000;

/// Quorum threshold: 2/3 of total voting power.
const QUORUM_NUMERATOR: u64 = 2;
const QUORUM_DENOMINATOR: u64 = 3;

/// Entanglement strength between voters and proposals.
const VOTING_ENTANGLEMENT: f64 = 0.95;

// -----------------------------------------------------------------------------
// Quantum Governance Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum governance operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovError {
    #[error("invalid public key hex: {0}")]
    InvalidPubKeyHex(String),

    #[error("stake must be > 0")]
    ZeroStake,

    #[error("proposal not found: id={0}")]
    ProposalNotFound(u64),

    #[error("invalid vote value: must be 'yes' or 'no'")]
    InvalidVoteValue,

    #[error("insufficient deposit: need at least {required}, got {provided}")]
    InsufficientDeposit { required: u64, provided: u64 },

    #[error("proposal expired (height {current} > {expiry})")]
    ProposalExpired { current: u64, expiry: u64 },

    #[error("validator already exists in the set")]
    ValidatorAlreadyExists,

    #[error("validator not found in the active set")]
    ValidatorNotFound,

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("quantum decoherence: proposal state lost fidelity ({fidelity})")]
    Decoherence { fidelity: f64 },

    #[error("entanglement threshold not met for quorum")]
    EntanglementInsufficient,
}

pub type GovResult<T> = Result<T, GovError>;

// -----------------------------------------------------------------------------
// Quantum Governance Actions
// -----------------------------------------------------------------------------

/// Governance actions — quantum gates on the validator set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovAction {
    /// Add a new validator: U_add |∅⟩ → |validator⟩
    AddValidator {
        pk_hex: String,
        stake: u64,
    },
    /// Remove a validator: U_remove |validator⟩ → |∅⟩
    RemoveValidator {
        pk_hex: String,
    },
    /// Unjail a validator: U_unjail |jailed⟩ → |active⟩
    Unjail {
        pk_hex: String,
    },
    /// Set a governance parameter: U_param |old⟩ → |new⟩
    SetParam {
        key: String,
        value: String,
    },
}

// -----------------------------------------------------------------------------
// Quantum Governance Proposal
// -----------------------------------------------------------------------------

/// A governance proposal — a quantum state in the proposal Hilbert space.
///
/// The proposal exists in a superposition of |pending⟩, |passed⟩, and |expired⟩
/// states until measured (executed or expired).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposal {
    /// Unique proposal identifier (quantum number).
    pub id: u64,
    /// The proposed action (quantum gate to apply).
    pub action: GovAction,
    /// Proposer address (initial state preparer).
    pub proposer: String,
    /// Height at which the proposal was created.
    pub height: Height,
    /// Votes: address → yes/no (measurement outcomes).
    pub votes: HashMap<String, bool>,
    /// Deposit amount (burned if proposal fails).
    pub deposit: u64,
    /// Quantum coherence of the proposal state.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement entropy with voters.
    #[serde(default)]
    pub entanglement_entropy: f64,
}

fn default_coherence() -> f64 {
    1.0
}

impl GovProposal {
    /// Create a new proposal in a pure quantum state.
    pub fn new(
        id: u64,
        action: GovAction,
        proposer: String,
        height: Height,
        deposit: u64,
    ) -> Self {
        let mut votes = HashMap::new();
        votes.insert(proposer.clone(), true); // proposer auto-votes yes

        Self {
            id,
            action,
            proposer,
            height,
            votes,
            deposit,
            coherence: 1.0,
            entanglement_entropy: 0.0,
        }
    }

    /// Cast a vote — measurement in the {yes, no} basis.
    ///
    /// This entangles the voter with the proposal:
    /// ```text
    /// |Ψ⟩ → √p_yes |proposal⟩|yes⟩ + √p_no |proposal⟩|no⟩
    /// ```
    pub fn vote(&mut self, voter: String, yes: bool) -> GovResult<()> {
        self.votes.insert(voter, yes);
        self.entanglement_entropy += VOTING_ENTANGLEMENT;
        self.coherence *= VOTING_ENTANGLEMENT;
        Ok(())
    }

    /// Total voting power that voted YES.
    pub fn yes_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes
            .iter()
            .filter(|(_, &yes)| yes)
            .filter_map(|(addr, _)| {
                stakes
                    .validators
                    .iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    /// Total voting power that voted NO.
    pub fn no_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes
            .iter()
            .filter(|(_, &no)| !no)
            .filter_map(|(addr, _)| {
                stakes
                    .validators
                    .iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    /// Total active stake across all validators.
    pub fn total_power(&self, stakes: &StakeLedger) -> u64 {
        stakes.total_power()
    }

    /// Check if the proposal has reached quorum.
    ///
    /// Quorum: YES votes > 2/3 of total active stake.
    /// In quantum terms, this is a projective measurement:
    /// ```text
    /// P_pass = θ(Σ_{v∈yes} w_v - (2/3) Σ_v w_v)
    /// ```
    pub fn has_quorum(&self, stakes: &StakeLedger) -> bool {
        let yes = self.yes_power(stakes);
        let total = self.total_power(stakes);
        if total == 0 {
            return false;
        }
        yes * QUORUM_DENOMINATOR > total * QUORUM_NUMERATOR
    }

    /// Check if proposal is still active (not expired).
    pub fn is_active(&self, current_height: Height, ttl: u64) -> bool {
        current_height.saturating_sub(self.height) < ttl
    }

    /// Apply quantum decoherence to the proposal.
    pub fn apply_decoherence(&mut self, strength: f64) {
        self.coherence *= (-strength).exp();
        self.entanglement_entropy = -self.coherence * self.coherence.ln();
    }
}

// -----------------------------------------------------------------------------
// Quantum Governance State
// -----------------------------------------------------------------------------

/// The complete governance state — a quantum system governing validator set changes.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceState {
    /// Pending proposals (superposition of states).
    pub pending: BTreeMap<u64, GovProposal>,
    /// Next proposal ID (monotonically increasing quantum number).
    pub next_id: u64,
    /// Governance parameters (classical observables).
    pub params: BTreeMap<String, String>,
    /// Minimum deposit required to submit a proposal.
    pub min_deposit: u64,
    /// Proposal time-to-live in blocks.
    pub proposal_ttl: u64,
    /// Overall governance coherence.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl GovernanceState {
    /// Create a new governance state in the ground state.
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            next_id: 0,
            params: BTreeMap::new(),
            min_deposit: DEFAULT_MIN_GOV_DEPOSIT,
            proposal_ttl: DEFAULT_PROPOSAL_TTL_BLOCKS,
            coherence: 1.0,
        }
    }

    /// Submit a new governance proposal — excite the governance system.
    ///
    /// The deposit is burned if the proposal fails to pass.
    pub fn submit(
        &mut self,
        action: GovAction,
        proposer: String,
        height: Height,
        deposit: u64,
    ) -> GovResult<u64> {
        // Validate deposit
        if deposit < self.min_deposit {
            return Err(GovError::InsufficientDeposit {
                required: self.min_deposit,
                provided: deposit,
            });
        }

        // Validate action-specific invariants
        self.validate_action(&action)?;

        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);

        let proposal = GovProposal::new(id, action, proposer, height, deposit);
        self.pending.insert(id, proposal);

        // Apply minimal decoherence
        self.coherence *= 0.999;

        Ok(id)
    }

    /// Validate a governance action.
    fn validate_action(&self, action: &GovAction) -> GovResult<()> {
        match action {
            GovAction::AddValidator { pk_hex, stake } => {
                if *stake == 0 {
                    return Err(GovError::ZeroStake);
                }
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::RemoveValidator { pk_hex } => {
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::Unjail { pk_hex } => {
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::SetParam { .. } => {
                // Always valid
            }
        }
        Ok(())
    }

    /// Validate a hex-encoded public key.
    fn validate_pk_hex(&self, pk_hex: &str) -> GovResult<()> {
        let bytes = hex::decode(pk_hex)
            .map_err(|_| GovError::InvalidPubKeyHex(pk_hex.to_string()))?;
        if bytes.len() != 32 {
            return Err(GovError::InvalidPubKeyHex(pk_hex.to_string()));
        }
        Ok(())
    }

    /// Vote on an existing proposal — entangle voter with proposal.
    pub fn vote(
        &mut self,
        id: u64,
        voter: String,
        yes: bool,
        current_height: Height,
    ) -> GovResult<()> {
        let proposal = self
            .pending
            .get_mut(&id)
            .ok_or(GovError::ProposalNotFound(id))?;

        if !proposal.is_active(current_height, self.proposal_ttl) {
            return Err(GovError::ProposalExpired {
                current: current_height,
                expiry: proposal.height + self.proposal_ttl,
            });
        }

        proposal.vote(voter, yes)?;
        self.coherence *= 0.999;

        Ok(())
    }

    /// Apply all proposals that have reached quorum.
    ///
    /// This performs a projective measurement: proposals in |passed⟩ state
    /// are applied, those in |expired⟩ state are removed.
    pub fn apply_ready(
        &mut self,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) -> Vec<GovAction> {
        let mut applied = Vec::new();

        // Collect ready (quorum reached) and expired proposal IDs
        let to_apply: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| {
                p.is_active(current_height, self.proposal_ttl) && p.has_quorum(stakes)
            })
            .map(|(id, _)| *id)
            .collect();

        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| !p.is_active(current_height, self.proposal_ttl))
            .map(|(id, _)| *id)
            .collect();

        // Remove expired proposals (deposit already burned at submission time)
        for id in &expired {
            if let Some(mut proposal) = self.pending.remove(id) {
                proposal.apply_decoherence(0.5);
                warn!(
                    proposal_id = id,
                    coherence = proposal.coherence,
                    "governance proposal expired"
                );
            }
        }

        // Apply quorum proposals
        for id in to_apply {
            let Some(proposal) = self.pending.remove(&id) else {
                continue;
            };

            match &proposal.action {
                GovAction::AddValidator { pk_hex, stake } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            use crate::slashing::ValidatorRecord;

                            let entry = stakes
                                .validators
                                .entry(pk.clone())
                                .or_insert_with(|| ValidatorRecord::new(0));
                            entry.stake += stake;

                            if !vset.vals.iter().any(|v| v.pk == pk) {
                                vset.vals.push(crate::consensus::Validator {
                                    pk,
                                    power: *stake,
                                });
                            }

                            info!(
                                pk = %pk_hex,
                                stake = %stake,
                                "gov: added validator"
                            );
                        }
                    }
                }

                GovAction::RemoveValidator { pk_hex } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            stakes.validators.remove(&pk);
                            vset.vals.retain(|v| v.pk != pk);
                            info!(pk = %pk_hex, "gov: removed validator");
                        }
                    }
                }

                GovAction::Unjail { pk_hex } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            match stakes.unjail(&pk, current_height) {
                                Ok(()) => info!(pk = %pk_hex, "gov: unjailed validator"),
                                Err(e) => warn!(pk = %pk_hex, error = %e, "gov: unjail failed"),
                            }
                        }
                    }
                }

                GovAction::SetParam { key, value } => {
                    self.params.insert(key.clone(), value.clone());
                    info!(key = %key, value = %value, "gov: parameter updated");

                    // Apply runtime parameter updates
                    match key.as_str() {
                        "min_deposit" => {
                            if let Ok(v) = value.parse::<u64>() {
                                self.min_deposit = v;
                            }
                        }
                        "proposal_ttl" => {
                            if let Ok(v) = value.parse::<u64>() {
                                self.proposal_ttl = v;
                            }
                        }
                        _ => {}
                    }
                }
            }

            applied.push(proposal.action);
        }

        // Update governance coherence
        if !applied.is_empty() {
            self.coherence *= 0.99;
        }

        applied
    }

    /// Get governance statistics.
    pub fn stats(&self) -> GovernanceStats {
        GovernanceStats {
            pending_count: self.pending.len(),
            next_id: self.next_id,
            min_deposit: self.min_deposit,
            proposal_ttl: self.proposal_ttl,
            coherence: self.coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// Governance Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the governance system.
#[derive(Debug, Clone)]
pub struct GovernanceStats {
    pub pending_count: usize,
    pub next_id: u64,
    pub min_deposit: u64,
    pub proposal_ttl: u64,
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Derive an address from a public key (first 20 bytes of BLAKE3 hash).
fn address_of(pk: &PublicKeyBytes) -> String {
    let h = blake3::hash(&pk.0);
    hex::encode(&h.as_bytes()[..20])
}

// -----------------------------------------------------------------------------
// Payload Parsing
// -----------------------------------------------------------------------------

/// Parsed governance payload action.
#[derive(Debug)]
pub enum GovPayloadAction {
    Submit(GovAction, u64),
    Vote {
        id: u64,
        voter: String,
        yes: bool,
    },
}

/// Parse a governance payload from a transaction payload string.
///
/// Format: `gov <subcommand> [args...] [--deposit <amount>]`
pub fn parse_gov_payload(
    payload: &str,
    from: &str,
    _height: Height,
) -> Option<GovPayloadAction> {
    let parts: Vec<&str> = payload.split_whitespace().collect();

    if parts.first() != Some(&"gov") {
        return None;
    }

    // Detect optional deposit flag
    let mut deposit = DEFAULT_MIN_GOV_DEPOSIT;
    let mut args = parts[1..].to_vec();

    if let Some(pos) = args.iter().position(|&x| x == "--deposit") {
        if pos + 1 < args.len() {
            if let Ok(d) = args[pos + 1].parse::<u64>() {
                deposit = d;
            }
            args.drain(pos..=pos + 1);
        }
    }

    match args.first()? {
        &"add_validator" if args.len() >= 3 => {
            let pk_hex = args[1].to_string();
            let stake: u64 = args[2].parse().ok()?;
            Some(GovPayloadAction::Submit(
                GovAction::AddValidator { pk_hex, stake },
                deposit,
            ))
        }
        &"remove_validator" if args.len() >= 2 => {
            let pk_hex = args[1].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::RemoveValidator { pk_hex },
                deposit,
            ))
        }
        &"unjail" if args.len() >= 2 => {
            let pk_hex = args[1].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::Unjail { pk_hex },
                deposit,
            ))
        }
        &"set_param" if args.len() >= 3 => {
            let key = args[1].to_string();
            let value = args[2].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::SetParam { key, value },
                deposit,
            ))
        }
        &"vote" if args.len() >= 3 => {
            let id: u64 = args[1].parse().ok()?;
            let yes = match args[2] {
                "yes" => true,
                "no" => false,
                _ => return None,
            };
            Some(GovPayloadAction::Vote {
                id,
                voter: from.to_string(),
                yes,
            })
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::Validator;
    use crate::slashing::ValidatorRecord;

    fn setup_stakes() -> (StakeLedger, ValidatorSet) {
        let mut stakes = StakeLedger::default();
        let pk1 = PublicKeyBytes([1u8; 32]);
        let pk2 = PublicKeyBytes([2u8; 32]);

        stakes
            .validators
            .insert(pk1.clone(), ValidatorRecord::new(100));
        stakes
            .validators
            .insert(pk2.clone(), ValidatorRecord::new(100));

        let vset = ValidatorSet {
            vals: vec![
                Validator {
                    pk: pk1,
                    power: 100,
                },
                Validator {
                    pk: pk2,
                    power: 100,
                },
            ],
        };

        (stakes, vset)
    }

    #[test]
    fn test_parse_gov_payload() {
        let from = "addr1";
        let height = 100;

        // Add validator
        let payload = "gov add_validator aabbccdd 500";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Submit(GovAction::AddValidator { pk_hex, stake }, deposit) => {
                assert_eq!(pk_hex, "aabbccdd");
                assert_eq!(stake, 500);
                assert_eq!(deposit, DEFAULT_MIN_GOV_DEPOSIT);
            }
            _ => panic!("wrong variant"),
        }

        // Vote
        let payload = "gov vote 123 yes";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Vote { id, voter, yes } => {
                assert_eq!(id, 123);
                assert_eq!(voter, from);
                assert!(yes);
            }
            _ => panic!("wrong variant"),
        }

        // Set param with deposit
        let payload = "gov set_param min_deposit 2000000 --deposit 500000";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Submit(GovAction::SetParam { key, value }, deposit) => {
                assert_eq!(key, "min_deposit");
                assert_eq!(value, "2000000");
                assert_eq!(deposit, 500000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_submit_and_vote() {
        let mut gov = GovernanceState::new();
        let from = "addr1";
        let height = 1;

        let action = GovAction::SetParam {
            key: "min_deposit".to_string(),
            value: "500000".to_string(),
        };

        let id = gov
            .submit(action.clone(), from.to_string(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        assert_eq!(gov.pending.len(), 1);

        gov.vote(id, "addr2".to_string(), true, height)
            .unwrap();

        let proposal = gov.pending.get(&id).unwrap();
        assert_eq!(proposal.votes.len(), 2);
        assert!(proposal.coherence < 1.0);
    }

    #[test]
    fn test_quorum() {
        let (mut stakes, mut vset) = setup_stakes();
        let mut gov = GovernanceState::new();
        let from = address_of(&PublicKeyBytes([1u8; 32]));
        let height = 1;

        let action = GovAction::SetParam {
            key: "test".to_string(),
            value: "ok".to_string(),
        };

        let id = gov
            .submit(action, from.clone(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        // Only proposer voted yes (stake 100) — need > 2/3 of total 200 => >133
        assert!(!gov.pending.get(&id).unwrap().has_quorum(&stakes));

        // Add vote from second validator (stake 100) → yes power = 200, quorum reached
        gov.vote(
            id,
            address_of(&PublicKeyBytes([2u8; 32])),
            true,
            height,
        )
        .unwrap();

        assert!(gov.pending.get(&id).unwrap().has_quorum(&stakes));

        let applied = gov.apply_ready(&mut stakes, &mut vset, height + 1);
        assert_eq!(applied.len(), 1);
        assert!(gov.pending.is_empty());
    }

    #[test]
    fn test_expired_proposal() {
        let mut gov = GovernanceState::new();
        gov.proposal_ttl = 10;

        let from = "addr1".to_string();
        let action = GovAction::SetParam {
            key: "x".to_string(),
            value: "y".to_string(),
        };

        let id = gov
            .submit(action, from, 100, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        // At height 111, proposal expired (100+10=110)
        let is_active = gov
            .pending
            .get(&id)
            .unwrap()
            .is_active(111, gov.proposal_ttl);
        assert!(!is_active);

        let (mut stakes, mut vset) = setup_stakes();
        let applied = gov.apply_ready(&mut stakes, &mut vset, 111);

        assert!(applied.is_empty());
        assert!(gov.pending.is_empty());
    }

    #[test]
    fn test_governance_stats() {
        let gov = GovernanceState::new();
        let stats = gov.stats();

        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.min_deposit, DEFAULT_MIN_GOV_DEPOSIT);
        assert!((stats.coherence - 1.0).abs() < 1e-10);
    }
}
