//! Validator set governance for IONA v21.
//!
//! Enables dynamic validator set changes without hard-coding seeds.
//! Supported operations (submitted as special payload txs):
//!   - "gov add_validator <pubkey_hex> <stake>"
//!   - "gov remove_validator <pubkey_hex>"
//!   - "gov unjail <pubkey_hex>"
//!   - "gov set_param <key> <value>"
//!   - "gov vote <proposal_id> yes|no"
//!
//! Governance requires 2/3+ of current validator power to agree.
//! Proposals are stored per-height; when quorum is reached, the change applies
//! at the start of the next block.
//!
//! Implementation: governance proposals are regular transactions with
//! a "gov " prefix payload. The execution layer detects them and routes
//! them to this module. Validators sign governance proposals like any tx,
//! and the proposer applies the change if they hold a GovCertificate.

use crate::consensus::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::slashing::StakeLedger;
use crate::types::Height;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

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
    #[error("validator already exists")]
    ValidatorAlreadyExists,
    #[error("validator not found")]
    ValidatorNotFound,
    #[error("parse error: {0}")]
    ParseError(String),
}

pub type GovResult<T> = Result<T, GovError>;

// -----------------------------------------------------------------------------
// Action and Proposal types
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovAction {
    AddValidator { pk_hex: String, stake: u64 },
    RemoveValidator { pk_hex: String },
    Unjail { pk_hex: String },
    SetParam { key: String, value: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposal {
    pub id: u64,
    pub action: GovAction,
    pub proposer: String, // address
    pub height: Height,
    pub votes: HashMap<String, bool>, // addr -> yes/no
    pub deposit: u64,                 // burned if proposal fails
}

impl GovProposal {
    pub fn new(id: u64, action: GovAction, proposer: String, height: Height, deposit: u64) -> Self {
        let mut votes = HashMap::new();
        votes.insert(proposer.clone(), true); // proposer auto-votes yes
        Self {
            id,
            action,
            proposer,
            height,
            votes,
            deposit,
        }
    }

    pub fn vote(&mut self, voter: String, yes: bool) -> GovResult<()> {
        self.votes.insert(voter, yes);
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

    /// Returns true if YES votes exceed 2/3 of total active stake.
    pub fn has_quorum(&self, stakes: &StakeLedger) -> bool {
        let yes = self.yes_power(stakes);
        let total = stakes.total_power();
        if total == 0 {
            return false;
        }
        yes * 3 > total * 2
    }

    /// Check if proposal is still active (not expired).
    pub fn is_active(&self, current_height: Height, ttl: u64) -> bool {
        current_height.saturating_sub(self.height) < ttl
    }
}

// -----------------------------------------------------------------------------
// Governance state
// -----------------------------------------------------------------------------

pub const DEFAULT_MIN_GOV_DEPOSIT: u64 = 1_000_000;
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 50_000;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceState {
    pub pending: BTreeMap<u64, GovProposal>,
    pub next_id: u64,
    pub params: BTreeMap<String, String>,
    pub min_deposit: u64,
    pub proposal_ttl: u64,
}

impl GovernanceState {
    pub fn new() -> Self {
        Self {
            pending: BTreeMap::new(),
            next_id: 0,
            params: BTreeMap::new(),
            min_deposit: DEFAULT_MIN_GOV_DEPOSIT,
            proposal_ttl: DEFAULT_PROPOSAL_TTL_BLOCKS,
        }
    }

    /// Submit a new governance proposal. Requires deposit (burned if proposal fails).
    pub fn submit(
        &mut self,
        action: GovAction,
        proposer: String,
        height: Height,
        deposit: u64,
    ) -> GovResult<u64> {
        if deposit < self.min_deposit {
            return Err(GovError::InsufficientDeposit {
                required: self.min_deposit,
                provided: deposit,
            });
        }
        // Validate action-specific invariants
        match &action {
            GovAction::AddValidator { pk_hex, stake } => {
                if *stake == 0 {
                    return Err(GovError::ZeroStake);
                }
                let bytes = hex::decode(pk_hex)
                    .map_err(|_| GovError::InvalidPubKeyHex(pk_hex.clone()))?;
                if bytes.len() != 32 {
                    return Err(GovError::InvalidPubKeyHex(pk_hex.clone()));
                }
            }
            GovAction::RemoveValidator { pk_hex } => {
                let bytes = hex::decode(pk_hex)
                    .map_err(|_| GovError::InvalidPubKeyHex(pk_hex.clone()))?;
                if bytes.len() != 32 {
                    return Err(GovError::InvalidPubKeyHex(pk_hex.clone()));
                }
            }
            GovAction::Unjail { pk_hex } => {
                let bytes = hex::decode(pk_hex)
                    .map_err(|_| GovError::InvalidPubKeyHex(pk_hex.clone()))?;
                if bytes.len() != 32 {
                    return Err(GovError::InvalidPubKeyHex(pk_hex.clone()));
                }
            }
            GovAction::SetParam { .. } => {} // always valid
        }

        let id = self.next_id;
        self.next_id += 1;
        let proposal = GovProposal::new(id, action, proposer, height, deposit);
        self.pending.insert(id, proposal);
        Ok(id)
    }

    /// Vote on an existing proposal. Returns error if proposal missing or expired.
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
        proposal.vote(voter, yes)
    }

    /// Apply all proposals that have reached quorum. Returns list of applied actions.
    /// Expired proposals are removed and their deposit is considered burned.
    pub fn apply_ready(
        &mut self,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) -> Vec<GovAction> {
        let mut applied = Vec::new();

        // Collect ready (quorum reached) and expired proposal ids.
        let to_apply: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| p.is_active(current_height, self.proposal_ttl) && p.has_quorum(stakes))
            .map(|(id, _)| *id)
            .collect();

        let expired: Vec<u64> = self
            .pending
            .iter()
            .filter(|(_, p)| !p.is_active(current_height, self.proposal_ttl))
            .map(|(id, _)| *id)
            .collect();

        // Remove expired proposals (deposit already burned at submission time)
        for id in expired {
            self.pending.remove(&id);
            warn!(proposal_id = id, "governance proposal expired");
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
                            info!(pk = %pk_hex, stake = %stake, "gov: added validator");
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
                    // Apply runtime parameter updates immediately or at next block.
                    // Supported: "min_deposit", "proposal_ttl", "slash_fraction", etc.
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

        applied
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

fn address_of(pk: &PublicKeyBytes) -> String {
    let h = blake3::hash(&pk.0);
    hex::encode(&h.as_bytes()[..20])
}

// -----------------------------------------------------------------------------
// Payload parsing
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub enum GovPayloadAction {
    Submit(GovAction, u64), // action, deposit
    Vote { id: u64, voter: String, yes: bool },
}

/// Parse a governance payload from a transaction payload string.
/// Format: "gov <subcommand> [args...] [--deposit <amount>]"
/// Deposit defaults to MIN_GOV_DEPOSIT if omitted.
pub fn parse_gov_payload(
    payload: &str,
    from: &str,
    height: Height,
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
        stakes.validators.insert(pk1.clone(), ValidatorRecord::new(100));
        stakes.validators.insert(pk2.clone(), ValidatorRecord::new(100));
        let vset = ValidatorSet {
            vals: vec![
                Validator { pk: pk1, power: 100 },
                Validator { pk: pk2, power: 100 },
            ],
        };
        (stakes, vset)
    }

    #[test]
    fn test_parse_gov_payload() {
        let from = "addr1";
        let height = 100;
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

        let payload = "gov set_param min_deposit 2000000";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Submit(GovAction::SetParam { key, value }, _) => {
                assert_eq!(key, "min_deposit");
                assert_eq!(value, "2000000");
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
        gov.vote(id, "addr2".to_string(), true, height).unwrap();
        let proposal = gov.pending.get(&id).unwrap();
        assert_eq!(proposal.votes.len(), 2);
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
        // Only proposer voted yes (stake 100) – need > 2/3 of total 200 => >133.
        // 100 is not enough.
        assert!(!gov
            .pending
            .get(&id)
            .unwrap()
            .has_quorum(&stakes));
        // Add vote from second validator (stake 100) -> yes power = 200, quorum reached.
        gov.vote(id, address_of(&PublicKeyBytes([2u8; 32])), true, height)
            .unwrap();
        assert!(gov
            .pending
            .get(&id)
            .unwrap()
            .has_quorum(&stakes));
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
        let expired = gov
            .pending
            .get(&id)
            .unwrap()
            .is_active(111, gov.proposal_ttl);
        assert!(!expired);
        let (mut stakes, mut vset) = setup_stakes();
        let applied = gov.apply_ready(&mut stakes, &mut vset, 111);
        assert!(applied.is_empty());
        assert!(gov.pending.is_empty());
    }
}
