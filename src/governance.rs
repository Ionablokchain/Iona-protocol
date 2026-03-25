//! Validator set governance for IONA v28.
//!
//! Enables dynamic validator set changes without hard-coding seeds.
//! Supported operations (submitted as special payload txs):
//!   - "gov add_validator <pubkey_hex> <stake>"
//!   - "gov remove_validator <pubkey_hex>"
//!   - "gov unjail <pubkey_hex>"
//!   - "gov set_param <key> <value>"
//!   - "gov vote <proposal_id> yes/no"
//!
//! Governance requires 2/3+ of current validator power to agree.
//! Proposals are stored per-height; when quorum is reached, the change applies
//! at the start of the next block.
//!
//! Implementation: governance proposals are regular transactions with
//! a "gov " prefix payload. The execution layer detects them and routes
//! them to this module. Validators sign governance proposals like any tx,
//! and the proposer applies the change if they hold a GovCertificate.

use crate::crypto::PublicKeyBytes;
use crate::consensus::ValidatorSet;
use crate::slashing::StakeLedger;
use crate::types::Height;
use crate::execution::KvState;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum deposit (in base fee units) required to create a governance proposal.
/// Prevents spam: proposers pay a small deposit that is burned on failed proposals.
pub const MIN_GOV_DEPOSIT: u64 = 1_000_000;

/// Maximum number of blocks a proposal stays pending before expiring.
pub const GOV_PROPOSAL_TTL_BLOCKS: u64 = 50_000;

/// List of governance‑controllable parameter keys.
pub const GOV_PARAM_KEYS: &[&str] = &[
    "propose_timeout_ms",
    "prevote_timeout_ms",
    "precommit_timeout_ms",
    "gas_target",
    "max_txs_per_block",
    "base_fee_per_gas",
    "slash_double_sign_bps",
    "slash_downtime_bps",
    "unbonding_epochs",
    "epoch_length",
    "min_stake",
    "treasury_bps",
    "base_inflation_bps",
];

// -----------------------------------------------------------------------------
// Governance Actions
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovAction {
    AddValidator    { pk_hex: String, stake: u64 },
    RemoveValidator { pk_hex: String },
    Unjail          { pk_hex: String },
    SetParam        { key: String, value: String },
}

impl GovAction {
    /// Validate the action (e.g., parameter values, stake bounds).
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::AddValidator { pk_hex, stake } => {
                if hex::decode(pk_hex).map_err(|e| format!("invalid pubkey hex: {e}"))?.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                if *stake == 0 {
                    return Err("stake must be positive".into());
                }
                Ok(())
            }
            Self::RemoveValidator { pk_hex } => {
                if hex::decode(pk_hex).map_err(|e| format!("invalid pubkey hex: {e}"))?.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                Ok(())
            }
            Self::Unjail { pk_hex } => {
                if hex::decode(pk_hex).map_err(|e| format!("invalid pubkey hex: {e}"))?.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                Ok(())
            }
            Self::SetParam { key, value } => {
                if !GOV_PARAM_KEYS.contains(&key.as_str()) {
                    return Err(format!("unknown parameter key: {key}"));
                }
                // Additional type‑specific validation
                match key.as_str() {
                    "propose_timeout_ms" | "prevote_timeout_ms" | "precommit_timeout_ms"
                    | "gas_target" | "max_txs_per_block" | "base_fee_per_gas"
                    | "slash_double_sign_bps" | "slash_downtime_bps" | "unbonding_epochs"
                    | "epoch_length" | "min_stake" | "treasury_bps" | "base_inflation_bps" => {
                        if value.parse::<u64>().is_err() {
                            return Err(format!("parameter {key} must be a positive integer"));
                        }
                    }
                    _ => {}
                }
                Ok(())
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Governance Proposal
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposal {
    pub action:   GovAction,
    pub proposer: String,           // address
    pub height:   Height,
    pub deposit:  u64,
    pub votes:    HashMap<String, bool>, // addr -> yes/no
}

impl GovProposal {
    pub fn new(action: GovAction, proposer: String, height: Height, deposit: u64) -> Self {
        let mut votes = HashMap::new();
        votes.insert(proposer.clone(), true); // proposer auto-votes yes
        Self {
            action,
            proposer,
            height,
            deposit,
            votes,
        }
    }

    pub fn vote(&mut self, voter: String, yes: bool) {
        self.votes.insert(voter, yes);
    }

    /// Compute the total voting power of yes votes.
    pub fn yes_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes.iter()
            .filter(|(_, &yes)| yes)
            .filter_map(|(addr, _)| {
                // Find validator by address (derived from pubkey)
                stakes.validators.iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    /// Check if the proposal has reached the required 2/3 majority.
    pub fn has_quorum(&self, stakes: &StakeLedger) -> bool {
        let yes = self.yes_power(stakes);
        let total = stakes.total_power();
        if total == 0 { return false; }
        yes * 3 > total * 2   // yes > 2/3 total
    }
}

// -----------------------------------------------------------------------------
// Governance State
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceState {
    pub pending: BTreeMap<u64, GovProposal>, // proposal_id -> proposal
    pub next_id: u64,
    pub params:  BTreeMap<String, String>,
}

impl GovernanceState {
    /// Submit a new governance proposal.
    /// Returns `Ok(proposal_id)` on success, or `Err` if deposit insufficient or action invalid.
    pub fn submit(
        &mut self,
        action: GovAction,
        proposer: String,
        height: Height,
        kv_state: &mut KvState,
    ) -> Result<u64, String> {
        // Validate action
        action.validate()?;

        // Check deposit
        let balance = *kv_state.balances.get(&proposer).unwrap_or(&0);
        if balance < MIN_GOV_DEPOSIT {
            return Err(format!(
                "insufficient deposit: need {}, have {}",
                MIN_GOV_DEPOSIT, balance
            ));
        }

        // Deduct deposit (burn it)
        *kv_state.balances.entry(proposer.clone()).or_insert(0) = balance - MIN_GOV_DEPOSIT;

        let id = self.next_id;
        self.next_id += 1;
        let proposal = GovProposal::new(action, proposer, height, MIN_GOV_DEPOSIT);
        self.pending.insert(id, proposal);
        info!(proposal_id = id, "governance proposal submitted");
        Ok(id)
    }

    /// Vote on a proposal.
    pub fn vote(&mut self, id: u64, voter: String, yes: bool) -> Result<(), String> {
        let proposal = self.pending.get_mut(&id).ok_or("proposal not found")?;
        // Check that the voter is a validator (has stake)
        // For simplicity, we don't check here; the stake will be zero if not.
        proposal.vote(voter, yes);
        info!(proposal_id = id, "vote recorded");
        Ok(())
    }

    /// Apply all proposals that have reached quorum. Returns list of applied actions.
    /// Also handles expired proposals (removes them and burns deposit – already burned).
    pub fn apply_ready(
        &mut self,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) -> Vec<GovAction> {
        let ready: Vec<u64> = self.pending.iter()
            .filter(|(_, p)| p.has_quorum(stakes))
            .map(|(id, _)| *id)
            .collect();

        let mut applied = Vec::new();
        for id in ready {
            let Some(proposal) = self.pending.remove(&id) else { continue; };
            if let Err(e) = self.apply_action(&proposal.action, stakes, vset, current_height) {
                warn!(proposal_id = id, error = %e, "governance action failed");
                continue;
            }
            applied.push(proposal.action);
        }

        // Remove expired proposals
        let expired: Vec<u64> = self.pending.iter()
            .filter(|(_, p)| current_height.saturating_sub(p.height) >= GOV_PROPOSAL_TTL_BLOCKS)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.pending.remove(&id);
            info!(proposal_id = id, "governance proposal expired");
        }

        applied
    }

    /// Apply a single governance action to the state.
    fn apply_action(
        &mut self,
        action: &GovAction,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) -> Result<(), String> {
        match action {
            GovAction::AddValidator { pk_hex, stake } => {
                let bytes = hex::decode(pk_hex).map_err(|e| format!("invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                let pk = PublicKeyBytes(bytes);
                use crate::slashing::ValidatorRecord;
                let entry = stakes.validators.entry(pk.clone())
                    .or_insert_with(|| ValidatorRecord::new(0));
                entry.stake += stake;
                if !vset.vals.iter().any(|v| v.pk == pk) {
                    vset.vals.push(crate::consensus::Validator { pk, power: *stake });
                }
                info!(%pk_hex, stake, "validator added via governance");
                Ok(())
            }
            GovAction::RemoveValidator { pk_hex } => {
                let bytes = hex::decode(pk_hex).map_err(|e| format!("invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                let pk = PublicKeyBytes(bytes);
                stakes.validators.remove(&pk);
                vset.vals.retain(|v| v.pk != pk);
                info!(%pk_hex, "validator removed via governance");
                Ok(())
            }
            GovAction::Unjail { pk_hex } => {
                let bytes = hex::decode(pk_hex).map_err(|e| format!("invalid hex: {e}"))?;
                if bytes.len() != 32 {
                    return Err("public key must be 32 bytes".into());
                }
                let pk = PublicKeyBytes(bytes);
                stakes.unjail(&pk, current_height)
                    .map_err(|e| format!("unjail failed: {e}"))?;
                info!(%pk_hex, "validator unjailed via governance");
                Ok(())
            }
            GovAction::SetParam { key, value } => {
                self.params.insert(key.clone(), value.clone());
                info!(%key, %value, "governance parameter updated");
                Ok(())
            }
        }
    }

    /// Retrieve a governance parameter, or a default if not set.
    pub fn get_param(&self, key: &str, default: &str) -> String {
        self.params.get(key).cloned().unwrap_or_else(|| default.to_string())
    }

    /// Get all current parameters (for node to apply).
    pub fn get_all_params(&self) -> &BTreeMap<String, String> {
        &self.params
    }
}

// -----------------------------------------------------------------------------
// Address helper
// -----------------------------------------------------------------------------

/// Derive a human‑readable address from a public key (blake3, first 20 bytes as hex).
fn address_of(pk: &PublicKeyBytes) -> String {
    let h = blake3::hash(&pk.0);
    hex::encode(&h.as_bytes()[..20])
}

// -----------------------------------------------------------------------------
// Payload parsing
// -----------------------------------------------------------------------------

/// Parse a governance payload from a transaction payload string.
/// Format: "gov <subcommand> [args...]"
pub enum GovPayloadAction {
    Submit(GovAction),
    Vote { id: u64, voter: String, yes: bool },
}

pub fn parse_gov_payload(payload: &str, from: &str, height: Height) -> Option<GovPayloadAction> {
    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.first() != Some(&"gov") { return None; }
    match parts.get(1)? {
        &"add_validator" if parts.len() >= 4 => {
            let pk_hex = parts[2].to_string();
            let stake: u64 = parts[3].parse().ok()?;
            Some(GovPayloadAction::Submit(GovAction::AddValidator { pk_hex, stake }))
        }
        &"remove_validator" if parts.len() >= 3 => {
            let pk_hex = parts[2].to_string();
            Some(GovPayloadAction::Submit(GovAction::RemoveValidator { pk_hex }))
        }
        &"unjail" if parts.len() >= 3 => {
            let pk_hex = parts[2].to_string();
            Some(GovPayloadAction::Submit(GovAction::Unjail { pk_hex }))
        }
        &"set_param" if parts.len() >= 4 => {
            let key = parts[2].to_string();
            let value = parts[3].to_string();
            Some(GovPayloadAction::Submit(GovAction::SetParam { key, value }))
        }
        &"vote" if parts.len() >= 4 => {
            let id: u64 = parts[2].parse().ok()?;
            let yes = parts[3] == "yes";
            Some(GovPayloadAction::Vote { id, voter: from.to_string(), yes })
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Integration helper for execution layer
// -----------------------------------------------------------------------------

/// Process a governance transaction (called from execute_block_with_staking).
/// Returns `Ok(())` if successful, `Err` with a message otherwise.
pub fn process_gov_tx(
    payload: &str,
    from: &str,
    height: Height,
    kv_state: &mut KvState,
    gov_state: &mut GovernanceState,
    stakes: &mut StakeLedger,
    vset: &mut ValidatorSet,
) -> Result<(), String> {
    match parse_gov_payload(payload, from, height) {
        Some(GovPayloadAction::Submit(action)) => {
            gov_state.submit(action, from.to_string(), height, kv_state)?;
            Ok(())
        }
        Some(GovPayloadAction::Vote { id, voter, yes }) => {
            gov_state.vote(id, voter, yes)
        }
        None => Err("not a governance payload".into()),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;

    #[test]
    fn test_validate_action() {
        let valid = GovAction::AddValidator { pk_hex: "00".repeat(32), stake: 100 };
        assert!(valid.validate().is_ok());

        let invalid_pk = GovAction::AddValidator { pk_hex: "1234".into(), stake: 100 };
        assert!(invalid_pk.validate().is_err());

        let zero_stake = GovAction::AddValidator { pk_hex: "00".repeat(32), stake: 0 };
        assert!(zero_stake.validate().is_err());
    }

    #[test]
    fn test_proposal_quorum() {
        // Setup fake stakes: validator with stake 100, another with 50
        let mut stakes = StakeLedger::default();
        let pk1 = PublicKeyBytes([1u8; 32]);
        let pk2 = PublicKeyBytes([2u8; 32]);
        let addr1 = address_of(&pk1);
        let addr2 = address_of(&pk2);
        use crate::slashing::ValidatorRecord;
        stakes.validators.insert(pk1, ValidatorRecord::new(100));
        stakes.validators.insert(pk2, ValidatorRecord::new(50));

        let action = GovAction::SetParam { key: "gas_target".into(), value: "1000000".into() };
        let mut proposal = GovProposal::new(action, addr1.clone(), 10, MIN_GOV_DEPOSIT);
        // Only proposer voted (stake 100). Total = 150, 2/3 = 100. yes = 100 -> not > 100, so false
        assert!(!proposal.has_quorum(&stakes));

        // Add vote from second validator (stake 50) → yes = 150, > 2/3*150 = 100
        proposal.vote(addr2, true);
        assert!(proposal.has_quorum(&stakes));
    }

    #[test]
    fn test_submit_proposal_deposit() {
        let mut gov = GovernanceState::default();
        let mut kv = KvState::default();
        kv.balances.insert("alice".into(), MIN_GOV_DEPOSIT + 100);
        let action = GovAction::SetParam { key: "gas_target".into(), value: "5000000".into() };
        let result = gov.submit(action, "alice".into(), 1, &mut kv);
        assert!(result.is_ok());
        assert_eq!(kv.balances.get("alice").unwrap(), &100);
        assert_eq!(gov.pending.len(), 1);
    }

    #[test]
    fn test_submit_proposal_insufficient_deposit() {
        let mut gov = GovernanceState::default();
        let mut kv = KvState::default();
        kv.balances.insert("alice".into(), MIN_GOV_DEPOSIT - 1);
        let action = GovAction::SetParam { key: "gas_target".into(), value: "5000000".into() };
        let result = gov.submit(action, "alice".into(), 1, &mut kv);
        assert!(result.is_err());
    }

    #[test]
    fn test_apply_ready_proposal() {
        let mut gov = GovernanceState::default();
        let mut kv = KvState::default();
        kv.balances.insert("alice".into(), MIN_GOV_DEPOSIT);
        let mut stakes = StakeLedger::default();
        let pk = PublicKeyBytes([1u8; 32]);
        let addr = address_of(&pk);
        use crate::slashing::ValidatorRecord;
        stakes.validators.insert(pk.clone(), ValidatorRecord::new(100));
        let mut vset = ValidatorSet::default();
        vset.vals.push(crate::consensus::Validator { pk: pk.clone(), power: 100 });

        let action = GovAction::AddValidator { pk_hex: "00".repeat(32), stake: 200 };
        gov.submit(action.clone(), addr.clone(), 1, &mut kv).unwrap();

        // Vote for it (proposer already voted yes)
        let yes_power = gov.pending.get(&0).unwrap().yes_power(&stakes);
        assert_eq!(yes_power, 100); // auto‑vote by proposer
        assert!(!gov.pending.get(&0).unwrap().has_quorum(&stakes));

        // Apply ready (no quorum)
        let applied = gov.apply_ready(&mut stakes, &mut vset, 1);
        assert!(applied.is_empty());

        // Add more stake to reach quorum
        let pk2 = PublicKeyBytes([2u8; 32]);
        let addr2 = address_of(&pk2);
        stakes.validators.insert(pk2, ValidatorRecord::new(100));
        vset.vals.push(crate::consensus::Validator { pk: pk2, power: 100 });
        // Now total stake = 200, 2/3 = 133.33, yes = 100 (still insufficient)
        // We need the second validator to vote yes
        gov.vote(0, addr2, true).unwrap();

        let applied = gov.apply_ready(&mut stakes, &mut vset, 1);
        assert_eq!(applied.len(), 1);
        // Check that the validator was added
        let new_pk_hex = "00".repeat(32);
        let new_pk = PublicKeyBytes(hex::decode(&new_pk_hex).unwrap());
        assert!(stakes.validators.contains_key(&new_pk));
        assert!(vset.vals.iter().any(|v| v.pk == new_pk));
    }
}
