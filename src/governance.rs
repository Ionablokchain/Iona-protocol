//! Validator set governance for IONA v21.
//!
//! Enables dynamic validator set changes without hard-coding seeds.
//! Supported operations (submitted as special payload txs):
//!   - "gov add_validator <pubkey_hex> <stake>"
//!   - "gov remove_validator <pubkey_hex>"
//!   - "gov unjail <pubkey_hex>"
//!   - "gov set_slash_fraction <numerator>"
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
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use tracing::{info, warn};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovAction {
    AddValidator    { pk_hex: String, stake: u64 },
    RemoveValidator { pk_hex: String },
    Unjail          { pk_hex: String },
    SetParam        { key: String, value: String },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposal {
    pub action:   GovAction,
    pub proposer: String,           // address
    pub height:   Height,
    pub votes:    HashMap<String, bool>, // addr -> yes/no
}

impl GovProposal {
    pub fn new(action: GovAction, proposer: String, height: Height) -> Self {
        let mut votes = HashMap::new();
        votes.insert(proposer.clone(), true); // proposer auto-votes yes
        Self { action, proposer, height, votes }
    }

    pub fn vote(&mut self, voter: String, yes: bool) {
        self.votes.insert(voter, yes);
    }

    pub fn yes_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes.iter()
            .filter(|(_, &yes)| yes)
            .filter_map(|(addr, _)| {
                // Find validator by address (hex of blake3(pk))
                stakes.validators.iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    pub fn has_quorum(&self, stakes: &StakeLedger) -> bool {
        let yes = self.yes_power(stakes);
        let total = stakes.total_power();
        if total == 0 { return false; }
        yes * 3 > total * 2   // yes > 2/3 total
    }
}

fn address_of(pk: &PublicKeyBytes) -> String {
    let h = blake3::hash(&pk.0);
    hex::encode(&h.as_bytes()[..20])
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct GovernanceState {
    pub pending: BTreeMap<u64, GovProposal>, // proposal_id -> proposal
    pub next_id: u64,
    pub params:  BTreeMap<String, String>,
}

/// Minimum deposit (in base fee units) required to create a governance proposal.
/// Prevents spam: proposers pay a small deposit that is burned on failed proposals.
pub const MIN_GOV_DEPOSIT: u64 = 1_000_000;

/// Maximum number of blocks a proposal stays pending before expiring.
pub const GOV_PROPOSAL_TTL_BLOCKS: u64 = 50_000;

impl GovernanceState {
    pub fn submit(&mut self, action: GovAction, proposer: String, height: Height) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.pending.insert(id, GovProposal::new(action, proposer, height));
        id
    }

    pub fn vote(&mut self, id: u64, voter: String, yes: bool) -> bool {
        if let Some(p) = self.pending.get_mut(&id) {
            p.vote(voter, yes);
            true
        } else {
            false
        }
    }

    /// Apply all proposals that have reached quorum. Returns list of applied actions.
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
            match &proposal.action {
                GovAction::AddValidator { pk_hex, stake } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            use crate::slashing::ValidatorRecord;
                            stakes.validators.entry(pk.clone())
                                .or_insert_with(|| ValidatorRecord::new(0))
                                .stake += stake;
                            if !vset.vals.iter().any(|v| v.pk == pk) {
                                vset.vals.push(crate::consensus::Validator { pk, power: *stake });
                            }
                            info!("gov: added validator {pk_hex} stake={stake}");
                        }
                    }
                }
                GovAction::RemoveValidator { pk_hex } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            stakes.validators.remove(&pk);
                            vset.vals.retain(|v| v.pk != pk);
                            info!("gov: removed validator {pk_hex}");
                        }
                    }
                }
                GovAction::Unjail { pk_hex } => {
                    if let Ok(bytes) = hex::decode(pk_hex) {
                        if bytes.len() == 32 {
                            let pk = PublicKeyBytes(bytes);
                            match stakes.unjail(&pk, current_height) {
                                Ok(()) => info!("gov: unjailed {pk_hex}"),
                                Err(e) => warn!("gov: unjail failed for {pk_hex}: {e}"),
                            }
                        }
                    }
                }
                GovAction::SetParam { key, value } => {
                    self.params.insert(key.clone(), value.clone());
                    info!(key = %key, value = %value, "gov: parameter updated via governance vote");
                    // Supported runtime params applied at next block:
                    // propose_timeout_ms, gas_target, max_txs_per_block,
                    // slash_fraction, unjail_delay_blocks, min_gov_deposit
                }
            }
            applied.push(proposal.action);
        }

        // Prune old expired proposals (use GOV_PROPOSAL_TTL_BLOCKS constant)
        self.pending.retain(|_, p| current_height.saturating_sub(p.height) < GOV_PROPOSAL_TTL_BLOCKS);

        applied
    }
}

/// Parse a governance payload from a tx payload string.
/// Format: "gov <subcommand> [args...]"
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
        &"vote" if parts.len() >= 4 => {
            let id: u64 = parts[2].parse().ok()?;
            let yes = parts[3] == "yes";
            Some(GovPayloadAction::Vote { id, voter: from.to_string(), yes })
        }
        _ => None,
    }
}

pub enum GovPayloadAction {
    Submit(GovAction),
    Vote { id: u64, voter: String, yes: bool },
}
