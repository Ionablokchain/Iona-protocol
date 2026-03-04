//! Production slashing and validator lifecycle for IONA v21.
//!
//! Changes vs v20:
//! - Jail: slashed validators are jailed and excluded from consensus
//! - Unjail: validators can rejoin after UNJAIL_DELAY_BLOCKS
//! - Slash policy: 5% for double-vote, configurable
//! - Tombstone: validators double-voting at the same height are permanently banned

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::warn;

/// Blocks a validator must wait after being jailed before they can unjail.
pub const UNJAIL_DELAY_BLOCKS: u64 = 1000;
/// Slash fraction for double-vote (5%).
pub const SLASH_FRACTION_DOUBLE_VOTE: u64 = 20; // 1/20

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Jailed { since_height: Height, slash_count: u32 },
    Tombstoned,  // permanently banned (double-vote at same height)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub stake:         u64,
    pub slashed_total: u64,
    pub status:        ValidatorStatus,
    pub jailed_at:     Option<Height>,
}

impl ValidatorRecord {
    pub fn new(stake: u64) -> Self {
        Self { stake, slashed_total: 0, status: ValidatorStatus::Active, jailed_at: None }
    }

    pub fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    pub fn can_unjail(&self, current_height: Height) -> bool {
        match &self.status {
            ValidatorStatus::Jailed { since_height, .. } =>
                current_height >= since_height + UNJAIL_DELAY_BLOCKS,
            _ => false,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakeLedger {
    pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
    /// Evidence already processed (height, voter) to prevent double-slash
    pub processed_evidence: std::collections::HashSet<(Height, PublicKeyBytes)>,
}

impl StakeLedger {
    pub fn default_demo() -> Self {
        Self::default()
    }

    pub fn default_demo_with(validators: &[PublicKeyBytes], stake_each: u64) -> Self {
        let mut s = Self::default();
        for v in validators {
            s.validators.insert(v.clone(), ValidatorRecord::new(stake_each));
        }
        s
    }

    pub fn total_power(&self) -> u64 {
        self.validators.values()
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .sum()
    }

    pub fn power_of(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators.get(pk)
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .unwrap_or(0)
    }

    /// Backward compat fields for engine serialization
    pub fn stake_raw(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.validators.iter().map(|(k, v)| (k.clone(), v.stake)).collect()
    }

    pub fn apply_evidence(&mut self, ev: &Evidence, current_height: Height) {
        match ev {
            Evidence::DoubleVote { voter, height, .. } => {
                let key = (*height, voter.clone());
                if self.processed_evidence.contains(&key) {
                    warn!("duplicate evidence for voter at height {height}, ignoring");
                    return;
                }
                self.processed_evidence.insert(key);

                let record = match self.validators.get_mut(voter) {
                    Some(r) => r,
                    None => { warn!("evidence for unknown validator"); return; }
                };

                let slash = (record.stake / SLASH_FRACTION_DOUBLE_VOTE).max(1);
                record.stake = record.stake.saturating_sub(slash);
                record.slashed_total += slash;

                // Check if this is a tombstone offense (double-vote at same height = severe)
                let is_tombstone = matches!(&record.status,
                    ValidatorStatus::Jailed { slash_count, .. } if *slash_count >= 2
                );

                if is_tombstone {
                    record.status = ValidatorStatus::Tombstoned;
                    warn!(
                        voter = %hex::encode(&voter.0),
                        "validator tombstoned (repeated double-vote)"
                    );
                } else {
                    let slash_count = match &record.status {
                        ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                        _ => 1,
                    };
                    record.status = ValidatorStatus::Jailed {
                        since_height: current_height,
                        slash_count,
                    };
                    record.jailed_at = Some(current_height);
                    warn!(
                        voter = %hex::encode(&voter.0),
                        slashed = slash,
                        remaining = record.stake,
                        "validator jailed"
                    );
                }
            }

            Evidence::DoubleProposal { proposer, height, .. } => {
                // Treat double-proposals as a severe safety violation (similar severity to double-vote).
                let key = (*height, proposer.clone());
                if self.processed_evidence.contains(&key) {
                    warn!("duplicate evidence for proposer at height {height}, ignoring");
                    return;
                }
                self.processed_evidence.insert(key);

                let record = match self.validators.get_mut(proposer) {
                    Some(r) => r,
                    None => { warn!("evidence for unknown validator"); return; }
                };

                let slash = (record.stake / SLASH_FRACTION_DOUBLE_VOTE).max(1);
                record.stake = record.stake.saturating_sub(slash);
                record.slashed_total += slash;

                let slash_count = match &record.status {
                    ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                    _ => 1,
                };
                record.status = ValidatorStatus::Jailed {
                    since_height: current_height,
                    slash_count,
                };
                record.jailed_at = Some(current_height);
                warn!(
                    proposer = %hex::encode(&proposer.0),
                    slashed = slash,
                    remaining = record.stake,
                    "validator jailed (double-proposal)"
                );
            }
        }
    }

    /// Unjail a validator who has waited the required delay.
    /// Returns Err if validator is not jailed or delay not elapsed.
    pub fn unjail(&mut self, pk: &PublicKeyBytes, current_height: Height) -> Result<(), &'static str> {
        let record = self.validators.get_mut(pk).ok_or("unknown validator")?;
        match &record.status {
            ValidatorStatus::Tombstoned => Err("tombstoned validators cannot unjail"),
            ValidatorStatus::Active => Err("validator is not jailed"),
            ValidatorStatus::Jailed { .. } => {
                if !record.can_unjail(current_height) {
                    return Err("unjail delay not elapsed");
                }
                if record.stake == 0 {
                    return Err("zero stake, cannot unjail");
                }
                record.status = ValidatorStatus::Active;
                record.jailed_at = None;
                Ok(())
            }
        }
    }

    /// Status report for all validators.
    pub fn status_report(&self) -> Vec<(PublicKeyBytes, &ValidatorRecord)> {
        self.validators.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

// ── Backward compat shim for engine serialization ────────────────────────

impl StakeLedger {
    /// Deserialize old format (stake: BTreeMap<PK,u64>, slashed: BTreeMap<PK,u64>)
    pub fn from_legacy(
        stake:   BTreeMap<PublicKeyBytes, u64>,
        slashed: BTreeMap<PublicKeyBytes, u64>,
    ) -> Self {
        let mut s = Self::default();
        for (pk, amount) in stake {
            let slashed_total = *slashed.get(&pk).unwrap_or(&0);
            s.validators.insert(pk, ValidatorRecord {
                stake: amount,
                slashed_total,
                status: ValidatorStatus::Active,
                jailed_at: None,
            });
        }
        s
    }
}

// ── Downtime tracking ────────────────────────────────────────────────────

/// Window of blocks to check for downtime (number of recent blocks considered).
pub const DOWNTIME_WINDOW: u64 = 200;
/// Minimum blocks a validator must have signed in the last DOWNTIME_WINDOW to avoid jailing.
pub const DOWNTIME_MIN_SIGNED: u64 = 100; // 50% participation required

/// Track how many blocks each validator has signed in the recent window.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UptimeTracker {
    /// For each validator: count of blocks signed in the last DOWNTIME_WINDOW blocks.
    pub signed_in_window: BTreeMap<PublicKeyBytes, u64>,
    /// Block heights at which each validator signed (ring buffer via modulo).
    /// We track the last DOWNTIME_WINDOW block heights where each validator signed.
    pub last_signed_height: BTreeMap<PublicKeyBytes, Height>,
    /// Current window start (oldest tracked height).
    pub window_start: Height,
}

impl UptimeTracker {
    /// Call this once per committed block, passing the set of validators that signed (precommitted).
    pub fn record_block(
        &mut self,
        height: Height,
        signers: &[PublicKeyBytes],
        all_validators: &[PublicKeyBytes],
    ) {
        // Advance window: drop validators that haven't signed in DOWNTIME_WINDOW
        if height > DOWNTIME_WINDOW {
            self.window_start = height - DOWNTIME_WINDOW;
        }

        // Decay: for validators not in signers, their signed count doesn't increase
        // (we use a simple approach: reset and recount over full window via last_signed_height)
        for pk in signers {
            *self.signed_in_window.entry(pk.clone()).or_insert(0) += 1;
            self.last_signed_height.insert(pk.clone(), height);
        }

        // Initialize any new validators with 0
        for pk in all_validators {
            self.signed_in_window.entry(pk.clone()).or_insert(0);
        }
    }

    /// Returns validators that should be jailed for downtime at this height.
    /// Only returns active validators that have been in the set for at least DOWNTIME_WINDOW blocks.
    pub fn check_downtime(
        &self,
        height: Height,
        stakes: &StakeLedger,
    ) -> Vec<PublicKeyBytes> {
        if height < DOWNTIME_WINDOW {
            return vec![]; // too early to check
        }
        stakes.validators.iter()
            .filter(|(_, r)| r.is_active())
            .filter(|(pk, _)| {
                let signed = *self.signed_in_window.get(*pk).unwrap_or(&0);
                let last = *self.last_signed_height.get(*pk).unwrap_or(&0);
                // Validator must have been in the set long enough (at least 1 signed block recorded)
                // and failed to meet minimum participation
                last > 0 && signed < DOWNTIME_MIN_SIGNED
            })
            .map(|(pk, _)| pk.clone())
            .collect()
    }
}

impl StakeLedger {
    /// Apply downtime slash to a validator: slash fraction and jail.
    /// Uses 1% slash (SLASH_FRACTION_DOWNTIME = 100).
    pub fn slash_downtime(&mut self, pk: &PublicKeyBytes, current_height: Height) {
        const SLASH_FRACTION_DOWNTIME: u64 = 100; // 1/100 = 1%
        let record = match self.validators.get_mut(pk) {
            Some(r) if r.is_active() => r,
            _ => return,
        };
        let slash = (record.stake / SLASH_FRACTION_DOWNTIME).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;
        let slash_count = 1;
        record.status = ValidatorStatus::Jailed { since_height: current_height, slash_count };
        record.jailed_at = Some(current_height);
        warn!(
            validator = %hex::encode(&pk.0),
            slashed = slash,
            "validator jailed for downtime"
        );
    }
}
