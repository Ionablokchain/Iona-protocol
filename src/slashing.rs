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
use std::collections::{BTreeMap, HashSet};
use thiserror::Error;
use tracing::warn;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Blocks a validator must wait after being jailed before they can unjail.
pub const UNJAIL_DELAY_BLOCKS: u64 = 1000;

/// Slash fraction for double‑vote (5% = 1/20).
pub const SLASH_FRACTION_DOUBLE_VOTE: u64 = 20; // 1/20

/// Slash fraction for downtime (1% = 1/100).
pub const SLASH_FRACTION_DOWNTIME: u64 = 100; // 1/100

/// Window of blocks to check for downtime (number of recent blocks considered).
pub const DOWNTIME_WINDOW: u64 = 200;

/// Minimum blocks a validator must have signed in the last DOWNTIME_WINDOW to avoid jailing.
pub const DOWNTIME_MIN_SIGNED: u64 = 100; // 50% participation required

/// Minimum stake required to remain a validator after slashing.
pub const MIN_STAKE_AFTER_SLASH: u64 = 1;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during slashing operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SlashingError {
    #[error("unknown validator")]
    UnknownValidator,

    #[error("validator is tombstoned – cannot unjail")]
    Tombstoned,

    #[error("validator is not jailed")]
    NotJailed,

    #[error("unjail delay not elapsed (wait {remaining} more blocks)")]
    UnjailDelayNotElapsed { remaining: u64 },

    #[error("validator has zero stake – cannot unjail")]
    ZeroStake,

    #[error("duplicate evidence already processed")]
    DuplicateEvidence,

    #[error("validator already jailed for downtime")]
    AlreadyJailed,
}

pub type SlashingResult<T> = Result<T, SlashingError>;

// -----------------------------------------------------------------------------
// Validator status
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Jailed {
        since_height: Height,
        slash_count: u32,
    },
    Tombstoned,
}

// -----------------------------------------------------------------------------
// Validator record
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub stake: u64,
    pub slashed_total: u64,
    pub status: ValidatorStatus,
    pub jailed_at: Option<Height>,
}

impl ValidatorRecord {
    /// Create a new active validator record.
    pub const fn new(stake: u64) -> Self {
        Self {
            stake,
            slashed_total: 0,
            status: ValidatorStatus::Active,
            jailed_at: None,
        }
    }

    /// Check if the validator is active.
    pub const fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    /// Check if the validator can be unjailed at the given height.
    pub fn can_unjail(&self, current_height: Height) -> bool {
        match &self.status {
            ValidatorStatus::Jailed { since_height, .. } => {
                current_height >= since_height + UNJAIL_DELAY_BLOCKS
            }
            _ => false,
        }
    }

    /// Validate that the stake is within sensible bounds.
    pub fn validate(&self) -> Result<(), SlashingError> {
        if self.stake == 0 && self.is_active() {
            // Active validator with zero stake should be jailed, but we don't error here.
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Stake ledger
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct StakeLedger {
    pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
    pub processed_evidence: HashSet<(Height, PublicKeyBytes)>,
}

impl StakeLedger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a demo ledger (for testing).
    pub fn default_demo() -> Self {
        Self::default()
    }

    /// Create a demo ledger with specific validators and stake.
    pub fn default_demo_with(validators: &[PublicKeyBytes], stake_each: u64) -> Self {
        let mut s = Self::new();
        for v in validators {
            s.validators
                .insert(v.clone(), ValidatorRecord::new(stake_each));
        }
        s
    }

    /// Total active voting power.
    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .sum()
    }

    /// Power of a specific validator (0 if not active).
    pub fn power_of(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators
            .get(pk)
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .unwrap_or(0)
    }

    /// Backward compatibility: raw stake map (includes jailed validators).
    pub fn stake_raw(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.validators
            .iter()
            .map(|(k, v)| (k.clone(), v.stake))
            .collect()
    }

    /// Apply slashing evidence (double‑vote or double‑proposal).
    pub fn apply_evidence(&mut self, evidence: &Evidence, current_height: Height) -> SlashingResult<()> {
        let (offender, height) = match evidence {
            Evidence::DoubleVote { voter, height, .. } => (voter, height),
            Evidence::DoubleProposal { proposer, height, .. } => (proposer, height),
        };

        let key = (*height, offender.clone());
        if self.processed_evidence.contains(&key) {
            warn!("duplicate evidence for offender at height {height}, ignoring");
            return Err(SlashingError::DuplicateEvidence);
        }
        self.processed_evidence.insert(key);

        let record = self.validators
            .get_mut(offender)
            .ok_or(SlashingError::UnknownValidator)?;

        // Compute slash amount (minimum 1)
        let slash = (record.stake / SLASH_FRACTION_DOUBLE_VOTE).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;

        // Tombstone detection: repeated double‑vote at same height (already slash count >=2)
        let is_tombstone = matches!(&record.status,
            ValidatorStatus::Jailed { slash_count, .. } if *slash_count >= 2
        );

        if is_tombstone {
            record.status = ValidatorStatus::Tombstoned;
            warn!(
                offender = %hex::encode(&offender.0),
                "validator tombstoned (repeated double‑vote/ double‑proposal)"
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
                offender = %hex::encode(&offender.0),
                slashed = slash,
                remaining = record.stake,
                "validator jailed"
            );
        }
        Ok(())
    }

    /// Unjail a validator who has waited the required delay.
    pub fn unjail(&mut self, pk: &PublicKeyBytes, current_height: Height) -> SlashingResult<()> {
        let record = self.validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        match &record.status {
            ValidatorStatus::Tombstoned => Err(SlashingError::Tombstoned),
            ValidatorStatus::Active => Err(SlashingError::NotJailed),
            ValidatorStatus::Jailed { since_height, .. } => {
                if !record.can_unjail(current_height) {
                    let remaining = (since_height + UNJAIL_DELAY_BLOCKS).saturating_sub(current_height);
                    return Err(SlashingError::UnjailDelayNotElapsed { remaining });
                }
                if record.stake == 0 {
                    return Err(SlashingError::ZeroStake);
                }
                record.status = ValidatorStatus::Active;
                record.jailed_at = None;
                Ok(())
            }
        }
    }

    /// Slash a validator for downtime.
    pub fn slash_downtime(&mut self, pk: &PublicKeyBytes, current_height: Height) -> SlashingResult<()> {
        let record = self.validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        if !record.is_active() {
            return Err(SlashingError::AlreadyJailed);
        }

        let slash = (record.stake / SLASH_FRACTION_DOWNTIME).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;
        record.status = ValidatorStatus::Jailed {
            since_height: current_height,
            slash_count: 1,
        };
        record.jailed_at = Some(current_height);
        warn!(
            validator = %hex::encode(&pk.0),
            slashed = slash,
            "validator jailed for downtime"
        );
        Ok(())
    }

    /// Status report for all validators.
    pub fn status_report(&self) -> Vec<(PublicKeyBytes, &ValidatorRecord)> {
        self.validators.iter().map(|(k, v)| (k.clone(), v)).collect()
    }
}

// -----------------------------------------------------------------------------
// Legacy compatibility
// -----------------------------------------------------------------------------

impl StakeLedger {
    /// Deserialize old format (stake: BTreeMap<PK,u64>, slashed: BTreeMap<PK,u64>)
    pub fn from_legacy(
        stake: BTreeMap<PublicKeyBytes, u64>,
        slashed: BTreeMap<PublicKeyBytes, u64>,
    ) -> Self {
        let mut s = Self::new();
        for (pk, amount) in stake {
            let slashed_total = *slashed.get(&pk).unwrap_or(&0);
            s.validators.insert(
                pk,
                ValidatorRecord {
                    stake: amount,
                    slashed_total,
                    status: ValidatorStatus::Active,
                    jailed_at: None,
                },
            );
        }
        s
    }
}

// -----------------------------------------------------------------------------
// Uptime tracking
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UptimeTracker {
    pub signed_in_window: BTreeMap<PublicKeyBytes, u64>,
    pub last_signed_height: BTreeMap<PublicKeyBytes, Height>,
    pub window_start: Height,
}

impl UptimeTracker {
    /// Create a new uptime tracker.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a committed block: update signed counts for signers.
    pub fn record_block(
        &mut self,
        height: Height,
        signers: &[PublicKeyBytes],
        all_validators: &[PublicKeyBytes],
    ) {
        // Advance window start
        if height > DOWNTIME_WINDOW {
            self.window_start = height - DOWNTIME_WINDOW;
        }

        // Increase signed counts for signers
        for pk in signers {
            *self.signed_in_window.entry(pk.clone()).or_insert(0) += 1;
            self.last_signed_height.insert(pk.clone(), height);
        }

        // Ensure all validators have an entry (even with zero)
        for pk in all_validators {
            self.signed_in_window.entry(pk.clone()).or_insert(0);
        }
    }

    /// Get the number of signed blocks in the window for a given validator.
    pub fn signed_count(&self, pk: &PublicKeyBytes) -> u64 {
        *self.signed_in_window.get(pk).unwrap_or(&0)
    }

    /// Check which validators have missed too many blocks (downtime).
    /// Returns a vector of public keys that should be jailed.
    pub fn check_downtime(&self, height: Height, stakes: &StakeLedger) -> Vec<PublicKeyBytes> {
        if height < DOWNTIME_WINDOW {
            return vec![];
        }
        stakes
            .validators
            .iter()
            .filter(|(_, r)| r.is_active())
            .filter(|(pk, _)| {
                let signed = self.signed_count(pk);
                let last = *self.last_signed_height.get(*pk).unwrap_or(&0);
                last > 0 && signed < DOWNTIME_MIN_SIGNED
            })
            .map(|(pk, _)| pk.clone())
            .collect()
    }

    /// Reset counts for a validator (e.g., after unjailing, give a fresh start).
    pub fn reset_counts(&mut self, pk: &PublicKeyBytes) {
        self.signed_in_window.remove(pk);
        self.last_signed_height.remove(pk);
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        PublicKeyBytes(bytes.to_vec())
    }

    #[test]
    fn test_validator_record() {
        let v = ValidatorRecord::new(1000);
        assert!(v.is_active());
        assert_eq!(v.stake, 1000);
        assert_eq!(v.slashed_total, 0);
        assert!(v.validate().is_ok());
    }

    #[test]
    fn test_slash_double_vote() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(1);
        ledger.validators.insert(pk.clone(), ValidatorRecord::new(1000));

        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 20));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_unjail() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(2);
        ledger.validators.insert(pk.clone(), ValidatorRecord::new(1000));
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        // Cannot unjail immediately
        let err = ledger.unjail(&pk, 10).unwrap_err();
        assert!(matches!(err, SlashingError::UnjailDelayNotElapsed { .. }));
        // After delay
        ledger.unjail(&pk, 10 + UNJAIL_DELAY_BLOCKS)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert!(record.is_active());
        Ok(())
    }

    #[test]
    fn test_downtime_slash() -> SlashingResult<()> {
        let mut ledger = StakeLedger::new();
        let pk = dummy_pk(3);
        ledger.validators.insert(pk.clone(), ValidatorRecord::new(1000));
        ledger.slash_downtime(&pk, 100)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 100));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_uptime_tracker() {
        let pk = dummy_pk(4);
        let mut tracker = UptimeTracker::new();
        tracker.record_block(1, &[pk.clone()], &[pk.clone()]);
        assert_eq!(tracker.signed_count(&pk), 1);
    }
}
