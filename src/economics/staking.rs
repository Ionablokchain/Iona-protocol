//! Staking state and operations for IONA PoS.
//!
//! Manages validators, delegations, unbonding, and slashing.
//! All operations are validated and return structured errors.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during staking operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum StakingError {
    #[error("delegation amount must be > 0, got {0}")]
    ZeroDelegation(u128),
    #[error("undelegation amount must be > 0, got {0}")]
    ZeroUndelegation(u128),
    #[error("insufficient delegated amount: have {have}, need {need}")]
    InsufficientDelegation { have: u128, need: u128 },
    #[error("validator '{0}' not found")]
    ValidatorNotFound(String),
    #[error("validator '{0}' is jailed and cannot receive new delegations")]
    ValidatorJailed(String),
    #[error("slashing percentage must be <= 10_000 (100%), got {0}")]
    InvalidSlashBps(u64),
    #[error("commission basis points must be between 0 and 10_000, got {0}")]
    InvalidCommissionBps(u64),
    #[error("no unbonding entry found for delegator '{0}' and validator '{1}'")]
    UnbondingNotFound(String, String),
}

pub type StakingResult<T> = Result<T, StakingError>;

// -----------------------------------------------------------------------------
// Validator
// -----------------------------------------------------------------------------

/// A PoS validator with its stake and commission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub operator: String,
    pub stake: u128,
    pub jailed: bool,
    pub commission_bps: u64,
}

impl Validator {
    /// Create a new validator with the given stake and commission.
    /// Commission must be between 0 and 10_000 basis points (100%).
    pub fn new(operator: String, stake: u128, commission_bps: u64) -> StakingResult<Self> {
        if commission_bps > 10_000 {
            return Err(StakingError::InvalidCommissionBps(commission_bps));
        }
        Ok(Self {
            operator,
            stake,
            jailed: false,
            commission_bps,
        })
    }

    /// Check if the validator is eligible to receive delegations.
    pub fn is_eligible(&self) -> bool {
        !self.jailed
    }
}

// -----------------------------------------------------------------------------
// StakingState
// -----------------------------------------------------------------------------

/// The core staking state: validators, delegations, and unbonding entries.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StakingState {
    pub validators: BTreeMap<String, Validator>,
    pub delegations: BTreeMap<(String, String), u128>, // (delegator, validator) -> amount
    pub unbonding: BTreeMap<(String, String), (u128, u64)>, // (delegator, validator) -> (amount, unlock_epoch)
}

impl StakingState {
    // -------------------------------------------------------------------------
    // Validator management
    // -------------------------------------------------------------------------

    /// Add or update a validator (only used during genesis or governance).
    pub fn add_validator(&mut self, validator: Validator) -> StakingResult<()> {
        // Commission already validated in Validator::new
        self.validators.insert(validator.operator.clone(), validator);
        Ok(())
    }

    /// Remove a validator (when slashed or removed by governance).
    pub fn remove_validator(&mut self, operator: &str) -> Option<Validator> {
        self.validators.remove(operator)
    }

    /// Get a validator by operator address.
    pub fn get_validator(&self, operator: &str) -> Option<&Validator> {
        self.validators.get(operator)
    }

    /// Check if a validator exists and is not jailed.
    pub fn is_active_validator(&self, operator: &str) -> bool {
        self.validators
            .get(operator)
            .map(|v| !v.jailed)
            .unwrap_or(false)
    }

    // -------------------------------------------------------------------------
    // Delegation operations
    // -------------------------------------------------------------------------

    /// Delegate tokens to a validator.
    ///
    /// # Errors
    /// - If `amount == 0`
    /// - If validator does not exist
    /// - If validator is jailed
    pub fn delegate(
        &mut self,
        delegator: String,
        validator: String,
        amount: u128,
    ) -> StakingResult<()> {
        if amount == 0 {
            return Err(StakingError::ZeroDelegation(amount));
        }
        let v = self
            .validators
            .get(&validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.clone()))?;
        if v.jailed {
            return Err(StakingError::ValidatorJailed(validator));
        }
        let key = (delegator, validator);
        *self.delegations.entry(key).or_insert(0) += amount;
        Ok(())
    }

    /// Initiate undelegation (unbonding). The tokens become withdrawable after `unbonding_epochs`.
    ///
    /// # Errors
    /// - If `amount == 0`
    /// - If insufficient delegated amount
    /// - If unbonding entry already exists (not allowed until previous unbonding completes)
    pub fn undelegate(
        &mut self,
        delegator: String,
        validator: String,
        amount: u128,
        current_epoch: u64,
        unbonding_epochs: u64,
    ) -> StakingResult<()> {
        if amount == 0 {
            return Err(StakingError::ZeroUndelegation(amount));
        }
        let key = (delegator.clone(), validator.clone());
        let current = self.delegations.get(&key).copied().unwrap_or(0);
        if current < amount {
            return Err(StakingError::InsufficientDelegation {
                have: current,
                need: amount,
            });
        }
        // Check if there's already an unbonding entry for this (delegator, validator)
        if self.unbonding.contains_key(&key) {
            // For simplicity, we could allow adding to existing unbonding, but here we reject.
            // In production, you might want to merge or allow multiple entries.
            // For now, we treat as error.
            return Err(StakingError::UnbondingNotFound(
                delegator,
                validator,
            ));
        }
        // Reduce delegation
        let new_balance = current - amount;
        if new_balance == 0 {
            self.delegations.remove(&key);
        } else {
            self.delegations.insert(key.clone(), new_balance);
        }
        let unlock_epoch = current_epoch.saturating_add(unbonding_epochs);
        self.unbonding.insert(key, (amount, unlock_epoch));
        Ok(())
    }

    /// Withdraw completed unbonding tokens.
    ///
    /// Returns the withdrawn amount (0 if not yet unlocked or no entry).
    pub fn withdraw(&mut self, delegator: String, validator: String, current_epoch: u64) -> u128 {
        let key = (delegator, validator);
        if let Some((amount, unlock_epoch)) = self.unbonding.get(&key).copied() {
            if current_epoch >= unlock_epoch {
                self.unbonding.remove(&key);
                return amount;
            }
        }
        0
    }

    /// Slash a validator for misbehaviour.
    ///
    /// # Errors
    /// - If validator does not exist
    /// - If `slash_bps > 10_000`
    pub fn slash(&mut self, validator: &str, slash_bps: u64) -> StakingResult<()> {
        if slash_bps > 10_000 {
            return Err(StakingError::InvalidSlashBps(slash_bps));
        }
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        let slash_amount = v
            .stake
            .saturating_mul(slash_bps as u128)
            .saturating_div(10_000);
        v.stake = v.stake.saturating_sub(slash_amount);
        v.jailed = true;
        Ok(())
    }

    /// Unjail a validator (by governance or after serving time).
    pub fn unjail(&mut self, validator: &str) -> StakingResult<()> {
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        v.jailed = false;
        Ok(())
    }

    /// Get total staked power (sum of all validator stakes, excluding jailed? Usually only active).
    pub fn total_power(&self) -> u128 {
        self.validators
            .values()
            .filter(|v| !v.jailed)
            .map(|v| v.stake)
            .sum()
    }

    /// Get the delegation amount for a (delegator, validator) pair.
    pub fn get_delegation(&self, delegator: &str, validator: &str) -> u128 {
        self.delegations
            .get(&(delegator.to_string(), validator.to_string()))
            .copied()
            .unwrap_or(0)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_validator(operator: &str, stake: u128, commission: u64) -> Validator {
        Validator::new(operator.to_string(), stake, commission).unwrap()
    }

    #[test]
    fn test_validator_creation() {
        let v = Validator::new("alice".into(), 1000, 500).unwrap();
        assert_eq!(v.commission_bps, 500);
        assert!(!v.jailed);
        assert!(Validator::new("bob".into(), 1000, 10_001).is_err());
    }

    #[test]
    fn test_delegate_ok() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state
            .delegate("carol".into(), "alice".into(), 500)
            .unwrap();
        assert_eq!(state.get_delegation("carol", "alice"), 500);
    }

    #[test]
    fn test_delegate_zero_amount() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        let err = state
            .delegate("carol".into(), "alice".into(), 0)
            .unwrap_err();
        assert!(matches!(err, StakingError::ZeroDelegation(0)));
    }

    #[test]
    fn test_delegate_to_nonexistent_validator() {
        let mut state = StakingState::default();
        let err = state
            .delegate("carol".into(), "bob".into(), 100)
            .unwrap_err();
        assert!(matches!(err, StakingError::ValidatorNotFound(s) if s == "bob"));
    }

    #[test]
    fn test_delegate_to_jailed_validator() {
        let mut state = StakingState::default();
        let mut v = sample_validator("alice", 1000, 500);
        v.jailed = true;
        state.add_validator(v).unwrap();
        let err = state
            .delegate("carol".into(), "alice".into(), 100)
            .unwrap_err();
        assert!(matches!(err, StakingError::ValidatorJailed(s) if s == "alice"));
    }

    #[test]
    fn test_undelegate_ok() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state.delegate("carol".into(), "alice".into(), 500).unwrap();
        state
            .undelegate("carol".into(), "alice".into(), 200, 10, 14)
            .unwrap();
        assert_eq!(state.get_delegation("carol", "alice"), 300);
        assert!(state.unbonding.contains_key(&("carol".into(), "alice".into())));
    }

    #[test]
    fn test_undelegate_insufficient() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state.delegate("carol".into(), "alice".into(), 100).unwrap();
        let err = state
            .undelegate("carol".into(), "alice".into(), 200, 10, 14)
            .unwrap_err();
        assert!(matches!(
            err,
            StakingError::InsufficientDelegation { have: 100, need: 200 }
        ));
    }

    #[test]
    fn test_withdraw_after_unbonding() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state.delegate("carol".into(), "alice".into(), 500).unwrap();
        state
            .undelegate("carol".into(), "alice".into(), 200, 100, 14)
            .unwrap(); // unlock at 114
        // Before unlock
        let withdrawn = state.withdraw("carol".into(), "alice".into(), 110);
        assert_eq!(withdrawn, 0);
        // After unlock
        let withdrawn = state.withdraw("carol".into(), "alice".into(), 114);
        assert_eq!(withdrawn, 200);
        assert!(!state.unbonding.contains_key(&("carol".into(), "alice".into())));
    }

    #[test]
    fn test_slash_validator() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state.slash("alice", 1000).unwrap(); // 10%
        let v = state.get_validator("alice").unwrap();
        assert_eq!(v.stake, 900);
        assert!(v.jailed);
    }

    #[test]
    fn test_slash_invalid_bps() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        let err = state.slash("alice", 10_001).unwrap_err();
        assert!(matches!(err, StakingError::InvalidSlashBps(10_001)));
    }

    #[test]
    fn test_total_power() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 500)).unwrap();
        state.add_validator(sample_validator("bob", 2000, 500)).unwrap();
        assert_eq!(state.total_power(), 3000);
        // Jail bob
        state.slash("bob", 0).unwrap(); // jail only
        assert_eq!(state.total_power(), 1000);
    }
}
