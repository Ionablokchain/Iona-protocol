//! Staking state and operations for IONA PoS.
//!
//! Manages validators, delegations, unbonding, and slashing.
//! All operations are validated, overflow-safe, and return structured errors.

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
    #[error("validator '{0}' already exists")]
    ValidatorAlreadyExists(String),
    #[error("validator '{0}' is jailed and cannot receive new delegations")]
    ValidatorJailed(String),
    #[error("slashing percentage must be <= 10_000 (100%), got {0}")]
    InvalidSlashBps(u64),
    #[error("commission basis points must be between 0 and 10_000, got {0}")]
    InvalidCommissionBps(u64),
    #[error("an unbonding is already in progress for delegator '{0}' and validator '{1}'")]
    UnbondingAlreadyExists(String, String),
    #[error("arithmetic overflow during staking operation")]
    Overflow,
}

pub type StakingResult<T> = Result<T, StakingError>;

// -----------------------------------------------------------------------------
// Validator
// -----------------------------------------------------------------------------

/// A PoS validator with its own stake (self-bond) and commission.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Validator {
    pub operator: String,
    /// Amount of tokens bonded by the validator operator themselves.
    pub self_stake: u128,
    pub jailed: bool,
    /// Commission rate in basis points (0 ..= 10_000).
    pub commission_bps: u64,
}

impl Validator {
    /// Create a new validator with the given self-stake and commission.
    pub fn new(operator: String, self_stake: u128, commission_bps: u64) -> StakingResult<Self> {
        if commission_bps > 10_000 {
            return Err(StakingError::InvalidCommissionBps(commission_bps));
        }
        Ok(Self {
            operator,
            self_stake,
            jailed: false,
            commission_bps,
        })
    }

    /// Check if the validator can receive new delegations.
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
    /// (delegator, validator) -> delegated amount
    pub delegations: BTreeMap<(String, String), u128>,
    /// (delegator, validator) -> (amount, unlock_epoch)
    pub unbonding: BTreeMap<(String, String), (u128, u64)>,
}

impl StakingState {
    // -------------------------------------------------------------------------
    // Validator management
    // -------------------------------------------------------------------------

    /// Insert a new validator. Fails if the operator already exists.
    pub fn add_validator(&mut self, validator: Validator) -> StakingResult<()> {
        if self.validators.contains_key(&validator.operator) {
            return Err(StakingError::ValidatorAlreadyExists(validator.operator));
        }
        self.validators.insert(validator.operator.clone(), validator);
        Ok(())
    }

    /// Update an existing validator’s self-stake and commission.
    /// Jailed status is not changed here; use `unjail` / `jail` for that.
    pub fn update_validator(
        &mut self,
        operator: &str,
        self_stake: u128,
        commission_bps: u64,
    ) -> StakingResult<()> {
        if commission_bps > 10_000 {
            return Err(StakingError::InvalidCommissionBps(commission_bps));
        }
        let v = self
            .validators
            .get_mut(operator)
            .ok_or_else(|| StakingError::ValidatorNotFound(operator.to_string()))?;
        v.self_stake = self_stake;
        v.commission_bps = commission_bps;
        Ok(())
    }

    /// Remove a validator completely.
    ///
    /// All delegations to this validator are instantly unbonded (becoming withdrawable
    /// immediately). Existing unbonding entries for this validator are also cleared.
    pub fn remove_validator(&mut self, operator: &str, current_epoch: u64) -> StakingResult<()> {
        if !self.validators.contains_key(operator) {
            return Err(StakingError::ValidatorNotFound(operator.to_string()));
        }

        // Force immediate withdrawal for all delegators: convert their delegation
        // into an unbonding entry with unlock_epoch = current_epoch.
        let delegator_keys: Vec<String> = self
            .delegations
            .iter()
            .filter(|((_del, val), _)| val == operator)
            .map(|((del, _), _)| del.clone())
            .collect();

        for delegator in delegator_keys {
            let key = (delegator.clone(), operator.to_string());
            if let Some(amount) = self.delegations.remove(&key) {
                self.unbonding
                    .insert(key, (amount, current_epoch));
            }
        }

        // Also remove any existing unbonding entries for this validator
        self.unbonding
            .retain(|(_del, val), _| val != operator);

        self.validators.remove(operator);
        Ok(())
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

    /// Compute the total bonded stake for a validator (self-stake + all delegations).
    pub fn validator_total_bond(&self, operator: &str) -> StakingResult<u128> {
        let v = self
            .validators
            .get(operator)
            .ok_or_else(|| StakingError::ValidatorNotFound(operator.to_string()))?;
        let delegations_sum: u128 = self
            .delegations
            .iter()
            .filter(|((_, val), _)| val == operator)
            .map(|(_, amount)| amount)
            .sum();
        v.self_stake
            .checked_add(delegations_sum)
            .ok_or(StakingError::Overflow)
    }

    // -------------------------------------------------------------------------
    // Delegation operations
    // -------------------------------------------------------------------------

    /// Delegate tokens to a validator.
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
        let entry = self.delegations.entry(key).or_insert(0);
        *entry = entry
            .checked_add(amount)
            .ok_or(StakingError::Overflow)?;
        Ok(())
    }

    /// Initiate undelegation (unbonding). Tokens become withdrawable after `unbonding_epochs`.
    ///
    /// Only one unbonding entry per (delegator, validator) can exist at a time.
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
        if self.unbonding.contains_key(&key) {
            return Err(StakingError::UnbondingAlreadyExists(
                delegator,
                validator,
            ));
        }

        // Reduce delegation
        let new_balance = current
            .checked_sub(amount)
            .ok_or(StakingError::Overflow)?;
        if new_balance == 0 {
            self.delegations.remove(&key);
        } else {
            self.delegations.insert(key.clone(), new_balance);
        }

        let unlock_epoch = current_epoch
            .checked_add(unbonding_epochs)
            .ok_or(StakingError::Overflow)?;
        self.unbonding.insert(key, (amount, unlock_epoch));
        Ok(())
    }

    /// Withdraw completed unbonding tokens.
    /// Returns the amount withdrawn (0 if nothing is ready).
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

    // -------------------------------------------------------------------------
    // Slashing & jailing
    // -------------------------------------------------------------------------

    /// Slash a validator for misbehaviour.
    ///
    /// Slashes both the validator’s self-stake and all delegations proportionally.
    /// The validator is jailed automatically.
    pub fn slash(&mut self, validator: &str, slash_bps: u64) -> StakingResult<()> {
        if slash_bps > 10_000 {
            return Err(StakingError::InvalidSlashBps(slash_bps));
        }

        // Ensure validator exists
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;

        // Collect total bonded stake (self-stake + delegations)
        let delegations_snapshot: Vec<(String, u128)> = self
            .delegations
            .iter()
            .filter(|((_, val), _)| val == validator)
            .map(|((del, _), &amount)| (del.clone(), amount))
            .collect();

        let total_bonded = v
            .self_stake
            .checked_add(delegations_snapshot.iter().map(|(_, a)| a).sum())
            .ok_or(StakingError::Overflow)?;

        // Calculate slash amount (integer math: total_bonded * slash_bps / 10_000)
        let slash_amount = total_bonded
            .checked_mul(slash_bps as u128)
            .ok_or(StakingError::Overflow)?
            .checked_div(10_000)
            .ok_or(StakingError::Overflow)?;

        if slash_amount == 0 {
            v.jailed = true;
            return Ok(());
        }

        // Compute slash proportion factor: slash_amount / total_bonded, then apply to each.
        // To avoid floating point, we compute remaining amounts by subtracting proportional part.
        // For each delegation (including self-stake), new = amount - (amount * slash_amount / total_bonded).
        // Using integer arithmetic carefully.
        let slash_self = multiply_ratio(v.self_stake, slash_amount, total_bonded)?;
        v.self_stake = v.self_stake.checked_sub(slash_self).ok_or(StakingError::Overflow)?;

        for (delegator, amount) in delegations_snapshot {
            let slash_deleg = multiply_ratio(amount, slash_amount, total_bonded)?;
            let new_amount = amount.checked_sub(slash_deleg).ok_or(StakingError::Overflow)?;
            let key = (delegator.clone(), validator.to_string());
            if new_amount == 0 {
                self.delegations.remove(&key);
            } else {
                self.delegations.insert(key, new_amount);
            }
        }

        // Slashing may result in dust, but total slash is exactly slash_amount (within rounding)
        v.jailed = true;
        Ok(())
    }

    /// Unjail a validator (governance or after serving time).
    pub fn unjail(&mut self, validator: &str) -> StakingResult<()> {
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        v.jailed = false;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Queries
    // -------------------------------------------------------------------------

    /// Total active voting power (sum of self-stake + delegations for non‑jailed validators).
    pub fn total_power(&self) -> StakingResult<u128> {
        let mut total = 0u128;
        for v in self.validators.values() {
            if v.jailed {
                continue;
            }
            let deleg_sum: u128 = self
                .delegations
                .iter()
                .filter(|((_, val), _)| val == &v.operator)
                .map(|(_, a)| a)
                .sum();
            total = total
                .checked_add(v.self_stake)
                .and_then(|t| t.checked_add(deleg_sum))
                .ok_or(StakingError::Overflow)?;
        }
        Ok(total)
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
// Helpers
// -----------------------------------------------------------------------------

/// Computes `value * numerator / denominator` safely, rounding down.
fn multiply_ratio(value: u128, numerator: u128, denominator: u128) -> StakingResult<u128> {
    if denominator == 0 {
        return Err(StakingError::Overflow);
    }
    value
        .checked_mul(numerator)
        .and_then(|p| p.checked_div(denominator))
        .ok_or(StakingError::Overflow)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_validator(operator: &str, self_stake: u128, commission: u64) -> Validator {
        Validator::new(operator.to_string(), self_stake, commission).unwrap()
    }

    // ---------- Validator ----------
    #[test]
    fn test_validator_new_ok() {
        let v = sample_validator("alice", 1000, 500);
        assert_eq!(v.commission_bps, 500);
        assert!(!v.jailed);
    }

    #[test]
    fn test_validator_new_invalid_commission() {
        assert!(Validator::new("bob".into(), 1000, 10_001).is_err());
    }

    // ---------- add / update / remove ----------
    #[test]
    fn test_add_duplicate_fails() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 100)).unwrap();
        let err = state.add_validator(sample_validator("alice", 200, 200)).unwrap_err();
        assert!(matches!(err, StakingError::ValidatorAlreadyExists(name) if name == "alice"));
    }

    #[test]
    fn test_update_validator() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 100)).unwrap();
        state.update_validator("alice", 500, 200).unwrap();
        let v = state.get_validator("alice").unwrap();
        assert_eq!(v.self_stake, 500);
        assert_eq!(v.commission_bps, 200);
    }

    #[test]
    fn test_remove_validator_clears_delegations() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.delegate("bob".into(), "alice".into(), 200).unwrap();
        state.delegate("carol".into(), "alice".into(), 300).unwrap();

        state.remove_validator("alice", 42).unwrap();

        // delegations should be gone
        assert_eq!(state.get_delegation("bob", "alice"), 0);
        assert_eq!(state.get_delegation("carol", "alice"), 0);
        // unbonding entries created with unlock_epoch = 42
        let entry_bob = state.unbonding.get(&("bob".into(), "alice".into()));
        assert_eq!(entry_bob, Some(&(200, 42)));
        let entry_carol = state.unbonding.get(&("carol".into(), "alice".into()));
        assert_eq!(entry_carol, Some(&(300, 42)));
        // validator removed
        assert!(state.get_validator("alice").is_none());
    }

    // ---------- delegation ----------
    #[test]
    fn test_delegate_and_undelegate_flow() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.delegate("bob".into(), "alice".into(), 500).unwrap();
        assert_eq!(state.get_delegation("bob", "alice"), 500);

        state
            .undelegate("bob".into(), "alice".into(), 200, 10, 14)
            .unwrap();
        assert_eq!(state.get_delegation("bob", "alice"), 300);
        assert!(state.unbonding.contains_key(&("bob".into(), "alice".into())));

        // Try withdrawing before unlock
        let w = state.withdraw("bob".into(), "alice".into(), 10 + 13);
        assert_eq!(w, 0);

        // Withdraw after unlock
        let w = state.withdraw("bob".into(), "alice".into(), 24);
        assert_eq!(w, 200);
        assert!(!state.unbonding.contains_key(&("bob".into(), "alice".into())));
    }

    #[test]
    fn test_cannot_undelegate_twice_simultaneously() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.delegate("bob".into(), "alice".into(), 500).unwrap();
        state
            .undelegate("bob".into(), "alice".into(), 100, 1, 10)
            .unwrap();
        let err = state
            .undelegate("bob".into(), "alice".into(), 50, 1, 10)
            .unwrap_err();
        assert!(matches!(
            err,
            StakingError::UnbondingAlreadyExists(del, val) if del == "bob" && val == "alice"
        ));
    }

    #[test]
    fn test_delegate_to_jailed() {
        let mut state = StakingState::default();
        let mut v = sample_validator("alice", 100, 0);
        v.jailed = true;
        state.add_validator(v).unwrap();
        let err = state.delegate("bob".into(), "alice".into(), 1).unwrap_err();
        assert!(matches!(err, StakingError::ValidatorJailed(name) if name == "alice"));
    }

    // ---------- slashing ----------
    #[test]
    fn test_slash_proportional() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1000, 0)).unwrap();
        state.delegate("bob".into(), "alice".into(), 500).unwrap();
        state.delegate("carol".into(), "alice".into(), 500).unwrap();

        // Total bond = 1000 + 500 + 500 = 2000. Slash 20% (2000 bps) -> slash 400.
        state.slash("alice", 2000).unwrap();

        let v = state.get_validator("alice").unwrap();
        assert!(v.jailed);
        // 20% of 1000 = 200, so self_stake becomes 800
        assert_eq!(v.self_stake, 800);

        assert_eq!(state.get_delegation("bob", "alice"), 400);
        assert_eq!(state.get_delegation("carol", "alice"), 400);
    }

    #[test]
    fn test_slash_zero_bps_just_jails() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.slash("alice", 0).unwrap();
        assert!(state.get_validator("alice").unwrap().jailed);
        assert_eq!(state.get_validator("alice").unwrap().self_stake, 100);
    }

    // ---------- total_power ----------
    #[test]
    fn test_total_power_includes_delegations() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.add_validator(sample_validator("bob", 200, 0)).unwrap();
        state.delegate("carol".into(), "alice".into(), 50).unwrap();

        let power = state.total_power().unwrap();
        assert_eq!(power, 100 + 50 + 200); // 350
    }

    #[test]
    fn test_total_power_excludes_jailed() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 100, 0)).unwrap();
        state.add_validator(sample_validator("bob", 200, 0)).unwrap();
        state.slash("bob", 0).unwrap(); // jailed
        let power = state.total_power().unwrap();
        assert_eq!(power, 100);
    }

    // ---------- overflow protection ----------
    #[test]
    fn test_overflow_delegate() {
        let mut state = StakingState::default();
        state.add_validator(sample_validator("alice", 1, 0)).unwrap();
        state.delegate("bob".into(), "alice".into(), u128::MAX).unwrap();
        let err = state.delegate("bob".into(), "alice".into(), 1).unwrap_err();
        assert!(matches!(err, StakingError::Overflow));
    }
}
