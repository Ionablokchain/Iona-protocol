//! Core staking logic for IONA.
//!
//! Manages validators, delegations, unbonding, slashing, and stake-based voting power.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Validator
// -----------------------------------------------------------------------------

/// A validator participating in consensus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    /// Operator address (account that manages the validator).
    pub operator: String,
    /// Self‑stake (tokens bonded by the operator).
    pub self_stake: u128,
    /// Total stake (self + delegations). This is the voting power.
    pub total_stake: u128,
    /// Whether the validator is jailed (temporarily removed from consensus).
    pub jailed: bool,
    /// Commission rate in basis points (0‑10000). 1 % = 100 bps.
    pub commission_bps: u64,
}

impl Validator {
    /// Creates a new validator with the given operator, initial self‑stake, and commission.
    /// Returns `None` if commission is out of range.
    pub fn new(operator: String, self_stake: u128, commission_bps: u64) -> Option<Self> {
        if commission_bps > 10000 {
            return None;
        }
        Some(Self {
            operator,
            self_stake,
            total_stake: self_stake,
            jailed: false,
            commission_bps,
        })
    }
}

// -----------------------------------------------------------------------------
// Delegation entry
// -----------------------------------------------------------------------------

/// A delegation from a delegator to a validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Delegation {
    /// Amount of tokens currently delegated.
    pub amount: u128,
    /// Pending unbonding queue (in order).
    pub unbondings: Vec<UnbondingEntry>,
}

/// An unbonding operation (pending withdrawal).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnbondingEntry {
    pub amount: u128,
    pub unlock_epoch: u64,
}

// -----------------------------------------------------------------------------
// Staking state
// -----------------------------------------------------------------------------

/// The main staking state, persisted on chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StakingState {
    pub validators: BTreeMap<String, Validator>,
    /// Delegations: (delegator, validator) -> Delegation.
    pub delegations: BTreeMap<(String, String), Delegation>,
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during staking operations.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StakingError {
    #[error("validator {0} does not exist")]
    ValidatorNotFound(String),
    #[error("delegator does not have enough funds")]
    InsufficientBalance,
    #[error("delegation amount must be positive")]
    ZeroAmount,
    #[error("cannot undelegate more than delegated")]
    UndelegateExceedsDelegation,
    #[error("validator is jailed and cannot accept new delegations")]
    ValidatorJailed,
    #[error("commission out of range (0‑10000)")]
    CommissionOutOfRange,
}

// -----------------------------------------------------------------------------
// Implementation
// -----------------------------------------------------------------------------

impl StakingState {
    /// Delegates tokens from a delegator to a validator.
    ///
    /// # Arguments
    /// - `delegator` – the account delegating tokens.
    /// - `validator` – the operator address of the target validator.
    /// - `amount` – number of tokens to delegate.
    /// - `balance_of` – callback that returns the current balance of the delegator.
    ///
    /// # Returns
    /// `Ok(())` on success, or a `StakingError`.
    pub fn delegate(
        &mut self,
        delegator: String,
        validator: String,
        amount: u128,
        balance_of: impl Fn(&str) -> u128,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::ZeroAmount);
        }
        if balance_of(&delegator) < amount {
            return Err(StakingError::InsufficientBalance);
        }

        let v = self.validators
            .get_mut(&validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.clone()))?;
        if v.jailed {
            return Err(StakingError::ValidatorJailed);
        }

        // Update delegation
        let key = (delegator, validator);
        let entry = self.delegations.entry(key).or_insert(Delegation {
            amount: 0,
            unbondings: Vec::new(),
        });
        entry.amount = entry.amount.saturating_add(amount);

        // Update validator total stake
        v.total_stake = v.total_stake.saturating_add(amount);

        // Emit event (in a real implementation, you would log or store an event)
        // Here we just return success.

        Ok(())
    }

    /// Starts unbonding (undelegation) of tokens.
    ///
    /// The tokens become available for withdrawal after `unbonding_epochs` epochs.
    pub fn undelegate(
        &mut self,
        delegator: String,
        validator: String,
        amount: u128,
        current_epoch: u64,
        unbonding_epochs: u64,
    ) -> Result<(), StakingError> {
        if amount == 0 {
            return Err(StakingError::ZeroAmount);
        }

        let key = (delegator, validator.clone());
        let delegation = self.delegations
            .get_mut(&key)
            .ok_or(StakingError::ValidatorNotFound(validator.clone()))?;

        if delegation.amount < amount {
            return Err(StakingError::UndelegateExceedsDelegation);
        }

        delegation.amount = delegation.amount.saturating_sub(amount);
        delegation.unbondings.push(UnbondingEntry {
            amount,
            unlock_epoch: current_epoch.saturating_add(unbonding_epochs),
        });

        // Update validator total stake
        if let Some(v) = self.validators.get_mut(&validator) {
            v.total_stake = v.total_stake.saturating_sub(amount);
        }

        Ok(())
    }

    /// Withdraws any unbonded tokens that have reached their unlock epoch.
    ///
    /// Returns the total amount withdrawn.
    pub fn withdraw(
        &mut self,
        delegator: String,
        validator: String,
        current_epoch: u64,
    ) -> u128 {
        let key = (delegator, validator);
        let delegation = match self.delegations.get_mut(&key) {
            Some(d) => d,
            None => return 0,
        };

        let mut withdrawn = 0u128;
        let mut keep = Vec::new();
        for entry in delegation.unbondings.drain(..) {
            if entry.unlock_epoch <= current_epoch {
                withdrawn = withdrawn.saturating_add(entry.amount);
            } else {
                keep.push(entry);
            }
        }
        delegation.unbondings = keep;
        withdrawn
    }

    /// Slashes a validator (and its delegators) by a given percentage.
    ///
    /// The slash amount is calculated as `total_stake * slash_bps / 10_000`.
    /// The slashed tokens are removed from both self‑stake and delegations.
    pub fn slash(&mut self, validator: &str, slash_bps: u64) -> Result<(), StakingError> {
        let v = self.validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;

        if slash_bps > 10000 {
            // Slashing more than 100% is nonsense
            return Err(StakingError::CommissionOutOfRange);
        }

        let slash_ratio = slash_bps as u128 / 10_000u128;
        let total_stake = v.total_stake;
        let slash_amount = total_stake.saturating_mul(slash_bps as u128) / 10_000u128;

        if slash_amount == 0 {
            return Ok(());
        }

        // Reduce self‑stake proportionally
        let self_slash = if v.self_stake > 0 {
            (v.self_stake * slash_amount) / total_stake
        } else {
            0
        };
        v.self_stake = v.self_stake.saturating_sub(self_slash);
        v.total_stake = v.total_stake.saturating_sub(slash_amount);

        // Reduce delegations proportionally
        for ((delegator, val_operator), delegation) in self.delegations.iter_mut() {
            if val_operator == validator {
                let delegation_slash = (delegation.amount * slash_amount) / total_stake;
                delegation.amount = delegation.amount.saturating_sub(delegation_slash);
                // Also slash unbondings? Usually unbonding entries are not slashed,
                // but to be safe, we could slash pending unbondings too.
                // This is a design choice; for simplicity we skip.
            }
        }

        // Jail the validator (optional, but common)
        v.jailed = true;

        Ok(())
    }

    /// Unjails a validator, allowing it to re‑enter consensus.
    pub fn unjail(&mut self, validator: &str) -> Result<(), StakingError> {
        let v = self.validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        v.jailed = false;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn balance_of(addr: &str) -> u128 {
        match addr {
            "alice" => 10_000,
            "bob"   => 5_000,
            "charlie" => 100_000,
            _ => 0,
        }
    }

    #[test]
    fn test_delegate() {
        let mut state = StakingState::default();
        let val = Validator::new("val1".to_string(), 1_000, 500).unwrap();
        state.validators.insert("val1".to_string(), val);

        let res = state.delegate("alice".to_string(), "val1".to_string(), 500, balance_of);
        assert!(res.is_ok());
        let delegation = state.delegations.get(&("alice".to_string(), "val1".to_string())).unwrap();
        assert_eq!(delegation.amount, 500);
        assert_eq!(state.validators.get("val1").unwrap().total_stake, 1_500);
    }

    #[test]
    fn test_undelegate() {
        let mut state = StakingState::default();
        let val = Validator::new("val1".to_string(), 1_000, 500).unwrap();
        state.validators.insert("val1".to_string(), val);
        state.delegate("alice".to_string(), "val1".to_string(), 500, balance_of).unwrap();

        let res = state.undelegate("alice".to_string(), "val1".to_string(), 200, 100, 14);
        assert!(res.is_ok());

        let delegation = state.delegations.get(&("alice".to_string(), "val1".to_string())).unwrap();
        assert_eq!(delegation.amount, 300);
        assert_eq!(delegation.unbondings.len(), 1);
        assert_eq!(delegation.unbondings[0].amount, 200);
        assert_eq!(state.validators.get("val1").unwrap().total_stake, 1_300);
    }

    #[test]
    fn test_slash() {
        let mut state = StakingState::default();
        let val = Validator::new("val1".to_string(), 1_000, 500).unwrap();
        state.validators.insert("val1".to_string(), val);
        state.delegate("alice".to_string(), "val1".to_string(), 500, balance_of).unwrap();

        state.slash("val1", 1000).unwrap(); // 10% slash

        let v = state.validators.get("val1").unwrap();
        assert_eq!(v.self_stake, 900);  // 10% of 1_000 = 100
        assert_eq!(v.total_stake, 1_350); // 1_500 - 150

        let delegation = state.delegations.get(&("alice".to_string(), "val1".to_string())).unwrap();
        assert_eq!(delegation.amount, 450); // 500 - 50 (10% of 500)
        assert!(v.jailed);
    }
}
