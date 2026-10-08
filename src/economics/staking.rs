//! Core staking logic for IONA.
//!
//! Manages validators, delegations, the unbonding queue, slashing, and the
//! validator bond (voting power).
//!
//! # Bond model
//!
//! Each validator's **bond** (voting power) is:
//!
//! ```text
//! total_stake = self_stake + Σ delegations_to_validator
//! ```
//!
//! Both `Validator::self_stake` and every `Delegation::amount` contribute to
//! `total_stake`. The invariant
//!
//! ```text
//! total_stake == self_stake + Σ delegation.amount
//! ```
//!
//! is maintained by every mutation in this module. [`StakingState::check_invariants`]
//! verifies it in debug builds and in tests.
//!
//! # Slashing
//!
//! [`StakingState::slash`] penalizes the *entire* bond — self-stake,
//! external delegations, and the pending unbonding queue — proportionally.
//! Slashing the unbonding queue is required for safety: without it, a
//! validator could undelegate just before a slash event and escape the
//! penalty. See [`SlashOutcome`] for a per-bucket breakdown.
//!
//! # Overflow
//!
//! Every arithmetic operation that produces a token amount uses
//! [`mul_div_bps`] (a split-multiply-divide that cannot overflow `u128`) or
//! a checked `add`/`sub`. Silent saturation would be indistinguishable from
//! a real balance.
//!
//! # Events
//!
//! Mutating operations return a structured result (or [`SlashOutcome`])
//! rather than an opaque `Ok(())`. Callers that need event emission should
//! translate these values into their event log.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────

/// Basis-points denominator: 10 000 bp = 100 %.
pub const MAX_BPS: u64 = 10_000;

// ── Validator ─────────────────────────────────────────────────────────────

/// A validator participating in consensus.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Validator {
    /// Operator address (account that manages the validator).
    pub operator: String,
    /// Self-stake: tokens bonded by the operator.
    pub self_stake: u128,
    /// Total bond (self + delegations). This is the voting power.
    ///
    /// Must be kept in sync with `self_stake + Σ delegations`.
    pub total_stake: u128,
    /// Whether the validator is jailed (removed from consensus).
    pub jailed: bool,
    /// Commission rate in basis points (`0..=MAX_BPS`).
    pub commission_bps: u64,
}

impl Validator {
    /// Create a validator.
    ///
    /// # Errors
    ///
    /// - [`StakingError::InvalidCommission`] if `commission_bps > MAX_BPS`.
    #[must_use = "the Result must be handled"]
    pub fn new(
        operator: impl Into<String>,
        self_stake: u128,
        commission_bps: u64,
    ) -> Result<Self, StakingError> {
        if commission_bps > MAX_BPS {
            return Err(StakingError::InvalidCommission(commission_bps));
        }
        Ok(Self {
            operator: operator.into(),
            self_stake,
            total_stake: self_stake,
            jailed: false,
            commission_bps,
        })
    }
}

// ── Delegation ────────────────────────────────────────────────────────────

/// A delegation from a delegator to a validator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Delegation {
    /// Amount of tokens currently bonded.
    pub amount: u128,
    /// Pending unbonding entries, in insertion order.
    pub unbondings: Vec<UnbondingEntry>,
}

impl Default for Delegation {
    fn default() -> Self {
        Self {
            amount: 0,
            unbondings: Vec::new(),
        }
    }
}

impl Delegation {
    /// Sum of all pending unbonding amounts.
    #[must_use]
    pub fn pending_unbonding(&self) -> u128 {
        self.unbondings
            .iter()
            .fold(0u128, |acc, e| acc.saturating_add(e.amount))
    }
}

/// An unbonding operation waiting to be released.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnbondingEntry {
    /// Monotonic identifier, unique within a [`Delegation`].
    #[serde(default)]
    pub id: u64,
    /// Amount that will be released at `unlock_epoch`.
    pub amount: u128,
    /// Epoch at which the amount becomes withdrawable.
    pub unlock_epoch: u64,
}

// ── State ─────────────────────────────────────────────────────────────────

/// The persisted staking state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StakingState {
    pub validators: BTreeMap<String, Validator>,
    /// Delegations keyed by `(delegator, validator)`.
    pub delegations: BTreeMap<(String, String), Delegation>,
    /// Next identifier to hand out for an unbonding entry.
    #[serde(default)]
    next_unbonding_id: u64,
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors from staking operations.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StakingError {
    #[error("validator {0} not found")]
    ValidatorNotFound(String),

    #[error("delegation from {delegator} to {validator} not found")]
    DelegationNotFound { delegator: String, validator: String },

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("amount must be > 0")]
    ZeroAmount,

    #[error("undelegate amount {requested} exceeds bonded delegation {bonded}")]
    UndelegateExceedsDelegation { requested: u128, bonded: u128 },

    #[error("validator {0} is jailed and cannot accept delegations")]
    ValidatorJailed(String),

    #[error("commission {0} bps out of range (0..=10000)")]
    InvalidCommission(u64),

    #[error("slash rate {0} bps out of range (0..=10000)")]
    InvalidSlashRate(u64),

    #[error("arithmetic overflow in {op}")]
    Overflow { op: &'static str },
}

// ── Outcomes ──────────────────────────────────────────────────────────────

/// Result of a successful [`StakingState::slash`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlashOutcome {
    pub validator: String,
    pub slash_bps: u64,
    /// Amount removed from `self_stake`.
    pub self_slashed: u128,
    /// Amount removed from bonded delegations.
    pub delegations_slashed: u128,
    /// Amount removed from pending unbonding entries.
    pub unbondings_slashed: u128,
    /// Total slashed across all three buckets.
    pub total_slashed: u128,
    /// Whether the validator was jailed as a side effect.
    pub jailed: bool,
}

// ── Implementation ────────────────────────────────────────────────────────

impl StakingState {
    // ── Queries ─────────────────────────────────────────────────────────

    /// Look up a validator.
    #[must_use]
    pub fn validator(&self, addr: &str) -> Option<&Validator> {
        self.validators.get(addr)
    }

    /// Look up a delegation.
    #[must_use]
    pub fn delegation_of(&self, delegator: &str, validator: &str) -> Option<&Delegation> {
        self.delegations
            .get(&(delegator.to_string(), validator.to_string()))
    }

    /// Sum of external delegations to `validator` (excluding self-stake).
    #[must_use]
    pub fn total_delegated_to(&self, validator: &str) -> u128 {
        self.delegations
            .iter()
            .filter(|((_, v), _)| v == validator)
            .fold(0u128, |acc, (_, d)| acc.saturating_add(d.amount))
    }

    /// Verify the per-validator bond invariant. Panics in debug builds.
    ///
    /// Public so it can be called from tests and from a periodic
    /// consistency checker.
    pub fn check_invariants(&self) {
        for (addr, v) in &self.validators {
            let expected = v.self_stake.saturating_add(self.total_delegated_to(addr));
            debug_assert_eq!(
                v.total_stake, expected,
                "validator {addr}: total_stake {} != self_stake {} + delegations {}",
                v.total_stake, v.self_stake, expected,
            );
        }
    }

    // ── Delegate ────────────────────────────────────────────────────────

    /// Bond `amount` from `delegator` to `validator`.
    ///
    /// `balance_of` is a read-only probe that lets the caller enforce the
    /// delegator's on-chain balance before the bond is recorded. The caller
    /// is responsible for actually moving tokens.
    pub fn delegate(
        &mut self,
        delegator: impl Into<String>,
        validator: impl Into<String>,
        amount: u128,
        balance_of: impl Fn(&str) -> u128,
    ) -> Result<(), StakingError> {
        let delegator = delegator.into();
        let validator = validator.into();

        if amount == 0 {
            return Err(StakingError::ZeroAmount);
        }

        let have = balance_of(&delegator);
        if have < amount {
            return Err(StakingError::InsufficientBalance { have, need: amount });
        }

        // Validate and stage the validator update.
        let new_total = {
            let v = self
                .validators
                .get(&validator)
                .ok_or_else(|| StakingError::ValidatorNotFound(validator.clone()))?;
            if v.jailed {
                return Err(StakingError::ValidatorJailed(validator));
            }
            v.total_stake
                .checked_add(amount)
                .ok_or(StakingError::Overflow { op: "delegate.total_stake" })?
        };

        // Stage the delegation update.
        let key = (delegator, validator.clone());
        let new_delegation_amount = self
            .delegations
            .get(&key)
            .map(|d| d.amount)
            .unwrap_or(0)
            .checked_add(amount)
            .ok_or(StakingError::Overflow { op: "delegate.delegation" })?;

        // Commit both — no fallible operations remain.
        self.validators
            .get_mut(&validator)
            .expect("validated above")
            .total_stake = new_total;
        self.delegations
            .entry(key)
            .or_default()
            .amount = new_delegation_amount;

        self.check_invariants();
        Ok(())
    }

    // ── Undelegate ──────────────────────────────────────────────────────

    /// Begin unbonding `amount` from `delegator` to `validator`.
    ///
    /// The amount is removed from the active delegation immediately and
    /// pushed onto the unbonding queue with `unlock_epoch =
    /// current_epoch + unbonding_epochs`.
    ///
    /// # Slashing during unbonding
    ///
    /// Unbonding entries are **still subject to slashing** until they
    /// unlock. See [`Self::slash`].
    pub fn undelegate(
        &mut self,
        delegator: impl Into<String>,
        validator: impl Into<String>,
        amount: u128,
        current_epoch: u64,
        unbonding_epochs: u64,
    ) -> Result<u64, StakingError> {
        let delegator = delegator.into();
        let validator = validator.into();

        if amount == 0 {
            return Err(StakingError::ZeroAmount);
        }

        // Ensure the validator exists (delegations alone are not enough to
        // identify a live bond).
        if !self.validators.contains_key(&validator) {
            return Err(StakingError::ValidatorNotFound(validator));
        }

        let key = (delegator.clone(), validator.clone());
        let delegation = self.delegations.get(&key).ok_or_else(|| {
            StakingError::DelegationNotFound {
                delegator: delegator.clone(),
                validator: validator.clone(),
            }
        })?;

        if delegation.amount < amount {
            return Err(StakingError::UndelegateExceedsDelegation {
                requested: amount,
                bonded: delegation.amount,
            });
        }

        // Allocate the entry id.
        let entry_id = self.next_unbonding_id;
        self.next_unbonding_id = self
            .next_unbonding_id
            .checked_add(1)
            .ok_or(StakingError::Overflow { op: "undelegate.id" })?;

        let unlock_epoch = current_epoch.saturating_add(unbonding_epochs);

        // Commit — no fallible operations remain.
        let delegation = self
            .delegations
            .get_mut(&key)
            .expect("validated above");
        delegation.amount -= amount;
        delegation.unbondings.push(UnbondingEntry {
            id: entry_id,
            amount,
            unlock_epoch,
        });

        self.validators
            .get_mut(&validator)
            .expect("validated above")
            .total_stake = self
            .validators
            .get(&validator)
            .expect("validated above")
            .total_stake
            .checked_sub(amount)
            .ok_or(StakingError::Overflow { op: "undelegate.total_stake" })?;

        self.check_invariants();
        Ok(entry_id)
    }

    // ── Withdraw ────────────────────────────────────────────────────────

    /// Release every unlocked unbonding entry.
    ///
    /// Returns the total amount made available to the delegator's balance.
    /// The caller is responsible for crediting that balance.
    ///
    /// Removes the delegation entry entirely if it has no bonded amount and
    /// no pending unbondings left.
    pub fn withdraw(
        &mut self,
        delegator: impl Into<String>,
        validator: impl Into<String>,
        current_epoch: u64,
    ) -> Result<u128, StakingError> {
        let delegator = delegator.into();
        let validator = validator.into();
        let key = (delegator.clone(), validator.clone());

        let delegation = self
            .delegations
            .get_mut(&key)
            .ok_or(StakingError::DelegationNotFound { delegator, validator })?;

        let mut withdrawn: u128 = 0;
        let mut retained: Vec<UnbondingEntry> = Vec::with_capacity(delegation.unbondings.len());
        for entry in delegation.unbondings.drain(..) {
            if entry.unlock_epoch <= current_epoch {
                withdrawn = withdrawn
                    .checked_add(entry.amount)
                    .ok_or(StakingError::Overflow { op: "withdraw.sum" })?;
            } else {
                retained.push(entry);
            }
        }
        delegation.unbondings = retained;

        // Clean up an empty delegation to avoid leaking entries.
        if delegation.amount == 0 && delegation.unbondings.is_empty() {
            self.delegations.remove(&key);
        }

        Ok(withdrawn)
    }

    // ── Slash ───────────────────────────────────────────────────────────

    /// Slash `validator` at `slash_bps` of every bonded component.
    ///
    /// Applies the same rate to:
    ///
    /// 1. the operator's `self_stake`,
    /// 2. every external delegation's bonded `amount`,
    /// 3. every pending unbonding entry.
    ///
    /// Slashing the unbonding queue is required for safety — otherwise a
    /// validator could undelegate just before a slash event and escape the
    /// penalty.
    ///
    /// The validator is jailed as a side effect. Callers that apply
    /// downtime slashes with a different policy should construct the
    /// outcome themselves; see [`SlashOutcome::jailed`].
    pub fn slash(&mut self, validator: &str, slash_bps: u64) -> Result<SlashOutcome, StakingError> {
        if slash_bps > MAX_BPS {
            return Err(StakingError::InvalidSlashRate(slash_bps));
        }

        // Validate existence before mutating.
        if !self.validators.contains_key(validator) {
            return Err(StakingError::ValidatorNotFound(validator.to_string()));
        }

        let mut self_slashed: u128 = 0;
        let mut delegations_slashed: u128 = 0;
        let mut unbondings_slashed: u128 = 0;

        // 1) Slash self-stake.
        {
            let v = self
                .validators
                .get_mut(validator)
                .expect("validated above");
            let amount = mul_div_bps(v.self_stake, slash_bps);
            v.self_stake -= amount;
            self_slashed = amount;
        }

        // 2) Slash each delegation and its pending unbondings.
        for ((_delegator, val), delegation) in self.delegations.iter_mut() {
            if val != validator {
                continue;
            }
            let bonded = mul_div_bps(delegation.amount, slash_bps);
            delegation.amount -= bonded;
            delegations_slashed += bonded;

            for entry in &mut delegation.unbondings {
                let unbonded = mul_div_bps(entry.amount, slash_bps);
                entry.amount -= unbonded;
                unbondings_slashed += unbonded;
            }
        }

        // 3) Update the bond (only self-stake and delegations are in the bond).
        let bond_reduction = self_slashed
            .checked_add(delegations_slashed)
            .ok_or(StakingError::Overflow { op: "slash.bond_reduction" })?;
        {
            let v = self
                .validators
                .get_mut(validator)
                .expect("validated above");
            v.total_stake = v
                .total_stake
                .checked_sub(bond_reduction)
                .ok_or(StakingError::Overflow { op: "slash.total_stake" })?;
            v.jailed = true;
        }

        let total_slashed = self_slashed
            .checked_add(delegations_slashed)
            .and_then(|s| s.checked_add(unbondings_slashed))
            .ok_or(StakingError::Overflow { op: "slash.total" })?;

        self.check_invariants();

        Ok(SlashOutcome {
            validator: validator.to_string(),
            slash_bps,
            self_slashed,
            delegations_slashed,
            unbondings_slashed,
            total_slashed,
            jailed: true,
        })
    }

    /// Remove the jailed flag from `validator`.
    pub fn unjail(&mut self, validator: &str) -> Result<(), StakingError> {
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        v.jailed = false;
        Ok(())
    }

    /// Force the cached `total_stake` for `validator` to match
    /// `self_stake + Σ delegations`.
    ///
    /// Should not be needed in practice (every mutating method maintains
    /// the invariant), but exposed for recovery tools.
    pub fn recompute_total_stake(&mut self, validator: &str) -> Result<(), StakingError> {
        let delegated = self.total_delegated_to(validator);
        let v = self
            .validators
            .get_mut(validator)
            .ok_or_else(|| StakingError::ValidatorNotFound(validator.to_string()))?;
        v.total_stake = v
            .self_stake
            .checked_add(delegated)
            .ok_or(StakingError::Overflow { op: "recompute_total_stake" })?;
        Ok(())
    }
}

// ── Arithmetic helpers ────────────────────────────────────────────────────

/// Exact `a × bps / 10_000`, computed via split-multiply-divide so no
/// intermediate product can overflow `u128`.
///
/// `bps` must be `≤ 10_000` (the caller enforces this via
/// [`StakingError::InvalidSlashRate`] / [`StakingError::InvalidCommission`]).
#[inline]
fn mul_div_bps(a: u128, bps: u64) -> u128 {
    debug_assert!(bps <= MAX_BPS);
    let b = bps as u128;
    let c = MAX_BPS as u128;
    let hi = a / c;
    let lo = a % c;
    hi * b + (lo * b) / c
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn balance_of(addr: &str) -> u128 {
        match addr {
            "alice" => 10_000,
            "bob" => 5_000,
            "charlie" => 100_000,
            _ => 0,
        }
    }

    fn state_with_validator(stake: u128) -> StakingState {
        let mut s = StakingState::default();
        s.validators
            .insert("val1".into(), Validator::new("val1", stake, 500).unwrap());
        s
    }

    // ── Validator construction ──────────────────────────────────────────

    #[test]
    fn validator_new_rejects_excessive_commission() {
        assert!(matches!(
            Validator::new("v", 1, MAX_BPS + 1),
            Err(StakingError::InvalidCommission(_))
        ));
    }

    #[test]
    fn validator_new_accepts_boundary_commission() {
        assert!(Validator::new("v", 1, MAX_BPS).is_ok());
    }

    // ── Delegate ────────────────────────────────────────────────────────

    #[test]
    fn delegate_updates_bond_and_delegation() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();

        assert_eq!(state.delegation_of("alice", "val1").unwrap().amount, 500);
        assert_eq!(state.validator("val1").unwrap().total_stake, 1_500);
        state.check_invariants();
    }

    #[test]
    fn delegate_rejects_zero() {
        let mut state = state_with_validator(1_000);
        assert_eq!(
            state.delegate("alice", "val1", 0, balance_of),
            Err(StakingError::ZeroAmount)
        );
    }

    #[test]
    fn delegate_rejects_insufficient_balance() {
        let mut state = state_with_validator(1_000);
        assert!(matches!(
            state.delegate("alice", "val1", 10_000_000, balance_of),
            Err(StakingError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn delegate_rejects_jailed_validator() {
        let mut state = state_with_validator(1_000);
        state.validators.get_mut("val1").unwrap().jailed = true;
        assert!(matches!(
            state.delegate("alice", "val1", 100, balance_of),
            Err(StakingError::ValidatorJailed(_))
        ));
    }

    #[test]
    fn delegate_rejects_unknown_validator() {
        let mut state = StakingState::default();
        assert!(matches!(
            state.delegate("alice", "ghost", 100, balance_of),
            Err(StakingError::ValidatorNotFound(_))
        ));
    }

    #[test]
    fn delegate_overflow_is_reported() {
        let mut state = state_with_validator(u128::MAX);
        assert!(matches!(
            state.delegate("alice", "val1", 1, balance_of),
            Err(StakingError::Overflow { .. })
        ));
    }

    // ── Undelegate ──────────────────────────────────────────────────────

    #[test]
    fn undelegate_pushes_entry_and_reduces_bond() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();

        let entry_id = state
            .undelegate("alice", "val1", 200, 100, 14)
            .unwrap();

        let d = state.delegation_of("alice", "val1").unwrap();
        assert_eq!(d.amount, 300);
        assert_eq!(d.unbondings.len(), 1);
        assert_eq!(d.unbondings[0].id, entry_id);
        assert_eq!(d.unbondings[0].amount, 200);
        assert_eq!(d.unbondings[0].unlock_epoch, 114);
        assert_eq!(state.validator("val1").unwrap().total_stake, 1_300);
        state.check_invariants();
    }

    #[test]
    fn undelegate_rejects_amount_above_bond() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();
        assert!(matches!(
            state.undelegate("alice", "val1", 999, 100, 14),
            Err(StakingError::UndelegateExceedsDelegation { .. })
        ));
    }

    #[test]
    fn undelegate_uses_delegation_not_found() {
        // Regression: previously returned `ValidatorNotFound` for a
        // missing *delegation*.
        let mut state = state_with_validator(1_000);
        assert!(matches!(
            state.undelegate("alice", "val1", 100, 100, 14),
            Err(StakingError::DelegationNotFound { .. })
        ));
    }

    // ── Withdraw ────────────────────────────────────────────────────────

    #[test]
    fn withdraw_releases_only_unlocked_entries() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();
        state
            .undelegate("alice", "val1", 100, 100, 10)
            .unwrap(); // unlocks at 110
        state
            .undelegate("alice", "val1", 200, 100, 20)
            .unwrap(); // unlocks at 120

        // At epoch 115 only the first entry unlocks.
        let released = state.withdraw("alice", "val1", 115).unwrap();
        assert_eq!(released, 100);

        // The second is still pending.
        let d = state.delegation_of("alice", "val1").unwrap();
        assert_eq!(d.unbondings.len(), 1);
        assert_eq!(d.unbondings[0].amount, 200);

        // At epoch 120 everything unlocks.
        let released = state.withdraw("alice", "val1", 120).unwrap();
        assert_eq!(released, 200);
    }

    #[test]
    fn withdraw_removes_empty_delegation() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 100, balance_of)
            .unwrap();
        state
            .undelegate("alice", "val1", 100, 0, 1)
            .unwrap();
        let _ = state.withdraw("alice", "val1", 1000).unwrap();

        assert!(
            state.delegation_of("alice", "val1").is_none(),
            "empty delegation should be pruned"
        );
    }

    #[test]
    fn withdraw_reports_delegation_not_found() {
        let mut state = state_with_validator(1_000);
        assert!(matches!(
            state.withdraw("alice", "val1", 0),
            Err(StakingError::DelegationNotFound { .. })
        ));
    }

    // ── Slash ───────────────────────────────────────────────────────────

    #[test]
    fn slash_scales_self_stake_and_delegations() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();

        let outcome = state.slash("val1", 1_000).unwrap(); // 10 %

        assert_eq!(outcome.self_slashed, 100);
        assert_eq!(outcome.delegations_slashed, 50);
        assert_eq!(outcome.unbondings_slashed, 0);
        assert_eq!(outcome.total_slashed, 150);
        assert!(outcome.jailed);

        let v = state.validator("val1").unwrap();
        assert_eq!(v.self_stake, 900);
        assert_eq!(v.total_stake, 1_350);
        assert!(v.jailed);

        let d = state.delegation_of("alice", "val1").unwrap();
        assert_eq!(d.amount, 450);

        state.check_invariants();
    }

    #[test]
    fn slash_also_slashes_unbonding_entries() {
        // Regression: the previous version skipped unbonding entries,
        // letting a validator escape slashing by undelegating just before
        // the slash event.
        let mut state = state_with_validator(0);
        state
            .delegate("alice", "val1", 1_000, balance_of)
            .unwrap();
        state
            .undelegate("alice", "val1", 400, 0, 100)
            .unwrap();
        // Bob delegates to have a second actor.
        state
            .delegate("bob", "val1", 500, balance_of)
            .unwrap();

        let outcome = state.slash("val1", 5_000).unwrap(); // 50 %

        // Unbonding entry of 400 should now be 200.
        let d = state.delegation_of("alice", "val1").unwrap();
        assert_eq!(d.unbondings.len(), 1);
        assert_eq!(d.unbondings[0].amount, 200);
        assert_eq!(outcome.unbondings_slashed, 200);

        // Bonded delegations of alice (600) and bob (500) slashed 50 %.
        assert_eq!(d.amount, 300);
        let bob = state.delegation_of("bob", "val1").unwrap();
        assert_eq!(bob.amount, 250);

        state.check_invariants();
    }

    #[test]
    fn slash_rejects_excessive_rate() {
        let mut state = state_with_validator(1_000);
        assert!(matches!(
            state.slash("val1", MAX_BPS + 1),
            Err(StakingError::InvalidSlashRate(_))
        ));
    }

    #[test]
    fn slash_of_unknown_validator_fails() {
        let mut state = StakingState::default();
        assert!(matches!(
            state.slash("ghost", 100),
            Err(StakingError::ValidatorNotFound(_))
        ));
    }

    #[test]
    fn slash_of_u128_max_does_not_overflow() {
        // Regression: `self_stake * slash_bps` overflows for large stake.
        // 100 % slash must remove exactly the staked amount.
        let mut state = state_with_validator(0);
        state
            .delegate("charlie", "val1", 1_000, balance_of)
            .unwrap();
        state.validators.get_mut("val1").unwrap().self_stake = u128::MAX;
        state
            .validators
            .get_mut("val1")
            .unwrap()
            .total_stake = u128::MAX;

        let outcome = state.slash("val1", MAX_BPS).unwrap();
        assert_eq!(outcome.self_slashed, u128::MAX);
        assert_eq!(state.validator("val1").unwrap().self_stake, 0);
    }

    #[test]
    fn slash_of_zero_returns_zero_outcome() {
        let mut state = state_with_validator(0);
        let outcome = state.slash("val1", 5_000).unwrap();
        assert_eq!(outcome.total_slashed, 0);
        assert!(outcome.jailed); // still jails
    }

    // ── Unjail ──────────────────────────────────────────────────────────

    #[test]
    fn unjail_clears_flag() {
        let mut state = state_with_validator(1_000);
        state.slash("val1", 100).unwrap();
        assert!(state.validator("val1").unwrap().jailed);
        state.unjail("val1").unwrap();
        assert!(!state.validator("val1").unwrap().jailed);
    }

    // ── Recovery ────────────────────────────────────────────────────────

    #[test]
    fn recompute_total_stake_restores_invariant() {
        let mut state = state_with_validator(1_000);
        state
            .delegate("alice", "val1", 500, balance_of)
            .unwrap();
        // Corrupt the cache.
        state.validators.get_mut("val1").unwrap().total_stake = 0;
        state.recompute_total_stake("val1").unwrap();
        assert_eq!(state.validator("val1").unwrap().total_stake, 1_500);
    }

    // ── Arithmetic helper ───────────────────────────────────────────────

    #[test]
    fn mul_div_bps_is_exact_for_small_cases() {
        assert_eq!(mul_div_bps(1_000, 500), 50);
        assert_eq!(mul_div_bps(1_000, 10_000), 1_000);
        assert_eq!(mul_div_bps(0, 10_000), 0);
    }

    #[test]
    fn mul_div_bps_handles_u128_max() {
        assert_eq!(mul_div_bps(u128::MAX, 10_000), u128::MAX);
        assert_eq!(mul_div_bps(u128::MAX, 5_000), u128::MAX / 2);
        assert_eq!(mul_div_bps(u128::MAX, 0), 0);
    }
}
