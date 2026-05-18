//! Staking transaction parsing and execution for IONA.
//!
//! Staking operations are submitted as regular transactions with a "stake " payload prefix.
//! This keeps the consensus layer clean — staking is just another KV application.
//!
//! Supported staking payloads:
//!   stake delegate <validator_addr> <amount>
//!   stake undelegate <validator_addr> <amount>
//!   stake withdraw <validator_addr>
//!   stake register <commission_bps>      — register self as validator
//!   stake deregister                     — remove self from validator set

use crate::economics::params::EconomicsParams;
use crate::economics::staking::{StakingState, Validator as EconValidator, StakingError};
use crate::execution::KvState;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Error
// -----------------------------------------------------------------------------

/// Errors that can occur during staking transaction processing.
#[derive(Debug, Error)]
pub enum StakingTxError {
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("delegation amount must be > 0, got {0}")]
    ZeroDelegation(u128),
    #[error("undelegation amount must be > 0, got {0}")]
    ZeroUndelegation(u128),
    #[error("invalid amount: {0}")]
    InvalidAmount(String),
    #[error("validator '{0}' not found")]
    ValidatorNotFound(String),
    #[error("validator '{0}' is jailed")]
    ValidatorJailed(String),
    #[error("insufficient delegated amount: have {have}, need {need}")]
    InsufficientDelegation { have: u128, need: u128 },
    #[error("nothing to withdraw (unbonding not complete or no unbonding)")]
    NothingToWithdraw,
    #[error("commission basis points must be between 0 and 10_000, got {0}")]
    InvalidCommissionBps(u64),
    #[error("already registered as validator")]
    AlreadyRegistered,
    #[error("cannot deregister: not a registered validator")]
    NotRegistered,
    #[error("cannot deregister: {external_delegations} stake from delegators still active")]
    DelegatorsStillActive { external_delegations: u128 },
    #[error("missing argument: {0}")]
    MissingArgument(&'static str),
    #[error("unknown staking action: {0}")]
    UnknownAction(String),
    #[error("staking state error: {0}")]
    StakingError(#[from] StakingError),
    #[error("arithmetic overflow")]
    Overflow,
}

pub type StakingTxResult<T> = Result<T, StakingTxError>;

/// Result of applying a staking transaction.
#[derive(Debug)]
pub struct StakingTxOutcome {
    pub success: bool,
    pub error: Option<String>,
    pub gas_used: u64,
}

// -----------------------------------------------------------------------------
// Main entry point
// -----------------------------------------------------------------------------

/// Parse and apply a staking payload.
/// `from`: the sender address (already verified by execution layer).
/// Returns `None` if the payload does not start with "stake ".
pub fn try_apply_staking_tx(
    payload: &str,
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
    epoch: u64,
) -> Option<StakingTxOutcome> {
    let payload = payload.trim();
    if !payload.starts_with("stake ") {
        return None;
    }

    let parts: Vec<&str> = payload.split_whitespace().collect();
    if parts.len() < 2 {
        return Some(StakingTxOutcome::failure("missing action after 'stake'"));
    }

    let action = parts[1];
    let result = match action {
        "delegate" => apply_delegate(&parts, from, kv, staking, params),
        "undelegate" => apply_undelegate(&parts, from, kv, staking, params, epoch),
        "withdraw" => apply_withdraw(&parts, from, kv, staking, epoch),
        "register" => apply_register(&parts, from, kv, staking, params),
        "deregister" => apply_deregister(from, kv, staking, epoch),
        _ => Err(StakingTxError::UnknownAction(action.to_string())),
    };

    Some(match result {
        Ok(gas) => StakingTxOutcome {
            success: true,
            error: None,
            gas_used: gas,
        },
        Err(e) => StakingTxOutcome {
            success: false,
            error: Some(e.to_string()),
            gas_used: 21_000, // base gas even on failure
        },
    })
}

impl StakingTxOutcome {
    fn failure(msg: &str) -> Self {
        Self {
            success: false,
            error: Some(msg.to_string()),
            gas_used: 21_000,
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Safely deduct `amount` from a KV balance, returning the new balance or error.
fn deduct_balance(kv: &mut KvState, address: &str, amount: u64) -> StakingTxResult<u64> {
    let bal = *kv.balances.get(address).unwrap_or(&0);
    if bal < amount {
        return Err(StakingTxError::InsufficientBalance {
            have: bal,
            need: amount,
        });
    }
    let new_bal = bal.checked_sub(amount).ok_or(StakingTxError::Overflow)?;
    kv.balances.insert(address.to_string(), new_bal);
    Ok(new_bal)
}

/// Safely add `amount` to a KV balance, returning the new balance or error.
fn add_balance(kv: &mut KvState, address: &str, amount: u64) -> StakingTxResult<u64> {
    let current = *kv.balances.get(address).unwrap_or(&0);
    let new_bal = current.checked_add(amount).ok_or(StakingTxError::Overflow)?;
    kv.balances.insert(address.to_string(), new_bal);
    Ok(new_bal)
}

// -----------------------------------------------------------------------------
// Action handlers
// -----------------------------------------------------------------------------

/// stake delegate <validator_addr> <amount>
fn apply_delegate(
    parts: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> StakingTxResult<u64> {
    if parts.len() != 4 {
        return Err(StakingTxError::MissingArgument("validator address and amount"));
    }
    let val_addr = parts[2];
    let amount_str = parts[3];
    let amount: u64 = amount_str
        .parse()
        .map_err(|_| StakingTxError::InvalidAmount(amount_str.to_string()))?;

    if amount == 0 {
        return Err(StakingTxError::ZeroDelegation(amount as u128));
    }

    // Validator must exist and not be jailed
    let val = staking
        .get_validator(val_addr)
        .ok_or_else(|| StakingTxError::ValidatorNotFound(val_addr.to_string()))?;
    if val.jailed {
        return Err(StakingTxError::ValidatorJailed(val_addr.to_string()));
    }

    // Deduct from sender's balance
    deduct_balance(kv, from, amount)?;

    // Record delegation (staking uses u128 internally)
    staking
        .delegate(from.to_string(), val_addr.to_string(), amount as u128)
        .map_err(StakingTxError::StakingError)?;

    Ok(21_000 + 5_000) // delegate costs slightly more gas
}

/// stake undelegate <validator_addr> <amount>
fn apply_undelegate(
    parts: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
    epoch: u64,
) -> StakingTxResult<u64> {
    if parts.len() != 4 {
        return Err(StakingTxError::MissingArgument("validator address and amount"));
    }
    let val_addr = parts[2];
    let amount_str = parts[3];
    let amount: u64 = amount_str
        .parse()
        .map_err(|_| StakingTxError::InvalidAmount(amount_str.to_string()))?;

    if amount == 0 {
        return Err(StakingTxError::ZeroUndelegation(amount as u128));
    }

    let key = (from.to_string(), val_addr.to_string());
    let delegated = staking.get_delegation(from, val_addr);
    if delegated < amount as u128 {
        return Err(StakingTxError::InsufficientDelegation {
            have: delegated,
            need: amount as u128,
        });
    }

    staking
        .undelegate(
            from.to_string(),
            val_addr.to_string(),
            amount as u128,
            epoch,
            params.unbonding_epochs,
        )
        .map_err(StakingTxError::StakingError)?;

    // No need to manually adjust validator stake; StakingState tracks delegations correctly.
    // Validator total bond is computed on the fly from self_stake + delegations.

    Ok(21_000 + 5_000)
}

/// stake withdraw <validator_addr>
fn apply_withdraw(
    parts: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    epoch: u64,
) -> StakingTxResult<u64> {
    if parts.len() != 3 {
        return Err(StakingTxError::MissingArgument("validator address"));
    }
    let val_addr = parts[2];

    let withdrawn = staking.withdraw(from.to_string(), val_addr.to_string(), epoch);
    if withdrawn == 0 {
        return Err(StakingTxError::NothingToWithdraw);
    }

    // Convert to u64 safely; unstaking amount shouldn't exceed u64 range under normal balances.
    let amount: u64 = withdrawn
        .try_into()
        .map_err(|_| StakingTxError::Overflow)?;
    add_balance(kv, from, amount)?;

    Ok(21_000)
}

/// stake register <commission_bps>
fn apply_register(
    parts: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> StakingTxResult<u64> {
    if parts.len() != 3 {
        return Err(StakingTxError::MissingArgument("commission_bps"));
    }
    let commission_str = parts[2];
    let commission_bps: u64 = commission_str
        .parse()
        .map_err(|_| StakingTxError::InvalidAmount(commission_str.to_string()))?;

    if commission_bps > 10_000 {
        return Err(StakingTxError::InvalidCommissionBps(commission_bps));
    }

    if staking.get_validator(from).is_some() {
        return Err(StakingTxError::AlreadyRegistered);
    }

    let min_stake = params.min_stake as u64;
    deduct_balance(kv, from, min_stake)?;

    let validator = EconValidator::new(from.to_string(), min_stake as u128, commission_bps)
        .map_err(StakingTxError::StakingError)?;
    staking
        .add_validator(validator)
        .map_err(StakingTxError::StakingError)?;

    // The self_stake is already recorded in the validator.
    // No separate delegation entry is needed; self_stake represents the validator's own bond.

    Ok(21_000 + 10_000) // register costs more gas
}

/// stake deregister
fn apply_deregister(
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    epoch: u64,
) -> StakingTxResult<u64> {
    let v = staking
        .get_validator(from)
        .ok_or(StakingTxError::NotRegistered)?;

    // Check for external delegations
    let external_delegations: u128 = staking
        .delegations
        .iter()
        .filter(|((delegator, validator), _)| validator == from && delegator != from)
        .map(|(_, &amt)| amt)
        .sum();

    if external_delegations > 0 {
        return Err(StakingTxError::DelegatorsStillActive {
            external_delegations,
        });
    }

    let self_stake = v.self_stake;

    // Remove validator and any remaining delegation entries (should be none except maybe self-delegation if present)
    staking
        .remove_validator(from, epoch)
        .map_err(StakingTxError::StakingError)?;

    // Return self_stake to balance
    let amount: u64 = self_stake
        .try_into()
        .map_err(|_| StakingTxError::Overflow)?;
    add_balance(kv, from, amount)?;

    Ok(21_000)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::params::EconomicsParams;
    use crate::economics::staking::StakingState;
    use crate::execution::KvState;

    fn setup() -> (KvState, StakingState, EconomicsParams) {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();

        // Pre-register alice as validator with self_stake
        let v = EconValidator::new("alice".into(), 1_000_000, 500).unwrap();
        staking.add_validator(v).unwrap();

        // Give bob some balance
        kv.balances.insert("bob".into(), 500_000);

        (kv, staking, params)
    }

    // -----------------------------------------------------------------------------
    // Delegate tests
    // -----------------------------------------------------------------------------

    #[test]
    fn test_delegate_success() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success, "{:?}", res.error);
        assert_eq!(*kv.balances.get("bob").unwrap(), 400_000);
        assert_eq!(staking.get_delegation("bob", "alice"), 100_000);
    }

    #[test]
    fn test_delegate_insufficient_balance() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 999999999",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("insufficient balance"));
    }

    #[test]
    fn test_delegate_zero_amount() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 0",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("amount must be > 0"));
    }

    #[test]
    fn test_delegate_to_nonexistent() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate nobody 100",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("not found"));
    }

    #[test]
    fn test_delegate_to_jailed_validator() {
        let (mut kv, mut staking, params) = setup();
        staking.validators.get_mut("alice").unwrap().jailed = true;
        let res = try_apply_staking_tx(
            "stake delegate alice 100",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("jailed"));
    }

    // -----------------------------------------------------------------------------
    // Undelegate & withdraw tests
    // -----------------------------------------------------------------------------

    #[test]
    fn test_undelegate_and_withdraw() {
        let (mut kv, mut staking, params) = setup();

        // First delegate
        try_apply_staking_tx(
            "stake delegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();

        // Undelegate
        let res = try_apply_staking_tx(
            "stake undelegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            5,
        )
        .unwrap();
        assert!(res.success, "{:?}", res.error);

        // Withdraw too early
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            10,
        )
        .unwrap();
        assert!(!res.success, "Should not be withdrawable before unbonding");

        // Withdraw after unbonding period (5 + 14 = 19, so epoch 19 is still not unlocked; need >= 19? 
        // In StakingState::undelegate unlock_epoch = current_epoch + unbonding_epochs. 
        // Here current=5, unbonding=14 -> unlock=19. So epoch=18 is not unlocked, epoch=19 is.
        // Let's use 19.)
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            19,
        )
        .unwrap();
        assert!(res.success, "{:?}", res.error);
        assert_eq!(
            *kv.balances.get("bob").unwrap(),
            500_000,
            "Full balance restored"
        );
    }

    #[test]
    fn test_undelegate_insufficient() {
        let (mut kv, mut staking, params) = setup();
        try_apply_staking_tx(
            "stake delegate alice 5000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        let res = try_apply_staking_tx(
            "stake undelegate alice 10000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("insufficient delegated amount"));
    }

    #[test]
    fn test_withdraw_nothing() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("nothing to withdraw"));
    }

    // -----------------------------------------------------------------------------
    // Register & deregister tests
    // -----------------------------------------------------------------------------

    #[test]
    fn test_register_validator() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000,
            ..Default::default()
        };

        kv.balances.insert("charlie".into(), 100_000);

        let res = try_apply_staking_tx(
            "stake register 500",
            "charlie",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success, "{:?}", res.error);
        assert!(staking.get_validator("charlie").is_some());
        assert_eq!(staking.get_validator("charlie").unwrap().commission_bps, 500);
        assert_eq!(
            staking.get_validator("charlie").unwrap().self_stake,
            1_000
        );
        // Balance reduced by min_stake
        assert_eq!(*kv.balances.get("charlie").unwrap(), 99_000);
    }

    #[test]
    fn test_register_insufficient_balance() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 100_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 50_000);

        let res = try_apply_staking_tx(
            "stake register 500",
            "charlie",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("insufficient balance"));
    }

    #[test]
    fn test_register_already_validator() {
        let (mut kv, mut staking, params) = setup();
        // alice already registered
        let res = try_apply_staking_tx(
            "stake register 1000",
            "alice",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("already registered"));
    }

    #[test]
    fn test_deregister_without_delegators() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 100_000);

        // Register
        try_apply_staking_tx(
            "stake register 500",
            "charlie",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        // Deregister
        let res = try_apply_staking_tx(
            "stake deregister",
            "charlie",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success);
        assert!(staking.get_validator("charlie").is_none());
        // Balance should be restored (100_000 - 1_000 + 1_000 = 100_000)
        assert_eq!(*kv.balances.get("charlie").unwrap(), 100_000);
    }

    #[test]
    fn test_deregister_with_external_delegations_fails() {
        let (mut kv, mut staking, params) = setup();
        // alice is a validator, bob delegated to her
        try_apply_staking_tx(
            "stake delegate alice 50000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        let res = try_apply_staking_tx(
            "stake deregister",
            "alice",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("delegators still active"));
    }

    // -----------------------------------------------------------------------------
    // Parsing tests
    // -----------------------------------------------------------------------------

    #[test]
    fn test_non_staking_payload_returns_none() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();
        let res = try_apply_staking_tx(
            "set mykey myval",
            "alice",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(res.is_none(), "Non-staking payload should return None");
    }

    #[test]
    fn test_unknown_action() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake unknown_action",
            "alice",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("unknown"));
    }

    #[test]
    fn test_missing_arguments() {
        let (mut kv, mut staking, params) = setup();
        // Delegate without amount
        let res = try_apply_staking_tx(
            "stake delegate alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("missing argument"));
    }

    #[test]
    fn test_invalid_amount_format() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice abc",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("invalid amount"));
    }

    // -----------------------------------------------------------------------------
    // Edge cases & security
    // -----------------------------------------------------------------------------

    #[test]
    fn test_delegate_exact_balance() {
        let (mut kv, mut staking, params) = setup();
        kv.balances.insert("bob".into(), 500_000);
        let res = try_apply_staking_tx(
            "stake delegate alice 500000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(*kv.balances.get("bob").unwrap(), 0);
    }

    #[test]
    fn test_overflow_protection_balance() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();
        kv.balances.insert("bob".into(), u64::MAX);
        staking.add_validator(EconValidator::new("alice".into(), 1, 0).unwrap()).unwrap();

        // Delegate a large amount that would overflow if added to balance after withdrawal? Not directly tested here.
        // But we test that adding to balance doesn't overflow
        // We'll just ensure deduct_balance works near max
        let res = try_apply_staking_tx(
            "stake delegate alice 500000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(
            *kv.balances.get("bob").unwrap(),
            u64::MAX - 500_000
        );
    }

    #[test]
    fn test_withdraw_overflow_balance() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            unbonding_epochs: 0,
            ..Default::default()
        };
        kv.balances.insert("bob".into(), u64::MAX - 1000);
        staking.add_validator(EconValidator::new("alice".into(), 1, 0).unwrap()).unwrap();

        // Delegate some amount
        try_apply_staking_tx(
            "stake delegate alice 500",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();

        // Undelegate and then withdraw immediately (unbonding_epochs = 0)
        try_apply_staking_tx(
            "stake undelegate alice 500",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            10,
        )
        .unwrap();

        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            10,
        )
        .unwrap();
        assert!(res.success);
        // Balance should now be u64::MAX - 1000 + 500 = u64::MAX - 500, no overflow
        assert_eq!(*kv.balances.get("bob").unwrap(), u64::MAX - 500);
    }
}
