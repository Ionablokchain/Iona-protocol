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
// Constants
// -----------------------------------------------------------------------------

/// Base gas for any staking transaction.
const BASE_GAS: u64 = 21_000;
/// Additional gas for delegation/undelegation (extra storage writes).
const DELEGATION_GAS: u64 = 5_000;
/// Additional gas for validator registration (more storage changes).
const REGISTER_GAS: u64 = 10_000;

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
    #[error("nothing to withdraw (no unbonding entries are mature yet)")]
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
    #[error("arithmetic overflow during balance conversion or addition")]
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

impl StakingTxOutcome {
    fn success(gas_used: u64) -> Self {
        Self {
            success: true,
            error: None,
            gas_used,
        }
    }

    fn failure(error: impl Into<String>, gas_used: u64) -> Self {
        Self {
            success: false,
            error: Some(error.into()),
            gas_used,
        }
    }
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
        return Some(StakingTxOutcome::failure(
            "missing action after 'stake'",
            BASE_GAS,
        ));
    }

    let action = parts[1];
    let result = match action {
        "delegate" => handle_delegate(&parts, from, kv, staking, params),
        "undelegate" => handle_undelegate(&parts, from, kv, staking, params, epoch),
        "withdraw" => handle_withdraw(&parts, from, kv, staking, epoch),
        "register" => handle_register(&parts, from, kv, staking, params),
        "deregister" => handle_deregister(from, kv, staking, epoch),
        _ => Err(StakingTxError::UnknownAction(action.to_string())),
    };

    Some(match result {
        Ok(gas) => StakingTxOutcome::success(gas),
        Err(e) => StakingTxOutcome::failure(e.to_string(), BASE_GAS),
    })
}

// -----------------------------------------------------------------------------
// Balance helpers
// -----------------------------------------------------------------------------

/// Deduct `amount` from `address` balance. Returns new balance on success.
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

/// Add `amount` to `address` balance. Returns new balance on success.
fn add_balance(kv: &mut KvState, address: &str, amount: u64) -> StakingTxResult<u64> {
    let current = *kv.balances.get(address).unwrap_or(&0);
    let new_bal = current
        .checked_add(amount)
        .ok_or(StakingTxError::Overflow)?;
    kv.balances.insert(address.to_string(), new_bal);
    Ok(new_bal)
}

/// Convert a u128 staking amount to u64, checking overflow.
fn to_u64_amount(amount: u128) -> StakingTxResult<u64> {
    amount.try_into().map_err(|_| StakingTxError::Overflow)
}

// -----------------------------------------------------------------------------
// Action handlers
// -----------------------------------------------------------------------------

/// stake delegate <validator_addr> <amount>
fn handle_delegate(
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

    let val = staking
        .get_validator(val_addr)
        .ok_or_else(|| StakingTxError::ValidatorNotFound(val_addr.to_string()))?;
    if val.jailed {
        return Err(StakingTxError::ValidatorJailed(val_addr.to_string()));
    }

    deduct_balance(kv, from, amount)?;
    staking
        .delegate(from.to_string(), val_addr.to_string(), amount as u128)
        .map_err(StakingTxError::StakingError)?;

    Ok(BASE_GAS + DELEGATION_GAS)
}

/// stake undelegate <validator_addr> <amount>
fn handle_undelegate(
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

    Ok(BASE_GAS + DELEGATION_GAS)
}

/// stake withdraw <validator_addr>
fn handle_withdraw(
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

    let amount_u64 = to_u64_amount(withdrawn)?;
    add_balance(kv, from, amount_u64)?;

    Ok(BASE_GAS)
}

/// stake register <commission_bps>
fn handle_register(
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

    Ok(BASE_GAS + REGISTER_GAS)
}

/// stake deregister
fn handle_deregister(
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    epoch: u64,
) -> StakingTxResult<u64> {
    let v = staking
        .get_validator(from)
        .ok_or(StakingTxError::NotRegistered)?;

    // Check for external delegations (any delegator other than self)
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

    staking
        .remove_validator(from, epoch)
        .map_err(StakingTxError::StakingError)?;

    let amount_u64 = to_u64_amount(self_stake)?;
    add_balance(kv, from, amount_u64)?;

    Ok(BASE_GAS)
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

        let v = EconValidator::new("alice".into(), 1_000_000, 500).unwrap();
        staking.add_validator(v).unwrap();
        kv.balances.insert("bob".into(), 500_000);

        (kv, staking, params)
    }

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
    fn test_delegate_to_jailed() {
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

    #[test]
    fn test_undelegate_and_withdraw() {
        let (mut kv, mut staking, params) = setup();
        try_apply_staking_tx(
            "stake delegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();

        let res = try_apply_staking_tx(
            "stake undelegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            5,
        )
        .unwrap();
        assert!(res.success);

        // Early withdraw fails
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            10,
        )
        .unwrap();
        assert!(!res.success);

        // Withdraw after unbonding (5 + 14 = 19)
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            19,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(*kv.balances.get("bob").unwrap(), 500_000);
    }

    #[test]
    fn test_multiple_undelegations_and_withdrawals() {
        let (mut kv, mut staking, params) = setup();
        kv.balances.insert("bob".into(), 1_000_000);
        try_apply_staking_tx(
            "stake delegate alice 500000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();

        // Undelegate in two parts
        try_apply_staking_tx(
            "stake undelegate alice 200000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            10,
        )
        .unwrap();
        try_apply_staking_tx(
            "stake undelegate alice 300000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            20,
        )
        .unwrap();

        // First unbonding matures at epoch 24 (10+14)
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            24,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(*kv.balances.get("bob").unwrap(), 500_000 + 200_000);

        // Second still not matured
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            24,
        )
        .unwrap();
        assert!(!res.success);

        // After second matures (20+14=34)
        let res = try_apply_staking_tx(
            "stake withdraw alice",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            34,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(*kv.balances.get("bob").unwrap(), 1_000_000);
    }

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
        assert!(res.success);
        let v = staking.get_validator("charlie").unwrap();
        assert_eq!(v.commission_bps, 500);
        assert_eq!(v.self_stake, 1_000);
        assert_eq!(*kv.balances.get("charlie").unwrap(), 99_000);
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
        try_apply_staking_tx(
            "stake register 500",
            "charlie",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();

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
        assert_eq!(*kv.balances.get("charlie").unwrap(), 100_000);
    }

    #[test]
    fn test_deregister_with_external_delegators_fails() {
        let (mut kv, mut staking, params) = setup();
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

    #[test]
    fn test_unknown_action() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake unknown",
            "bob",
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

    #[test]
    fn test_overflow_protection() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();
        kv.balances.insert("bob".into(), u64::MAX);
        staking
            .add_validator(EconValidator::new("alice".into(), 1, 0).unwrap())
            .unwrap();

        // Delegate almost all
        let res = try_apply_staking_tx(
            &format!("stake delegate alice {}", u64::MAX - 1000),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        )
        .unwrap();
        assert!(res.success);
        assert_eq!(*kv.balances.get("bob").unwrap(), 1000);

        // Withdraw later would overflow if not checked
        staking
            .undelegate(
                "bob".into(),
                "alice".into(),
                u64::MAX as u128 - 1000,
                0,
                0,
            )
            .unwrap();
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
        assert!(res.error.unwrap().contains("overflow"));
    }
}
