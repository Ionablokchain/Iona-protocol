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

use crate::economics::staking::{StakingState, StakingError, Validator as EconValidator};
use crate::economics::params::EconomicsParams;
use crate::execution::KvState;

// Gas costs for staking operations (in gas units)
const GAS_DELEGATE: u64 = 21_000 + 5_000;
const GAS_UNDELEGATE: u64 = 21_000 + 5_000;
const GAS_WITHDRAW: u64 = 21_000;
const GAS_REGISTER: u64 = 21_000 + 10_000;
const GAS_DEREGISTER: u64 = 21_000;
const GAS_DEFAULT: u64 = 21_000;

/// Result of applying a staking transaction to StakingState.
#[derive(Debug)]
pub struct StakingTxResult {
    pub success: bool,
    pub error:   Option<String>,
    pub gas_used: u64,
}

/// Parse and apply a staking payload.
/// `from`: the sender address (already verified by execution layer).
/// Returns `None` if the payload is not a staking tx (doesn't start with "stake ").
pub fn try_apply_staking_tx(
    payload:  &str,
    from:     &str,
    kv:       &mut KvState,
    staking:  &mut StakingState,
    params:   &EconomicsParams,
    epoch:    u64,
) -> Option<StakingTxResult> {
    let payload = payload.trim();
    if !payload.starts_with("stake ") {
        return None;
    }

    let parts: Vec<&str> = payload.split_whitespace().collect();
    let action = parts.get(1).copied().unwrap_or("");

    let result = match action {
        "delegate" => apply_delegate(&parts, from, kv, staking, params),
        "undelegate" => apply_undelegate(&parts, from, kv, staking, params, epoch),
        "withdraw" => apply_withdraw(&parts, from, kv, staking, epoch),
        "register" => apply_register(&parts, from, kv, staking, params),
        "deregister" => apply_deregister(from, kv, staking),
        _ => Err(StakingError::InvalidStakingAction(action.to_string())),
    };

    Some(match result {
        Ok(gas) => StakingTxResult { success: true, error: None, gas_used: gas },
        Err(e)  => StakingTxResult { success: false, error: Some(e.to_string()), gas_used: GAS_DEFAULT },
    })
}

/// stake delegate <validator_addr> <amount>
/// Lock `amount` of sender's balance as delegation to `validator_addr`.
fn apply_delegate(
    parts:   &[&str],
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
    params:  &EconomicsParams,
) -> Result<u64, StakingError> {
    let val_addr = parts.get(2).ok_or(StakingError::MissingArgument("validator"))?;
    let amount: u128 = parts.get(3)
        .ok_or(StakingError::MissingArgument("amount"))?
        .parse()
        .map_err(|_| StakingError::InvalidArgument("amount"))?;

    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }

    // Get current balance of sender (as u128 to avoid overflow)
    let bal = *kv.balances.get(from).unwrap_or(&0) as u128;
    if bal < amount {
        return Err(StakingError::InsufficientBalance);
    }

    // Use the improved delegate method that does validation and updates totals
    staking.delegate(from.to_string(), val_addr.to_string(), amount, |addr| {
        // The delegate method expects a balance_of callback; we already have the balance
        // so we can just pass a closure that returns the balance (it will be called again,
        // but we can compute from kv).
        *kv.balances.get(addr).unwrap_or(&0) as u128
    }).map_err(|e| e)?;

    // Deduct amount from sender's balance AFTER successful delegation
    *kv.balances.entry(from.to_string()).or_insert(0) = (bal - amount) as u64;

    Ok(GAS_DELEGATE)
}

/// stake undelegate <validator_addr> <amount>
/// Begin unbonding period. Funds locked until epoch + unbonding_epochs.
fn apply_undelegate(
    parts:   &[&str],
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
    params:  &EconomicsParams,
    epoch:   u64,
) -> Result<u64, StakingError> {
    let val_addr = parts.get(2).ok_or(StakingError::MissingArgument("validator"))?;
    let amount: u128 = parts.get(3)
        .ok_or(StakingError::MissingArgument("amount"))?
        .parse()
        .map_err(|_| StakingError::InvalidArgument("amount"))?;

    if amount == 0 {
        return Err(StakingError::ZeroAmount);
    }

    // Use improved undelegate method
    staking.undelegate(from.to_string(), val_addr.to_string(), amount, epoch, params.unbonding_epochs)
        .map_err(|e| e)?;

    // Note: undelegate does not immediately change balance; it will be available after unbonding.
    Ok(GAS_UNDELEGATE)
}

/// stake withdraw <validator_addr>
/// Claim unlocked (post-unbonding) funds back into balance.
fn apply_withdraw(
    parts:   &[&str],
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
    epoch:   u64,
) -> Result<u64, StakingError> {
    let val_addr = parts.get(2).ok_or(StakingError::MissingArgument("validator"))?;

    let withdrawn = staking.withdraw(from.to_string(), val_addr.to_string(), epoch);
    if withdrawn == 0 {
        return Err(StakingError::NothingToWithdraw);
    }

    *kv.balances.entry(from.to_string()).or_insert(0) =
        kv.balances.get(from).copied().unwrap_or(0).saturating_add(withdrawn as u64);

    Ok(GAS_WITHDRAW)
}

/// stake register <commission_bps>
/// Register the sender as a validator with the given commission rate.
/// Sender must have min_stake already delegated to themselves.
fn apply_register(
    parts:   &[&str],
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
    params:  &EconomicsParams,
) -> Result<u64, StakingError> {
    let commission_bps: u64 = parts.get(2)
        .ok_or(StakingError::MissingArgument("commission_bps"))?
        .parse()
        .map_err(|_| StakingError::InvalidArgument("commission_bps"))?;

    if commission_bps > 10_000 {
        return Err(StakingError::CommissionOutOfRange);
    }

    if staking.validators.contains_key(from) {
        return Err(StakingError::ValidatorAlreadyExists);
    }

    // Check min balance for self-bond
    let bal = *kv.balances.get(from).unwrap_or(&0) as u128;
    if bal < params.min_stake {
        return Err(StakingError::InsufficientBalanceForMinStake(params.min_stake));
    }

    // Lock min_stake as self-delegation
    *kv.balances.entry(from.to_string()).or_insert(0) = (bal - params.min_stake) as u64;

    // Create validator
    let validator = EconValidator::new(from.to_string(), params.min_stake, commission_bps)
        .ok_or(StakingError::CommissionOutOfRange)?;
    staking.validators.insert(from.to_string(), validator);

    // Record self-delegation
    staking.delegate(from.to_string(), from.to_string(), params.min_stake, |addr| {
        // At this point, the balance has been reduced, but the closure will be called
        // to verify balance again. We'll just return the current balance (which is already
        // reduced, but that's okay because we know we have enough).
        *kv.balances.get(addr).unwrap_or(&0) as u128
    }).map_err(|e| e)?;

    Ok(GAS_REGISTER)
}

/// stake deregister
/// Remove self from active validator set. Must have no delegations from others.
fn apply_deregister(
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
) -> Result<u64, StakingError> {
    if !staking.validators.contains_key(from) {
        return Err(StakingError::ValidatorNotFound(from.to_string()));
    }

    // Check no external delegations (using the new delegation structure)
    let key = (from.to_string(), from.to_string()); // self-delegation key
    let external_delegations: u128 = staking.delegations.iter()
        .filter(|((delegator, validator), delegation)| {
            validator == from && delegator != from
        })
        .map(|(_, delegation)| delegation.amount)
        .sum();

    if external_delegations > 0 {
        return Err(StakingError::HasExternalDelegations(external_delegations));
    }

    // Return self-bond to balance
    let self_stake = staking.validators.get(from).map(|v| v.self_stake).unwrap_or(0);
    *kv.balances.entry(from.to_string()).or_insert(0) =
        kv.balances.get(from).copied().unwrap_or(0).saturating_add(self_stake as u64);

    staking.validators.remove(from);
    // Remove all delegations from this validator (including self)
    staking.delegations.retain(|(_, validator), _| validator != from);

    Ok(GAS_DEREGISTER)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::staking::{StakingState, Validator as EconValidator};
    use crate::execution::KvState;
    use crate::economics::params::EconomicsParams;

    fn setup() -> (KvState, StakingState, EconomicsParams) {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();

        // Pre-register alice as validator with some stake
        let validator = EconValidator::new("alice".to_string(), 1_000_000, 500).unwrap();
        staking.validators.insert("alice".to_string(), validator);
        // Add self-delegation for alice
        staking.delegate("alice".to_string(), "alice".to_string(), 1_000_000, |_| 1_000_000).unwrap();

        // Give bob some balance to delegate
        kv.balances.insert("bob".to_string(), 500_000);

        (kv, staking, params)
    }

    #[test]
    fn test_delegate_success() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 100000",
            "bob", &mut kv, &mut staking, &params, 0
        ).unwrap();
        assert!(res.success, "{:?}", res.error);
        assert_eq!(*kv.balances.get("bob").unwrap(), 400_000);
        let delegation = staking.delegations.get(&("bob".to_string(), "alice".to_string())).unwrap();
        assert_eq!(delegation.amount, 100_000);
        assert_eq!(staking.validators.get("alice").unwrap().total_stake, 1_100_000);
    }

    #[test]
    fn test_delegate_insufficient_balance() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 999999999",
            "bob", &mut kv, &mut staking, &params, 0
        ).unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("insufficient"));
    }

    #[test]
    fn test_undelegate_and_withdraw() {
        let (mut kv, mut staking, params) = setup();

        // First delegate
        try_apply_staking_tx("stake delegate alice 100000", "bob", &mut kv, &mut staking, &params, 0).unwrap();

        // Undelegate
        let res = try_apply_staking_tx(
            "stake undelegate alice 100000",
            "bob", &mut kv, &mut staking, &params, 5
        ).unwrap();
        assert!(res.success, "{:?}", res.error);

        // Cannot withdraw yet (unbonding_epochs = 14)
        let res = try_apply_staking_tx("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 10).unwrap();
        assert!(!res.success, "Should not be withdrawable before unbonding");

        // Advance past unbonding period
        let res = try_apply_staking_tx("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 20).unwrap();
        assert!(res.success, "{:?}", res.error);
        assert_eq!(*kv.balances.get("bob").unwrap(), 500_000, "Full balance restored");
    }

    #[test]
    fn test_register_validator() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let mut params = EconomicsParams::default();
        params.min_stake = 1_000;

        kv.balances.insert("charlie".to_string(), 100_000);

        let res = try_apply_staking_tx(
            "stake register 500",
            "charlie", &mut kv, &mut staking, &params, 0
        ).unwrap();
        assert!(res.success, "{:?}", res.error);
        assert!(staking.validators.contains_key("charlie"));
        assert_eq!(staking.validators["charlie"].commission_bps, 500);
        assert_eq!(staking.validators["charlie"].total_stake, params.min_stake);
        assert_eq!(*kv.balances.get("charlie").unwrap(), 100_000 - params.min_stake);
    }

    #[test]
    fn test_non_staking_payload_returns_none() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();
        let res = try_apply_staking_tx("set mykey myval", "alice", &mut kv, &mut staking, &params, 0);
        assert!(res.is_none(), "Non-staking payload should return None");
    }

    #[test]
    fn test_deregister_with_external_delegations_fails() {
        let (mut kv, mut staking, params) = setup();

        // Bob delegates to alice
        try_apply_staking_tx("stake delegate alice 100000", "bob", &mut kv, &mut staking, &params, 0).unwrap();

        // Alice tries to deregister while bob still delegates
        let res = try_apply_staking_tx("stake deregister", "alice", &mut kv, &mut staking, &params, 0).unwrap();
        assert!(!res.success);
        assert!(res.error.unwrap().contains("delegations"));
    }

    #[test]
    fn test_deregister_success() {
        let (mut kv, mut staking, params) = setup();

        // No external delegations
        let res = try_apply_staking_tx("stake deregister", "alice", &mut kv, &mut staking, &params, 0).unwrap();
        assert!(res.success, "{:?}", res.error);
        assert!(!staking.validators.contains_key("alice"));
        assert_eq!(*kv.balances.get("alice").unwrap(), 1_000_000, "Self-stake returned");
    }
}
