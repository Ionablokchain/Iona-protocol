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

use crate::economics::staking::StakingState;
use crate::economics::staking::Validator as EconValidator;
use crate::economics::params::EconomicsParams;
use crate::execution::KvState;

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
        _ => Err(format!("unknown staking action: {action}")),
    };

    Some(match result {
        Ok(gas) => StakingTxResult { success: true, error: None, gas_used: gas },
        Err(e)  => StakingTxResult { success: false, error: Some(e), gas_used: 21_000 },
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
) -> Result<u64, String> {
    let val_addr = parts.get(2).ok_or("delegate: missing validator")?;
    let amount: u128 = parts.get(3)
        .ok_or("delegate: missing amount")?
        .parse()
        .map_err(|_| "delegate: invalid amount")?;

    if amount == 0 {
        return Err("delegate: amount must be > 0".into());
    }

    // Validator must exist and not be jailed
    let val = staking.validators.get(*val_addr)
        .ok_or_else(|| format!("delegate: validator {} not found", val_addr))?;
    if val.jailed {
        return Err(format!("delegate: validator {} is jailed", val_addr));
    }

    // Deduct from sender's balance
    let bal = *kv.balances.get(from).unwrap_or(&0) as u128;
    if bal < amount {
        return Err(format!("delegate: insufficient balance (have {bal}, need {amount})"));
    }
    *kv.balances.entry(from.to_string()).or_insert(0) = (bal - amount) as u64;

    // Record delegation
    staking.delegate(from.to_string(), val_addr.to_string(), amount);

    // Increase validator total stake
    if let Some(v) = staking.validators.get_mut(*val_addr) {
        v.stake = v.stake.saturating_add(amount);
    }

    Ok(21_000 + 5_000) // delegate costs slightly more gas
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
) -> Result<u64, String> {
    let val_addr = parts.get(2).ok_or("undelegate: missing validator")?;
    let amount: u128 = parts.get(3)
        .ok_or("undelegate: missing amount")?
        .parse()
        .map_err(|_| "undelegate: invalid amount")?;

    if amount == 0 {
        return Err("undelegate: amount must be > 0".into());
    }

    let k = (from.to_string(), val_addr.to_string());
    let delegated = *staking.delegations.get(&k).unwrap_or(&0);
    if delegated < amount {
        return Err(format!("undelegate: insufficient delegation (have {delegated}, need {amount})"));
    }

    staking.undelegate(from.to_string(), val_addr.to_string(), amount, epoch, params.unbonding_epochs);

    // Decrease validator total stake
    if let Some(v) = staking.validators.get_mut(*val_addr) {
        v.stake = v.stake.saturating_sub(amount);
    }

    Ok(21_000 + 5_000)
}

/// stake withdraw <validator_addr>
/// Claim unlocked (post-unbonding) funds back into balance.
fn apply_withdraw(
    parts:   &[&str],
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
    epoch:   u64,
) -> Result<u64, String> {
    let val_addr = parts.get(2).ok_or("withdraw: missing validator")?;

    let withdrawn = staking.withdraw(from.to_string(), val_addr.to_string(), epoch);
    if withdrawn == 0 {
        return Err("withdraw: nothing to withdraw (unbonding not complete or no unbonding)".into());
    }

    *kv.balances.entry(from.to_string()).or_insert(0) =
        kv.balances.get(from).copied().unwrap_or(0).saturating_add(withdrawn as u64);

    Ok(21_000)
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
) -> Result<u64, String> {
    let commission_bps: u64 = parts.get(2)
        .ok_or("register: missing commission_bps")?
        .parse()
        .map_err(|_| "register: invalid commission_bps")?;

    if commission_bps > 10_000 {
        return Err("register: commission_bps cannot exceed 10000 (100%)".into());
    }

    if staking.validators.contains_key(from) {
        return Err("register: already registered as validator".into());
    }

    // Check min balance for self-bond
    let bal = *kv.balances.get(from).unwrap_or(&0) as u128;
    if bal < params.min_stake {
        return Err(format!(
            "register: insufficient balance for min_stake (have {bal}, need {})",
            params.min_stake
        ));
    }

    // Lock min_stake as self-delegation
    *kv.balances.entry(from.to_string()).or_insert(0) = (bal - params.min_stake) as u64;

    staking.validators.insert(from.to_string(), EconValidator {
        operator: from.to_string(),
        stake: params.min_stake,
        jailed: false,
        commission_bps,
    });
    staking.delegate(from.to_string(), from.to_string(), params.min_stake);

    Ok(21_000 + 10_000) // register costs more gas
}

/// stake deregister
/// Remove self from active validator set. Must have no delegations from others.
fn apply_deregister(
    from:    &str,
    kv:      &mut KvState,
    staking: &mut StakingState,
) -> Result<u64, String> {
    if !staking.validators.contains_key(from) {
        return Err("deregister: not a registered validator".into());
    }

    // Check no external delegators
    let external_delegations: u128 = staking.delegations.iter()
        .filter(|((delegator, validator), _)| validator == from && delegator != from)
        .map(|(_, &amt)| amt)
        .sum();

    if external_delegations > 0 {
        return Err(format!(
            "deregister: cannot deregister with {external_delegations} stake from delegators still active"
        ));
    }

    // Return self-bond to balance
    let self_stake = staking.validators.get(from).map(|v| v.stake).unwrap_or(0);
    *kv.balances.entry(from.to_string()).or_insert(0) =
        kv.balances.get(from).copied().unwrap_or(0).saturating_add(self_stake as u64);

    staking.validators.remove(from);
    staking.delegations.retain(|(_, v), _| v != from);

    Ok(21_000)
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
        staking.validators.insert("alice".into(), EconValidator {
            operator: "alice".into(),
            stake: 1_000_000,
            jailed: false,
            commission_bps: 500,
        });

        // Give bob some balance to delegate
        kv.balances.insert("bob".into(), 500_000);

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
        assert_eq!(*staking.delegations.get(&("bob".into(), "alice".into())).unwrap(), 100_000);
    }

    #[test]
    fn test_delegate_insufficient_balance() {
        let (mut kv, mut staking, params) = setup();
        let res = try_apply_staking_tx(
            "stake delegate alice 999999999",
            "bob", &mut kv, &mut staking, &params, 0
        ).unwrap();
        assert!(!res.success);
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
        let params = EconomicsParams { min_stake: 1_000, ..Default::default() };

        kv.balances.insert("charlie".into(), 100_000);

        let res = try_apply_staking_tx(
            "stake register 500",
            "charlie", &mut kv, &mut staking, &params, 0
        ).unwrap();
        assert!(res.success, "{:?}", res.error);
        assert!(staking.validators.contains_key("charlie"));
        assert_eq!(staking.validators["charlie"].commission_bps, 500);
    }

    #[test]
    fn test_non_staking_payload_returns_none() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();
        let res = try_apply_staking_tx("set mykey myval", "alice", &mut kv, &mut staking, &params, 0);
        assert!(res.is_none(), "Non-staking payload should return None");
    }
}
