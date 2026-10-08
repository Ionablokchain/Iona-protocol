//! Staking transaction parsing and execution for IONA.
//!
//! Staking operations are submitted as regular transactions with a
//! `"stake "` payload prefix. This keeps the consensus layer clean:
//! staking is just another key-value application.
//!
//! # Payload format
//!
//! ```text
//! stake delegate   <validator> <amount>
//! stake undelegate <validator> <amount>
//! stake withdraw   <validator>
//! stake register   <commission_bps>
//! stake deregister
//! ```
//!
//! Whitespace between tokens is collapsed; the payload is trimmed before
//! parsing. Amounts are decimal `u128`; commission is a decimal `u64` in
//! basis points (`0..=10_000`). The action word is case-sensitive.
//!
//! # Atomicity
//!
//! Each action is atomic: all validations run before any state mutation,
//! so a rejected transaction leaves both [`KvState`] and [`StakingState`]
//! untouched. Handlers use checked arithmetic throughout and return
//! [`StakingTxError::Overflow`] on overflow rather than truncating.
//!
//! # Bond model
//!
//! A validator's [`EconValidator::self_stake`] **is** the operator's bond.
//! The register action does **not** create a self-delegation — that would
//! double-count. `total_stake == self_stake + Σ external delegations`,
//! matching the invariant enforced by [`StakingState::check_invariants`].
//!
//! # Gas
//!
//! `StakingTxResult::gas_used` is charged for the action identified in the
//! payload, **even when the action fails**. An unidentified action is
//! charged [`GAS_UNKNOWN_ACTION`]. Callers must not assume that
//! `success == false` implies zero gas.
//!
//! # Detecting staking transactions
//!
//! [`try_apply_staking_tx`] returns `None` **only** when the payload does
//! not begin with `"stake "` after trimming. Every other outcome is a
//! `Some(StakingTxResult)`.

use crate::economics::params::EconomicsParams;
use crate::economics::staking::{
    StakingError, StakingState, Validator as EconValidator, MAX_BPS,
};
use crate::execution::KvState;
use thiserror::Error;

// ── Gas constants ─────────────────────────────────────────────────────────

const GAS_BASE: u64 = 21_000;
const GAS_DELEGATE: u64 = GAS_BASE + 5_000;
const GAS_UNDELEGATE: u64 = GAS_BASE + 5_000;
const GAS_WITHDRAW: u64 = GAS_BASE;
const GAS_REGISTER: u64 = GAS_BASE + 10_000;
const GAS_DEREGISTER: u64 = GAS_BASE;
const GAS_UNKNOWN_ACTION: u64 = GAS_BASE;

/// Prefix identifying a staking payload.
const PAYLOAD_PREFIX: &str = "stake ";

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced while parsing or applying a staking payload.
///
/// Wraps [`StakingError`] as [`Domain`](Self::Domain) for errors raised
/// inside the state module.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum StakingTxError {
    #[error("sender address must not be empty")]
    EmptySender,

    #[error("missing argument: {0}")]
    MissingArgument(&'static str),

    #[error("invalid argument `{name}`: {value:?}")]
    InvalidArgument { name: &'static str, value: String },

    #[error("unknown staking action `{0}`")]
    UnknownAction(String),

    #[error("amount must be > 0")]
    ZeroAmount,

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("balance below minimum stake: have {have}, need {need}")]
    BelowMinStake { have: u128, need: u128 },

    #[error("validator {0} already exists")]
    ValidatorExists(String),

    #[error("validator {0} not found")]
    ValidatorMissing(String),

    #[error("commission {0} bps out of range (0..=10_000)")]
    CommissionOutOfRange(u64),

    #[error("nothing to withdraw for validator {0}")]
    NothingToWithdraw(String),

    #[error("validator {0} still has external delegations totalling {1}")]
    HasExternalDelegations(String, u128),

    #[error("arithmetic overflow in {0}")]
    Overflow(&'static str),

    #[error(transparent)]
    Domain(#[from] StakingError),
}

// ── Result ────────────────────────────────────────────────────────────────

/// Outcome of applying a staking transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StakingTxResult {
    pub success: bool,
    /// Human-readable error message on failure; `None` on success.
    pub error: Option<String>,
    /// Gas charged, even on failure. See module-level docs.
    pub gas_used: u64,
}

impl StakingTxResult {
    fn ok(gas_used: u64) -> Self {
        Self { success: true, error: None, gas_used }
    }
    fn err(err: StakingTxError, gas_used: u64) -> Self {
        Self {
            success: false,
            error: Some(err.to_string()),
            gas_used,
        }
    }
}

// ── Entry point ───────────────────────────────────────────────────────────

/// Parse and apply a staking payload.
///
/// `from` is the sender address (already verified by the execution layer).
///
/// Returns `None` if `payload` is not a staking transaction (does not begin
/// with `"stake "` after trimming).
#[must_use = "the outcome carries the gas charge and error reason"]
pub fn try_apply_staking_tx(
    payload: &str,
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
    epoch: u64,
) -> Option<StakingTxResult> {
    let rest = payload.trim().strip_prefix(PAYLOAD_PREFIX)?;

    if from.is_empty() {
        return Some(StakingTxResult::err(
            StakingTxError::EmptySender,
            GAS_UNKNOWN_ACTION,
        ));
    }

    let mut tokens = rest.split_whitespace();
    let action = tokens.next().unwrap_or("");
    let args: Vec<&str> = tokens.collect();

    let outcome: Result<u64, StakingTxError> = match action {
        "delegate" => apply_delegate(&args, from, kv, staking),
        "undelegate" => apply_undelegate(&args, from, staking, params, epoch),
        "withdraw" => apply_withdraw(&args, from, kv, staking, epoch),
        "register" => apply_register(&args, from, kv, staking, params),
        "deregister" => apply_deregister(from, kv, staking),
        other => Err(StakingTxError::UnknownAction(other.to_string())),
    };

    Some(match outcome {
        Ok(gas) => StakingTxResult::ok(gas),
        Err(err) => StakingTxResult::err(err, gas_for_action(action)),
    })
}

// ── Handlers ──────────────────────────────────────────────────────────────

/// `stake delegate <validator> <amount>`
fn apply_delegate(
    args: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
) -> Result<u64, StakingTxError> {
    let val_addr = args
        .first()
        .copied()
        .ok_or(StakingTxError::MissingArgument("validator"))?;
    let amount = parse_u128(
        args.get(1)
            .copied()
            .ok_or(StakingTxError::MissingArgument("amount"))?,
        "amount",
    )?;

    if amount == 0 {
        return Err(StakingTxError::ZeroAmount);
    }

    // Snapshot the sender's balance once; the closure passed to `delegate`
    // gets a copy so it does not borrow `kv` across the mutation.
    let balance = read_balance(kv, from);
    if balance < amount {
        return Err(StakingTxError::InsufficientBalance {
            have: balance,
            need: amount,
        });
    }

    staking.delegate(
        from.to_string(),
        val_addr.to_string(),
        amount,
        move |_| balance,
    )?;
    debit_balance(kv, from, amount)?;

    Ok(GAS_DELEGATE)
}

/// `stake undelegate <validator> <amount>`
fn apply_undelegate(
    args: &[&str],
    from: &str,
    staking: &mut StakingState,
    params: &EconomicsParams,
    epoch: u64,
) -> Result<u64, StakingTxError> {
    let val_addr = args
        .first()
        .copied()
        .ok_or(StakingTxError::MissingArgument("validator"))?;
    let amount = parse_u128(
        args.get(1)
            .copied()
            .ok_or(StakingTxError::MissingArgument("amount"))?,
        "amount",
    )?;

    if amount == 0 {
        return Err(StakingTxError::ZeroAmount);
    }

    staking.undelegate(
        from.to_string(),
        val_addr.to_string(),
        amount,
        epoch,
        params.unbonding_epochs,
    )?;

    Ok(GAS_UNDELEGATE)
}

/// `stake withdraw <validator>`
fn apply_withdraw(
    args: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    epoch: u64,
) -> Result<u64, StakingTxError> {
    let val_addr = args
        .first()
        .copied()
        .ok_or(StakingTxError::MissingArgument("validator"))?;

    let withdrawn = staking.withdraw(from.to_string(), val_addr.to_string(), epoch)?;
    if withdrawn == 0 {
        return Err(StakingTxError::NothingToWithdraw(val_addr.to_string()));
    }

    credit_balance(kv, from, withdrawn)?;
    Ok(GAS_WITHDRAW)
}

/// `stake register <commission_bps>`
fn apply_register(
    args: &[&str],
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> Result<u64, StakingTxError> {
    let commission_bps = parse_u64(
        args.first()
            .copied()
            .ok_or(StakingTxError::MissingArgument("commission_bps"))?,
        "commission_bps",
    )?;

    if commission_bps > MAX_BPS {
        return Err(StakingTxError::CommissionOutOfRange(commission_bps));
    }
    if staking.validators.contains_key(from) {
        return Err(StakingTxError::ValidatorExists(from.to_string()));
    }

    let balance = read_balance(kv, from);
    if balance < params.min_stake {
        return Err(StakingTxError::BelowMinStake {
            have: balance,
            need: params.min_stake,
        });
    }

    // Pre-check the debit; nothing mutates until it succeeds.
    let new_balance = balance
        .checked_sub(params.min_stake)
        .and_then(|b| u64::try_from(b).ok())
        .ok_or(StakingTxError::Overflow("register.debit"))?;

    // `Validator::new` sets `total_stake = self_stake`. We do NOT also
    // create a self-delegation — the self-bond IS the operator's stake.
    let validator = EconValidator::new(from.to_string(), params.min_stake, commission_bps)?;
    staking.validators.insert(from.to_string(), validator);
    kv.balances.insert(from.to_string(), new_balance);

    Ok(GAS_REGISTER)
}

/// `stake deregister`
fn apply_deregister(
    from: &str,
    kv: &mut KvState,
    staking: &mut StakingState,
) -> Result<u64, StakingTxError> {
    let validator = staking
        .validators
        .get(from)
        .cloned()
        .ok_or_else(|| StakingTxError::ValidatorMissing(from.to_string()))?;

    // Reject if any external delegation is still bonded.
    let external: u128 = staking
        .delegations
        .iter()
        .filter(|((delegator, val), _)| val == from && delegator != from)
        .map(|(_, d)| d.amount)
        .fold(0u128, |acc, x| acc.saturating_add(x));
    if external > 0 {
        return Err(StakingTxError::HasExternalDelegations(
            from.to_string(),
            external,
        ));
    }

    // Pre-check the credit.
    let balance = read_balance(kv, from);
    let new_balance = balance
        .checked_add(validator.self_stake)
        .and_then(|b| u64::try_from(b).ok())
        .ok_or(StakingTxError::Overflow("deregister.credit"))?;

    // Commit.
    staking.validators.remove(from);

    // Drop any bonded self-delegation entry, but keep pending unbondings
    // so they remain withdrawable after deregistration.
    let self_key = (from.to_string(), from.to_string());
    if let Some(d) = staking.delegations.get_mut(&self_key) {
        d.amount = 0;
        if d.unbondings.is_empty() {
            staking.delegations.remove(&self_key);
        }
    }

    kv.balances.insert(from.to_string(), new_balance);
    Ok(GAS_DEREGISTER)
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn parse_u128(s: &str, name: &'static str) -> Result<u128, StakingTxError> {
    s.parse::<u128>().map_err(|_| StakingTxError::InvalidArgument {
        name,
        value: s.to_string(),
    })
}

fn parse_u64(s: &str, name: &'static str) -> Result<u64, StakingTxError> {
    s.parse::<u64>().map_err(|_| StakingTxError::InvalidArgument {
        name,
        value: s.to_string(),
    })
}

fn read_balance(kv: &KvState, addr: &str) -> u128 {
    kv.balances.get(addr).copied().unwrap_or(0) as u128
}

fn debit_balance(kv: &mut KvState, addr: &str, amount: u128) -> Result<(), StakingTxError> {
    let balance = read_balance(kv, addr);
    let new_balance = balance
        .checked_sub(amount)
        .and_then(|b| u64::try_from(b).ok())
        .ok_or(StakingTxError::Overflow("debit_balance"))?;
    kv.balances.insert(addr.to_string(), new_balance);
    Ok(())
}

fn credit_balance(kv: &mut KvState, addr: &str, amount: u128) -> Result<(), StakingTxError> {
    let balance = read_balance(kv, addr);
    let new_balance = balance
        .checked_add(amount)
        .and_then(|b| u64::try_from(b).ok())
        .ok_or(StakingTxError::Overflow("credit_balance"))?;
    kv.balances.insert(addr.to_string(), new_balance);
    Ok(())
}

fn gas_for_action(action: &str) -> u64 {
    match action {
        "delegate" => GAS_DELEGATE,
        "undelegate" => GAS_UNDELEGATE,
        "withdraw" => GAS_WITHDRAW,
        "register" => GAS_REGISTER,
        "deregister" => GAS_DEREGISTER,
        _ => GAS_UNKNOWN_ACTION,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::params::EconomicsParams;
    use crate::economics::staking::{StakingState, Validator as EconValidator};
    use crate::execution::KvState;

    fn setup() -> (KvState, StakingState, EconomicsParams) {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();

        // Register alice as a validator with 1 M self-stake.
        // We deliberately do NOT create a self-delegation: `self_stake` is
        // the operator's bond, so a self-delegation would double-count.
        let validator = EconValidator::new("alice", 1_000_000, 500).unwrap();
        staking.validators.insert("alice".to_string(), validator);

        // Give bob some spendable balance.
        kv.balances.insert("bob".to_string(), 500_000);

        (kv, staking, params)
    }

    fn delegate(from: &str, val: &str, amount: &str) -> String {
        format!("stake delegate {val} {amount}")
    }

    fn run<'a>(
        payload: &str,
        from: &'a str,
        kv: &mut KvState,
        staking: &mut StakingState,
        params: &EconomicsParams,
        epoch: u64,
    ) -> StakingTxResult {
        try_apply_staking_tx(payload, from, kv, staking, params, epoch)
            .expect("payload must be recognised as staking")
    }

    // ── Recognition ─────────────────────────────────────────────────────

    #[test]
    fn non_staking_payload_returns_none() {
        let (mut kv, mut staking, params) = setup();
        let cases = ["set mykey myval", "stake", "", "  ", "STAKE delegate alice 1"];
        for payload in cases {
            assert!(
                try_apply_staking_tx(payload, "alice", &mut kv, &mut staking, &params, 0)
                    .is_none(),
                "payload {payload:?} should not be recognised",
            );
        }
    }

    #[test]
    fn whitespace_and_leading_space_are_tolerated() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            "   stake    delegate   alice   100   ",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(r.success, "{:?}", r.error);
    }

    #[test]
    fn empty_sender_is_rejected() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            "stake deregister",
            "",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("must not be empty"));
    }

    #[test]
    fn unknown_action_is_rejected() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            "stake fizzbuzz",
            "alice",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("unknown staking action"));
    }

    // ── Delegate ────────────────────────────────────────────────────────

    #[test]
    fn delegate_success() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            &delegate("bob", "alice", "100000"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(r.success, "{:?}", r.error);
        assert_eq!(r.gas_used, GAS_DELEGATE);
        assert_eq!(kv.balances["bob"], 400_000);
        let d = &staking.delegations[&("bob".to_string(), "alice".to_string())];
        assert_eq!(d.amount, 100_000);
        assert_eq!(staking.validators["alice"].total_stake, 1_100_000);
    }

    #[test]
    fn delegate_rejects_insufficient_balance() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            &delegate("bob", "alice", "999999999"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("insufficient balance"));
        // No state was mutated.
        assert_eq!(kv.balances["bob"], 500_000);
        assert!(staking.delegations.is_empty());
    }

    #[test]
    fn delegate_rejects_zero_amount() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            &delegate("bob", "alice", "0"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("amount must be > 0"));
    }

    #[test]
    fn delegate_rejects_non_numeric_amount() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            &delegate("bob", "alice", "lots"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("invalid argument `amount`"));
    }

    #[test]
    fn delegate_rejects_unknown_validator() {
        let (mut kv, mut staking, params) = setup();
        let r = run(
            &delegate("bob", "ghost", "100"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("ghost"));
    }

    #[test]
    fn delegate_missing_args() {
        let (mut kv, mut staking, params) = setup();
        let r = run("stake delegate", "bob", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("missing argument"));

        let r = run("stake delegate alice", "bob", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("missing argument"));
    }

    // ── Undelegate / withdraw ───────────────────────────────────────────

    #[test]
    fn undelegate_then_withdraw_after_unbonding() {
        let (mut kv, mut staking, params) = setup();

        run(&delegate("bob", "alice", "100000"), "bob", &mut kv, &mut staking, &params, 0);
        assert!(run(
            "stake undelegate alice 100000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            5,
        )
        .success);

        // Before unlock (unbonding_epochs = 14 → unlock at 19).
        let r = run("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 10);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("nothing to withdraw"));

        // After unlock.
        let r = run("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 20);
        assert!(r.success, "{:?}", r.error);
        assert_eq!(kv.balances["bob"], 500_000);
    }

    #[test]
    fn undelegate_rejects_excessive_amount() {
        let (mut kv, mut staking, params) = setup();
        run(&delegate("bob", "alice", "100000"), "bob", &mut kv, &mut staking, &params, 0);
        let r = run(
            "stake undelegate alice 200000",
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert!(r.error.unwrap().contains("exceeds"));
    }

    // ── Register ────────────────────────────────────────────────────────

    #[test]
    fn register_success() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 100_000);

        let r = run("stake register 500", "charlie", &mut kv, &mut staking, &params, 0);
        assert!(r.success, "{:?}", r.error);

        let v = &staking.validators["charlie"];
        assert_eq!(v.commission_bps, 500);
        // Regression: total_stake must equal the operator's bond, NOT 2×.
        assert_eq!(v.total_stake, params.min_stake);
        assert_eq!(v.self_stake, params.min_stake);
        // Regression: exactly one debit.
        assert_eq!(kv.balances["charlie"], 100_000 - params.min_stake);

        // Invariant: no self-delegation created.
        let self_key = ("charlie".to_string(), "charlie".to_string());
        assert!(!staking.delegations.contains_key(&self_key));
    }

    #[test]
    fn register_rejects_duplicate() {
        let (mut kv, mut staking, params) = setup();
        // Alice already exists.
        let r = run("stake register 100", "alice", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("already exists"));
    }

    #[test]
    fn register_rejects_below_min_stake() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 100);

        let r = run("stake register 500", "charlie", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("below minimum stake"));
    }

    #[test]
    fn register_rejects_commission_above_max() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 100_000);

        let r = run("stake register 10001", "charlie", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("out of range"));
    }

    #[test]
    fn register_at_exactly_min_stake_succeeds() {
        // Regression: the old implementation created a self-delegation on
        // top of the self-bond and would fail when the operator's balance
        // exactly equalled `min_stake`.
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams {
            min_stake: 1_000,
            ..Default::default()
        };
        kv.balances.insert("charlie".into(), 1_000);

        let r = run("stake register 0", "charlie", &mut kv, &mut staking, &params, 0);
        assert!(r.success, "{:?}", r.error);
        assert_eq!(kv.balances["charlie"], 0);
    }

    // ── Deregister ──────────────────────────────────────────────────────

    #[test]
    fn deregister_success() {
        let (mut kv, mut staking, params) = setup();
        let r = run("stake deregister", "alice", &mut kv, &mut staking, &params, 0);
        assert!(r.success, "{:?}", r.error);
        assert!(!staking.validators.contains_key("alice"));
        assert_eq!(kv.balances["alice"], 1_000_000);
    }

    #[test]
    fn deregister_rejects_external_delegations() {
        let (mut kv, mut staking, params) = setup();
        run(&delegate("bob", "alice", "100000"), "bob", &mut kv, &mut staking, &params, 0);
        let r = run("stake deregister", "alice", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("external delegations"));
    }

    #[test]
    fn deregister_preserves_pending_unbondings() {
        let (mut kv, mut staking, params) = setup();
        // Alice has no external delegations. She self-undelegates by first
        // registering as a self-delegator (for the test only) — this is
        // unusual but exercises the pending-unbonding path.
        staking
            .delegate("alice", "alice", 0, |_| 0) // no-op, ensures entry exists
            .ok();
        // Manually inject a pending unbonding on the (alice, alice) key.
        staking
            .delegations
            .entry(("alice".into(), "alice".into()))
            .or_default()
            .unbondings
            .push(crate::economics::staking::UnbondingEntry {
                id: 0,
                amount: 500,
                unlock_epoch: 100,
            });

        let r = run("stake deregister", "alice", &mut kv, &mut staking, &params, 0);
        assert!(r.success, "{:?}", r.error);

        // The delegation entry must survive because unbondings remain.
        let d = &staking.delegations[&("alice".into(), "alice".into())];
        assert_eq!(d.amount, 0);
        assert_eq!(d.unbondings.len(), 1);
    }

    #[test]
    fn deregister_of_unknown_validator_fails() {
        let (mut kv, mut staking, params) = setup();
        let r = run("stake deregister", "ghost", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert!(r.error.unwrap().contains("not found"));
    }

    // ── Gas on failure ──────────────────────────────────────────────────

    #[test]
    fn gas_is_charged_on_domain_failure() {
        let (mut kv, mut staking, params) = setup();
        // Delegate with insufficient funds still burns the delegate gas.
        let r = run(
            &delegate("bob", "alice", "999999999"),
            "bob",
            &mut kv,
            &mut staking,
            &params,
            0,
        );
        assert!(!r.success);
        assert_eq!(r.gas_used, GAS_DELEGATE);
    }

    #[test]
    fn gas_for_unknown_action_is_base() {
        let (mut kv, mut staking, params) = setup();
        let r = run("stake fizzbuzz", "alice", &mut kv, &mut staking, &params, 0);
        assert!(!r.success);
        assert_eq!(r.gas_used, GAS_UNKNOWN_ACTION);
    }
}
