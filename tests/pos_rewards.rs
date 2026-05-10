//! Tests for PoS epoch reward distribution and staking transactions.
//!
//! Run with: cargo test --test pos_rewards

use iona::economics::params::EconomicsParams;
use iona::economics::rewards::{
    distribute_epoch_rewards, epoch_at, is_epoch_boundary, EPOCH_BLOCKS, TREASURY_ADDR,
};
use iona::economics::staking::{StakingState, Validator as EconValidator};
use iona::economics::staking_tx::try_apply_staking_tx;
use iona::execution::KvState;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default stake amount for test validators.
const DEFAULT_STAKE: u128 = 10_000_000_000;

/// Default commission rate (basis points) for Alice.
const ALICE_COMMISSION_BPS: u64 = 1000;

/// Default commission rate (basis points) for Bob.
const BOB_COMMISSION_BPS: u64 = 500;

/// Amount delegated by Bob.
const DELEGATION_AMOUNT: u128 = 200_000;

/// Amount delegated by Carol.
const CAROL_DELEGATION: u128 = 2_000_000_000;

/// Amount delegated by Dave.
const DAVE_DELEGATION: u128 = 1_000_000_000;

/// Minimum stake for validator registration.
const MIN_STAKE: u64 = 10_000;

/// Initial balance for test accounts.
const INITIAL_BALANCE: u64 = 1_000_000;

/// Amount to delegate in tests.
const DELEGATE_AMOUNT: u64 = 100_000;

/// Unbonding epochs for undelegation tests.
const UNBONDING_EPOCHS: u64 = 3;

/// Start epoch for undelegation.
const UNDELEGATE_START_EPOCH: u64 = 1;

/// Withdraw attempt epoch (should fail).
const WITHDRAW_FAIL_EPOCH: u64 = 3;

/// Successful withdraw epoch.
const WITHDRAW_SUCCESS_EPOCH: u64 = 4;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a validator record with the given parameters.
fn make_validator(addr: &str, stake: u128, commission_bps: u64) -> (String, EconValidator) {
    (
        addr.to_string(),
        EconValidator {
            operator: addr.to_string(),
            stake,
            jailed: false,
            commission_bps,
        },
    )
}

/// Create a default test environment with two validators (Alice and Bob).
fn default_staking() -> (KvState, StakingState, EconomicsParams) {
    let kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, v) = make_validator("alice", DEFAULT_STAKE, ALICE_COMMISSION_BPS);
    staking.validators.insert(a, v);
    let (b, v) = make_validator("bob", DEFAULT_STAKE, BOB_COMMISSION_BPS);
    staking.validators.insert(b, v);

    (kv, staking, params)
}

// -----------------------------------------------------------------------------
// Epoch boundary tests
// -----------------------------------------------------------------------------

#[test]
fn test_epoch_boundaries() {
    assert!(!is_epoch_boundary(0));
    assert!(!is_epoch_boundary(1));
    assert!(!is_epoch_boundary(EPOCH_BLOCKS - 1));
    assert!(is_epoch_boundary(EPOCH_BLOCKS));
    assert!(!is_epoch_boundary(EPOCH_BLOCKS + 1));
    assert!(is_epoch_boundary(EPOCH_BLOCKS * 2));
    assert!(is_epoch_boundary(EPOCH_BLOCKS * 100));
}

#[test]
fn test_epoch_numbers() {
    assert_eq!(epoch_at(0), 0);
    assert_eq!(epoch_at(EPOCH_BLOCKS - 1), 0);
    assert_eq!(epoch_at(EPOCH_BLOCKS), 1);
    assert_eq!(epoch_at(EPOCH_BLOCKS * 5), 5);
}

// -----------------------------------------------------------------------------
// Reward distribution invariants
// -----------------------------------------------------------------------------

/// INVARIANT: `inflation_minted == treasury_share + all validator rewards` (within 1 unit rounding).
#[test]
fn test_reward_distribution_invariant() {
    let (mut kv, mut staking, params) = default_staking();

    let reward = distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let distributed: u128 = reward.validator_rewards.values().sum::<u128>() + reward.treasury_share;

    // Allow up to 2 units of rounding error (integer division)
    let diff = if distributed > reward.inflation_minted {
        distributed - reward.inflation_minted
    } else {
        reward.inflation_minted - distributed
    };
    assert!(
        diff <= 2,
        "Distributed ({distributed}) differs from minted ({}) by {diff}",
        reward.inflation_minted
    );
}

/// INVARIANT: Treasury balance grows every epoch.
#[test]
fn test_treasury_grows_each_epoch() {
    let (mut kv, mut staking, params) = default_staking();

    for e in 1..=5u64 {
        distribute_epoch_rewards(e * EPOCH_BLOCKS, &mut kv, &mut staking, &params);
        let treasury = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(treasury > 0, "Treasury should be non‑zero after epoch {e}");
    }

    // Treasury grows monotonically
    let mut kv2 = KvState::default();
    let mut staking2 = default_staking().1;
    let params2 = EconomicsParams::default();
    let mut prev = 0u64;
    for e in 1..=5u64 {
        distribute_epoch_rewards(e * EPOCH_BLOCKS, &mut kv2, &mut staking2, &params2);
        let treasury = *kv2.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(
            treasury >= prev,
            "Treasury must not decrease at epoch {e}: {treasury} < {prev}"
        );
        prev = treasury;
    }
}

/// INVARIANT: Jailed validator gets no reward.
#[test]
fn test_jailed_gets_no_reward() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, mut v) = make_validator("alice", DEFAULT_STAKE, 0);
    v.jailed = true;
    staking.validators.insert(a, v);
    let (b, v) = make_validator("bob", DEFAULT_STAKE, 1000);
    staking.validators.insert(b, v);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let alice_balance = *kv.balances.get("alice").unwrap_or(&0);
    let bob_balance = *kv.balances.get("bob").unwrap_or(&0);
    assert_eq!(alice_balance, 0, "Jailed Alice should receive nothing");
    assert!(bob_balance > 0, "Active Bob should receive a reward");
}

/// INVARIANT: Higher commission rate → more operator reward for equal stake.
#[test]
fn test_higher_commission_means_more_operator_reward() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (high, v_high) = make_validator("high_commission", DEFAULT_STAKE, 5000); // 50%
    staking.validators.insert(high, v_high);
    let (low, v_low) = make_validator("low_commission", DEFAULT_STAKE, 100); // 1%
    staking.validators.insert(low, v_low);

    // Add equal delegations so the difference comes only from commission.
    staking
        .delegations
        .insert(("d1".into(), "high_commission".into()), DEFAULT_STAKE / 2);
    staking
        .delegations
        .insert(("d2".into(), "low_commission".into()), DEFAULT_STAKE / 2);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let high_balance = *kv.balances.get("high_commission").unwrap_or(&0);
    let low_balance = *kv.balances.get("low_commission").unwrap_or(&0);
    assert!(
        high_balance > low_balance,
        "High commission ({high_balance}) should earn more than low ({low_balance})"
    );
}

/// INVARIANT: Delegator receives reward proportional to their share.
#[test]
fn test_delegator_reward_proportional() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    // 0% commission to simplify calculation.
    let (a, v) = make_validator("alice", DEFAULT_STAKE, 0);
    staking.validators.insert(a, v);

    staking
        .delegations
        .insert(("carol".into(), "alice".into()), CAROL_DELEGATION);
    staking
        .delegations
        .insert(("dave".into(), "alice".into()), DAVE_DELEGATION);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let carol_balance = *kv.balances.get("carol").unwrap_or(&0);
    let dave_balance = *kv.balances.get("dave").unwrap_or(&0);
    assert!(carol_balance > 0 && dave_balance > 0, "Both delegators should earn");

    let ratio = carol_balance as f64 / dave_balance as f64;
    let expected_ratio = CAROL_DELEGATION as f64 / DAVE_DELEGATION as f64;
    assert!(
        (ratio - expected_ratio).abs() < 0.3,
        "Carol/Dave reward ratio should be ~{expected_ratio:.2}, got {ratio:.2}"
    );
}

// -----------------------------------------------------------------------------
// Staking transaction tests
// -----------------------------------------------------------------------------

#[test]
fn test_delegate_flow() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, v) = make_validator("alice", 1_000_000, 500);
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let result = try_apply_staking_tx(
        "stake delegate alice 200000",
        "bob",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert_eq!(*kv.balances.get("bob").unwrap(), 800_000);
    assert_eq!(
        *staking
            .delegations
            .get(&("bob".into(), "alice".into()))
            .unwrap(),
        200_000
    );
    assert_eq!(staking.validators["alice"].stake, 1_200_000);
}

#[test]
fn test_undelegate_and_withdraw_full_flow() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams {
        unbonding_epochs: UNBONDING_EPOCHS,
        ..Default::default()
    };

    let (a, v) = make_validator("alice", 1_000_000, 0);
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), INITIAL_BALANCE);

    // 1. Delegate
    try_apply_staking_tx(
        &format!("stake delegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert_eq!(*kv.balances.get("bob").unwrap(), INITIAL_BALANCE - DELEGATE_AMOUNT);

    // 2. Undelegate at epoch 1
    let result = try_apply_staking_tx(
        &format!("stake undelegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut kv,
        &mut staking,
        &params,
        UNDELEGATE_START_EPOCH,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);

    // 3. Cannot withdraw at epoch < 4
    let result = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut kv,
        &mut staking,
        &params,
        WITHDRAW_FAIL_EPOCH,
    )
    .unwrap();
    assert!(!result.success, "Withdrawal should be locked until after unbonding");

    // 4. Can withdraw at epoch 4
    let result = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut kv,
        &mut staking,
        &params,
        WITHDRAW_SUCCESS_EPOCH,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        *kv.balances.get("bob").unwrap(),
        INITIAL_BALANCE,
        "Balance should be restored after withdrawal"
    );
}

#[test]
fn test_register_and_deregister_validator() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams {
        min_stake: MIN_STAKE,
        ..Default::default()
    };

    kv.balances.insert("charlie".into(), INITIAL_BALANCE);

    // Register
    let result = try_apply_staking_tx(
        "stake register 500",
        "charlie",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert!(staking.validators.contains_key("charlie"));
    assert_eq!(staking.validators["charlie"].commission_bps, 500);
    let balance_after = *kv.balances.get("charlie").unwrap();
    assert_eq!(balance_after, INITIAL_BALANCE - MIN_STAKE);

    // Deregister (no external delegators)
    let result = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert!(!staking.validators.contains_key("charlie"));
    assert_eq!(*kv.balances.get("charlie").unwrap(), INITIAL_BALANCE);
}

#[test]
fn test_cannot_deregister_with_external_delegators() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams {
        min_stake: MIN_STAKE,
        ..Default::default()
    };

    // Register Charlie
    kv.balances.insert("charlie".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        "stake register 0",
        "charlie",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();

    // Dave delegates to Charlie
    kv.balances.insert("dave".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        &format!("stake delegate charlie {}", DELEGATE_AMOUNT),
        "dave",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();

    // Charlie cannot deregister because he has external delegators
    let result = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert!(
        !result.success,
        "Validator with external delegators should not be allowed to deregister"
    );
}

#[test]
fn test_cannot_delegate_to_jailed_validator() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, mut v) = make_validator("alice", 1_000_000, 0);
    v.jailed = true;
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let result = try_apply_staking_tx(
        &format!("stake delegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut kv,
        &mut staking,
        &params,
        0,
    )
    .unwrap();
    assert!(
        !result.success,
        "Delegation to jailed validator should be rejected"
    );
}

#[test]
fn test_stake_rewards_auto_compound() {
    let (mut kv, mut staking, params) = default_staking();
    let initial_stake = staking.validators["alice"].stake;

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let new_stake = staking.validators["alice"].stake;
    assert!(
        new_stake > initial_stake,
        "Validator stake should auto‑compound from rewards: was {initial_stake}, now {new_stake}"
    );
}
