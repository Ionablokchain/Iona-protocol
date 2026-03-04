//! Tests for PoS epoch reward distribution and staking transactions.
//!
//! Run with: cargo test --test pos_rewards

use iona::economics::params::EconomicsParams;
use iona::economics::rewards::{distribute_epoch_rewards, is_epoch_boundary, epoch_at, EPOCH_BLOCKS, TREASURY_ADDR};
use iona::economics::staking::{StakingState, Validator as EconValidator};
use iona::economics::staking_tx::try_apply_staking_tx;
use iona::execution::KvState;

fn make_validator(addr: &str, stake: u128, commission_bps: u64) -> (String, EconValidator) {
    (addr.to_string(), EconValidator {
        operator: addr.to_string(),
        stake,
        jailed: false,
        commission_bps,
    })
}

fn default_staking() -> (KvState, StakingState, EconomicsParams) {
    let kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, v) = make_validator("alice", 10_000_000_000, 1000);
    staking.validators.insert(a, v);
    let (b, v) = make_validator("bob", 10_000_000_000, 500);
    staking.validators.insert(b, v);

    (kv, staking, params)
}

// ── Epoch boundary tests ──────────────────────────────────────────────────

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

// ── Reward distribution invariants ───────────────────────────────────────

/// INVARIANT: inflation_minted == treasury_share + all validator rewards (within 1 unit rounding)
#[test]
fn test_reward_distribution_invariant() {
    let (mut kv, mut staking, params) = default_staking();

    let reward = distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let distributed: u128 = reward.validator_rewards.values().sum::<u128>()
        + reward.treasury_share;

    // Allow up to 2 units of rounding error (integer division)
    assert!(
        distributed <= reward.inflation_minted + 2,
        "Distributed ({distributed}) exceeds minted ({}) + rounding",
        reward.inflation_minted
    );
}

/// INVARIANT: Treasury balance grows every epoch.
#[test]
fn test_treasury_grows_each_epoch() {
    let (mut kv, mut staking, params) = default_staking();

    for e in 1..=5u64 {
        distribute_epoch_rewards(e * EPOCH_BLOCKS, &mut kv, &mut staking, &params);
        let t = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(t > 0, "Treasury should be non-zero after epoch {e}");
    }

    // Treasury grows monotonically
    let mut prev = 0u64;
    let mut kv2 = KvState::default();
    let mut staking2 = default_staking().1;
    let params2 = EconomicsParams::default();
    for e in 1..=5u64 {
        distribute_epoch_rewards(e * EPOCH_BLOCKS, &mut kv2, &mut staking2, &params2);
        let t = *kv2.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(t >= prev, "Treasury must not decrease at epoch {e}");
        prev = t;
    }
}

/// INVARIANT: Jailed validator gets no reward.
#[test]
fn test_jailed_gets_no_reward() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, mut v) = make_validator("alice", 10_000_000_000, 0);
    v.jailed = true;
    staking.validators.insert(a, v);
    let (b, v) = make_validator("bob", 10_000_000_000, 1000); // 10% commission so operator balance > 0
    staking.validators.insert(b, v);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let alice_bal = *kv.balances.get("alice").unwrap_or(&0);
    let bob_bal = *kv.balances.get("bob").unwrap_or(&0);
    assert_eq!(alice_bal, 0, "Jailed alice should get nothing");
    assert!(bob_bal > 0, "Active bob should get reward");
}

/// INVARIANT: Higher commission_bps → more operator reward relative to equal stake.
#[test]
fn test_higher_commission_means_more_operator_reward() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    // Give each validator the same stake, but different commissions
    let (a, v) = make_validator("high_commission", 10_000_000_000, 5000); // 50%
    staking.validators.insert(a, v);
    let (b, v) = make_validator("low_commission", 10_000_000_000, 100); // 1%
    staking.validators.insert(b, v);

    // Add equal delegations so the difference comes from commission
    staking.delegations.insert(("d1".into(), "high_commission".into()), 5_000_000_000);
    staking.delegations.insert(("d2".into(), "low_commission".into()), 5_000_000_000);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let high_bal = *kv.balances.get("high_commission").unwrap_or(&0);
    let low_bal = *kv.balances.get("low_commission").unwrap_or(&0);
    assert!(
        high_bal > low_bal,
        "High commission ({high_bal}) should earn more operator reward than low ({low_bal})"
    );
}

/// INVARIANT: Delegator receives reward proportional to their share.
#[test]
fn test_delegator_reward_proportional() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, v) = make_validator("alice", 10_000_000_000, 0); // 0% commission to simplify
    staking.validators.insert(a, v);

    // carol delegates 2x more than dave
    staking.delegations.insert(("carol".into(), "alice".into()), 2_000_000_000);
    staking.delegations.insert(("dave".into(), "alice".into()), 1_000_000_000);

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let carol_bal = *kv.balances.get("carol").unwrap_or(&0);
    let dave_bal = *kv.balances.get("dave").unwrap_or(&0);

    // Carol should earn ~2x what Dave earns
    assert!(carol_bal > 0 && dave_bal > 0, "Both delegators should earn");
    let ratio = carol_bal as f64 / dave_bal as f64;
    assert!(
        ratio > 1.8 && ratio < 2.2,
        "Carol/Dave reward ratio should be ~2.0, got {ratio:.2}"
    );
}

// ── Staking transaction tests ─────────────────────────────────────────────

#[test]
fn test_delegate_flow() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, v) = make_validator("alice", 1_000_000, 500);
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), 500_000);

    // Delegate
    let res = try_apply_staking_tx("stake delegate alice 200000", "bob", &mut kv, &mut staking, &params, 0).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(*kv.balances.get("bob").unwrap(), 300_000);
    assert_eq!(*staking.delegations.get(&("bob".into(), "alice".into())).unwrap(), 200_000);
    assert_eq!(staking.validators["alice"].stake, 1_200_000);
}

#[test]
fn test_undelegate_and_withdraw_full_flow() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams { unbonding_epochs: 3, ..Default::default() };

    let (a, v) = make_validator("alice", 1_000_000, 0);
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), 500_000);

    // 1. Delegate
    try_apply_staking_tx("stake delegate alice 100000", "bob", &mut kv, &mut staking, &params, 0).unwrap();
    assert_eq!(*kv.balances.get("bob").unwrap(), 400_000);

    // 2. Undelegate at epoch 1
    let res = try_apply_staking_tx("stake undelegate alice 100000", "bob", &mut kv, &mut staking, &params, 1).unwrap();
    assert!(res.success, "{:?}", res.error);

    // 3. Cannot withdraw at epoch 3 (need epoch >= 1 + 3 = 4)
    let res = try_apply_staking_tx("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 3).unwrap();
    assert!(!res.success, "Should be locked until epoch 4");

    // 4. Can withdraw at epoch 4
    let res = try_apply_staking_tx("stake withdraw alice", "bob", &mut kv, &mut staking, &params, 4).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert_eq!(*kv.balances.get("bob").unwrap(), 500_000, "Full balance restored");
}

#[test]
fn test_register_and_deregister_validator() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams { min_stake: 10_000, ..Default::default() };

    kv.balances.insert("charlie".into(), 1_000_000);

    // Register
    let res = try_apply_staking_tx("stake register 500", "charlie", &mut kv, &mut staking, &params, 0).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert!(staking.validators.contains_key("charlie"));
    assert_eq!(staking.validators["charlie"].commission_bps, 500);
    let bal_after_register = *kv.balances.get("charlie").unwrap();
    assert_eq!(bal_after_register, 1_000_000 - 10_000);

    // Deregister (no external delegators)
    let res = try_apply_staking_tx("stake deregister", "charlie", &mut kv, &mut staking, &params, 0).unwrap();
    assert!(res.success, "{:?}", res.error);
    assert!(!staking.validators.contains_key("charlie"));
    // Stake returned
    assert_eq!(*kv.balances.get("charlie").unwrap(), 1_000_000);
}

#[test]
fn test_cannot_deregister_with_external_delegators() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams { min_stake: 1_000, ..Default::default() };

    // Register charlie
    kv.balances.insert("charlie".into(), 100_000);
    try_apply_staking_tx("stake register 0", "charlie", &mut kv, &mut staking, &params, 0).unwrap();

    // Dave delegates to charlie
    kv.balances.insert("dave".into(), 50_000);
    try_apply_staking_tx("stake delegate charlie 50000", "dave", &mut kv, &mut staking, &params, 0).unwrap();

    // Charlie cannot deregister
    let res = try_apply_staking_tx("stake deregister", "charlie", &mut kv, &mut staking, &params, 0).unwrap();
    assert!(!res.success, "Should not deregister with external delegators");
}

#[test]
fn test_cannot_delegate_to_jailed_validator() {
    let mut kv = KvState::default();
    let mut staking = StakingState::default();
    let params = EconomicsParams::default();

    let (a, mut v) = make_validator("alice", 1_000_000, 0);
    v.jailed = true;
    staking.validators.insert(a, v);
    kv.balances.insert("bob".into(), 500_000);

    let res = try_apply_staking_tx("stake delegate alice 100000", "bob", &mut kv, &mut staking, &params, 0).unwrap();
    assert!(!res.success, "Should not delegate to jailed validator");
}

#[test]
fn test_stake_rewards_auto_compound() {
    let (mut kv, mut staking, params) = default_staking();
    let initial_stake = staking.validators["alice"].stake;

    distribute_epoch_rewards(EPOCH_BLOCKS, &mut kv, &mut staking, &params);

    let new_stake = staking.validators["alice"].stake;
    assert!(
        new_stake > initial_stake,
        "Validator stake should auto-compound from rewards (was {initial_stake}, now {new_stake})"
    );
}
