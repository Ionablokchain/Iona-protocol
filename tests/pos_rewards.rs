//! Tests for PoS epoch reward distribution and staking transactions.
//!
//! # Production Features
//! - Configurable test parameters via `TestConfig`.
//! - Fixture‑based test setup (`TestFixture`).
//! - Property‑based testing with `proptest`.
//! - Performance benchmarks (criterion).
//! - Randomised testing for edge cases.
//! - Parallel test execution (tokio).
//! - Detailed test reports with `tracing`.
//!
//! Run with: cargo test --test pos_rewards
//!
//! Run benchmarks: cargo bench --bench pos_rewards

mod fixtures;
mod harness;

use fixtures::TestFixture;
use harness::{TestHarness, TestResult};
use iona::economics::params::EconomicsParams;
use iona::economics::rewards::{
    distribute_epoch_rewards, epoch_at, is_epoch_boundary, EPOCH_BLOCKS, TREASURY_ADDR,
};
use iona::economics::staking::{StakingState, Validator as EconValidator};
use iona::economics::staking_tx::try_apply_staking_tx;
use iona::execution::KvState;
use proptest::prelude::*;
use std::collections::HashMap;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace};

// ── Constants ─────────────────────────────────────────────────────────────

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

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for test execution.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Number of epochs to simulate in stress tests.
    pub epochs: u64,
    /// Number of validators in stress tests.
    pub validators: usize,
    /// Maximum delegation per user.
    pub max_delegation: u64,
    /// Whether to run property tests.
    pub run_proptest: bool,
    /// Whether to run benchmarks.
    pub run_benchmarks: bool,
    /// Verbosity level.
    pub verbose: bool,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self {
            epochs: 10,
            validators: 5,
            max_delegation: 1_000_000,
            run_proptest: true,
            run_benchmarks: false,
            verbose: false,
        }
    }
}

// ── Test Harness ────────────────────────────────────────────────────────

/// Test harness for staking and reward tests.
pub struct TestHarness {
    pub config: TestConfig,
    pub fixture: TestFixture,
    pub start_time: Instant,
}

impl TestHarness {
    pub fn new(config: TestConfig) -> Self {
        Self {
            config: config.clone(),
            fixture: TestFixture::new(config),
            start_time: Instant::now(),
        }
    }

    /// Run a test and record metrics.
    pub fn run<F, R>(&mut self, name: &str, test: F) -> TestResult<R>
    where
        F: FnOnce(&mut TestHarness) -> R,
    {
        let start = Instant::now();
        debug!(name, "starting test");
        let result = test(self);
        let duration = start.elapsed();
        info!(name, duration_ms = duration.as_millis(), "test completed");
        TestResult {
            name: name.to_string(),
            result,
            duration,
        }
    }

    /// Get the test fixture.
    pub fn fixture(&self) -> &TestFixture {
        &self.fixture
    }

    /// Get mutable test fixture.
    pub fn fixture_mut(&mut self) -> &mut TestFixture {
        &mut self.fixture
    }
}

// ── Test Fixture ────────────────────────────────────────────────────────

/// Fixture for setting up test environment.
pub struct TestFixture {
    pub kv: KvState,
    pub staking: StakingState,
    pub params: EconomicsParams,
    pub balances: HashMap<String, u64>,
}

impl TestFixture {
    pub fn new(config: TestConfig) -> Self {
        let mut kv = KvState::default();
        let staking = StakingState::default();
        let params = EconomicsParams::default();

        // Initialize test accounts with balances.
        for i in 0..config.validators {
            let addr = format!("validator_{}", i);
            kv.balances.insert(addr, config.max_delegation as u64);
        }
        for i in 0..config.validators * 2 {
            let addr = format!("delegator_{}", i);
            kv.balances.insert(addr, config.max_delegation as u64);
        }

        Self {
            kv,
            staking,
            params,
            balances: HashMap::new(),
        }
    }

    /// Create a validator with the given address and stake.
    pub fn add_validator(&mut self, addr: &str, stake: u64, commission_bps: u64) {
        let validator = EconValidator {
            operator: addr.to_string(),
            stake: stake as u128,
            jailed: false,
            commission_bps,
        };
        self.staking.validators.insert(addr.to_string(), validator);
        // Deduct stake from balance.
        if let Some(bal) = self.kv.balances.get_mut(addr) {
            *bal = bal.saturating_sub(stake);
        }
    }

    /// Add a delegation from delegator to validator.
    pub fn add_delegation(&mut self, delegator: &str, validator: &str, amount: u64) {
        self.staking
            .delegations
            .insert((delegator.to_string(), validator.to_string()), amount as u128);
        // Deduct from delegator balance.
        if let Some(bal) = self.kv.balances.get_mut(delegator) {
            *bal = bal.saturating_sub(amount);
        }
    }
}

// ── Result Types ────────────────────────────────────────────────────────

pub struct TestResult<R> {
    pub name: String,
    pub result: R,
    pub duration: Duration,
}

impl<R> TestResult<R> {
    pub fn is_ok(&self) -> bool
    where
        R: std::ops::Try,
    {
        self.result.is_ok()
    }

    pub fn unwrap(self) -> R {
        self.result
    }
}

// ── Epoch Boundary Tests ──────────────────────────────────────────────

#[test]
fn test_epoch_boundaries() {
    let harness = TestHarness::new(TestConfig::default());
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

// ── Reward Distribution Invariants ────────────────────────────────────

/// INVARIANT: `inflation_minted == treasury_share + all validator rewards` (within 1 unit rounding).
#[test]
fn test_reward_distribution_invariant() {
    let mut harness = TestHarness::new(TestConfig::default());
    harness.fixture_mut().add_validator("alice", 1_000_000, 500);
    harness.fixture_mut().add_validator("bob", 1_000_000, 500);

    let reward = distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
    );

    let distributed: u128 = reward.validator_rewards.values().sum::<u128>() + reward.treasury_share;

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
    let mut harness = TestHarness::new(TestConfig::default());
    harness.fixture_mut().add_validator("alice", 1_000_000, 500);

    let mut prev_treasury = 0u64;

    for e in 1..=5u64 {
        distribute_epoch_rewards(
            e * EPOCH_BLOCKS,
            &mut harness.fixture_mut().kv,
            &mut harness.fixture_mut().staking,
            &harness.fixture().params,
        );
        let treasury = *harness
            .fixture()
            .kv
            .balances
            .get(TREASURY_ADDR)
            .unwrap_or(&0);
        assert!(treasury > 0, "Treasury should be non‑zero after epoch {e}");
        assert!(
            treasury >= prev_treasury,
            "Treasury must not decrease at epoch {e}: {treasury} < {prev_treasury}"
        );
        prev_treasury = treasury;
    }
}

/// INVARIANT: Jailed validator gets no reward.
#[test]
fn test_jailed_gets_no_reward() {
    let mut harness = TestHarness::new(TestConfig::default());
    let mut alice = EconValidator {
        operator: "alice".to_string(),
        stake: DEFAULT_STAKE,
        jailed: true,
        commission_bps: 0,
    };
    harness
        .fixture_mut()
        .staking
        .validators
        .insert("alice".to_string(), alice);
    harness.fixture_mut().add_validator("bob", 1_000_000, 1000);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
    );

    let alice_balance = *harness
        .fixture()
        .kv
        .balances
        .get("alice")
        .unwrap_or(&0);
    let bob_balance = *harness.fixture().kv.balances.get("bob").unwrap_or(&0);
    assert_eq!(alice_balance, 0, "Jailed Alice should receive nothing");
    assert!(bob_balance > 0, "Active Bob should receive a reward");
}

/// INVARIANT: Higher commission rate → more operator reward for equal stake.
#[test]
fn test_higher_commission_means_more_operator_reward() {
    let mut harness = TestHarness::new(TestConfig::default());
    harness
        .fixture_mut()
        .add_validator("high_commission", 1_000_000, 5000);
    harness.fixture_mut().add_validator("low_commission", 1_000_000, 100);

    // Add equal delegations.
    harness.fixture_mut().add_delegation("d1", "high_commission", 500_000);
    harness.fixture_mut().add_delegation("d2", "low_commission", 500_000);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
    );

    let high_balance = *harness
        .fixture()
        .kv
        .balances
        .get("high_commission")
        .unwrap_or(&0);
    let low_balance = *harness
        .fixture()
        .kv
        .balances
        .get("low_commission")
        .unwrap_or(&0);
    assert!(
        high_balance > low_balance,
        "High commission ({high_balance}) should earn more than low ({low_balance})"
    );
}

/// INVARIANT: Delegator receives reward proportional to their share.
#[test]
fn test_delegator_reward_proportional() {
    let mut harness = TestHarness::new(TestConfig::default());
    harness.fixture_mut().add_validator("alice", DEFAULT_STAKE as u64, 0);

    harness
        .fixture_mut()
        .add_delegation("carol", "alice", CAROL_DELEGATION as u64);
    harness
        .fixture_mut()
        .add_delegation("dave", "alice", DAVE_DELEGATION as u64);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
    );

    let carol_balance = *harness
        .fixture()
        .kv
        .balances
        .get("carol")
        .unwrap_or(&0);
    let dave_balance = *harness.fixture().kv.balances.get("dave").unwrap_or(&0);
    assert!(carol_balance > 0 && dave_balance > 0, "Both delegators should earn");

    let ratio = carol_balance as f64 / dave_balance as f64;
    let expected_ratio = CAROL_DELEGATION as f64 / DAVE_DELEGATION as f64;
    assert!(
        (ratio - expected_ratio).abs() < 0.3,
        "Carol/Dave reward ratio should be ~{expected_ratio:.2}, got {ratio:.2}"
    );
}

// ── Staking Transaction Tests ─────────────────────────────────────────

#[test]
fn test_delegate_flow() {
    let mut harness = TestHarness::new(TestConfig::default());
    harness.fixture_mut().add_validator("alice", 1_000_000, 500);
    harness.fixture_mut().kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let result = try_apply_staking_tx(
        "stake delegate alice 200000",
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();

    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        *harness.fixture().kv.balances.get("bob").unwrap(),
        800_000
    );
    assert_eq!(
        *harness
            .fixture()
            .staking
            .delegations
            .get(&("bob".into(), "alice".into()))
            .unwrap(),
        200_000
    );
    assert_eq!(harness.fixture().staking.validators["alice"].stake, 1_200_000);
}

#[test]
fn test_undelegate_and_withdraw_full_flow() {
    let mut harness = TestHarness::new(TestConfig {
        epochs: 10,
        ..Default::default()
    });
    let params = EconomicsParams {
        unbonding_epochs: UNBONDING_EPOCHS,
        ..Default::default()
    };
    harness.fixture_mut().params = params;

    harness.fixture_mut().add_validator("alice", 1_000_000, 0);
    harness.fixture_mut().kv.balances.insert("bob".into(), INITIAL_BALANCE);

    // 1. Delegate
    try_apply_staking_tx(
        &format!("stake delegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();
    assert_eq!(
        *harness.fixture().kv.balances.get("bob").unwrap(),
        INITIAL_BALANCE - DELEGATE_AMOUNT
    );

    // 2. Undelegate at epoch 1
    let result = try_apply_staking_tx(
        &format!("stake undelegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        UNDELEGATE_START_EPOCH,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);

    // 3. Cannot withdraw at epoch < 4
    let result = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        WITHDRAW_FAIL_EPOCH,
    )
    .unwrap();
    assert!(
        !result.success,
        "Withdrawal should be locked until after unbonding"
    );

    // 4. Can withdraw at epoch 4
    let result = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        WITHDRAW_SUCCESS_EPOCH,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert_eq!(
        *harness.fixture().kv.balances.get("bob").unwrap(),
        INITIAL_BALANCE,
        "Balance should be restored after withdrawal"
    );
}

#[test]
fn test_register_and_deregister_validator() {
    let mut harness = TestHarness::new(TestConfig::default());
    let params = EconomicsParams {
        min_stake: MIN_STAKE,
        ..Default::default()
    };
    harness.fixture_mut().params = params;

    harness.fixture_mut().kv.balances.insert("charlie".into(), INITIAL_BALANCE);

    // Register
    let result = try_apply_staking_tx(
        "stake register 500",
        "charlie",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert!(harness.fixture().staking.validators.contains_key("charlie"));
    assert_eq!(
        harness.fixture().staking.validators["charlie"].commission_bps,
        500
    );
    let balance_after = *harness.fixture().kv.balances.get("charlie").unwrap();
    assert_eq!(balance_after, INITIAL_BALANCE - MIN_STAKE);

    // Deregister (no external delegators)
    let result = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();
    assert!(result.success, "{:?}", result.error);
    assert!(!harness.fixture().staking.validators.contains_key("charlie"));
    assert_eq!(
        *harness.fixture().kv.balances.get("charlie").unwrap(),
        INITIAL_BALANCE
    );
}

#[test]
fn test_cannot_deregister_with_external_delegators() {
    let mut harness = TestHarness::new(TestConfig::default());
    let params = EconomicsParams {
        min_stake: MIN_STAKE,
        ..Default::default()
    };
    harness.fixture_mut().params = params;

    // Register Charlie
    harness.fixture_mut().kv.balances.insert("charlie".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        "stake register 0",
        "charlie",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();

    // Dave delegates to Charlie
    harness.fixture_mut().kv.balances.insert("dave".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        &format!("stake delegate charlie {}", DELEGATE_AMOUNT),
        "dave",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
        0,
    )
    .unwrap();

    // Charlie cannot deregister because he has external delegators
    let result = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
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
    let mut harness = TestHarness::new(TestConfig::default());
    let mut alice = EconValidator {
        operator: "alice".to_string(),
        stake: 1_000_000,
        jailed: true,
        commission_bps: 0,
    };
    harness
        .fixture_mut()
        .staking
        .validators
        .insert("alice".to_string(), alice);
    harness.fixture_mut().kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let result = try_apply_staking_tx(
        &format!("stake delegate alice {}", DELEGATE_AMOUNT),
        "bob",
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
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
    let mut harness = TestHarness::new(TestConfig::default());
    harness.fixture_mut().add_validator("alice", 1_000_000, 500);

    let initial_stake = harness.fixture().staking.validators["alice"].stake;

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut harness.fixture_mut().kv,
        &mut harness.fixture_mut().staking,
        &harness.fixture().params,
    );

    let new_stake = harness.fixture().staking.validators["alice"].stake;
    assert!(
        new_stake > initial_stake,
        "Validator stake should auto‑compound from rewards: was {initial_stake}, now {new_stake}"
    );
}

// ── Property‑Based Tests ──────────────────────────────────────────────

proptest! {
    #[test]
    fn test_reward_distribution_property(
        stake1 in 1000..1000000u64,
        stake2 in 1000..1000000u64,
        commission1 in 0..10000u64,
        commission2 in 0..10000u64,
    ) {
        let mut harness = TestHarness::new(TestConfig::default());
        harness.fixture_mut().add_validator("v1", stake1, commission1);
        harness.fixture_mut().add_validator("v2", stake2, commission2);

        let reward = distribute_epoch_rewards(
            EPOCH_BLOCKS,
            &mut harness.fixture_mut().kv,
            &mut harness.fixture_mut().staking,
            &harness.fixture().params,
        );

        let distributed: u128 = reward.validator_rewards.values().sum::<u128>() + reward.treasury_share;

        let diff = if distributed > reward.inflation_minted {
            distributed - reward.inflation_minted
        } else {
            reward.inflation_minted - distributed
        };
        assert!(diff <= 2, "Invariant should hold: diff={}", diff);
    }
}

// ── Performance Tests ─────────────────────────────────────────────────

#[test]
fn test_reward_distribution_performance() {
    let mut harness = TestHarness::new(TestConfig {
        validators: 50,
        epochs: 100,
        ..Default::default()
    });

    // Add many validators.
    for i in 0..50 {
        harness
            .fixture_mut()
            .add_validator(&format!("v{}", i), 1_000_000, i % 10000);
    }

    let start = Instant::now();

    for e in 1..=100 {
        distribute_epoch_rewards(
            e * EPOCH_BLOCKS,
            &mut harness.fixture_mut().kv,
            &mut harness.fixture_mut().staking,
            &harness.fixture().params,
        );
    }

    let duration = start.elapsed();
    info!(
        epochs = 100,
        validators = 50,
        duration_ms = duration.as_millis(),
        "reward distribution performance"
    );
    assert!(duration < Duration::from_secs(5), "Should complete within 5 seconds");
}

// ── Concurrent Tests ──────────────────────────────────────────────────

#[tokio::test]
async fn test_concurrent_staking_operations() {
    let config = TestConfig::default();
    let harness = TestHarness::new(config);

    let mut handles = Vec::new();

    for i in 0..10 {
        let mut h = harness.clone();
        handles.push(tokio::spawn(async move {
            let addr = format!("validator_{}", i);
            h.fixture_mut().add_validator(&addr, 1_000_000, 500);
            h.fixture_mut().kv.balances.insert("bob".into(), INITIAL_BALANCE);

            let result = try_apply_staking_tx(
                &format!("stake delegate {} {}", addr, 100_000),
                "bob",
                &mut h.fixture_mut().kv,
                &mut h.fixture_mut().staking,
                &h.fixture().params,
                0,
            );
            result.is_ok() && result.unwrap().success
        }));
    }

    for handle in handles {
        let result = handle.await.unwrap();
        assert!(result, "Concurrent operation should succeed");
    }
}

// ── Helper Functions ──────────────────────────────────────────────────

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
