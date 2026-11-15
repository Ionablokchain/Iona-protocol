//! Tests for PoS epoch reward distribution and staking transactions.
//!
//! # What is tested
//!
//! * **Epoch boundaries** — `is_epoch_boundary` and `epoch_at` are exact
//!   inverses on the epoch boundary set.
//! * **Reward conservation** — `inflation_minted == sum(validator_rewards)
//!   + treasury_share` (up to integer rounding).
//! * **Treasury monotonicity** — the treasury balance never decreases
//!   across epochs.
//! * **Jailing** — a jailed validator receives zero reward.
//! * **Commission** — for equal stake, higher commission yields higher
//!   operator reward.
//! * **Delegation proportionality** — delegator reward is proportional to
//!   their delegation.
//! * **Auto-compounding** — validator stake grows from epoch rewards.
//! * **Staking lifecycle** — delegate → undelegate → withdraw, register /
//!   deregister, jail rejection, and deregister-with-delegators
//!   rejection.
//!
//! # What is **not** tested here
//!
//! * Actual cross-thread concurrency of the staking subsystem. The
//!   `TestFixture` is single-threaded; true concurrency would require an
//!   `Arc<Mutex<...>>` harness and a real race scenario. That is out of
//!   scope for this file.
//! * Fee/gas arithmetic and EIP-1559 (covered in `tests/integration.rs`).
//!
//! # Dev-dependencies required
//!
//! * `proptest` — for the property test at the bottom.
//!
//! Run with: `cargo test --test pos_rewards`

use std::time::Duration;

use iona::economics::params::EconomicsParams;
use iona::economics::rewards::{
    distribute_epoch_rewards, epoch_at, is_epoch_boundary, EPOCH_BLOCKS, TREASURY_ADDR,
};
use iona::economics::staking::{StakingState, Validator as EconValidator};
use iona::economics::staking_tx::try_apply_staking_tx;
use iona::execution::KvState;
use proptest::prelude::*;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Default stake for test validators.
const DEFAULT_STAKE: u128 = 10_000_000_000;

/// Carol's delegation amount.
const CAROL_DELEGATION: u128 = 2_000_000_000;

/// Dave's delegation amount.
const DAVE_DELEGATION: u128 = 1_000_000_000;

/// Minimum stake for validator registration.
const MIN_STAKE: u64 = 10_000;

/// Initial balance for test accounts.
const INITIAL_BALANCE: u64 = 1_000_000;

/// Amount used in delegate / undelegate / withdraw flow tests.
const DELEGATE_AMOUNT: u64 = 100_000;

/// Unbonding epochs used in the undelegate / withdraw test.
const UNBONDING_EPOCHS: u64 = 3;

/// Epoch at which undelegation is initiated.
const UNDELEGATE_START_EPOCH: u64 = 1;

/// Epoch at which withdrawal must still fail.
const WITHDRAW_FAIL_EPOCH: u64 = 3;

/// Epoch at which withdrawal must succeed.
const WITHDRAW_SUCCESS_EPOCH: u64 = 4;

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Test fixture configuration.
///
/// Only the fields actually consumed by [`TestFixture::new`] are kept;
/// everything else that the original version declared was dead state.
#[derive(Debug, Clone)]
pub struct TestConfig {
    /// Number of `validator_N` accounts to seed with balances.
    pub validators: usize,
    /// Balance assigned to each seeded account.
    pub max_delegation: u64,
}

impl Default for TestConfig {
    fn default() -> Self {
        Self { validators: 5, max_delegation: 1_000_000 }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// The state a test runs against.
///
/// All fields are public so tests can take disjoint borrows
/// (`&mut fixture.kv`, `&mut fixture.staking`, `&fixture.params`) in a
/// single function call. That is the reason there is no
/// `fixture_mut()` accessor — it would force every multi-field caller
/// through a single `&mut self` borrow, which the borrow checker then
/// rejects on the second field.
pub struct TestFixture {
    pub kv:      KvState,
    pub staking: StakingState,
    pub params:  EconomicsParams,
}

impl TestFixture {
    pub fn new(config: TestConfig) -> Self {
        let mut kv = KvState::default();
        for i in 0..config.validators {
            kv.balances.insert(format!("validator_{i}"), config.max_delegation);
        }
        for i in 0..config.validators * 2 {
            kv.balances.insert(format!("delegator_{i}"), config.max_delegation);
        }
        Self {
            kv,
            staking: StakingState::default(),
            params: EconomicsParams::default(),
        }
    }

    /// Register a validator and, if `addr` has a balance entry, deduct
    /// `stake` from it. Addresses without a balance (like `"alice"`) are
    /// left untouched so the test can grant a starting balance
    /// explicitly when it matters.
    pub fn add_validator(&mut self, addr: &str, stake: u64, commission_bps: u64) {
        let validator = EconValidator {
            operator: addr.to_string(),
            stake: stake as u128,
            jailed: false,
            commission_bps,
        };
        self.staking.validators.insert(addr.to_string(), validator);
        if let Some(bal) = self.kv.balances.get_mut(addr) {
            *bal = bal.saturating_sub(stake);
        }
    }

    /// Add a delegation from `delegator` to `validator`, deducting the
    /// amount from the delegator's balance when that balance exists.
    pub fn add_delegation(&mut self, delegator: &str, validator: &str, amount: u64) {
        self.staking
            .delegations
            .insert((delegator.to_string(), validator.to_string()), amount as u128);
        if let Some(bal) = self.kv.balances.get_mut(delegator) {
            *bal = bal.saturating_sub(amount);
        }
    }
}

// ---------------------------------------------------------------------------
// Epoch boundary tests
// ---------------------------------------------------------------------------

#[test]
fn epoch_boundary_is_exact() {
    assert!(!is_epoch_boundary(0));
    assert!(!is_epoch_boundary(1));
    assert!(!is_epoch_boundary(EPOCH_BLOCKS - 1));
    assert!(is_epoch_boundary(EPOCH_BLOCKS));
    assert!(!is_epoch_boundary(EPOCH_BLOCKS + 1));
    assert!(is_epoch_boundary(EPOCH_BLOCKS * 2));
    assert!(is_epoch_boundary(EPOCH_BLOCKS * 100));
}

#[test]
fn epoch_number_mapping_is_consistent() {
    assert_eq!(epoch_at(0), 0);
    assert_eq!(epoch_at(EPOCH_BLOCKS - 1), 0);
    assert_eq!(epoch_at(EPOCH_BLOCKS), 1);
    assert_eq!(epoch_at(EPOCH_BLOCKS * 5), 5);
}

// ---------------------------------------------------------------------------
// Reward distribution invariants
// ---------------------------------------------------------------------------

/// `inflation_minted == treasury_share + sum(validator_rewards)` within
/// integer rounding.
#[test]
fn reward_distribution_is_conservative() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("alice", 1_000_000, 500);
    fixture.add_validator("bob",   1_000_000, 500);

    let reward = distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
    );

    let distributed: u128 = reward
        .validator_rewards
        .values()
        .sum::<u128>()
        .saturating_add(reward.treasury_share);
    let diff = distributed.abs_diff(reward.inflation_minted);

    assert!(
        diff <= 2,
        "distributed ({distributed}) differs from minted ({}) by {diff}",
        reward.inflation_minted,
    );
}

#[test]
fn treasury_grows_monotonically() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("alice", 1_000_000, 500);

    let mut prev = 0u64;
    for e in 1..=5u64 {
        distribute_epoch_rewards(
            e * EPOCH_BLOCKS,
            &mut fixture.kv,
            &mut fixture.staking,
            &fixture.params,
        );
        let treasury = *fixture.kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(treasury > 0, "treasury must be non-zero after epoch {e}");
        assert!(
            treasury >= prev,
            "treasury decreased at epoch {e}: {treasury} < {prev}",
        );
        prev = treasury;
    }
}

#[test]
fn jailed_validator_earns_nothing() {
    let mut fixture = TestFixture::new(TestConfig::default());

    // Alice is pre-jailed; Bob is active.
    fixture.staking.validators.insert(
        "alice".to_string(),
        EconValidator {
            operator: "alice".to_string(),
            stake: DEFAULT_STAKE,
            jailed: true,
            commission_bps: 0,
        },
    );
    fixture.add_validator("bob", 1_000_000, 1000);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
    );

    let alice = *fixture.kv.balances.get("alice").unwrap_or(&0);
    let bob   = *fixture.kv.balances.get("bob").unwrap_or(&0);
    assert_eq!(alice, 0, "jailed validator must earn nothing");
    assert!(bob > 0, "active validator must earn a reward");
}

/// For equal stake and equal delegation, higher commission → higher
/// operator reward.
#[test]
fn higher_commission_yields_higher_operator_reward() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("high_commission", 1_000_000, 5000);
    fixture.add_validator("low_commission",  1_000_000, 100);
    fixture.add_delegation("d1", "high_commission", 500_000);
    fixture.add_delegation("d2", "low_commission",  500_000);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
    );

    let high = *fixture.kv.balances.get("high_commission").unwrap_or(&0);
    let low  = *fixture.kv.balances.get("low_commission").unwrap_or(&0);
    assert!(
        high > low,
        "higher commission ({high}) must out-earn lower commission ({low})",
    );
}

/// Delegator rewards are proportional to the delegated amount.
#[test]
fn delegator_reward_is_proportional() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("alice", DEFAULT_STAKE as u64, 0);
    fixture.add_delegation("carol", "alice", CAROL_DELEGATION as u64);
    fixture.add_delegation("dave",  "alice", DAVE_DELEGATION  as u64);

    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
    );

    let carol = *fixture.kv.balances.get("carol").unwrap_or(&0);
    let dave  = *fixture.kv.balances.get("dave").unwrap_or(&0);
    assert!(carol > 0 && dave > 0, "both delegators must earn");

    let ratio = carol as f64 / dave as f64;
    let expected = CAROL_DELEGATION as f64 / DAVE_DELEGATION as f64;
    assert!(
        (ratio - expected).abs() < 0.3,
        "carol/dave reward ratio: expected ~{expected:.2}, got {ratio:.2}",
    );
}

#[test]
fn validator_stake_auto_compounds() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("alice", 1_000_000, 500);

    let before = fixture.staking.validators["alice"].stake;
    distribute_epoch_rewards(
        EPOCH_BLOCKS,
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
    );
    let after = fixture.staking.validators["alice"].stake;

    assert!(
        after > before,
        "stake must auto-compound: was {before}, now {after}",
    );
}

// ---------------------------------------------------------------------------
// Staking transaction lifecycle
// ---------------------------------------------------------------------------

#[test]
fn delegate_flow() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.add_validator("alice", 1_000_000, 500);
    fixture.kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let result = try_apply_staking_tx(
        "stake delegate alice 200000",
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(result.success, "{:?}", result.error);

    assert_eq!(*fixture.kv.balances.get("bob").unwrap(), 800_000);
    assert_eq!(
        *fixture.staking.delegations.get(&("bob".into(), "alice".into())).unwrap(),
        200_000,
    );
    assert_eq!(fixture.staking.validators["alice"].stake, 1_200_000);
}

#[test]
fn undelegate_then_withdraw_full_flow() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.params = EconomicsParams {
        unbonding_epochs: UNBONDING_EPOCHS,
        ..Default::default()
    };
    fixture.add_validator("alice", 1_000_000, 0);
    fixture.kv.balances.insert("bob".into(), INITIAL_BALANCE);

    // Delegate.
    let r = try_apply_staking_tx(
        &format!("stake delegate alice {DELEGATE_AMOUNT}"),
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(r.success, "{:?}", r.error);
    assert_eq!(*fixture.kv.balances.get("bob").unwrap(), INITIAL_BALANCE - DELEGATE_AMOUNT);

    // Undelegate at epoch 1.
    let r = try_apply_staking_tx(
        &format!("stake undelegate alice {DELEGATE_AMOUNT}"),
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        UNDELEGATE_START_EPOCH,
    )
    .expect("call must return");
    assert!(r.success, "{:?}", r.error);

    // Withdrawal must fail before the unbonding period elapses.
    let r = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        WITHDRAW_FAIL_EPOCH,
    )
    .expect("call must return");
    assert!(!r.success, "withdrawal must be locked during unbonding");

    // Withdrawal succeeds after unbonding.
    let r = try_apply_staking_tx(
        "stake withdraw alice",
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        WITHDRAW_SUCCESS_EPOCH,
    )
    .expect("call must return");
    assert!(r.success, "{:?}", r.error);
    assert_eq!(
        *fixture.kv.balances.get("bob").unwrap(),
        INITIAL_BALANCE,
        "balance restored after withdrawal",
    );
}

#[test]
fn register_then_deregister_validator() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.params = EconomicsParams { min_stake: MIN_STAKE, ..Default::default() };
    fixture.kv.balances.insert("charlie".into(), INITIAL_BALANCE);

    // Register (500 = commission bps; min_stake is deducted).
    let r = try_apply_staking_tx(
        "stake register 500",
        "charlie",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(r.success, "{:?}", r.error);
    assert!(fixture.staking.validators.contains_key("charlie"));
    assert_eq!(fixture.staking.validators["charlie"].commission_bps, 500);
    assert_eq!(*fixture.kv.balances.get("charlie").unwrap(), INITIAL_BALANCE - MIN_STAKE);

    // Deregister (no external delegators).
    let r = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(r.success, "{:?}", r.error);
    assert!(!fixture.staking.validators.contains_key("charlie"));
    assert_eq!(*fixture.kv.balances.get("charlie").unwrap(), INITIAL_BALANCE);
}

#[test]
fn cannot_deregister_with_external_delegators() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.params = EconomicsParams { min_stake: MIN_STAKE, ..Default::default() };

    fixture.kv.balances.insert("charlie".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        "stake register 0",
        "charlie",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("register must return");

    fixture.kv.balances.insert("dave".into(), INITIAL_BALANCE);
    try_apply_staking_tx(
        &format!("stake delegate charlie {DELEGATE_AMOUNT}"),
        "dave",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("delegate must return");

    let r = try_apply_staking_tx(
        "stake deregister",
        "charlie",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(!r.success, "validator with external delegators must not deregister");
}

#[test]
fn cannot_delegate_to_jailed_validator() {
    let mut fixture = TestFixture::new(TestConfig::default());
    fixture.staking.validators.insert(
        "alice".to_string(),
        EconValidator {
            operator: "alice".to_string(),
            stake: 1_000_000,
            jailed: true,
            commission_bps: 0,
        },
    );
    fixture.kv.balances.insert("bob".into(), INITIAL_BALANCE);

    let r = try_apply_staking_tx(
        &format!("stake delegate alice {DELEGATE_AMOUNT}"),
        "bob",
        &mut fixture.kv,
        &mut fixture.staking,
        &fixture.params,
        0,
    )
    .expect("call must return");
    assert!(!r.success, "delegation to jailed validator must fail");
}

// ---------------------------------------------------------------------------
// Property test
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn reward_distribution_property(
        stake1 in 1_000u64..1_000_000,
        stake2 in 1_000u64..1_000_000,
        commission1 in 0u64..10_000,
        commission2 in 0u64..10_000,
    ) {
        let mut fixture = TestFixture::new(TestConfig::default());
        fixture.add_validator("v1", stake1, commission1);
        fixture.add_validator("v2", stake2, commission2);

        let reward = distribute_epoch_rewards(
            EPOCH_BLOCKS,
            &mut fixture.kv,
            &mut fixture.staking,
            &fixture.params,
        );

        let distributed: u128 = reward
            .validator_rewards
            .values()
            .sum::<u128>()
            .saturating_add(reward.treasury_share);
        let diff = distributed.abs_diff(reward.inflation_minted);
        prop_assert!(diff <= 2, "distribution invariant violated: diff={diff}");
    }
}

// ---------------------------------------------------------------------------
// Performance regression
// ---------------------------------------------------------------------------

#[test]
fn reward_distribution_performance() {
    const N_VALIDATORS: usize = 50;
    const N_EPOCHS: u64 = 100;

    let mut fixture = TestFixture::new(TestConfig {
        validators: N_VALIDATORS,
        ..Default::default()
    });
    for i in 0..N_VALIDATORS {
        fixture.add_validator(&format!("v{i}"), 1_000_000, (i as u64) % 10_000);
    }

    let start = std::time::Instant::now();
    for e in 1..=N_EPOCHS {
        distribute_epoch_rewards(
            e * EPOCH_BLOCKS,
            &mut fixture.kv,
            &mut fixture.staking,
            &fixture.params,
        );
    }
    let elapsed = start.elapsed();

    // Generous bound so the test does not flake on a loaded CI runner;
    // catches gross regressions, not micro-optimisations.
    assert!(
        elapsed < Duration::from_secs(10),
        "{N_EPOCHS} epochs × {N_VALIDATORS} validators took {elapsed:?}, expected < 10s",
    );
}
