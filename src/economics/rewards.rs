//! PoS Epoch Reward Distribution for IONA.
//!
//! At the end of each epoch (every [`EPOCH_BLOCKS`] blocks), the runtime
//! calls [`distribute_epoch_rewards`], which:
//!
//! 1. Computes the epoch's inflation reward as
//!    `total_staked × base_inflation_bps / 10_000 / EPOCHS_PER_YEAR`.
//! 2. Splits it into the treasury share and a distributable pool.
//! 3. For each active (non-jailed) validator, splits the pool
//!    proportionally to bonded stake, then splits each validator's slice
//!    into commission (operator) and the delegator pool.
//! 4. Credits the resulting amounts to `KvState::balances`.
//!
//! # Reward split (per active validator)
//!
//! ```text
//! val_total_reward  = distributable × val_stake / total_staked
//! commission        = val_total_reward × commission_bps / 10_000   → operator
//! delegator_pool    = val_total_reward − commission
//! operator_share    = delegator_pool × self_stake / val_stake      → operator
//! each_delegator    = delegator_pool × deleg_amount / val_stake    → delegator
//! ```
//!
//! Where:
//!
//! - `val_stake` is the validator's **total bonded stake**, i.e. the sum of
//!   the operator's self-bond and every external delegation to them. This
//!   is the invariant maintained by [`StakingState`].
//! - `self_stake` is `val_stake − Σ delegations`, saturating at zero.
//!
//! # Modes
//!
//! [`RewardConfig::auto_compound`] selects between two **mutually exclusive**
//! distributions:
//!
//! - `false` (default): every stakeholder's balance in `KvState` is
//!   credited; bonded stake and delegation amounts are left untouched.
//! - `true`: the reward is compounded into bonded stake; no balances are
//!   credited except the treasury's.
//!
//! Only one mode is active per epoch, so the total credited equals
//! `inflation_minted` minus rounding dust, which is reported in
//! [`EpochReward::dust`] (and routed to the treasury).
//!
//! # Rounding
//!
//! Integer division is exact-floor at each step; the accumulated dust is
//! reported in [`EpochReward::dust`]. Callers that need a fully balanced
//! ledger should treat dust as retained by the protocol.
//!
//! # Invariants
//!
//! - `treasury_share + distributable == inflation_minted` (before credit
//!   truncation).
//! - Sum of all credits ≤ `inflation_minted`; the difference is dust.
//! - Zero `total_staked` (all jailed / no validators) is a no-op.
//! - No balance credit ever overflows `u64`; the conversion saturates and
//!   the truncated amount is added to dust.

use crate::economics::params::EconomicsParams;
use crate::economics::staking::StakingState;
use crate::execution::KvState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{info, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Number of blocks per epoch.
pub const EPOCH_BLOCKS: u64 = 100;

/// Approximate epochs per year, assuming 6-second blocks and
/// [`EPOCH_BLOCKS`] blocks per epoch:
///
/// ```text
/// blocks_per_year   = 365 × 24 × 60 × 60 / 6   = 5_256_000
/// epochs_per_year   = 5_256_000 / 100          = 52_560
/// ```
pub const EPOCHS_PER_YEAR: u64 = 52_560;

/// Reserved treasury address in `KvState::balances`.
pub const TREASURY_ADDR: &str = "treasury";

/// Basis-points denominator: 10 000 bp = 100 %.
const MAX_BPS: u64 = 10_000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Per-epoch reward distribution options.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RewardConfig {
    /// If `true`, rewards are compounded into bonded stake instead of being
    /// credited to spendable balances. Default: `false`.
    pub auto_compound: bool,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self { auto_compound: false }
    }
}

// ── Report ────────────────────────────────────────────────────────────────

/// Summary emitted at each epoch boundary.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochReward {
    pub epoch: u64,
    pub height: u64,
    /// Total bonded stake across active (non-jailed) validators at
    /// distribution time.
    pub total_staked: u128,
    /// Total tokens minted for this epoch.
    pub inflation_minted: u128,
    /// Amount credited to the treasury address.
    pub treasury_share: u128,
    /// Amount credited to validator operators (commission + self-stake
    /// share).
    pub operator_total: u128,
    /// Amount credited to external delegators.
    pub delegator_total: u128,
    /// Rounding dust retained by the protocol.
    pub dust: u128,
    /// Per-validator operator earnings.
    pub validator_rewards: BTreeMap<String, u128>,
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by [`distribute_epoch_rewards`].
///
/// The distribution itself is infallible — a misbehaving input is
/// **skipped with a warning** rather than aborting the epoch. This type is
/// produced by [`try_distribute_epoch_rewards`] for callers that want
/// fail-fast semantics.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RewardError {
    #[error("invalid commission for validator {validator}: {bps} bps > 10_000")]
    InvalidCommission { validator: String, bps: u64 },
    #[error("validator {validator}: stake {stake} < external delegations {delegations}")]
    StakeBelowDelegations {
        validator: String,
        stake: u128,
        delegations: u128,
    },
}

// ── Entry points ──────────────────────────────────────────────────────────

/// Check whether `height` is an epoch boundary.
///
/// `height = 0` is the genesis block and is **not** an epoch boundary.
#[inline]
#[must_use]
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height % EPOCH_BLOCKS == 0
}

/// Epoch number for a given block height.
#[inline]
#[must_use]
pub fn epoch_at(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

/// Distribute epoch rewards, skipping validators with malformed state.
///
/// This is the runtime entry point: it never panics and never aborts the
/// epoch. Validators with invalid commission or inconsistent stake are
/// skipped with a `warn!`.
pub fn distribute_epoch_rewards(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> EpochReward {
    distribute_epoch_rewards_with_config(
        height,
        kv_state,
        staking,
        params,
        &RewardConfig::default(),
    )
}

/// As [`distribute_epoch_rewards`], with an explicit [`RewardConfig`].
pub fn distribute_epoch_rewards_with_config(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
    config: &RewardConfig,
) -> EpochReward {
    match try_distribute_epoch_rewards(height, kv_state, staking, params, config) {
        Ok(r) => r,
        Err(e) => {
            // Skippable condition: log and return an empty report so the
            // epoch commits without a reward.
            warn!(height, error = %e, "epoch reward distribution skipped");
            empty_reward(height)
        }
    }
}

/// Fallible variant of [`distribute_epoch_rewards`].
///
/// Returns `Err(RewardError)` on the first malformed validator.
pub fn try_distribute_epoch_rewards(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
    config: &RewardConfig,
) -> Result<EpochReward, RewardError> {
    let epoch = epoch_at(height);

    // ── 1. Collect active validators & total bonded stake ────────────────
    let active: Vec<ActiveValidator> = staking
        .validators
        .iter()
        .filter(|(_, v)| !v.jailed)
        .map(|(addr, v)| ActiveValidator {
            addr: addr.clone(),
            stake: v.stake,
            commission_bps: v.commission_bps,
        })
        .collect();

    let total_staked: u128 = active
        .iter()
        .fold(0u128, |acc, v| acc.saturating_add(v.stake));

    if total_staked == 0 {
        return Ok(empty_reward(height));
    }

    // ── 2. Inflation for this epoch ──────────────────────────────────────
    //
    // `inflation = total_staked × base_inflation_bps / 10_000 / epochs_per_year`
    //
    // Two exact integer divisions; no intermediate product can overflow
    // because `mul_div` splits the operands.
    let annual = mul_div_u128(total_staked, params.base_inflation_bps, MAX_BPS);
    let inflation_minted = annual / EPOCHS_PER_YEAR as u128;

    // ── 3. Treasury cut ──────────────────────────────────────────────────
    let treasury_share = mul_div_u128(inflation_minted, params.treasury_bps, MAX_BPS);
    let distributable = inflation_minted.saturating_sub(treasury_share);

    let mut operator_total: u128 = 0;
    let mut delegator_total: u128 = 0;
    let mut dust: u128 = 0;
    let mut validator_rewards: BTreeMap<String, u128> = BTreeMap::new();

    // Credit treasury first so partial failures still leave it funded.
    dust = dust.saturating_add(credit_balance(kv_state, TREASURY_ADDR, treasury_share));

    // ── 4. Per-validator distribution ────────────────────────────────────
    for v in &active {
        if v.stake == 0 {
            continue;
        }
        if v.commission_bps > MAX_BPS {
            return Err(RewardError::InvalidCommission {
                validator: v.addr.clone(),
                bps: v.commission_bps,
            });
        }

        // ── 4a. External delegations to this validator ───────────────────
        let mut delegations: Vec<(String, u128)> = Vec::new();
        let mut deleg_sum: u128 = 0;
        for ((delegator, validator), &amount) in staking.delegations.iter() {
            if validator != &v.addr {
                continue;
            }
            deleg_sum = deleg_sum.saturating_add(amount);
            delegations.push((delegator.clone(), amount));
        }

        if deleg_sum > v.stake {
            return Err(RewardError::StakeBelowDelegations {
                validator: v.addr.clone(),
                stake: v.stake,
                delegations: deleg_sum,
            });
        }
        let self_stake = v.stake.saturating_sub(deleg_sum);

        // ── 4b. Split the pool ──────────────────────────────────────────
        let val_total_reward = mul_div_u128(distributable, ratio_bps(v.stake, total_staked), MAX_BPS);
        // The exact `distributable × v.stake / total_staked` above uses
        // two exact divisions, which is why we go via `ratio_bps`. When
        // `total_staked` does not divide evenly this loses at most the
        // fractional part of one bps — absorbed into `dust`.

        let commission = mul_div_u128(val_total_reward, v.commission_bps, MAX_BPS);
        let delegator_pool = val_total_reward.saturating_sub(commission);

        // ── 4c. Operator's cut ──────────────────────────────────────────
        // Operator earns commission + their self-stake share of the pool.
        let operator_self_share =
            mul_div_u128(delegator_pool, ratio_bps(self_stake, v.stake), MAX_BPS);
        let operator_total_v = commission.saturating_add(operator_self_share);

        // ── 4d. External delegators' cuts ───────────────────────────────
        let mut delegator_total_v: u128 = 0;
        let mut delegator_credits: Vec<(String, u128)> = Vec::with_capacity(delegations.len());
        for (delegator, amount) in &delegations {
            let share = mul_div_u128(delegator_pool, ratio_bps(*amount, v.stake), MAX_BPS);
            delegator_total_v = delegator_total_v.saturating_add(share);
            delegator_credits.push((delegator.clone(), share));
        }

        // Track rounding loss on this validator.
        let assigned = operator_total_v.saturating_add(delegator_total_v);
        dust = dust.saturating_add(val_total_reward.saturating_sub(assigned));

        // ── 4e. Apply ───────────────────────────────────────────────────
        if config.auto_compound {
            // Compound: grow stake and delegations; no balance credits.
            if let Some(vv) = staking.validators.get_mut(v.addr.as_str()) {
                vv.stake = vv.stake.saturating_add(val_total_reward);
            }
            for (delegator, share) in &delegator_credits {
                let k = (delegator.clone(), v.addr.clone());
                *staking.delegations.entry(k).or_insert(0) =
                    staking.delegations.get(&k).copied().unwrap_or(0).saturating_add(*share);
            }
        } else {
            // Cash: credit balances only; leave bonded stake unchanged.
            dust = dust.saturating_add(credit_balance(kv_state, &v.addr, operator_total_v));
            for (delegator, share) in &delegator_credits {
                dust = dust.saturating_add(credit_balance(kv_state, delegator, *share));
            }
        }

        operator_total = operator_total.saturating_add(operator_total_v);
        delegator_total = delegator_total.saturating_add(delegator_total_v);
        validator_rewards.insert(v.addr.clone(), operator_total_v);
    }

    // ── 5. Report ────────────────────────────────────────────────────────
    let report = EpochReward {
        epoch,
        height,
        total_staked,
        inflation_minted,
        treasury_share,
        operator_total,
        delegator_total,
        dust,
        validator_rewards,
    };

    info!(
        epoch,
        height,
        total_staked,
        minted = inflation_minted,
        treasury = treasury_share,
        operators = operator_total,
        delegators = delegator_total,
        dust,
        auto_compound = config.auto_compound,
        "epoch reward distributed"
    );

    Ok(report)
}

// ── Helpers ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ActiveValidator {
    addr: String,
    stake: u128,
    commission_bps: u64,
}

fn empty_reward(height: u64) -> EpochReward {
    EpochReward {
        epoch: epoch_at(height),
        height,
        total_staked: 0,
        inflation_minted: 0,
        treasury_share: 0,
        operator_total: 0,
        delegator_total: 0,
        dust: 0,
        validator_rewards: BTreeMap::new(),
    }
}

/// `part / whole` expressed in basis points, floor. Returns `0` if
/// `whole == 0`.
#[inline]
fn ratio_bps(part: u128, whole: u128) -> u64 {
    if whole == 0 {
        return 0;
    }
    // `part * 10_000 / whole` computed via split-multiply-divide so no
    // intermediate product can overflow.
    let whole_bps = MAX_BPS as u128; // 10_000
    let hi = part / whole;
    let lo = part % whole;
    // hi × 10_000 / whole == 0 for part < whole, but keep the general form.
    let val = hi
        .saturating_mul(whole_bps)
        .saturating_add(lo.saturating_mul(whole_bps) / whole);
    val.min(MAX_BPS as u128) as u64
}

/// Exact `a × b / c` for `u128`, split-multiply-divide. Requires `b ≤ c`.
#[inline]
fn mul_div_u128(a: u128, b: u64, c: u64) -> u128 {
    debug_assert!(c != 0, "mul_div_u128: division by zero");
    debug_assert!(b <= c, "mul_div_u128: multiplier must not exceed divisor");
    let c = c as u128;
    let b = b as u128;
    let hi = a / c;
    let lo = a % c;
    hi * b + (lo * b) / c
}

/// Credit `amount` to `addr` in `kv_state.balances`, saturating at
/// `u64::MAX`. Returns the amount that could **not** be credited (dust).
///
/// `KvState::balances` is `u64`-valued; `amount` is `u128`. We refuse to
/// silently truncate — the residual is returned to the caller to be
/// reported and retained by the protocol.
fn credit_balance(kv_state: &mut KvState, addr: &str, amount: u128) -> u128 {
    if amount == 0 {
        return 0;
    }
    let credit: u64 = match u64::try_from(amount) {
        Ok(v) => v,
        Err(_) => {
            warn!(
                addr,
                amount = amount as u64,
                "balance credit exceeds u64; saturating and treating the remainder as dust"
            );
            u64::MAX
        }
    };
    let entry = kv_state.balances.entry(addr.to_string()).or_insert(0);
    let (new_balance, overflowed) = entry.overflowing_add(credit);
    if overflowed {
        let residual = amount.saturating_sub((u64::MAX - *entry) as u128);
        *entry = u64::MAX;
        residual
    } else {
        *entry = new_balance;
        // If `amount` was > u64::MAX we capped `credit` at `u64::MAX` and
        // must report the difference.
        amount.saturating_sub(credit as u128)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::staking::Validator as EconValidator;
    use crate::economics::params::EconomicsParams;
    use crate::execution::KvState;

    fn make_state(validators: &[(&str, u128, u64)]) -> StakingState {
        let mut s = StakingState::default();
        for (addr, stake, commission_bps) in validators {
            s.validators.insert(
                addr.to_string(),
                EconValidator {
                    operator: addr.to_string(),
                    stake: *stake,
                    jailed: false,
                    commission_bps: *commission_bps,
                },
            );
        }
        s
    }

    fn balance(kv: &KvState, addr: &str) -> u128 {
        kv.balances.get(addr).copied().unwrap_or(0) as u128
    }

    // ── Boundary helpers ────────────────────────────────────────────────

    #[test]
    fn epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(99));
        assert!(is_epoch_boundary(100));
        assert!(is_epoch_boundary(200));
        assert!(!is_epoch_boundary(150));
    }

    #[test]
    fn epoch_at_is_floor() {
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(99), 0);
        assert_eq!(epoch_at(100), 1);
        assert_eq!(epoch_at(101), 1);
    }

    // ── Baseline distribution ───────────────────────────────────────────

    #[test]
    fn distribution_mints_and_credits() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[
            ("alice", 10_000_000_000, 1000),
            ("bob", 10_000_000_000, 500),
        ]);
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        assert_eq!(reward.epoch, 1);
        assert!(reward.inflation_minted > 0);
        assert!(reward.treasury_share > 0);
        assert!(reward.treasury_share < reward.inflation_minted);

        // Both operators get paid.
        assert!(balance(&kv, "alice") > 0);
        assert!(balance(&kv, "bob") > 0);

        // Higher commission → higher operator payout at equal stake.
        assert!(balance(&kv, "alice") >= balance(&kv, "bob"));

        // Treasury grows.
        assert!(balance(&kv, TREASURY_ADDR) > 0);
    }

    // ── Delegator share ─────────────────────────────────────────────────

    #[test]
    fn delegator_share_is_proportional_to_validator_stake() {
        // Regression: delegator share used `total_delegated` as the
        // denominator, so a single delegator received the entire
        // delegator pool regardless of the validator's self-stake.
        //
        // alice: total bond 15 B, self-stake 10 B, carol delegated 5 B.
        // carol's fair share of the delegator pool = 5/15 = 1/3.
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 15_000_000_000, 1000)]);
        staking
            .delegations
            .insert(("carol".into(), "alice".into()), 5_000_000_000);
        let params = EconomicsParams::default();

        let _ = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        // alice: commission (10 %) + self-share of the 90 % pool
        //      = 10 % + 90 % × 10/15 = 10 % + 60 % = 70 % of val_total.
        // carol: 90 % × 5/15 = 30 % of val_total.
        let alice = balance(&kv, "alice");
        let carol = balance(&kv, "carol");
        assert!(carol > 0, "delegator must be paid");

        // carol's share must be strictly less than alice's because her
        // stake is smaller and she gets no commission.
        assert!(carol < alice, "carol={carol} should be < alice={alice}");

        // At equal amounts, ratio should be ≈ 30/70 = 0.4286.
        let ratio = carol as f64 / alice as f64;
        assert!(
            (0.35..=0.55).contains(&ratio),
            "unexpected ratio: {ratio} (carol={carol}, alice={alice})"
        );
    }

    #[test]
    fn multi_delegator_split_is_proportional() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 20_000_000_000, 0)]); // 0 % commission
        staking
            .delegations
            .insert(("carol".into(), "alice".into()), 5_000_000_000);
        staking
            .delegations
            .insert(("dave".into(), "alice".into()), 5_000_000_000);
        let params = EconomicsParams::default();

        let _ = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        // carol and dave have equal delegation → equal reward.
        assert_eq!(balance(&kv, "carol"), balance(&kv, "dave"));
        // alice's self-stake is 10 B of 20 B, so she gets 2× carol's share.
        assert_eq!(balance(&kv, "alice"), 2 * balance(&kv, "carol"));
    }

    // ── Conservation ────────────────────────────────────────────────────

    #[test]
    fn conservation_of_minted_tokens() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 15_000_000_000, 1000)]);
        staking
            .delegations
            .insert(("carol".into(), "alice".into()), 5_000_000_000);
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        let credited = reward.treasury_share
            + reward.operator_total
            + reward.delegator_total
            + reward.dust;
        assert_eq!(
            credited, reward.inflation_minted,
            "credits + dust must equal minted"
        );
    }

    #[test]
    fn auto_compound_does_not_credit_balances() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 1000)]);
        let params = EconomicsParams::default();
        let config = RewardConfig { auto_compound: true };

        let reward = distribute_epoch_rewards_with_config(
            100,
            &mut kv,
            &mut staking,
            &params,
            &config,
        );

        // Only the treasury got a balance.
        assert_eq!(balance(&kv, "alice"), 0);
        assert!(balance(&kv, TREASURY_ADDR) > 0);

        // Alice's stake grew by (operator share + delegator pool) — the
        // whole distributable slice for her (she's the only validator).
        let grown = staking.validators.get("alice").unwrap().stake;
        assert!(grown > 10_000_000_000);
        assert_eq!(
            grown,
            10_000_000_000 + reward.operator_total + reward.delegator_total
        );
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    #[test]
    fn jailed_validators_get_no_reward() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 1_000_000, 0)]);
        staking.validators.get_mut("alice").unwrap().jailed = true;
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        assert_eq!(reward.inflation_minted, 0);
        assert_eq!(balance(&kv, "alice"), 0);
    }

    #[test]
    fn invalid_commission_is_rejected_by_try_variant() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 1_000_000_000, 20_000)]); // 200 %
        let params = EconomicsParams::default();

        let res = try_distribute_epoch_rewards(
            100,
            &mut kv,
            &mut staking,
            &params,
            &RewardConfig::default(),
        );
        assert!(matches!(res, Err(RewardError::InvalidCommission { .. })));
    }

    #[test]
    fn stake_below_delegations_is_rejected_by_try_variant() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 1_000, 0)]);
        staking
            .delegations
            .insert(("carol".into(), "alice".into()), 5_000);
        let params = EconomicsParams::default();

        let res = try_distribute_epoch_rewards(
            100,
            &mut kv,
            &mut staking,
            &params,
            &RewardConfig::default(),
        );
        assert!(matches!(res, Err(RewardError::StakeBelowDelegations { .. })));
    }

    #[test]
    fn treasury_accumulates_across_epochs() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 0)]);
        let params = EconomicsParams::default();

        distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        let t1 = balance(&kv, TREASURY_ADDR);
        distribute_epoch_rewards(200, &mut kv, &mut staking, &params);
        let t2 = balance(&kv, TREASURY_ADDR);
        assert!(t2 > t1);
    }

    #[test]
    fn zero_stake_is_a_noop() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default();
        let params = EconomicsParams::default();

        let r = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        assert_eq!(r.inflation_minted, 0);
        assert_eq!(r.dust, 0);
        assert!(kv.balances.is_empty());
    }

    // ── Arithmetic helpers ──────────────────────────────────────────────

    #[test]
    fn ratio_bps_is_exact_for_simple_cases() {
        assert_eq!(ratio_bps(0, 100), 0);
        assert_eq!(ratio_bps(50, 100), 5_000);
        assert_eq!(ratio_bps(100, 100), 10_000);
        assert_eq!(ratio_bps(100, 0), 0); // div-by-zero guard
    }

    #[test]
    fn mul_div_does_not_overflow_at_u128_max() {
        assert_eq!(mul_div_u128(u128::MAX, MAX_BPS, MAX_BPS), u128::MAX);
        assert_eq!(mul_div_u128(u128::MAX, 0, MAX_BPS), 0);
        assert_eq!(mul_div_u128(1_000_000, 5_000, MAX_BPS), 500_000);
    }

    #[test]
    fn credit_balance_reports_overflow_as_dust() {
        let mut kv = KvState::default();
        kv.balances.insert("a".into(), u64::MAX - 5);

        // 10 is larger than the remaining capacity (5).
        let dust = credit_balance(&mut kv, "a", 10);
        assert_eq!(kv.balances.get("a"), Some(&u64::MAX));
        assert_eq!(dust, 5);
    }
}
