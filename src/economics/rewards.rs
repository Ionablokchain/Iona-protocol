//! PoS Epoch Reward Distribution for IONA.
//!
//! At the end of each epoch (every EPOCH_BLOCKS blocks), this module:
//!   1. Computes the inflation reward for the epoch
//!   2. Splits it: validator commission + delegator share + treasury
//!   3. Applies block fee revenue similarly (tip already goes to proposer;
//!      this distributes the remaining protocol share)
//!   4. Updates StakingState balances in KvState
//!
//! Epoch = 100 blocks by default (configurable via EconomicsParams).
//!
//! Reward formula per epoch:
//!   epoch_inflation = total_staked * base_inflation_bps / 10_000 / epochs_per_year
//!   epochs_per_year ≈ 365 * 24 * 60 * 60 / (block_time_s * EPOCH_BLOCKS)
//!
//! For simplicity we use a fixed epochs_per_year = 87_600
//! (365 days * 24h * 60min * 60s / 6s block time / 100 blocks per epoch).

use crate::economics::params::EconomicsParams;
use crate::economics::staking::StakingState;
use crate::execution::KvState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use tracing::info;

/// Number of blocks per epoch. Rewards are distributed at epoch boundaries.
pub const EPOCH_BLOCKS: u64 = 100;

/// Approximate number of epochs per year (for inflation rate calculation).
/// Assumes 6-second block time and 100 blocks/epoch:
///   365 * 24 * 3600 / 6 / 100 = 52_560
pub const EPOCHS_PER_YEAR: u64 = 52_560;

/// Reserved treasury address in KvState balances.
pub const TREASURY_ADDR: &str = "treasury";

/// Epoch reward summary emitted on each epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochReward {
    pub epoch:             u64,
    pub height:            u64,
    pub total_staked:      u128,
    pub inflation_minted:  u128,
    pub treasury_share:    u128,
    pub validator_rewards: BTreeMap<String, u128>, // validator_addr -> reward
}

/// Check whether `height` is an epoch boundary.
#[inline]
pub fn is_epoch_boundary(height: u64) -> bool {
    height > 0 && height % EPOCH_BLOCKS == 0
}

/// Current epoch number for a given block height.
#[inline]
pub fn epoch_at(height: u64) -> u64 {
    height / EPOCH_BLOCKS
}

/// Distribute epoch rewards.
///
/// Returns an `EpochReward` summary and mutates:
/// - `kv_state.balances` — validator and delegator balances increased
/// - `staking.validators` — stakes increased proportionally (auto-compounding)
///
/// Called from `after_commit` when `is_epoch_boundary(height)`.
pub fn distribute_epoch_rewards(
    height:      u64,
    kv_state:    &mut KvState,
    staking:     &mut StakingState,
    params:      &EconomicsParams,
) -> EpochReward {
    let epoch = epoch_at(height);

    // ── 1. Compute total staked across all active (non-jailed) validators ──
    let total_staked: u128 = staking.validators.values()
        .filter(|v| !v.jailed)
        .map(|v| v.stake)
        .sum();

    if total_staked == 0 {
        return EpochReward {
            epoch,
            height,
            total_staked: 0,
            inflation_minted: 0,
            treasury_share: 0,
            validator_rewards: BTreeMap::new(),
        };
    }

    // ── 2. Inflation reward for this epoch ──────────────────────────────────
    // epoch_inflation = total_staked * base_inflation_bps / 10_000 / epochs_per_year
    let inflation_minted: u128 = total_staked
        .saturating_mul(params.base_inflation_bps as u128)
        / 10_000
        / EPOCHS_PER_YEAR as u128;

    // ── 3. Treasury cut ─────────────────────────────────────────────────────
    let treasury_share: u128 = inflation_minted
        .saturating_mul(params.treasury_bps as u128)
        / 10_000;
    let distributable: u128 = inflation_minted.saturating_sub(treasury_share);

    // Credit treasury balance
    let tb = kv_state.balances.entry(TREASURY_ADDR.to_string()).or_insert(0);
    *tb = tb.saturating_add(treasury_share as u64);

    // ── 4. Per-validator distribution ────────────────────────────────────────
    // Each active validator earns: distributable * validator_stake / total_staked
    // Of that, commission_bps goes to the validator operator.
    // The rest goes to delegators proportionally to their delegated share.

    let mut validator_rewards: BTreeMap<String, u128> = BTreeMap::new();

    let active_validators: Vec<(String, u128, u64)> = staking.validators.iter()
        .filter(|(_, v)| !v.jailed)
        .map(|(addr, v)| (addr.clone(), v.stake, v.commission_bps))
        .collect();

    for (val_addr, val_stake, commission_bps) in &active_validators {
        if *val_stake == 0 { continue; }

        // Validator's share of the distributable pool
        let val_total_reward: u128 = distributable
            .saturating_mul(*val_stake)
            / total_staked;

        // Commission to operator
        let commission: u128 = val_total_reward
            .saturating_mul(*commission_bps as u128)
            / 10_000;
        let delegator_pool: u128 = val_total_reward.saturating_sub(commission);

        // Credit commission to validator operator balance
        let op_bal = kv_state.balances.entry(val_addr.clone()).or_insert(0);
        *op_bal = op_bal.saturating_add(commission as u64);

        // Auto-compound: add validator's earned commission back to their stake
        if let Some(v) = staking.validators.get_mut(val_addr.as_str()) {
            v.stake = v.stake.saturating_add(commission);
        }

        // Distribute delegator_pool to delegators proportionally
        let delegations_for_val: Vec<(String, u128)> = staking.delegations.iter()
            .filter(|((_, v), _)| v == val_addr)
            .map(|((d, _), &amt)| (d.clone(), amt))
            .collect();

        let total_delegated: u128 = delegations_for_val.iter().map(|(_, a)| *a).sum();

        if total_delegated > 0 {
            for (delegator, del_amount) in &delegations_for_val {
                let del_reward: u128 = delegator_pool
                    .saturating_mul(*del_amount)
                    / total_delegated;

                // Credit delegator's balance
                let db = kv_state.balances.entry(delegator.clone()).or_insert(0);
                *db = db.saturating_add(del_reward as u64);

                // Auto-compound: add reward back to delegation stake
                let k = (delegator.clone(), val_addr.clone());
                *staking.delegations.entry(k).or_insert(0) += del_reward;
            }
        }

        // Also credit the validator's self-stake (as if they delegated to themselves)
        let self_reward = val_total_reward;  // total already tracked; commission already credited
        validator_rewards.insert(val_addr.clone(), self_reward);

        // Grow total stake for the validator (including delegations)
        if let Some(v) = staking.validators.get_mut(val_addr.as_str()) {
            v.stake = v.stake.saturating_add(delegator_pool);
        }
    }

    info!(
        epoch,
        height,
        total_staked = total_staked,
        minted = inflation_minted,
        treasury = treasury_share,
        "epoch reward distributed"
    );

    EpochReward {
        epoch,
        height,
        total_staked,
        inflation_minted,
        treasury_share,
        validator_rewards,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::staking::{StakingState, Validator as EconValidator};
    use crate::execution::KvState;
    use crate::economics::params::EconomicsParams;

    fn make_state(validators: &[(&str, u128, u64)]) -> StakingState {
        let mut s = StakingState::default();
        for (addr, stake, commission_bps) in validators {
            s.validators.insert(addr.to_string(), EconValidator {
                operator: addr.to_string(),
                stake: *stake,
                jailed: false,
                commission_bps: *commission_bps,
            });
        }
        s
    }

    #[test]
    fn test_epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(99));
        assert!(is_epoch_boundary(100));
        assert!(is_epoch_boundary(200));
        assert!(!is_epoch_boundary(150));
    }

    #[test]
    fn test_reward_distribution_basic() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[
            ("alice", 10_000_000_000, 1000), // 10% commission
            ("bob",   10_000_000_000, 500),  // 5% commission
        ]);
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        assert_eq!(reward.epoch, 1);
        assert!(reward.inflation_minted > 0, "Should mint inflation");
        assert!(reward.treasury_share > 0, "Treasury should receive share");
        assert!(reward.treasury_share < reward.inflation_minted, "Treasury < total");

        // Validator balances should have increased
        let alice_bal = *kv.balances.get("alice").unwrap_or(&0);
        let bob_bal = *kv.balances.get("bob").unwrap_or(&0);
        assert!(alice_bal > 0, "Alice should receive commission");
        assert!(bob_bal > 0, "Bob should receive commission");

        // Alice has higher commission so should have higher operator reward
        assert!(alice_bal >= bob_bal, "Higher commission = more operator reward");
    }

    #[test]
    fn test_reward_with_delegators() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 1000)]);
        // carol delegates to alice
        staking.delegations.insert(("carol".to_string(), "alice".to_string()), 5_000_000_000);
        let params = EconomicsParams::default();

        let _reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        let carol_bal = *kv.balances.get("carol").unwrap_or(&0);
        assert!(carol_bal > 0, "Delegator carol should receive reward");
    }

    #[test]
    fn test_jailed_validator_gets_no_reward() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 1_000_000, 0)]);
        staking.validators.get_mut("alice").unwrap().jailed = true;
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);

        assert_eq!(reward.inflation_minted, 0, "Jailed-only set: no inflation");
        assert!(kv.balances.get("alice").unwrap_or(&0) == &0, "Jailed validator gets no reward");
    }

    #[test]
    fn test_treasury_accumulates() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 0)]);
        let params = EconomicsParams::default();

        distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        let t1 = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        distribute_epoch_rewards(200, &mut kv, &mut staking, &params);
        let t2 = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);

        assert!(t2 > t1, "Treasury should grow each epoch");
    }
}
