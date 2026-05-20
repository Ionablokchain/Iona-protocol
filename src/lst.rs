//! IONA — Liquid Staking Tokens (stIONA).
//!
//! Allows stakers to maintain liquidity while earning staking rewards.
//! 1 stIONA = proportional claim on the staking pool (price appreciation model).
//!
//! # How it works
//!
//! - User stakes N IONA → receives N * exchange_rate stIONA
//! - Exchange rate increases as rewards accumulate
//! - User holds stIONA freely (transferable, DeFi-composable)
//! - To unstake: burn stIONA → receive IONA + accumulated rewards
//! - Unbonding period applies (v35: 7 days)

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// stIONA token symbol.
pub const STIONA_SYMBOL: &str = "stIONA";
/// Precision: stIONA uses 18 decimal places.
pub const STIONA_DECIMALS: u8 = 18;
/// Minimum stake to receive stIONA (prevents dust attacks).
pub const MIN_STAKE: u64 = 1_000;

/// The liquid staking pool state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstPool {
    /// Total IONA staked (including pending rewards).
    pub total_staked:   u64,
    /// Total stIONA in circulation.
    pub total_shares:   u128,
    /// Epoch when rewards were last distributed.
    pub last_reward_epoch: u64,
    /// Per-address stIONA balances.
    pub balances: BTreeMap<String, u128>,
    /// Pending withdrawals: (address, iona_amount, completion_height)
    pub pending_withdrawals: Vec<(String, u64, u64)>,
}

impl Default for LstPool {
    fn default() -> Self {
        Self {
            total_staked:        0,
            total_shares:        0,
            last_reward_epoch:   0,
            balances:            BTreeMap::new(),
            pending_withdrawals: Vec::new(),
        }
    }
}

impl LstPool {
    /// Current exchange rate: IONA per stIONA (in units of 1e18).
    /// Starts at 1.0 and increases as rewards accumulate.
    pub fn exchange_rate(&self) -> u128 {
        if self.total_shares == 0 || self.total_staked == 0 {
            return 1_000_000_000_000_000_000; // 1.0 * 1e18
        }
        // rate = total_staked * 1e18 / total_shares
        (self.total_staked as u128)
            .saturating_mul(1_000_000_000_000_000_000)
            / self.total_shares
    }

    /// Stake IONA → receive stIONA.
    /// Returns the amount of stIONA minted.
    pub fn stake(&mut self, staker: &str, iona_amount: u64) -> Result<u128, LstError> {
        if iona_amount < MIN_STAKE {
            return Err(LstError::AmountTooSmall { min: MIN_STAKE, got: iona_amount });
        }

        let rate = self.exchange_rate();
        // shares = iona_amount * 1e18 / rate
        let shares = (iona_amount as u128)
            .saturating_mul(1_000_000_000_000_000_000)
            / rate;

        if shares == 0 {
            return Err(LstError::ZeroShares);
        }

        self.total_staked  += iona_amount;
        self.total_shares  += shares;
        *self.balances.entry(staker.to_string()).or_insert(0) += shares;

        tracing::info!(
            staker  = %staker,
            iona    = iona_amount,
            stiona  = shares,
            rate    = rate,
            "LST: staked"
        );
        Ok(shares)
    }

    /// Request unstake: burn stIONA → queue IONA withdrawal.
    /// Returns IONA amount that will be received after unbonding.
    pub fn request_unstake(
        &mut self,
        staker: &str,
        shares: u128,
        current_height: u64,
        unbonding_blocks: u64,
    ) -> Result<u64, LstError> {
        let balance = self.balances.get(staker).copied().unwrap_or(0);
        if balance < shares {
            return Err(LstError::InsufficientShares { have: balance, need: shares });
        }

        let rate = self.exchange_rate();
        let iona_amount = (shares.saturating_mul(rate) / 1_000_000_000_000_000_000) as u64;

        // Burn shares
        *self.balances.entry(staker.to_string()).or_insert(0) -= shares;
        self.total_shares = self.total_shares.saturating_sub(shares);
        self.total_staked = self.total_staked.saturating_sub(iona_amount);

        let completion_height = current_height + unbonding_blocks;
        self.pending_withdrawals.push((staker.to_string(), iona_amount, completion_height));

        tracing::info!(
            staker   = %staker,
            shares   = shares,
            iona     = iona_amount,
            unlocks_at = completion_height,
            "LST: unstake queued"
        );
        Ok(iona_amount)
    }

    /// Process completed withdrawals. Returns (staker, iona_amount) pairs.
    pub fn process_withdrawals(
        &mut self,
        current_height: u64,
    ) -> Vec<(String, u64)> {
        let (ready, pending): (Vec<_>, Vec<_>) = self.pending_withdrawals
            .drain(..)
            .partition(|(_, _, h)| current_height >= *h);
        self.pending_withdrawals = pending;
        ready.into_iter().map(|(addr, amt, _)| (addr, amt)).collect()
    }

    /// Distribute rewards to the pool (increases exchange rate).
    pub fn add_rewards(&mut self, reward_iona: u64) {
        self.total_staked += reward_iona;
        // Exchange rate increases automatically — stIONA holders get richer
        tracing::debug!(reward = reward_iona, new_rate = self.exchange_rate(), "LST: rewards added");
    }

    /// Transfer stIONA between addresses.
    pub fn transfer(&mut self, from: &str, to: &str, shares: u128) -> Result<(), LstError> {
        let from_bal = self.balances.get(from).copied().unwrap_or(0);
        if from_bal < shares {
            return Err(LstError::InsufficientShares { have: from_bal, need: shares });
        }
        *self.balances.entry(from.to_string()).or_insert(0) -= shares;
        *self.balances.entry(to.to_string()).or_insert(0) += shares;
        Ok(())
    }

    pub fn balance_of(&self, addr: &str) -> u128 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    /// Convert stIONA shares to IONA value (for display).
    pub fn shares_to_iona(&self, shares: u128) -> u64 {
        let rate = self.exchange_rate();
        (shares.saturating_mul(rate) / 1_000_000_000_000_000_000) as u64
    }
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum LstError {
    #[error("amount too small: min={min}, got={got}")]
    AmountTooSmall { min: u64, got: u64 },
    #[error("zero shares minted")]
    ZeroShares,
    #[error("insufficient shares: have={have}, need={need}")]
    InsufficientShares { have: u128, need: u128 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stake_and_unstake_roundtrip() {
        let mut pool = LstPool::default();
        let shares = pool.stake("alice", 1_000_000).unwrap();
        assert!(shares > 0);
        // Add rewards — exchange rate increases
        pool.add_rewards(100_000);
        // Unstake: should get more IONA back
        let iona_back = pool.request_unstake("alice", shares, 0, 1).unwrap();
        assert!(iona_back >= 1_000_000); // at least original amount
        // Process withdrawal
        let released = pool.process_withdrawals(1);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0, "alice");
    }

    #[test]
    fn exchange_rate_grows_with_rewards() {
        let mut pool = LstPool::default();
        pool.stake("alice", 1_000_000).unwrap();
        let rate_before = pool.exchange_rate();
        pool.add_rewards(100_000);
        let rate_after = pool.exchange_rate();
        assert!(rate_after > rate_before);
    }

    #[test]
    fn transfer_stiona() {
        let mut pool = LstPool::default();
        let shares = pool.stake("alice", 1_000_000).unwrap();
        pool.transfer("alice", "bob", shares / 2).unwrap();
        assert_eq!(pool.balance_of("alice"), shares / 2);
        assert_eq!(pool.balance_of("bob"), shares / 2);
    }
}
