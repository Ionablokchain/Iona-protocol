//! IONA — Quantum Liquid Staking Tokens (stIONA).
//!
//! # Quantum Liquid Staking Model
//!
//! Liquid staking is modeled as a quantum superposition of staked and
//! liquid states. stIONA tokens represent shares in the staking pool,
//! analogous to quantum harmonic oscillator eigenstates.
//!
//! # Hamiltonian for Liquid Staking
//!
//! ```text
//! Ĥ_lst = Ĥ_stake + Ĥ_reward + Ĥ_unstake + Ĥ_transfer
//!
//! Ĥ_stake    = Σ_s g_s (|staked⟩⟨liquid|_s + h.c.)
//! Ĥ_reward   = Σ_r ω_r a†_r a_r                     (reward oscillator)
//! Ĥ_unstake  = Σ_u Δ_u (|bonded⟩⟨free|_u + h.c.)    (unbonding transition)
//! Ĥ_transfer = Σ_t J_t (|from⟩⟨to|_t + h.c.)        (ownership transfer)
//! ```
//!
//! # Quantum Exchange Rate
//!
//! The exchange rate is a quantum observable that evolves with rewards:
//! ```text
//! R(t) = ⟨ψ(t)|Ô_rate|ψ(t)⟩
//! Ô_rate = (total_staked / total_shares) × Î
//! ```
//!
//! # Unbonding as Quantum Tunneling
//!
//! The unbonding period is modeled as quantum tunneling through a
//! potential barrier of height proportional to the unbonding duration:
//! ```text
//! T_unbond ~ exp(-2πΔE·τ_unbond/ℏ)
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// stIONA token symbol.
pub const STIONA_SYMBOL: &str = "stIONA";

/// Precision: stIONA uses 18 decimal places (quantum precision).
pub const STIONA_DECIMALS: u8 = 18;

/// Minimum stake to receive stIONA (prevents quantum dust attacks).
pub const MIN_STAKE: u64 = 1_000;

/// Exchange rate scaling factor (1e18 for fixed-point arithmetic).
pub const RATE_SCALING_FACTOR: u128 = 1_000_000_000_000_000_000;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Quantum tunneling coefficient for unbonding.
const TUNNELING_COEFFICIENT: f64 = 0.95;

/// Coherence decay per operation.
const OPERATION_DECOHERENCE: f64 = 0.0001;

/// Minimum coherence threshold for valid operations.
const MIN_COHERENCE: f64 = 0.9;

// -----------------------------------------------------------------------------
// Quantum LST Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum liquid staking operations.
#[derive(Debug, Clone, thiserror::Error)]
pub enum LstError {
    #[error("amount too small: min={min}, got={got}")]
    AmountTooSmall { min: u64, got: u64 },

    #[error("zero shares minted — quantum amplitude collapsed to zero")]
    ZeroShares,

    #[error("insufficient shares: have={have}, need={need}")]
    InsufficientShares { have: u128, need: u128 },

    #[error("quantum decoherence: coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("unbonding not complete: current_height={current}, completes_at={completes}")]
    UnbondingNotComplete { current: u64, completes: u64 },

    #[error("entanglement broken: pool state corrupted")]
    EntanglementBroken,
}

// -----------------------------------------------------------------------------
// Quantum Liquid Staking Pool
// -----------------------------------------------------------------------------

/// The quantum liquid staking pool state.
///
/// Maintains the superposition of all staker positions and the
/// global exchange rate observable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LstPool {
    /// Total IONA staked (including pending rewards).
    pub total_staked: u64,
    /// Total stIONA in circulation (total quantum shares).
    pub total_shares: u128,
    /// Epoch when rewards were last distributed.
    pub last_reward_epoch: u64,
    /// Per-address stIONA balances (quantum amplitudes).
    pub balances: BTreeMap<String, u128>,
    /// Pending withdrawals: (address, iona_amount, completion_height).
    pub pending_withdrawals: Vec<(String, u64, u64)>,
    /// Pool coherence (1.0 = pure quantum state).
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement entropy of the pool.
    #[serde(default)]
    pub entanglement_entropy: f64,
    /// Total rewards distributed (cumulative).
    #[serde(default)]
    pub total_rewards_distributed: u64,
    /// Number of stake operations performed.
    #[serde(default)]
    pub total_stake_operations: u64,
    /// Number of unstake operations performed.
    #[serde(default)]
    pub total_unstake_operations: u64,
}

fn default_coherence() -> f64 {
    1.0
}

impl Default for LstPool {
    fn default() -> Self {
        Self {
            total_staked: 0,
            total_shares: 0,
            last_reward_epoch: 0,
            balances: BTreeMap::new(),
            pending_withdrawals: Vec::new(),
            coherence: 1.0,
            entanglement_entropy: 0.0,
            total_rewards_distributed: 0,
            total_stake_operations: 0,
            total_unstake_operations: 0,
        }
    }
}

impl LstPool {
    // ── Quantum Exchange Rate ──────────────────────────────────────────

    /// Current exchange rate: IONA per stIONA (scaled by 1e18).
    ///
    /// This is a quantum observable:
    /// ```text
    /// R = ⟨ψ|Ô_rate|ψ⟩ = total_staked × 1e18 / total_shares
    /// ```
    pub fn exchange_rate(&self) -> u128 {
        if self.total_shares == 0 || self.total_staked == 0 {
            return RATE_SCALING_FACTOR; // 1.0 in fixed-point
        }
        (self.total_staked as u128)
            .saturating_mul(RATE_SCALING_FACTOR)
            .checked_div(self.total_shares)
            .unwrap_or(RATE_SCALING_FACTOR)
    }

    /// Exchange rate as a floating-point value (for display).
    pub fn exchange_rate_f64(&self) -> f64 {
        self.exchange_rate() as f64 / RATE_SCALING_FACTOR as f64
    }

    // ── Quantum Stake Operation ────────────────────────────────────────

    /// Stake IONA → receive stIONA (quantum state preparation).
    ///
    /// Creates a superposition of staked/liquid states:
    /// ```text
    /// U_stake |liquid⟩ → √p |staked⟩ + √(1-p) |liquid⟩
    /// ```
    pub fn stake(&mut self, staker: &str, iona_amount: u64) -> Result<u128, LstError> {
        // Validate minimum stake
        if iona_amount < MIN_STAKE {
            return Err(LstError::AmountTooSmall {
                min: MIN_STAKE,
                got: iona_amount,
            });
        }

        // Check pool coherence
        if self.coherence < MIN_COHERENCE {
            return Err(LstError::Decoherence {
                coherence: self.coherence,
                threshold: MIN_COHERENCE,
            });
        }

        let rate = self.exchange_rate();

        // Calculate shares using fixed-point arithmetic
        let shares = (iona_amount as u128)
            .saturating_mul(RATE_SCALING_FACTOR)
            .checked_div(rate)
            .unwrap_or(0);

        if shares == 0 {
            return Err(LstError::ZeroShares);
        }

        // Update pool state
        self.total_staked = self.total_staked.saturating_add(iona_amount);
        self.total_shares = self.total_shares.saturating_add(shares);
        *self.balances.entry(staker.to_string()).or_insert(0) += shares;

        // Update quantum properties
        self.total_stake_operations += 1;
        self.apply_operation_decoherence();
        self.entanglement_entropy += OPERATION_DECOHERENCE as f64;

        tracing::info!(
            staker = %staker,
            iona = iona_amount,
            stiona = shares,
            rate = rate,
            coherence = self.coherence,
            "quantum LST: staked"
        );

        Ok(shares)
    }

    // ── Quantum Unstake Request ────────────────────────────────────────

    /// Request unstake: burn stIONA → queue IONA withdrawal.
    ///
    /// Initiates quantum tunneling through the unbonding barrier:
    /// ```text
    /// T_unbond ~ exp(-2π × ΔE × τ_unbond / ℏ)
    /// ```
    pub fn request_unstake(
        &mut self,
        staker: &str,
        shares: u128,
        current_height: u64,
        unbonding_blocks: u64,
    ) -> Result<u64, LstError> {
        // Check balance
        let balance = self.balances.get(staker).copied().unwrap_or(0);
        if balance < shares {
            return Err(LstError::InsufficientShares {
                have: balance,
                need: shares,
            });
        }

        // Check pool coherence
        if self.coherence < MIN_COHERENCE {
            return Err(LstError::Decoherence {
                coherence: self.coherence,
                threshold: MIN_COHERENCE,
            });
        }

        let rate = self.exchange_rate();
        let iona_amount =
            (shares.saturating_mul(rate) / RATE_SCALING_FACTOR) as u64;

        // Burn shares (annihilation operator)
        *self.balances.entry(staker.to_string()).or_insert(0) =
            balance.saturating_sub(shares);
        self.total_shares = self.total_shares.saturating_sub(shares);
        self.total_staked = self.total_staked.saturating_sub(iona_amount);

        // Calculate completion height with quantum tunneling factor
        let tunneling_factor = (TUNNELING_COEFFICIENT
            * (1.0 - self.entanglement_entropy).max(0.0))
            .max(0.5);
        let effective_unbonding =
            (unbonding_blocks as f64 * tunneling_factor) as u64;
        let completion_height = current_height
            .saturating_add(effective_unbonding)
            .max(current_height + 1);

        self.pending_withdrawals.push((
            staker.to_string(),
            iona_amount,
            completion_height,
        ));

        // Update quantum properties
        self.total_unstake_operations += 1;
        self.apply_operation_decoherence();
        self.entanglement_entropy += OPERATION_DECOHERENCE as f64 * 2.0;

        tracing::info!(
            staker = %staker,
            shares = shares,
            iona = iona_amount,
            unlocks_at = completion_height,
            tunneling = tunneling_factor,
            coherence = self.coherence,
            "quantum LST: unstake queued"
        );

        Ok(iona_amount)
    }

    // ── Quantum Withdrawal Processing ──────────────────────────────────

    /// Process completed withdrawals — quantum tunneling complete.
    ///
    /// Returns (staker, iona_amount) pairs for withdrawals that have
    /// successfully tunneled through the unbonding barrier.
    pub fn process_withdrawals(
        &mut self,
        current_height: u64,
    ) -> Vec<(String, u64)> {
        let (ready, pending): (Vec<_>, Vec<_>) = self
            .pending_withdrawals
            .drain(..)
            .partition(|(_, _, h)| current_height >= *h);

        self.pending_withdrawals = pending;

        if !ready.is_empty() {
            self.apply_operation_decoherence();

            tracing::info!(
                count = ready.len(),
                "quantum LST: withdrawals processed"
            );
        }

        ready.into_iter().map(|(addr, amt, _)| (addr, amt)).collect()
    }

    // ── Quantum Reward Distribution ────────────────────────────────────

    /// Distribute rewards to the pool — excite the reward oscillator.
    ///
    /// ```text
    /// a†_r |n⟩ → √(n+1) |n+1⟩
    /// ```
    pub fn add_rewards(&mut self, reward_iona: u64) {
        self.total_staked = self.total_staked.saturating_add(reward_iona);
        self.total_rewards_distributed =
            self.total_rewards_distributed.saturating_add(reward_iona);

        // Reward distribution slightly increases coherence
        self.coherence = (self.coherence * 1.0001).min(1.0);
        self.entanglement_entropy =
            (self.entanglement_entropy * 0.9999).max(0.0);

        tracing::debug!(
            reward = reward_iona,
            new_rate = self.exchange_rate(),
            coherence = self.coherence,
            "quantum LST: rewards added"
        );
    }

    // ── Quantum Transfer ───────────────────────────────────────────────

    /// Transfer stIONA between addresses — quantum state transfer.
    ///
    /// ```text
    /// U_transfer |from⟩|to⟩ → |from - Δ⟩|to + Δ⟩
    /// ```
    pub fn transfer(
        &mut self,
        from: &str,
        to: &str,
        shares: u128,
    ) -> Result<(), LstError> {
        let from_bal = self.balances.get(from).copied().unwrap_or(0);
        if from_bal < shares {
            return Err(LstError::InsufficientShares {
                have: from_bal,
                need: shares,
            });
        }

        *self.balances.entry(from.to_string()).or_insert(0) =
            from_bal.saturating_sub(shares);
        *self.balances.entry(to.to_string()).or_insert(0) += shares;

        self.apply_operation_decoherence();

        tracing::debug!(
            from = %from,
            to = %to,
            shares = shares,
            "quantum LST: transferred"
        );

        Ok(())
    }

    // ── Quantum Queries ────────────────────────────────────────────────

    /// Get stIONA balance for an address.
    pub fn balance_of(&self, addr: &str) -> u128 {
        self.balances.get(addr).copied().unwrap_or(0)
    }

    /// Convert stIONA shares to IONA value (for display).
    pub fn shares_to_iona(&self, shares: u128) -> u64 {
        let rate = self.exchange_rate();
        (shares.saturating_mul(rate) / RATE_SCALING_FACTOR) as u64
    }

    /// Convert IONA value to stIONA shares (for display).
    pub fn iona_to_shares(&self, iona: u64) -> u128 {
        let rate = self.exchange_rate();
        (iona as u128).saturating_mul(RATE_SCALING_FACTOR) / rate.max(1)
    }

    /// Get pending withdrawal count.
    pub fn pending_withdrawal_count(&self) -> usize {
        self.pending_withdrawals.len()
    }

    /// Get total IONA in pending withdrawals.
    pub fn pending_withdrawal_total(&self) -> u64 {
        self.pending_withdrawals.iter().map(|(_, amt, _)| amt).sum()
    }

    /// Get pool statistics.
    pub fn stats(&self) -> LstStats {
        LstStats {
            total_staked: self.total_staked,
            total_shares: self.total_shares,
            exchange_rate: self.exchange_rate(),
            exchange_rate_f64: self.exchange_rate_f64(),
            total_holders: self.balances.len(),
            pending_withdrawals: self.pending_withdrawals.len(),
            total_rewards: self.total_rewards_distributed,
            coherence: self.coherence,
            entanglement_entropy: self.entanglement_entropy,
        }
    }

    // ── Internal Helpers ───────────────────────────────────────────────

    /// Apply decoherence from an operation.
    fn apply_operation_decoherence(&mut self) {
        self.coherence = (self.coherence * (1.0 - OPERATION_DECOHERENCE))
            .max(0.0);
        self.entanglement_entropy =
            -self.coherence * self.coherence.ln().max(0.0);
    }
}

// -----------------------------------------------------------------------------
// LST Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the quantum liquid staking pool.
#[derive(Debug, Clone)]
pub struct LstStats {
    pub total_staked: u64,
    pub total_shares: u128,
    pub exchange_rate: u128,
    pub exchange_rate_f64: f64,
    pub total_holders: usize,
    pub pending_withdrawals: usize,
    pub total_rewards: u64,
    pub coherence: f64,
    pub entanglement_entropy: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stake_and_unstake_roundtrip() {
        let mut pool = LstPool::default();

        // Stake
        let shares = pool.stake("alice", 1_000_000).unwrap();
        assert!(shares > 0);
        assert_eq!(pool.balance_of("alice"), shares);
        assert!((pool.coherence - 1.0).abs() > 1e-10); // decohered

        // Add rewards
        pool.add_rewards(100_000);

        // Unstake: should get more IONA back
        let iona_back = pool
            .request_unstake("alice", shares, 0, 1)
            .unwrap();
        assert!(iona_back >= 1_000_000);

        // Process withdrawal
        let released = pool.process_withdrawals(1);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].0, "alice");
    }

    #[test]
    fn test_exchange_rate_grows_with_rewards() {
        let mut pool = LstPool::default();
        pool.stake("alice", 1_000_000).unwrap();

        let rate_before = pool.exchange_rate();
        pool.add_rewards(100_000);
        let rate_after = pool.exchange_rate();

        assert!(rate_after > rate_before);
    }

    #[test]
    fn test_transfer_stiona() {
        let mut pool = LstPool::default();
        let shares = pool.stake("alice", 1_000_000).unwrap();

        pool.transfer("alice", "bob", shares / 2).unwrap();

        assert_eq!(pool.balance_of("alice"), shares / 2);
        assert_eq!(pool.balance_of("bob"), shares / 2);
    }

    #[test]
    fn test_min_stake_enforcement() {
        let mut pool = LstPool::default();
        let result = pool.stake("alice", MIN_STAKE - 1);
        assert!(matches!(result, Err(LstError::AmountTooSmall { .. })));
    }

    #[test]
    fn test_insufficient_shares() {
        let mut pool = LstPool::default();
        pool.stake("alice", 1_000_000).unwrap();

        let result = pool.transfer("alice", "bob", 999_999_999);
        assert!(matches!(result, Err(LstError::InsufficientShares { .. })));
    }

    #[test]
    fn test_quantum_decoherence_tracking() {
        let mut pool = LstPool::default();
        let initial_coherence = pool.coherence;

        pool.stake("alice", 10_000).unwrap();
        assert!(pool.coherence < initial_coherence);

        pool.stake("bob", 10_000).unwrap();
        assert!(pool.coherence < initial_coherence);
    }

    #[test]
    fn test_stats() {
        let mut pool = LstPool::default();
        pool.stake("alice", 1_000_000).unwrap();
        pool.add_rewards(50_000);

        let stats = pool.stats();
        assert!(stats.total_staked > 0);
        assert!(stats.total_shares > 0);
        assert_eq!(stats.total_holders, 1);
        assert!(stats.coherence < 1.0);
    }

    #[test]
    fn test_conversion_functions() {
        let mut pool = LstPool::default();
        pool.stake("alice", 1_000_000).unwrap();

        let iona_val = pool.shares_to_iona(pool.balance_of("alice"));
        assert!(iona_val >= 1_000_000);

        let shares_val = pool.iona_to_shares(1_000_000);
        assert!(shares_val > 0);
    }

    #[test]
    fn test_unbonding_tunneling() {
        let mut pool = LstPool::default();
        let shares = pool.stake("alice", 1_000_000).unwrap();

        // Request unstake with long unbonding
        let iona = pool
            .request_unstake("alice", shares, 100, 1000)
            .unwrap();

        // Should not be ready at height 200
        let released = pool.process_withdrawals(200);
        assert!(released.is_empty());

        // Should be ready after sufficient height
        let released = pool.process_withdrawals(2000);
        assert_eq!(released.len(), 1);
    }
}
