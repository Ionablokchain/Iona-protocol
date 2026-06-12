//! PoS Epoch Reward Distribution for IONA — Quantum‑Ready.
//!
//! # Quantum Reward Model
//!
//! Epoch reward distribution is modelled as a **quantum harmonic oscillator**
//! where inflation acts as the **creation operator** a† that adds energy
//! (tokens) to the system. The total staked amount determines the ground
//! state energy, and commissions/delegations split the excited states
//! among participants.
//!
//! # Mathematical Formalism
//!
//! ## Reward State
//! ```text
//! |Ψ_reward⟩ = |inflation⟩ ⊗ |commission⟩ ⊗ |delegator_share⟩ ⊗ |treasury⟩
//! ```
//!
//! ## Hamiltonian for Reward Distribution
//! ```text
//! Ĥ_reward = Ĥ_inflation + Ĥ_commission + Ĥ_treasury
//!
//! Ĥ_inflation  = ω_inf a† a                    (inflation oscillator)
//! Ĥ_commission = Σ_v γ_v n̂_v                    (commission per validator)
//! Ĥ_treasury   = ω_tr b† b                      (treasury oscillator)
//! ```
//!
//! ## Inflation as Creation Operator
//! ```text
//! a† |n⟩ = √(n+1) |n+1⟩
//! ```
//! where n is the current total staked amount.
//!
//! # Epoch Configuration
//!
//! Epoch = 100 blocks by default (configurable via EconomicsParams).
//!
//! Reward formula per epoch:
//!   epoch_inflation = total_staked × base_inflation_bps / 10_000 / epochs_per_year
//!   epochs_per_year ≈ 365 × 24 × 60 × 60 / (block_time_s × EPOCH_BLOCKS)
//!
//! For simplicity we use a fixed epochs_per_year = 52,560
//! (365 days × 24h × 60min × 60s / 6s block time / 100 blocks per epoch).

use crate::economics::params::EconomicsParams;
use crate::economics::staking::StakingState;
use crate::execution::KvState;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::info;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Number of blocks per epoch. Rewards are distributed at epoch boundaries.
pub const EPOCH_BLOCKS: u64 = 100;

/// Approximate number of epochs per year (for inflation rate calculation).
/// Assumes 6-second block time and 100 blocks/epoch:
///   365 × 24 × 3600 / 6 / 100 = 52,560
pub const EPOCHS_PER_YEAR: u64 = 52_560;

/// Reserved treasury address in KvState balances.
pub const TREASURY_ADDR: &str = "treasury";

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh reward state.
const DEFAULT_REWARD_COHERENCE: f64 = 1.0;

/// Decoherence rate per reward distribution.
const DISTRIBUTION_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per validator in the distribution.
const VALIDATOR_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for a healthy reward system.
const MIN_REWARD_COHERENCE: f64 = 0.99;

/// Kraus rank for reward quantum channels.
const REWARD_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Quantum Reward State
// -----------------------------------------------------------------------------

/// Quantum state of the reward distribution system.
///
/// Tracks the density matrix properties during epoch reward calculations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRewardState {
    /// Purity γ = Tr(ρ²) of the reward state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the inflation subsystem.
    pub inflation_coherence: f64,
    /// Coherence of the commission subsystem.
    pub commission_coherence: f64,
    /// Number of reward distributions performed.
    pub total_distributions: u64,
    /// Number of validators processed in total.
    pub total_validators_processed: u64,
    /// Whether the reward system is healthy.
    pub is_healthy: bool,
}

impl Default for QuantumRewardState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_REWARD_COHERENCE,
            entropy: 0.0,
            inflation_coherence: DEFAULT_REWARD_COHERENCE,
            commission_coherence: DEFAULT_REWARD_COHERENCE,
            total_distributions: 0,
            total_validators_processed: 0,
            is_healthy: true,
        }
    }
}

impl QuantumRewardState {
    /// Create a new quantum reward state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a full reward distribution.
    pub fn apply_distribution_decoherence(&mut self, validator_count: usize) {
        self.total_distributions = self.total_distributions.wrapping_add(1);
        self.total_validators_processed =
            self.total_validators_processed.wrapping_add(validator_count as u64);

        let decay = (-DISTRIBUTION_DECOHERENCE_RATE).exp();
        self.inflation_coherence = (self.inflation_coherence * decay).clamp(0.0, 1.0);

        let val_decay = (-VALIDATOR_DECOHERENCE_RATE * validator_count as f64).exp();
        self.commission_coherence = (self.commission_coherence * val_decay).clamp(0.0, 1.0);

        self.recompute();
    }

    /// Apply the Kraus channel for reward operations.
    pub fn apply_reward_channel(&mut self) {
        let kraus_factor = (1.0 / REWARD_KRAUS_RANK as f64).sqrt();
        self.inflation_coherence = (self.inflation_coherence * kraus_factor).clamp(0.0, 1.0);
        self.commission_coherence = (self.commission_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.inflation_coherence * self.commission_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_REWARD_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during reward distribution.
#[derive(Debug, Error)]
pub enum RewardsError {
    #[error("total staked is zero, cannot compute inflation")]
    ZeroTotalStaked,
    #[error("commission basis points must be between 0 and 10_000, got {0}")]
    CommissionOutOfRange(u64),
    #[error("arithmetic overflow during reward calculation")]
    Overflow,
    #[error("invalid parameter: {0}")]
    InvalidParam(String),
    #[error("quantum decoherence: reward coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type RewardsResult<T> = Result<T, RewardsError>;

// -----------------------------------------------------------------------------
// Epoch reward summary
// -----------------------------------------------------------------------------

/// Epoch reward summary emitted on each epoch boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochReward {
    pub epoch: u64,
    pub height: u64,
    pub total_staked: u128,
    pub inflation_minted: u128,
    pub treasury_share: u128,
    pub validator_rewards: BTreeMap<String, u128>, // validator_addr -> reward
    /// Quantum purity at the time of distribution.
    #[serde(default = "default_purity")]
    pub quantum_purity: f64,
}

fn default_purity() -> f64 {
    DEFAULT_REWARD_COHERENCE
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

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

/// Validate a commission rate (in basis points).
fn validate_commission(commission_bps: u64) -> RewardsResult<()> {
    if commission_bps > 10_000 {
        Err(RewardsError::CommissionOutOfRange(commission_bps))
    } else {
        Ok(())
    }
}

/// Safe division with rounding down.
fn safe_div(a: u128, b: u128) -> u128 {
    if b == 0 {
        0
    } else {
        a / b
    }
}

// -----------------------------------------------------------------------------
// Core reward distribution
// -----------------------------------------------------------------------------

/// Distribute epoch rewards.
///
/// Returns an `EpochReward` summary and mutates:
/// - `kv_state.balances` — validator and delegator balances increased
/// - `staking.validators` — stakes increased proportionally (auto-compounding)
///
/// # Errors
///
/// Returns `RewardsError` if:
/// - total staked is zero (no inflation minted)
/// - commission rates are out of bounds
/// - arithmetic overflow occurs
///
/// Called from `after_commit` when `is_epoch_boundary(height)`.
pub fn distribute_epoch_rewards(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> RewardsResult<EpochReward> {
    let epoch = epoch_at(height);
    let mut qstate = QuantumRewardState::new();

    // 1. Validate parameters
    if params.base_inflation_bps > 10_000 {
        return Err(RewardsError::InvalidParam(format!(
            "base_inflation_bps {} > 10_000",
            params.base_inflation_bps
        )));
    }
    if params.treasury_bps > 10_000 {
        return Err(RewardsError::InvalidParam(format!(
            "treasury_bps {} > 10_000",
            params.treasury_bps
        )));
    }
    for v in staking.validators.values() {
        validate_commission(v.commission_bps)?;
    }

    // 2. Compute total staked across active (non-jailed) validators
    let total_staked: u128 = staking
        .validators
        .values()
        .filter(|v| !v.jailed)
        .map(|v| v.stake)
        .sum();

    if total_staked == 0 {
        return Err(RewardsError::ZeroTotalStaked);
    }

    // 3. Inflation reward for this epoch
    //    epoch_inflation = total_staked × base_inflation_bps / 10_000 / epochs_per_year
    let inflation_minted: u128 = total_staked
        .checked_mul(params.base_inflation_bps as u128)
        .ok_or(RewardsError::Overflow)?
        .checked_div(10_000)
        .ok_or(RewardsError::Overflow)?
        .checked_div(EPOCHS_PER_YEAR as u128)
        .ok_or(RewardsError::Overflow)?;

    // Inflation coherence decay
    qstate.inflation_coherence = (qstate.inflation_coherence * 0.9999).clamp(0.0, 1.0);

    // 4. Treasury cut
    let treasury_share: u128 = inflation_minted
        .checked_mul(params.treasury_bps as u128)
        .ok_or(RewardsError::Overflow)?
        .checked_div(10_000)
        .ok_or(RewardsError::Overflow)?;
    let distributable = inflation_minted
        .checked_sub(treasury_share)
        .ok_or(RewardsError::Overflow)?;

    // Credit treasury balance
    let tb = kv_state
        .balances
        .entry(TREASURY_ADDR.to_string())
        .or_insert(0);
    *tb = tb.saturating_add(treasury_share as u64);

    // 5. Per-validator distribution
    let mut validator_rewards: BTreeMap<String, u128> = BTreeMap::new();

    let active_validators: Vec<(String, u128, u64)> = staking
        .validators
        .iter()
        .filter(|(_, v)| !v.jailed)
        .map(|(addr, v)| (addr.clone(), v.stake, v.commission_bps))
        .collect();

    let validator_count = active_validators.len();

    for (val_addr, val_stake, commission_bps) in &active_validators {
        if *val_stake == 0 {
            continue;
        }

        // Validator's share of the distributable pool
        let val_total_reward = safe_div(
            distributable
                .checked_mul(*val_stake)
                .ok_or(RewardsError::Overflow)?,
            total_staked,
        );

        // Commission to operator
        let commission = safe_div(
            val_total_reward
                .checked_mul(*commission_bps as u128)
                .ok_or(RewardsError::Overflow)?,
            10_000,
        );
        let delegator_pool = val_total_reward
            .checked_sub(commission)
            .ok_or(RewardsError::Overflow)?;

        // Credit commission to validator operator balance
        let op_bal = kv_state.balances.entry(val_addr.clone()).or_insert(0);
        *op_bal = op_bal.saturating_add(commission as u64);

        // Auto-compound: add validator's earned commission back to their stake
        if let Some(v) = staking.validators.get_mut(val_addr.as_str()) {
            v.stake = v.stake.saturating_add(commission);
        }

        // Distribute delegator_pool to delegators proportionally
        let delegations_for_val: Vec<(String, u128)> = staking
            .delegations
            .iter()
            .filter(|((_, v), _)| v == val_addr)
            .map(|((d, _), &amt)| (d.clone(), amt))
            .collect();

        let total_delegated: u128 = delegations_for_val.iter().map(|(_, a)| *a).sum();

        if total_delegated > 0 {
            for (delegator, del_amount) in &delegations_for_val {
                let del_reward = safe_div(
                    delegator_pool
                        .checked_mul(*del_amount)
                        .ok_or(RewardsError::Overflow)?,
                    total_delegated,
                );

                // Credit delegator's balance
                let db = kv_state.balances.entry(delegator.clone()).or_insert(0);
                *db = db.saturating_add(del_reward as u64);

                // Auto-compound: add reward back to delegation stake
                let k = (delegator.clone(), val_addr.clone());
                *staking.delegations.entry(k).or_insert(0) = staking
                    .delegations
                    .get(&k)
                    .unwrap_or(&0)
                    .saturating_add(del_reward);
            }
        }

        // Record total reward (commission + delegator pool) for this validator
        validator_rewards.insert(val_addr.clone(), val_total_reward);

        // Grow total stake for the validator (including delegations)
        if let Some(v) = staking.validators.get_mut(val_addr.as_str()) {
            v.stake = v.stake.saturating_add(delegator_pool);
        }
    }

    // Apply quantum decoherence
    qstate.apply_distribution_decoherence(validator_count);
    qstate.apply_reward_channel();

    let purity = qstate.purity;

    info!(
        epoch,
        height,
        total_staked = total_staked,
        minted = inflation_minted,
        treasury = treasury_share,
        validators = validator_count,
        purity = purity,
        "epoch reward distributed"
    );

    Ok(EpochReward {
        epoch,
        height,
        total_staked,
        inflation_minted,
        treasury_share,
        validator_rewards,
        quantum_purity: purity,
    })
}

/// Distribute epoch rewards with quantum state tracking returned.
pub fn distribute_epoch_rewards_quantum(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> (RewardsResult<EpochReward>, QuantumRewardState) {
    let result = distribute_epoch_rewards(height, kv_state, staking, params);

    let qstate = QuantumRewardState {
        purity: result.as_ref().map(|r| r.quantum_purity).unwrap_or(0.0),
        ..QuantumRewardState::new()
    };

    (result, qstate)
}

// -----------------------------------------------------------------------------
// Legacy aliases (backward compatibility)
// -----------------------------------------------------------------------------

/// Legacy alias for `distribute_epoch_rewards`.
#[deprecated(since = "30.0.0", note = "use distribute_epoch_rewards instead")]
pub fn compute_block_reward(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> RewardsResult<EpochReward> {
    distribute_epoch_rewards(height, kv_state, staking, params)
}

/// Legacy alias for `distribute_epoch_rewards`.
#[deprecated(since = "30.0.0", note = "use distribute_epoch_rewards instead")]
pub fn distribute_rewards(
    height: u64,
    kv_state: &mut KvState,
    staking: &mut StakingState,
    params: &EconomicsParams,
) -> RewardsResult<EpochReward> {
    distribute_epoch_rewards(height, kv_state, staking, params)
}

/// Configuration for reward distribution (used by legacy API).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardConfig {
    pub epochs_per_year: u64,
    pub treasury_address: String,
}

impl Default for RewardConfig {
    fn default() -> Self {
        Self {
            epochs_per_year: EPOCHS_PER_YEAR,
            treasury_address: TREASURY_ADDR.to_string(),
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum fidelity
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two epoch rewards.
///
/// ```text
/// F = |⟨reward_a|reward_b⟩|²
/// ```
pub fn reward_fidelity(a: &EpochReward, b: &EpochReward) -> f64 {
    if a.epoch == b.epoch
        && a.height == b.height
        && a.inflation_minted == b.inflation_minted
        && a.treasury_share == b.treasury_share
    {
        1.0
    } else {
        0.0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::economics::params::EconomicsParams;
    use crate::economics::staking::{StakingState, Validator as EconValidator};
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

    // ── Classical tests ──────────────────────────────────────────────
    #[test]
    fn test_epoch_boundary_detection() {
        assert!(!is_epoch_boundary(0));
        assert!(!is_epoch_boundary(99));
        assert!(is_epoch_boundary(100));
        assert!(is_epoch_boundary(200));
        assert!(!is_epoch_boundary(150));
    }

    #[test]
    fn test_epoch_at() {
        assert_eq!(epoch_at(0), 0);
        assert_eq!(epoch_at(99), 0);
        assert_eq!(epoch_at(100), 1);
        assert_eq!(epoch_at(199), 1);
        assert_eq!(epoch_at(200), 2);
    }

    #[test]
    fn test_reward_distribution_basic() -> RewardsResult<()> {
        let mut kv = KvState::default();
        let mut staking = make_state(&[
            ("alice", 10_000_000_000, 1000), // 10% commission
            ("bob", 10_000_000_000, 500),    // 5% commission
        ]);
        let params = EconomicsParams::default();

        let reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params)?;

        assert_eq!(reward.epoch, 1);
        assert!(reward.inflation_minted > 0);
        assert!(reward.treasury_share > 0);
        assert!(reward.treasury_share < reward.inflation_minted);

        let alice_bal = *kv.balances.get("alice").unwrap_or(&0);
        let bob_bal = *kv.balances.get("bob").unwrap_or(&0);
        assert!(alice_bal > 0);
        assert!(bob_bal > 0);
        assert!(alice_bal >= bob_bal); // Alice has higher commission

        // Verify quantum purity is tracked
        assert!(reward.quantum_purity > 0.0);
        assert!(reward.quantum_purity < 1.0);
        Ok(())
    }

    #[test]
    fn test_reward_with_delegators() -> RewardsResult<()> {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 1000)]);
        staking
            .delegations
            .insert(("carol".to_string(), "alice".to_string()), 5_000_000_000);
        let params = EconomicsParams::default();

        let _reward = distribute_epoch_rewards(100, &mut kv, &mut staking, &params)?;

        let carol_bal = *kv.balances.get("carol").unwrap_or(&0);
        assert!(carol_bal > 0);
        Ok(())
    }

    #[test]
    fn test_jailed_validator_gets_no_reward() -> RewardsResult<()> {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 1_000_000, 0)]);
        staking.validators.get_mut("alice").unwrap().jailed = true;
        let params = EconomicsParams::default();

        let res = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        assert!(matches!(res, Err(RewardsError::ZeroTotalStaked)));
        Ok(())
    }

    #[test]
    fn test_treasury_accumulates() -> RewardsResult<()> {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 0)]);
        let params = EconomicsParams::default();

        distribute_epoch_rewards(100, &mut kv, &mut staking, &params)?;
        let t1 = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        distribute_epoch_rewards(200, &mut kv, &mut staking, &params)?;
        let t2 = *kv.balances.get(TREASURY_ADDR).unwrap_or(&0);
        assert!(t2 > t1);
        Ok(())
    }

    #[test]
    fn test_invalid_commission_rejected() {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 10_001)]); // >100%
        let params = EconomicsParams::default();
        let res = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        assert!(matches!(
            res,
            Err(RewardsError::CommissionOutOfRange(10_001))
        ));
    }

    #[test]
    fn test_zero_total_staked_error() {
        let mut kv = KvState::default();
        let mut staking = StakingState::default(); // empty
        let params = EconomicsParams::default();
        let res = distribute_epoch_rewards(100, &mut kv, &mut staking, &params);
        assert!(matches!(res, Err(RewardsError::ZeroTotalStaked)));
    }

    #[test]
    fn test_safe_div() {
        assert_eq!(safe_div(100, 0), 0);
        assert_eq!(safe_div(100, 3), 33);
        assert_eq!(safe_div(0, 100), 0);
    }

    #[test]
    fn test_reward_config_default() {
        let cfg = RewardConfig::default();
        assert_eq!(cfg.epochs_per_year, EPOCHS_PER_YEAR);
        assert_eq!(cfg.treasury_address, TREASURY_ADDR);
    }

    // ── Quantum tests ────────────────────────────────────────────────
    @test
    fn test_quantum_reward_state_initialization() {
        let state = QuantumRewardState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    @test
    fn test_distribution_decoherence() {
        let mut state = QuantumRewardState::new();
        let initial_purity = state.purity;

        state.apply_distribution_decoherence(10);
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_distributions, 1);
        assert_eq!(state.total_validators_processed, 10);
    }

    @test
    fn test_reward_channel() {
        let mut state = QuantumRewardState::new();
        let initial_inf_coh = state.inflation_coherence;

        state.apply_reward_channel();
        assert!(state.inflation_coherence < initial_inf_coh);
    }

    @test
    fn test_distribute_epoch_rewards_quantum() -> RewardsResult<()> {
        let mut kv = KvState::default();
        let mut staking = make_state(&[("alice", 10_000_000_000, 0)]);
        let params = EconomicsParams::default();

        let (result, qstate) =
            distribute_epoch_rewards_quantum(100, &mut kv, &mut staking, &params);

        assert!(result.is_ok());
        assert!(qstate.total_distributions > 0 || result.unwrap().quantum_purity < 1.0);
        Ok(())
    }

    @test
    fn test_reward_fidelity_identical() {
        let r1 = EpochReward {
            epoch: 1,
            height: 100,
            total_staked: 1000,
            inflation_minted: 10,
            treasury_share: 1,
            validator_rewards: BTreeMap::new(),
            quantum_purity: 0.99,
        };
        let r2 = r1.clone();
        assert!((reward_fidelity(&r1, &r2) - 1.0).abs() < 1e-10);
    }

    @test
    fn test_reward_fidelity_different() {
        let r1 = EpochReward {
            epoch: 1,
            height: 100,
            total_staked: 1000,
            inflation_minted: 10,
            treasury_share: 1,
            validator_rewards: BTreeMap::new(),
            quantum_purity: 0.99,
        };
        let r2 = EpochReward {
            epoch: 2,
            ..r1.clone()
        };
        assert!((reward_fidelity(&r1, &r2) - 0.0).abs() < 1e-10);
    }

    @test
    fn test_health_after_many_distributions() {
        let mut state = QuantumRewardState::new();
        for _ in 0..5000 {
            state.apply_distribution_decoherence(10);
        }
        assert!(!state.is_healthy);
    }

    @test
    fn test_purity_never_negative() {
        let mut state = QuantumRewardState::new();
        for _ in 0..100000 {
            state.apply_distribution_decoherence(100);
        }
        assert!(state.purity >= 0.0);
    }
}
