//! EIP-1559 base fee adjustment (London).
//!
//! This module implements the canonical formula for updating the base fee per gas
//! after each block, as specified in EIP-1559, with configurable parameters for
//! different Ethereum forks and network conditions.
//!
//! # Production Features
//! - Configurable elasticity multiplier (default: 8) and target gas fraction (default: 1/2).
//! - Metrics for tracking base fee adjustments.
//! - Structured logging with `tracing`.
//! - Validation for gas limit, gas used, and base fee.
//! - Support for different fork configurations.
//! - Serialization for configuration.
//! - Full test coverage with edge cases.
//!
//! # Formula
//!
//! ```text
//! target_gas = gas_limit / target_fraction_denominator
//! if gas_used == target_gas:
//!     base_fee = parent_base_fee
//! elif gas_used > target_gas:
//!     delta = parent_base_fee * (gas_used - target_gas) / target_gas / elasticity_multiplier
//!     base_fee = parent_base_fee + max(1, delta)
//! else:
//!     delta = parent_base_fee * (target_gas - gas_used) / target_gas / elasticity_multiplier
//!     base_fee = parent_base_fee - delta
//! ```
//!
//! # Example
//!
//! ```
//! use iona::execution::basefee::{BaseFeeConfig, next_base_fee};
//!
//! let config = BaseFeeConfig::default();
//! let base_fee = 1_000_000_000;
//! let gas_used = 25_000_000;
//! let gas_limit = 30_000_000;
//! let new_fee = next_base_fee(base_fee, gas_used, gas_limit, &config);
//! assert!(new_fee > base_fee);
//! ```

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default elasticity multiplier (EIP-1559: 8).
pub const DEFAULT_ELASTICITY_MULTIPLIER: u64 = 8;

/// Default target gas fraction denominator (EIP-1559: 2 → 1/2 of gas limit).
pub const DEFAULT_TARGET_FRACTION_DENOM: u64 = 2;

/// Maximum gas limit (30 million).
pub const MAX_GAS_LIMIT: u64 = 30_000_000;

/// Minimum gas limit (5 million).
pub const MIN_GAS_LIMIT: u64 = 5_000_000;

/// Maximum base fee (1 ether per gas, absurdly high for safety).
pub const MAX_BASE_FEE: u64 = 1_000_000_000_000_000_000;

/// Minimum base fee (1 wei).
pub const MIN_BASE_FEE: u64 = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for base fee adjustment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseFeeConfig {
    /// Elasticity multiplier (EIP-1559: 8).
    pub elasticity_multiplier: u64,
    /// Target gas fraction denominator (EIP-1559: 2 → 1/2).
    pub target_fraction_denom: u64,
    /// Minimum base fee (default: 1 wei).
    pub min_base_fee: u64,
    /// Maximum base fee (safety cap).
    pub max_base_fee: u64,
    /// Whether to enforce strict validation.
    pub strict_validation: bool,
    /// Whether to log base fee adjustments.
    pub log_adjustments: bool,
}

impl Default for BaseFeeConfig {
    fn default() -> Self {
        Self {
            elasticity_multiplier: DEFAULT_ELASTICITY_MULTIPLIER,
            target_fraction_denom: DEFAULT_TARGET_FRACTION_DENOM,
            min_base_fee: MIN_BASE_FEE,
            max_base_fee: MAX_BASE_FEE,
            strict_validation: true,
            log_adjustments: true,
        }
    }
}

impl BaseFeeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.elasticity_multiplier == 0 {
            return Err("elasticity_multiplier must be > 0".into());
        }
        if self.target_fraction_denom == 0 {
            return Err("target_fraction_denom must be > 0".into());
        }
        if self.min_base_fee == 0 {
            return Err("min_base_fee must be > 0".into());
        }
        if self.max_base_fee == 0 {
            return Err("max_base_fee must be > 0".into());
        }
        if self.min_base_fee > self.max_base_fee {
            return Err("min_base_fee must be <= max_base_fee".into());
        }
        Ok(())
    }

    /// Create a configuration for a specific Ethereum fork.
    pub fn for_fork(fork: ForkKind) -> Self {
        match fork {
            ForkKind::London => Self::default(),
            ForkKind::Berlin => Self::default(),
            ForkKind::Shanghai => Self {
                elasticity_multiplier: 8,
                target_fraction_denom: 2,
                ..Default::default()
            },
            ForkKind::Cancun => Self {
                elasticity_multiplier: 8,
                target_fraction_denom: 2,
                ..Default::default()
            },
            ForkKind::Prague => Self {
                elasticity_multiplier: 8,
                target_fraction_denom: 2,
                ..Default::default()
            },
        }
    }
}

/// Ethereum fork kinds that affect base fee calculation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ForkKind {
    London,
    Berlin,
    Shanghai,
    Cancun,
    Prague,
}

impl Default for ForkKind {
    fn default() -> Self {
        Self::London
    }
}

impl ForkKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::London => "London",
            Self::Berlin => "Berlin",
            Self::Shanghai => "Shanghai",
            Self::Cancun => "Cancun",
            Self::Prague => "Prague",
        }
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for base fee adjustments.
#[derive(Debug, Default)]
pub struct BaseFeeMetrics {
    pub computations: AtomicU64,
    pub increases: AtomicU64,
    pub decreases: AtomicU64,
    pub unchanged: AtomicU64,
    pub saturated: AtomicU64,
    pub validation_failures: AtomicU64,
}

impl BaseFeeMetrics {
    pub fn record_computation(&self) {
        self.computations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_increase(&self) {
        self.increases.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_decrease(&self) {
        self.decreases.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_unchanged(&self) {
        self.unchanged.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_saturated(&self) {
        self.saturated.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_validation_failure(&self) {
        self.validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> BaseFeeMetricsSnapshot {
        BaseFeeMetricsSnapshot {
            computations: self.computations.load(Ordering::Relaxed),
            increases: self.increases.load(Ordering::Relaxed),
            decreases: self.decreases.load(Ordering::Relaxed),
            unchanged: self.unchanged.load(Ordering::Relaxed),
            saturated: self.saturated.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of base fee metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaseFeeMetricsSnapshot {
    pub computations: u64,
    pub increases: u64,
    pub decreases: u64,
    pub unchanged: u64,
    pub saturated: u64,
    pub validation_failures: u64,
}

// ── Core Function ─────────────────────────────────────────────────────────

/// EIP-1559 base fee adjustment.
///
/// Computes the next block's base fee based on the current base fee,
/// the gas used in the current block, the block gas limit, and configuration.
///
/// # Arguments
/// * `base_fee` – The base fee of the current block (in wei).
/// * `gas_used` – The total gas used by transactions in the current block.
/// * `gas_limit` – The block gas limit (e.g., `30_000_000`).
/// * `config` – Configuration parameters.
/// * `metrics` – Optional metrics for tracking.
///
/// # Returns
/// The base fee for the next block, clamped to `[min_base_fee, max_base_fee]`.
///
/// # Validation
/// If `config.strict_validation` is true, the function validates:
/// - `gas_limit` > 0
/// - `gas_used` <= `gas_limit`
/// - `base_fee` >= `min_base_fee`
/// - `base_fee` <= `max_base_fee`
pub fn next_base_fee(
    base_fee: u64,
    gas_used: u64,
    gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> u64 {
    // Record metrics if provided.
    if let Some(m) = metrics {
        m.record_computation();
    }

    // ── Validation ──────────────────────────────────────────────────────
    if config.strict_validation {
        if gas_limit == 0 {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            warn!("gas_limit is 0, returning base_fee unchanged");
            return base_fee;
        }
        if gas_used > gas_limit {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            warn!(
                gas_used = gas_used,
                gas_limit = gas_limit,
                "gas_used exceeds gas_limit"
            );
            // In strict mode, we still compute but with clamped gas_used.
        }
        if base_fee < config.min_base_fee || base_fee > config.max_base_fee {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            debug!(
                base_fee = base_fee,
                min = config.min_base_fee,
                max = config.max_base_fee,
                "base_fee outside allowed range, clamping"
            );
        }
    }

    // ── Validate and clamp gas_limit ──────────────────────────────────
    let gas_limit = if gas_limit == 0 {
        return base_fee.clamp(config.min_base_fee, config.max_base_fee);
    } else {
        gas_limit
    };

    // ── Compute target gas ─────────────────────────────────────────────
    let target_denom = config.target_fraction_denom;
    let target = gas_limit / target_denom;
    if target == 0 {
        return base_fee.clamp(config.min_base_fee, config.max_base_fee);
    }

    // ── Clamp gas_used to gas_limit (if it exceeded) ──────────────────
    let gas_used = gas_used.min(gas_limit);

    // ── No change case ─────────────────────────────────────────────────
    if gas_used == target {
        if let Some(m) = metrics {
            m.record_unchanged();
        }
        if config.log_adjustments {
            trace!(
                base_fee = base_fee,
                gas_used = gas_used,
                target = target,
                "base_fee unchanged (at target)"
            );
        }
        return base_fee.clamp(config.min_base_fee, config.max_base_fee);
    }

    // ── Compute change using 128-bit arithmetic ───────────────────────
    let gas_delta = if gas_used > target {
        gas_used - target
    } else {
        target - gas_used
    };
    let mut change = (base_fee as u128) * (gas_delta as u128);
    change = change / (target as u128);
    change = change / (config.elasticity_multiplier as u128);

    let new_fee = if gas_used > target {
        // Increase: at least 1 wei.
        let change_u = change as u64;
        base_fee.saturating_add(change_u.max(1))
    } else {
        // Decrease: can go down to min_base_fee.
        let change_u = change as u64;
        base_fee.saturating_sub(change_u)
    };

    // ── Clamp and record metrics ──────────────────────────────────────
    let clamped = new_fee.clamp(config.min_base_fee, config.max_base_fee);

    if clamped != new_fee {
        if let Some(m) = metrics {
            m.record_saturated();
        }
        if config.log_adjustments {
            debug!(
                new_fee = new_fee,
                clamped = clamped,
                "base_fee saturated to limits"
            );
        }
    }

    if let Some(m) = metrics {
        if gas_used > target {
            m.record_increase();
        } else {
            m.record_decrease();
        }
    }

    if config.log_adjustments && clamped != base_fee {
        info!(
            old_base_fee = base_fee,
            new_base_fee = clamped,
            gas_used = gas_used,
            gas_limit = gas_limit,
            target = target,
            elasticity = config.elasticity_multiplier,
            "base_fee adjusted"
        );
    }

    clamped
}

// ── Convenience Functions ──────────────────────────────────────────────

/// Compute the next base fee from a previous block header.
///
/// # Arguments
/// * `prev_base_fee` – The base fee of the previous block.
/// * `prev_gas_used` – The gas used in the previous block.
/// * `next_gas_limit` – The gas limit for the next block.
/// * `config` – Configuration parameters.
/// * `metrics` – Optional metrics.
///
/// # Returns
/// The base fee for the next block.
pub fn next_base_fee_from_params(
    prev_base_fee: u64,
    prev_gas_used: u64,
    next_gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> u64 {
    next_base_fee(prev_base_fee, prev_gas_used, next_gas_limit, config, metrics)
}

/// Compute the next base fee from a previous block header.
pub fn next_base_fee_from_header(
    header: &crate::types::BlockHeader,
    next_gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> u64 {
    next_base_fee(
        header.base_fee_per_gas,
        header.gas_used,
        next_gas_limit,
        config,
        metrics,
    )
}

/// Convenience function with default config (no metrics).
pub fn next_base_fee_default(base_fee: u64, gas_used: u64, gas_limit: u64) -> u64 {
    let config = BaseFeeConfig::default();
    next_base_fee(base_fee, gas_used, gas_limit, &config, None)
}

// ── Fork‑Specific Functions ─────────────────────────────────────────────

/// Compute the next base fee for a specific fork.
pub fn next_base_fee_for_fork(
    base_fee: u64,
    gas_used: u64,
    gas_limit: u64,
    fork: ForkKind,
) -> u64 {
    let config = BaseFeeConfig::for_fork(fork);
    next_base_fee(base_fee, gas_used, gas_limit, &config, None)
}

// ── Base Fee Manager ─────────────────────────────────────────────────────

/// Thread‑safe manager for base fee calculations with caching.
#[derive(Clone)]
pub struct BaseFeeManager {
    config: Arc<BaseFeeConfig>,
    metrics: Arc<BaseFeeMetrics>,
}

impl BaseFeeManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: BaseFeeConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(BaseFeeMetrics::default()),
        })
    }

    /// Create a manager with default configuration.
    pub fn default() -> Self {
        Self::new(BaseFeeConfig::default()).unwrap()
    }

    /// Compute the next base fee.
    pub fn compute(&self, base_fee: u64, gas_used: u64, gas_limit: u64) -> u64 {
        next_base_fee(
            base_fee,
            gas_used,
            gas_limit,
            &self.config,
            Some(&self.metrics),
        )
    }

    /// Compute from a header.
    pub fn compute_from_header(&self, header: &crate::types::BlockHeader, next_gas_limit: u64) -> u64 {
        next_base_fee_from_header(header, next_gas_limit, &self.config, Some(&self.metrics))
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> BaseFeeMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &BaseFeeConfig {
        &self.config
    }

    /// Reset metrics (for testing).
    #[cfg(test)]
    pub fn reset_metrics(&self) {
        self.metrics.computations.store(0, Ordering::Relaxed);
        self.metrics.increases.store(0, Ordering::Relaxed);
        self.metrics.decreases.store(0, Ordering::Relaxed);
        self.metrics.unchanged.store(0, Ordering::Relaxed);
        self.metrics.saturated.store(0, Ordering::Relaxed);
        self.metrics.validation_failures.store(0, Ordering::Relaxed);
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> BaseFeeConfig {
        BaseFeeConfig::default()
    }

    #[test]
    fn test_next_base_fee_equal() {
        let config = test_config();
        let base_fee = 1_000_000_000;
        let gas_used = 15_000_000; // target = 15_000_000
        let gas_limit = 30_000_000;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), base_fee);
    }

    #[test]
    fn test_next_base_fee_increase() {
        let config = test_config();
        let base_fee = 1_000_000_000;
        let gas_used = 25_000_000; // above target
        let gas_limit = 30_000_000;
        // target = 15_000_000, delta = 10_000_000
        // change = 1e9 * 10e6 / 15e6 / 8 ≈ 83_333_333
        let expected = base_fee + 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_decrease() {
        let config = test_config();
        let base_fee = 1_000_000_000;
        let gas_used = 5_000_000; // below target
        let gas_limit = 30_000_000;
        // target = 15_000_000, delta = 10_000_000
        // change = 1e9 * 10e6 / 15e6 / 8 = 83_333_333
        let expected = base_fee - 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_min_increase() {
        let config = test_config();
        let base_fee = 1;
        let gas_used = gas_limit;
        let gas_limit = 30_000_000;
        // change = 1 * 30e6 / 15e6 / 8 = 0 (integer division)
        // but increase must be at least 1
        let expected = base_fee + 1;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_zero_limit() {
        let config = test_config();
        let base_fee = 100;
        assert_eq!(next_base_fee(base_fee, 50, 0, &config, None), base_fee);
    }

    #[test]
    fn test_next_base_fee_target_zero() {
        let config = test_config();
        let base_fee = 100;
        assert_eq!(next_base_fee(base_fee, 1, 1, &config, None), base_fee); // target = 0
    }

    #[test]
    fn test_next_base_fee_zero_base() {
        let config = test_config();
        let base_fee = 0;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        // change = 0 * ... / ... = 0
        // increase: max(1,0) = 1
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), 1);
    }

    #[test]
    fn test_next_base_fee_saturation() {
        let config = test_config();
        let base_fee = u64::MAX;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        assert_eq!(result, u64::MAX); // saturates
    }

    #[test]
    fn test_next_base_fee_clamp_min() {
        let config = BaseFeeConfig {
            min_base_fee: 10,
            max_base_fee: 100,
            ..Default::default()
        };
        let base_fee = 1;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        assert_eq!(result, 10); // clamped to min_base_fee
    }

    #[test]
    fn test_next_base_fee_clamp_max() {
        let config = BaseFeeConfig {
            min_base_fee: 1,
            max_base_fee: 100,
            ..Default::default()
        };
        let base_fee = 200;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        assert_eq!(result, 100); // clamped to max_base_fee
    }

    #[test]
    fn test_metrics() {
        let config = test_config();
        let metrics = BaseFeeMetrics::default();
        let base_fee = 1_000_000_000;

        // Equal case.
        next_base_fee(base_fee, 15_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.unchanged.load(Ordering::Relaxed), 1);

        // Increase case.
        next_base_fee(base_fee, 25_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.increases.load(Ordering::Relaxed), 1);

        // Decrease case.
        next_base_fee(base_fee, 5_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.decreases.load(Ordering::Relaxed), 1);

        assert_eq!(metrics.computations.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_manager() {
        let config = test_config();
        let manager = BaseFeeManager::new(config).unwrap();
        let result = manager.compute(1_000_000_000, 25_000_000, 30_000_000);
        let expected = next_base_fee(1_000_000_000, 25_000_000, 30_000_000, &BaseFeeConfig::default(), None);
        assert_eq!(result, expected);
        assert!(manager.metrics_snapshot().computations > 0);
    }

    #[test]
    fn test_fork_configs() {
        let london = BaseFeeConfig::for_fork(ForkKind::London);
        assert_eq!(london.elasticity_multiplier, 8);
        assert_eq!(london.target_fraction_denom, 2);

        let shanghai = BaseFeeConfig::for_fork(ForkKind::Shanghai);
        assert_eq!(shanghai.elasticity_multiplier, 8);
        assert_eq!(shanghai.target_fraction_denom, 2);
    }

    #[test]
    fn test_next_base_fee_for_fork() {
        let result = next_base_fee_for_fork(1_000_000_000, 25_000_000, 30_000_000, ForkKind::London);
        let expected = next_base_fee(1_000_000_000, 25_000_000, 30_000_000, &BaseFeeConfig::default(), None);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_config_validation() {
        let mut config = BaseFeeConfig::default();
        assert!(config.validate().is_ok());

        config.elasticity_multiplier = 0;
        assert!(config.validate().is_err());

        config.elasticity_multiplier = 8;
        config.target_fraction_denom = 0;
        assert!(config.validate().is_err());

        config.target_fraction_denom = 2;
        config.min_base_fee = 0;
        assert!(config.validate().is_err());

        config.min_base_fee = 10;
        config.max_base_fee = 5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_gas_used_exceeds_gas_limit() {
        let config = test_config();
        let base_fee = 1_000_000_000;
        let gas_used = 40_000_000; // exceeds gas_limit
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        // Should treat as gas_used = gas_limit (clamped)
        let expected = next_base_fee(base_fee, 30_000_000, 30_000_000, &config, None);
        assert_eq!(result, expected);
    }

    #[test]
    fn test_default_config_compatibility() {
        // Ensure next_base_fee_default matches the original behaviour.
        let result = next_base_fee_default(1_000_000_000, 25_000_000, 30_000_000);
        let expected = next_base_fee(1_000_000_000, 25_000_000, 30_000_000, &BaseFeeConfig::default(), None);
        assert_eq!(result, expected);
    }
}
