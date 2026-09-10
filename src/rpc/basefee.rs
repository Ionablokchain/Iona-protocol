//! EIP-1559 base fee adjustment (London).
//!
//! This module implements the canonical formula for updating the base fee per gas
//! after each block, as specified in EIP-1559, with configurable parameters for
//! different Ethereum forks and network conditions.
//!
//! # Production Features
//! - Configurable elasticity multiplier (default: 8) and target gas fraction (default: 1/2).
//! - Prometheus metrics (optional) with atomic fallback for tracking adjustments.
//! - Overflow‑safe u128 → u64 conversion using saturating conversion.
//! - Structured logging with `tracing`.
//! - Validation for gas limit, gas used, and base fee.
//! - `Result`-returning variants for strict callers.
//! - Support for different fork configurations.
//! - Serialization for configuration (metrics excluded).
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
//! let new_fee = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
//! assert!(new_fee > base_fee);
//! ```

use prometheus::{register_counter, Counter};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
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

// ── Error types ──────────────────────────────────────────────────────────

/// Errors that can occur during base fee computation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum BaseFeeError {
    #[error("gas_limit must be > 0")]
    ZeroGasLimit,

    #[error("gas_used ({gas_used}) exceeds gas_limit ({gas_limit})")]
    GasUsedExceedsLimit { gas_used: u64, gas_limit: u64 },

    #[error("base_fee ({base_fee}) below minimum ({min})")]
    BaseFeeBelowMin { base_fee: u64, min: u64 },

    #[error("base_fee ({base_fee}) above maximum ({max})")]
    BaseFeeAboveMax { base_fee: u64, max: u64 },

    #[error("target gas is zero for gas_limit {gas_limit} and denominator {denom}")]
    ZeroTarget { gas_limit: u64, denom: u64 },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("integer overflow during computation")]
    Overflow,
}

pub type BaseFeeResult<T> = Result<T, BaseFeeError>;

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
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
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
            enable_metrics: false,
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
            ForkKind::London | ForkKind::Berlin => Self::default(),
            ForkKind::Shanghai | ForkKind::Cancun | ForkKind::Prague => Self {
                elasticity_multiplier: 8,
                target_fraction_denom: 2,
                ..Default::default()
            },
        }
    }

    /// Enable Prometheus metrics.
    pub fn with_prometheus(mut self) -> Self {
        self.enable_metrics = true;
        self
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

// ── Prometheus metrics ──────────────────────────────────────────────────

/// Prometheus counters for base fee adjustments.
#[derive(Clone)]
pub struct BaseFeePrometheus {
    pub computations_total: Counter,
    pub increases_total: Counter,
    pub decreases_total: Counter,
    pub unchanged_total: Counter,
    pub saturated_total: Counter,
    pub validation_failures_total: Counter,
}

impl BaseFeePrometheus {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            computations_total: register_counter!(
                "iona_basefee_computations_total",
                "Total base fee computations"
            )?,
            increases_total: register_counter!(
                "iona_basefee_increases_total",
                "Total base fee increases"
            )?,
            decreases_total: register_counter!(
                "iona_basefee_decreases_total",
                "Total base fee decreases"
            )?,
            unchanged_total: register_counter!(
                "iona_basefee_unchanged_total",
                "Total base fee unchanged events"
            )?,
            saturated_total: register_counter!(
                "iona_basefee_saturated_total",
                "Total base fee saturations to min/max"
            )?,
            validation_failures_total: register_counter!(
                "iona_basefee_validation_failures_total",
                "Total base fee validation failures"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            computations_total: Counter::new("iona_basefee_computations_total", "Computations").unwrap(),
            increases_total: Counter::new("iona_basefee_increases_total", "Increases").unwrap(),
            decreases_total: Counter::new("iona_basefee_decreases_total", "Decreases").unwrap(),
            unchanged_total: Counter::new("iona_basefee_unchanged_total", "Unchanged").unwrap(),
            saturated_total: Counter::new("iona_basefee_saturated_total", "Saturated").unwrap(),
            validation_failures_total: Counter::new("iona_basefee_validation_failures_total", "Failures").unwrap(),
        }
    }
}

// ── Metrics (atomic + optional Prometheus) ──────────────────────────────

/// Metrics for base fee adjustments.
/// Provides atomic counters (always available) and optional Prometheus counters.
#[derive(Debug, Clone)]
pub struct BaseFeeMetrics {
    pub computations: Arc<AtomicU64>,
    pub increases: Arc<AtomicU64>,
    pub decreases: Arc<AtomicU64>,
    pub unchanged: Arc<AtomicU64>,
    pub saturated: Arc<AtomicU64>,
    pub validation_failures: Arc<AtomicU64>,
    /// Optional Prometheus integration.
    pub prometheus: Option<Arc<BaseFeePrometheus>>,
}

impl Default for BaseFeeMetrics {
    fn default() -> Self {
        Self {
            computations: Arc::new(AtomicU64::new(0)),
            increases: Arc::new(AtomicU64::new(0)),
            decreases: Arc::new(AtomicU64::new(0)),
            unchanged: Arc::new(AtomicU64::new(0)),
            saturated: Arc::new(AtomicU64::new(0)),
            validation_failures: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl BaseFeeMetrics {
    /// Create a new metrics instance, optionally with Prometheus integration.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(BaseFeePrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            computations: Arc::new(AtomicU64::new(0)),
            increases: Arc::new(AtomicU64::new(0)),
            decreases: Arc::new(AtomicU64::new(0)),
            unchanged: Arc::new(AtomicU64::new(0)),
            saturated: Arc::new(AtomicU64::new(0)),
            validation_failures: Arc::new(AtomicU64::new(0)),
            prometheus,
        })
    }

    pub fn record_computation(&self) {
        self.computations.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.computations_total.inc();
        }
    }
    pub fn record_increase(&self) {
        self.increases.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.increases_total.inc();
        }
    }
    pub fn record_decrease(&self) {
        self.decreases.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.decreases_total.inc();
        }
    }
    pub fn record_unchanged(&self) {
        self.unchanged.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.unchanged_total.inc();
        }
    }
    pub fn record_saturated(&self) {
        self.saturated.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.saturated_total.inc();
        }
    }
    pub fn record_validation_failure(&self) {
        self.validation_failures.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.validation_failures_total.inc();
        }
    }

    /// Snapshot of atomic counters.
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

    /// Reset atomic counters (for testing).
    #[cfg(test)]
    pub fn reset(&self) {
        self.computations.store(0, Ordering::Relaxed);
        self.increases.store(0, Ordering::Relaxed);
        self.decreases.store(0, Ordering::Relaxed);
        self.unchanged.store(0, Ordering::Relaxed);
        self.saturated.store(0, Ordering::Relaxed);
        self.validation_failures.store(0, Ordering::Relaxed);
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

/// EIP-1559 base fee adjustment (infallible variant, clamps on error).
///
/// Computes the next block's base fee based on the current base fee,
/// the gas used in the current block, the block gas limit, and configuration.
///
/// On validation errors, logs a warning and returns the base fee clamped to
/// `[min_base_fee, max_base_fee]`. Use [`next_base_fee_checked`] for strict
/// error handling.
pub fn next_base_fee(
    base_fee: u64,
    gas_used: u64,
    gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> u64 {
    match next_base_fee_checked(base_fee, gas_used, gas_limit, config, metrics) {
        Ok(fee) => fee,
        Err(e) => {
            warn!(error = %e, "base_fee computation failed; returning clamped input");
            base_fee.clamp(config.min_base_fee, config.max_base_fee)
        }
    }
}

/// EIP-1559 base fee adjustment (strict variant).
///
/// Returns `Err` on validation failures instead of silently clamping.
/// Use this in consensus-critical paths where invalid inputs must be rejected.
pub fn next_base_fee_checked(
    base_fee: u64,
    gas_used: u64,
    gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> BaseFeeResult<u64> {
    // Record computation attempt.
    if let Some(m) = metrics {
        m.record_computation();
    }

    // ── Validation ──────────────────────────────────────────────────────
    if config.strict_validation {
        if gas_limit == 0 {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            return Err(BaseFeeError::ZeroGasLimit);
        }
        if gas_used > gas_limit {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            return Err(BaseFeeError::GasUsedExceedsLimit { gas_used, gas_limit });
        }
        if base_fee < config.min_base_fee {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            return Err(BaseFeeError::BaseFeeBelowMin {
                base_fee,
                min: config.min_base_fee,
            });
        }
        if base_fee > config.max_base_fee {
            if let Some(m) = metrics {
                m.record_validation_failure();
            }
            return Err(BaseFeeError::BaseFeeAboveMax {
                base_fee,
                max: config.max_base_fee,
            });
        }
    } else if gas_limit == 0 {
        return Ok(base_fee.clamp(config.min_base_fee, config.max_base_fee));
    }

    // ── Compute target gas ─────────────────────────────────────────────
    let target = gas_limit / config.target_fraction_denom;
    if target == 0 {
        return Err(BaseFeeError::ZeroTarget {
            gas_limit,
            denom: config.target_fraction_denom,
        });
    }

    // ── No change case ─────────────────────────────────────────────────
    if gas_used == target {
        if let Some(m) = metrics {
            m.record_unchanged();
        }
        if config.log_adjustments {
            trace!(
                base_fee,
                gas_used,
                target,
                "base_fee unchanged (at target)"
            );
        }
        return Ok(base_fee);
    }

    // ── Compute change using 128-bit arithmetic ───────────────────────
    let gas_delta = if gas_used > target {
        gas_used - target
    } else {
        target - gas_used
    };

    let numerator = (base_fee as u128)
        .checked_mul(gas_delta as u128)
        .ok_or(BaseFeeError::Overflow)?;
    let divisor = (target as u128)
        .checked_mul(config.elasticity_multiplier as u128)
        .ok_or(BaseFeeError::Overflow)?;
    let change_u128 = numerator / divisor;

    // ── Convert change to u64 safely ──────────────────────────────────
    // If change_u128 > u64::MAX, the fee saturates anyway, so clamp the
    // intermediate value to u64::MAX to avoid silent truncation.
    let change_u: u64 = if change_u128 > u64::MAX as u128 {
        u64::MAX
    } else {
        change_u128 as u64
    };

    let new_fee = if gas_used > target {
        // Increase: at least 1 wei.
        base_fee.saturating_add(change_u.max(1))
    } else {
        // Decrease: can go down to min_base_fee.
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
                new_fee,
                clamped,
                min = config.min_base_fee,
                max = config.max_base_fee,
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
            gas_used,
            gas_limit,
            target,
            elasticity = config.elasticity_multiplier,
            "base_fee adjusted"
        );
    }

    Ok(clamped)
}

// ── Convenience Functions ──────────────────────────────────────────────

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

/// Strict variant from a previous block header.
pub fn next_base_fee_from_header_checked(
    header: &crate::types::BlockHeader,
    next_gas_limit: u64,
    config: &BaseFeeConfig,
    metrics: Option<&BaseFeeMetrics>,
) -> BaseFeeResult<u64> {
    next_base_fee_checked(
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

/// Thread‑safe manager for base fee calculations with metrics.
#[derive(Clone)]
pub struct BaseFeeManager {
    config: Arc<BaseFeeConfig>,
    metrics: Arc<BaseFeeMetrics>,
}

impl BaseFeeManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: BaseFeeConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = BaseFeeMetrics::new(config.enable_metrics)
            .map_err(|e| format!("failed to register base fee metrics: {}", e))?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
        })
    }

    /// Create a manager with default configuration.
    pub fn default() -> Self {
        Self::new(BaseFeeConfig::default()).expect("default base fee config should be valid")
    }

    /// Compute the next base fee (infallible, clamps on error).
    pub fn compute(&self, base_fee: u64, gas_used: u64, gas_limit: u64) -> u64 {
        next_base_fee(
            base_fee,
            gas_used,
            gas_limit,
            &self.config,
            Some(&self.metrics),
        )
    }

    /// Compute the next base fee (strict).
    pub fn compute_checked(
        &self,
        base_fee: u64,
        gas_used: u64,
        gas_limit: u64,
    ) -> BaseFeeResult<u64> {
        next_base_fee_checked(
            base_fee,
            gas_used,
            gas_limit,
            &self.config,
            Some(&self.metrics),
        )
    }

    /// Compute from a header (infallible).
    pub fn compute_from_header(
        &self,
        header: &crate::types::BlockHeader,
        next_gas_limit: u64,
    ) -> u64 {
        next_base_fee_from_header(header, next_gas_limit, &self.config, Some(&self.metrics))
    }

    /// Compute from a header (strict).
    pub fn compute_from_header_checked(
        &self,
        header: &crate::types::BlockHeader,
        next_gas_limit: u64,
    ) -> BaseFeeResult<u64> {
        next_base_fee_from_header_checked(
            header,
            next_gas_limit,
            &self.config,
            Some(&self.metrics),
        )
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
        self.metrics.reset();
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
        let gas_used = 25_000_000;
        let gas_limit = 30_000_000;
        // target = 15e6, delta = 10e6, change = 1e9 * 10e6 / 15e6 / 8 ≈ 83_333_333
        let expected = base_fee + 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_decrease() {
        let config = test_config();
        let base_fee = 1_000_000_000;
        let gas_used = 5_000_000;
        let gas_limit = 30_000_000;
        let expected = base_fee - 83_333_333;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_min_increase() {
        let config = test_config();
        let base_fee = 1;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let expected = base_fee + 1;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), expected);
    }

    #[test]
    fn test_next_base_fee_zero_limit() {
        let config = test_config();
        let base_fee = 100;
        // Infallible variant returns clamped base_fee on error.
        assert_eq!(next_base_fee(base_fee, 50, 0, &config, None), base_fee);
    }

    #[test]
    fn test_next_base_fee_target_zero() {
        let config = test_config();
        let base_fee = 100;
        // gas_limit = 1 → target = 0, infallible variant returns clamped base_fee.
        assert_eq!(next_base_fee(base_fee, 0, 1, &config, None), base_fee);
    }

    #[test]
    fn test_next_base_fee_zero_base() {
        let config = test_config();
        // Zero base fee violates min_base_fee in strict mode; infallible
        // variant clamps to min_base_fee.
        let base_fee = 0;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        assert_eq!(next_base_fee(base_fee, gas_used, gas_limit, &config, None), 1);
    }

    #[test]
    fn test_next_base_fee_saturation() {
        let config = BaseFeeConfig {
            max_base_fee: u64::MAX,
            ..Default::default()
        };
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
            strict_validation: false,
            ..Default::default()
        };
        let base_fee = 1;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        assert_eq!(result, 10);
    }

    #[test]
    fn test_next_base_fee_clamp_max() {
        let config = BaseFeeConfig {
            min_base_fee: 1,
            max_base_fee: 100,
            ..Default::default()
        };
        let base_fee = 90;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        assert_eq!(result, 100);
    }

    #[test]
    fn test_checked_zero_gas_limit() {
        let config = test_config();
        let result = next_base_fee_checked(100, 50, 0, &config, None);
        assert!(matches!(result, Err(BaseFeeError::ZeroGasLimit)));
    }

    #[test]
    fn test_checked_gas_used_exceeds() {
        let config = test_config();
        let result = next_base_fee_checked(100, 50, 30, &config, None);
        assert!(matches!(result, Err(BaseFeeError::GasUsedExceedsLimit { .. })));
    }

    #[test]
    fn test_checked_base_fee_below_min() {
        let config = test_config();
        let result = next_base_fee_checked(0, 15_000_000, 30_000_000, &config, None);
        assert!(matches!(result, Err(BaseFeeError::BaseFeeBelowMin { .. })));
    }

    #[test]
    fn test_checked_base_fee_above_max() {
        let config = BaseFeeConfig {
            max_base_fee: 100,
            ..Default::default()
        };
        let result = next_base_fee_checked(200, 15_000_000, 30_000_000, &config, None);
        assert!(matches!(result, Err(BaseFeeError::BaseFeeAboveMax { .. })));
    }

    #[test]
    fn test_checked_success() {
        let config = test_config();
        let result = next_base_fee_checked(1_000_000_000, 25_000_000, 30_000_000, &config, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1_000_000_000 + 83_333_333);
    }

    #[test]
    fn test_metrics() {
        let config = test_config();
        let metrics = BaseFeeMetrics::default();
        let base_fee = 1_000_000_000;

        next_base_fee(base_fee, 15_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.unchanged.load(Ordering::Relaxed), 1);

        next_base_fee(base_fee, 25_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.increases.load(Ordering::Relaxed), 1);

        next_base_fee(base_fee, 5_000_000, 30_000_000, &config, Some(&metrics));
        assert_eq!(metrics.decreases.load(Ordering::Relaxed), 1);

        assert_eq!(metrics.computations.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_prometheus_metrics() {
        // Use unregistered to avoid global registry clashes.
        let p = BaseFeePrometheus::new_unregistered();
        p.computations_total.inc();
        p.increases_total.inc_by(2);
        p.decreases_total.inc_by(3);
        p.saturated_total.inc();
        p.validation_failures_total.inc_by(4);
        assert_eq!(p.computations_total.get(), 1);
        assert_eq!(p.increases_total.get(), 2);
        assert_eq!(p.decreases_total.get(), 3);
        assert_eq!(p.saturated_total.get(), 1);
        assert_eq!(p.validation_failures_total.get(), 4);
    }

    #[test]
    fn test_manager() {
        let config = test_config();
        let manager = BaseFeeManager::new(config).unwrap();
        let result = manager.compute(1_000_000_000, 25_000_000, 30_000_000);
        let expected = next_base_fee(
            1_000_000_000,
            25_000_000,
            30_000_000,
            &BaseFeeConfig::default(),
            None,
        );
        assert_eq!(result, expected);
        assert!(manager.metrics_snapshot().computations > 0);
    }

    #[test]
    fn test_manager_checked() {
        let manager = BaseFeeManager::default();
        let result = manager.compute_checked(1_000_000_000, 25_000_000, 30_000_000);
        assert!(result.is_ok());
        let result = manager.compute_checked(1_000_000_000, 40_000_000, 30_000_000);
        assert!(matches!(result, Err(BaseFeeError::GasUsedExceedsLimit { .. })));
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
    fn test_gas_used_exceeds_gas_limit_non_strict() {
        let config = BaseFeeConfig {
            strict_validation: false,
            ..Default::default()
        };
        let base_fee = 1_000_000_000;
        let gas_used = 40_000_000;
        let gas_limit = 30_000_000;
        // In non-strict mode, we still compute but with clamped gas_used.
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        // In non-strict mode, gas_used is not clamped; computation proceeds.
        // The formula uses (gas_used - target), so gas_used = 40e6, target = 15e6,
        // delta = 25e6, change = 1e9 * 25e6 / 15e6 / 8 ≈ 208_333_333
        let expected = base_fee + 208_333_333;
        assert_eq!(result, expected);
    }

    #[test]
    fn test_default_config_compatibility() {
        let result = next_base_fee_default(1_000_000_000, 25_000_000, 30_000_000);
        let expected = next_base_fee(
            1_000_000_000,
            25_000_000,
            30_000_000,
            &BaseFeeConfig::default(),
            None,
        );
        assert_eq!(result, expected);
    }

    #[test]
    fn test_overflow_protection_large_values() {
        // Use large values close to u64::MAX to verify no silent truncation.
        let config = BaseFeeConfig {
            max_base_fee: u64::MAX,
            ..Default::default()
        };
        let base_fee = u64::MAX / 2;
        let gas_used = 30_000_000;
        let gas_limit = 30_000_000;
        let result = next_base_fee(base_fee, gas_used, gas_limit, &config, None);
        // Result should be at least base_fee (saturating at u64::MAX).
        assert!(result >= base_fee);
    }
}
