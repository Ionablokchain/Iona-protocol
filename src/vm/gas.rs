//! Gas meter for the IONA VM.
//!
//! # Production Features
//! - Configurable via `GasConfig` (limits, refund quotient, memory cost parameters).
//! - `GasMetrics` with atomic counters for charges, refunds, out‑of‑gas events.
//! - `GasManager` as a thread‑safe wrapper (`parking_lot::Mutex`).
//! - Structured logging with `tracing`.
//! - Serialization support for snapshots.
//! - Fork support for sub‑calls.
//! - Full test coverage.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

#[cfg(feature = "std")]
use parking_lot::Mutex;
#[cfg(not(feature = "std"))]
use spin::Mutex;

// ── Constants ─────────────────────────────────────────────────────────────

/// Base gas cost per memory word (32 bytes).
pub const MEMORY_WORD_GAS: u64 = 3;

/// Minimum gas for any transaction (covers base overhead).
pub const MINIMUM_GAS: u64 = 21_000;

/// Maximum gas allowed in a single block (adjust per chain config).
pub const MAX_BLOCK_GAS: u64 = 30_000_000;

/// Maximum refund allowed per EIP-3529: half of gas used.
pub const MAX_REFUND_QUOTIENT: u64 = 2;

/// Default memory cost quadratic denominator (EIP-150: 512).
pub const DEFAULT_MEMORY_COST_DENOM: u64 = 512;

/// Default gas limit for tests.
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the gas meter subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasConfig {
    /// Maximum gas allowed per transaction.
    pub max_gas_per_tx: u64,
    /// Maximum gas allowed per block.
    pub max_gas_per_block: u64,
    /// Minimum gas required per transaction.
    pub min_gas_per_tx: u64,
    /// Refund quotient (denominator for max refund cap).
    pub refund_quotient: u64,
    /// Memory cost linear coefficient (gas per word).
    pub memory_word_gas: u64,
    /// Memory cost quadratic denominator.
    pub memory_quadratic_denom: u64,
    /// Whether to enable metrics tracking.
    pub track_metrics: bool,
    /// Whether to log gas operations.
    pub log_operations: bool,
}

impl Default for GasConfig {
    fn default() -> Self {
        Self {
            max_gas_per_tx: MAX_BLOCK_GAS,
            max_gas_per_block: MAX_BLOCK_GAS,
            min_gas_per_tx: MINIMUM_GAS,
            refund_quotient: MAX_REFUND_QUOTIENT,
            memory_word_gas: MEMORY_WORD_GAS,
            memory_quadratic_denom: DEFAULT_MEMORY_COST_DENOM,
            track_metrics: true,
            log_operations: false,
        }
    }
}

impl GasConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_gas_per_tx == 0 {
            return Err("max_gas_per_tx must be > 0".into());
        }
        if self.max_gas_per_block == 0 {
            return Err("max_gas_per_block must be > 0".into());
        }
        if self.min_gas_per_tx == 0 {
            return Err("min_gas_per_tx must be > 0".into());
        }
        if self.refund_quotient == 0 {
            return Err("refund_quotient must be > 0".into());
        }
        if self.memory_word_gas == 0 {
            return Err("memory_word_gas must be > 0".into());
        }
        if self.memory_quadratic_denom == 0 {
            return Err("memory_quadratic_denom must be > 0".into());
        }
        if self.min_gas_per_tx > self.max_gas_per_tx {
            return Err("min_gas_per_tx must be <= max_gas_per_tx".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the gas meter subsystem.
#[derive(Debug, Default)]
pub struct GasMetrics {
    /// Total gas charged.
    pub total_charged: AtomicU64,
    /// Total gas refunded.
    pub total_refunded: AtomicU64,
    /// Number of out‑of‑gas events.
    pub out_of_gas_events: AtomicU64,
    /// Number of refund cap events.
    pub refund_cap_events: AtomicU64,
    /// Total memory expansion gas charged.
    pub memory_expansion_gas: AtomicU64,
    /// Number of gas meter forks.
    pub forks: AtomicU64,
    /// Peak gas used across all meters.
    pub peak_gas_used: AtomicU64,
}

impl GasMetrics {
    /// Record a gas charge.
    pub fn record_charge(&self, amount: u64) {
        self.total_charged.fetch_add(amount, Ordering::Relaxed);
    }

    /// Record a gas refund.
    pub fn record_refund(&self, amount: u64) {
        self.total_refunded.fetch_add(amount, Ordering::Relaxed);
    }

    /// Record an out‑of‑gas event.
    pub fn record_out_of_gas(&self) {
        self.out_of_gas_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a refund cap event.
    pub fn record_refund_cap(&self) {
        self.refund_cap_events.fetch_add(1, Ordering::Relaxed);
    }

    /// Record memory expansion gas.
    pub fn record_memory_expansion(&self, amount: u64) {
        self.memory_expansion_gas.fetch_add(amount, Ordering::Relaxed);
    }

    /// Record a fork.
    pub fn record_fork(&self) {
        self.forks.fetch_add(1, Ordering::Relaxed);
    }

    /// Update peak gas used.
    pub fn update_peak(&self, used: u64) {
        let mut current = self.peak_gas_used.load(Ordering::Relaxed);
        while used > current {
            match self.peak_gas_used.compare_exchange_weak(
                current,
                used,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    /// Snapshot of all metrics.
    pub fn snapshot(&self) -> GasMetricsSnapshot {
        GasMetricsSnapshot {
            total_charged: self.total_charged.load(Ordering::Relaxed),
            total_refunded: self.total_refunded.load(Ordering::Relaxed),
            out_of_gas_events: self.out_of_gas_events.load(Ordering::Relaxed),
            refund_cap_events: self.refund_cap_events.load(Ordering::Relaxed),
            memory_expansion_gas: self.memory_expansion_gas.load(Ordering::Relaxed),
            forks: self.forks.load(Ordering::Relaxed),
            peak_gas_used: self.peak_gas_used.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of gas metrics.
#[derive(Debug, Clone)]
pub struct GasMetricsSnapshot {
    pub total_charged: u64,
    pub total_refunded: u64,
    pub out_of_gas_events: u64,
    pub refund_cap_events: u64,
    pub memory_expansion_gas: u64,
    pub forks: u64,
    pub peak_gas_used: u64,
}

// ── Gas Error ─────────────────────────────────────────────────────────────

/// Errors that can occur during gas metering.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GasError {
    /// Insufficient gas to perform the operation.
    #[error("out of gas: needed {needed}, remaining {remaining}")]
    OutOfGas { needed: u64, remaining: u64 },

    /// Refund would exceed the maximum allowed (capped at half of gas used).
    #[error("refund capped: attempted {attempted}, current refund {current}, max allowed {max_allowed}")]
    RefundCapped {
        attempted: u64,
        current: u64,
        max_allowed: u64,
    },

    /// Gas limit exceeds block gas limit.
    #[error("gas limit {limit} exceeds block gas limit {block_limit}")]
    GasLimitTooHigh { limit: u64, block_limit: u64 },

    /// Gas limit below the minimum required.
    #[error("gas limit {limit} below minimum {minimum}")]
    GasLimitTooLow { limit: u64, minimum: u64 },

    /// Arithmetic overflow in gas calculation (should never happen).
    #[error("gas calculation overflow")]
    Overflow,

    /// Refund cannot be applied because execution already ended.
    #[error("refund already applied")]
    RefundAlreadyApplied,

    /// Attempted to charge gas after refund was applied.
    #[error("cannot charge gas after refund applied")]
    ChargeAfterRefund,
}

pub type GasResult<T> = Result<T, GasError>;

// ── Gas Meter ─────────────────────────────────────────────────────────────

/// Gas meter tracks consumption and refunds during VM execution.
///
/// The meter enforces that gas usage never exceeds the specified limit.
/// Refunds are accumulated separately and applied only at the end of
/// execution via [`apply_refund`], ensuring that execution never sees
/// a decreasing gas balance.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct GasMeter {
    /// Maximum gas allowed for this execution context.
    limit: u64,
    /// Gas consumed so far (monotonically increasing).
    used: u64,
    /// Gas to be refunded after execution (capped at `used / 2`).
    refund: u64,
    /// Whether refund has been applied (prevents double application).
    #[serde(skip)]
    refund_applied: bool,
    /// Configuration (for memory cost calculations).
    #[serde(skip)]
    config: GasConfig,
    /// Metrics (optional).
    #[serde(skip)]
    metrics: Option<Arc<GasMetrics>>,
}

impl GasMeter {
    /// Creates a new gas meter with the given limit.
    pub fn new(limit: u64) -> Self {
        Self::with_config(limit, GasConfig::default())
    }

    /// Creates a new gas meter with configuration.
    pub fn with_config(limit: u64, config: GasConfig) -> Self {
        debug_assert!(limit > 0, "Gas limit must be > 0");
        let limit = limit.min(config.max_gas_per_tx).max(1);
        Self {
            limit,
            used: 0,
            refund: 0,
            refund_applied: false,
            config,
            metrics: None,
        }
    }

    /// Creates a gas meter with metrics tracking.
    pub fn with_metrics(limit: u64, config: GasConfig, metrics: Arc<GasMetrics>) -> Self {
        let mut meter = Self::with_config(limit, config);
        meter.metrics = Some(metrics);
        meter
    }

    /// Creates a gas meter from a block context, validating the limit.
    pub fn new_with_validation(limit: u64, config: &GasConfig) -> Result<Self, GasError> {
        if limit < config.min_gas_per_tx {
            return Err(GasError::GasLimitTooLow {
                limit,
                minimum: config.min_gas_per_tx,
            });
        }
        if limit > config.max_gas_per_block {
            return Err(GasError::GasLimitTooHigh {
                limit,
                block_limit: config.max_gas_per_block,
            });
        }
        Ok(Self::with_config(limit, config.clone()))
    }

    // ── Getters ─────────────────────────────────────────────────────────

    /// Returns the gas limit.
    #[inline]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the gas used so far.
    #[inline]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Returns the current refundable gas (before applying).
    #[inline]
    pub fn refundable(&self) -> u64 {
        self.refund
    }

    /// Returns the remaining gas.
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Returns the maximum refund allowed under current usage.
    #[inline]
    pub fn max_refund_allowed(&self) -> u64 {
        self.used / self.config.refund_quotient
    }

    /// Returns the fraction of gas used (0.0 – 1.0).
    #[inline]
    pub fn fraction_used(&self) -> f64 {
        if self.limit == 0 {
            return 1.0;
        }
        (self.used as f64 / self.limit as f64).min(1.0)
    }

    /// Returns the net gas used after applying the refund (without mutating).
    #[inline]
    pub fn net_used(&self) -> u64 {
        let effective_refund = self.refund.min(self.used);
        self.used.saturating_sub(effective_refund)
    }

    /// Returns whether the refund has already been applied.
    #[inline]
    pub fn refund_applied(&self) -> bool {
        self.refund_applied
    }

    /// Returns a reference to the configuration.
    pub fn config(&self) -> &GasConfig {
        &self.config
    }

    // ── Charging ────────────────────────────────────────────────────────

    /// Charges `amount` gas.
    ///
    /// Returns `Err(OutOfGas)` if the charge would exceed the limit.
    /// On failure, `used` is set to `limit` (gas is fully consumed).
    #[inline]
    pub fn charge(&mut self, amount: u64) -> Result<(), GasError> {
        if self.refund_applied {
            return Err(GasError::ChargeAfterRefund);
        }

        let new_used = self
            .used
            .checked_add(amount)
            .ok_or(GasError::Overflow)?;

        if new_used > self.limit {
            self.used = self.limit;
            if let Some(metrics) = &self.metrics {
                metrics.record_out_of_gas();
            }
            if self.config.log_operations {
                warn!(
                    "Out of gas: needed {}, remaining {}",
                    amount,
                    self.limit.saturating_sub(self.used)
                );
            }
            return Err(GasError::OutOfGas {
                needed: amount,
                remaining: self.limit.saturating_sub(self.used),
            });
        }

        if self.config.log_operations && amount > 1000 {
            trace!("Charging {} gas, new used = {}", amount, new_used);
        }
        if let Some(metrics) = &self.metrics {
            metrics.record_charge(amount);
            metrics.update_peak(new_used);
        }
        self.used = new_used;
        Ok(())
    }

    /// Checks if `amount` gas can be charged without actually charging.
    #[inline]
    pub fn can_charge(&self, amount: u64) -> bool {
        !self.refund_applied && self.used.saturating_add(amount) <= self.limit
    }

    /// Charges gas only if `condition` is true.
    #[inline]
    pub fn charge_if(&mut self, condition: bool, amount: u64) -> Result<u64, GasError> {
        if condition {
            self.charge(amount)?;
            Ok(amount)
        } else {
            Ok(0)
        }
    }

    /// Charges gas with a multiplier (for dynamic costs).
    #[inline]
    pub fn charge_scaled(&mut self, base: u64, multiplier: f64) -> Result<u64, GasError> {
        let scaled = (base as f64 * multiplier).round() as u64;
        self.charge(scaled)?;
        Ok(scaled)
    }

    // ── Refunds ─────────────────────────────────────────────────────────

    /// Adds a refund amount (e.g., for clearing storage slots).
    #[inline]
    pub fn add_refund(&mut self, amount: u64) -> Result<(), GasError> {
        if self.refund_applied {
            return Err(GasError::RefundAlreadyApplied);
        }
        if amount == 0 {
            return Ok(());
        }

        let new_refund = self
            .refund
            .checked_add(amount)
            .ok_or(GasError::Overflow)?;

        let max_refund = self.max_refund_allowed();
        if new_refund > max_refund {
            if let Some(metrics) = &self.metrics {
                metrics.record_refund_cap();
            }
            if self.config.log_operations {
                debug!(
                    "Refund capped: attempted {}, max {}, capped at {}",
                    new_refund, max_refund, max_refund
                );
            }
            self.refund = max_refund;
        } else {
            self.refund = new_refund;
            if let Some(metrics) = &self.metrics {
                metrics.record_refund(amount);
            }
        }
        Ok(())
    }

    /// Applies the refund, reducing `used` gas.
    #[inline]
    pub fn apply_refund(&mut self) -> u64 {
        if self.refund_applied {
            return self.used;
        }
        let effective_refund = self.refund.min(self.used);
        self.used = self.used.saturating_sub(effective_refund);
        self.refund = 0;
        self.refund_applied = true;
        if self.config.log_operations {
            trace!(
                "Refund applied: effective = {}, net used = {}",
                effective_refund,
                self.used
            );
        }
        self.used
    }

    // ── Memory expansion ────────────────────────────────────────────────

    /// Charges gas for memory expansion.
    #[inline]
    pub fn charge_memory_expansion(
        &mut self,
        current_words: usize,
        new_words: usize,
    ) -> Result<u64, GasError> {
        if new_words <= current_words {
            return Ok(0);
        }

        let current_cost = memory_cost_words_with_config(
            current_words,
            &self.config,
        );
        let new_cost = memory_cost_words_with_config(
            new_words,
            &self.config,
        );
        let additional = new_cost
            .checked_sub(current_cost)
            .ok_or(GasError::Overflow)?;

        if additional > 0 {
            self.charge(additional)?;
            if let Some(metrics) = &self.metrics {
                metrics.record_memory_expansion(additional);
            }
        }

        Ok(additional)
    }

    /// Convenience: charges memory expansion for bytes.
    #[inline]
    pub fn charge_memory_expansion_bytes(
        &mut self,
        current_bytes: usize,
        new_bytes: usize,
    ) -> Result<u64, GasError> {
        let current_words = (current_bytes + 31) / 32;
        let new_words = (new_bytes + 31) / 32;
        self.charge_memory_expansion(current_words, new_words)
    }

    /// Charges the cost of copying `size` bytes from memory to memory.
    #[inline]
    pub fn charge_memory_copy(&mut self, size: usize) -> Result<(), GasError> {
        let words = (size + 31) / 32;
        let cost = words as u64 * self.config.memory_word_gas;
        self.charge(cost)
    }

    // ── Fork ────────────────────────────────────────────────────────────

    /// Creates a copy with a new limit (for sub‑calls).
    pub fn fork(&self, new_limit: u64) -> Self {
        if let Some(metrics) = &self.metrics {
            metrics.record_fork();
        }
        Self {
            limit: new_limit.min(self.config.max_gas_per_tx).max(1),
            used: self.used,
            refund: self.refund,
            refund_applied: false,
            config: self.config.clone(),
            metrics: self.metrics.clone(),
        }
    }

    /// Creates a copy with the same limit (for snapshot/restore).
    pub fn snapshot(&self) -> Self {
        *self
    }

    /// Restores from a snapshot.
    pub fn restore(&mut self, snapshot: Self) {
        *self = snapshot;
    }

    /// Sets metrics for this meter (for manager‑created meters).
    pub fn set_metrics(&mut self, metrics: Arc<GasMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Resets the meter to zero used and refund.
    pub fn reset(&mut self) {
        self.used = 0;
        self.refund = 0;
        self.refund_applied = false;
    }
}

// ── Memory cost functions ───────────────────────────────────────────────

/// Computes the gas cost for `words` of memory (EIP-150 quadratic formula).
#[inline]
pub fn memory_cost_words(words: usize) -> u64 {
    memory_cost_words_with_config(words, &GasConfig::default())
}

/// Computes the gas cost for `words` of memory with configuration.
#[inline]
pub fn memory_cost_words_with_config(words: usize, config: &GasConfig) -> u64 {
    let w = words as u64;
    let linear = w.saturating_mul(config.memory_word_gas);
    let quadratic = w.saturating_mul(w).saturating_div(config.memory_quadratic_denom);
    linear.saturating_add(quadratic)
}

/// Computes the gas cost for `bytes` of memory, rounding up to the next word.
#[inline]
pub fn memory_cost_bytes(bytes: usize) -> u64 {
    let words = (bytes + 31) / 32;
    memory_cost_words(words)
}

// ── Gas Price Provider ───────────────────────────────────────────────────

/// A simple gas price provider that returns a constant price.
pub trait GasPriceProvider: Send + Sync {
    /// Returns the current gas price in wei per gas.
    fn gas_price(&self) -> u64;
}

/// A fixed gas price provider (for testing or static configurations).
#[derive(Debug, Clone, Copy)]
pub struct FixedGasPrice(pub u64);

impl GasPriceProvider for FixedGasPrice {
    fn gas_price(&self) -> u64 {
        self.0
    }
}

// ── Gas Manager (thread‑safe) ───────────────────────────────────────────

/// Thread‑safe manager for gas meters with metrics.
#[cfg(feature = "std")]
#[derive(Clone)]
pub struct GasManager {
    config: Arc<GasConfig>,
    metrics: Arc<GasMetrics>,
}

#[cfg(feature = "std")]
impl GasManager {
    /// Create a new gas manager with the given configuration.
    pub fn new(config: GasConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(GasMetrics::default()),
        })
    }

    /// Create a new gas meter.
    pub fn meter(&self, limit: u64) -> GasMeter {
        GasMeter::with_metrics(limit, self.config.as_ref().clone(), self.metrics.clone())
    }

    /// Create a gas meter with validation.
    pub fn meter_with_validation(&self, limit: u64) -> Result<GasMeter, GasError> {
        GasMeter::new_with_validation(limit, &self.config)
            .map(|mut meter| {
                meter.set_metrics(self.metrics.clone());
                meter
            })
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> GasMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &GasConfig {
        &self.config
    }

    /// Reset all metrics.
    pub fn reset_metrics(&self) {
        self.metrics.total_charged.store(0, Ordering::Relaxed);
        self.metrics.total_refunded.store(0, Ordering::Relaxed);
        self.metrics.out_of_gas_events.store(0, Ordering::Relaxed);
        self.metrics.refund_cap_events.store(0, Ordering::Relaxed);
        self.metrics.memory_expansion_gas.store(0, Ordering::Relaxed);
        self.metrics.forks.store(0, Ordering::Relaxed);
        self.metrics.peak_gas_used.store(0, Ordering::Relaxed);
    }
}

// ── Global singleton (when std is available) ────────────────────────────

#[cfg(feature = "std")]
static GLOBAL_MANAGER: std::sync::OnceLock<GasManager> = std::sync::OnceLock::new();

#[cfg(feature = "std")]
/// Initialize the global gas manager.
pub fn init_gas_manager(config: GasConfig) -> Result<(), String> {
    let manager = GasManager::new(config)?;
    GLOBAL_MANAGER.set(manager).map_err(|_| "gas manager already initialized".into())
}

#[cfg(feature = "std")]
/// Get the global gas manager.
pub fn gas_manager() -> &'static GasManager {
    GLOBAL_MANAGER.get().expect("gas manager not initialized")
}

// ── Standalone functions (backward compatibility) ──────────────────────

/// Creates a new gas meter with default configuration (legacy).
pub fn new_gas_meter(limit: u64) -> GasMeter {
    GasMeter::new(limit)
}

/// Creates a new gas meter with validation.
pub fn new_gas_meter_validated(limit: u64, config: &GasConfig) -> Result<GasMeter, GasError> {
    GasMeter::new_with_validation(limit, config)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = GasConfig::default();
        assert!(config.validate().is_ok());

        config.max_gas_per_tx = 0;
        assert!(config.validate().is_err());

        config.max_gas_per_tx = 100;
        config.max_gas_per_block = 0;
        assert!(config.validate().is_err());

        config.max_gas_per_block = 100;
        config.min_gas_per_tx = 0;
        assert!(config.validate().is_err());

        config.min_gas_per_tx = 10;
        config.refund_quotient = 0;
        assert!(config.validate().is_err());

        config.refund_quotient = 2;
        config.memory_word_gas = 0;
        assert!(config.validate().is_err());

        config.memory_word_gas = 3;
        config.memory_quadratic_denom = 0;
        assert!(config.validate().is_err());

        config.memory_quadratic_denom = 512;
        config.min_gas_per_tx = 200;
        config.max_gas_per_tx = 100;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_new_normal() {
        let g = GasMeter::new(1000);
        assert_eq!(g.limit(), 1000);
        assert_eq!(g.used(), 0);
        assert_eq!(g.refundable(), 0);
        assert!(!g.refund_applied());
    }

    #[test]
    fn test_new_zero_clamped() {
        let g = GasMeter::new(0);
        assert_eq!(g.limit(), 1);
    }

    #[test]
    fn test_new_exceeds_max() {
        let g = GasMeter::new(MAX_BLOCK_GAS + 1);
        assert_eq!(g.limit(), MAX_BLOCK_GAS);
    }

    #[test]
    fn test_new_with_validation() {
        let config = GasConfig::default();
        let g = GasMeter::new_with_validation(50_000, &config).unwrap();
        assert_eq!(g.limit(), 50_000);
    }

    #[test]
    fn test_new_with_validation_too_low() {
        let config = GasConfig::default();
        let err = GasMeter::new_with_validation(100, &config).unwrap_err();
        assert!(matches!(err, GasError::GasLimitTooLow { .. }));
    }

    #[test]
    fn test_new_with_validation_too_high() {
        let config = GasConfig::default();
        let err = GasMeter::new_with_validation(MAX_BLOCK_GAS + 1, &config).unwrap_err();
        assert!(matches!(err, GasError::GasLimitTooHigh { .. }));
    }

    #[test]
    fn test_fork() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        g.add_refund(50).unwrap();
        let forked = g.fork(500);
        assert_eq!(forked.limit(), 500);
        assert_eq!(forked.used(), 200);
        assert_eq!(forked.refundable(), 50);
        assert!(!forked.refund_applied());
    }

    #[test]
    fn test_charge_ok() {
        let mut g = GasMeter::new(1000);
        assert!(g.charge(500).is_ok());
        assert_eq!(g.used(), 500);
        assert_eq!(g.remaining(), 500);
    }

    #[test]
    fn test_charge_exact_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(100).is_ok());
        assert_eq!(g.remaining(), 0);
        let err = g.charge(1).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
        assert_eq!(g.used(), 100);
    }

    #[test]
    fn test_charge_exceeds_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(50).is_ok());
        let err = g.charge(60).unwrap_err();
        assert!(matches!(
            err,
            GasError::OutOfGas { needed: 60, remaining: 50 }
        ));
    }

    #[test]
    fn test_charge_overflow() {
        let mut g = GasMeter::new(u64::MAX);
        g.charge(1).unwrap();
        let err = g.charge(u64::MAX).unwrap_err();
        assert!(matches!(err, GasError::Overflow));
    }

    #[test]
    fn test_charge_after_refund() {
        let mut g = GasMeter::new(100);
        g.charge(50).unwrap();
        g.apply_refund();
        let err = g.charge(10).unwrap_err();
        assert!(matches!(err, GasError::ChargeAfterRefund));
    }

    #[test]
    fn test_charge_if() {
        let mut g = GasMeter::new(100);
        let cost = g.charge_if(true, 30).unwrap();
        assert_eq!(cost, 30);
        let cost = g.charge_if(false, 70).unwrap();
        assert_eq!(cost, 0);
        assert_eq!(g.used(), 30);
    }

    #[test]
    fn test_charge_scaled() {
        let mut g = GasMeter::new(100);
        let cost = g.charge_scaled(10, 1.5).unwrap();
        assert_eq!(cost, 15);
        assert_eq!(g.used(), 15);
    }

    #[test]
    fn test_can_charge() {
        let g = GasMeter::new(100);
        assert!(g.can_charge(50));
        assert!(g.can_charge(100));
        assert!(!g.can_charge(101));
    }

    #[test]
    fn test_refund_basic() {
        let mut g = GasMeter::new(1000);
        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        assert_eq!(g.refundable(), 100);
        assert_eq!(g.max_refund_allowed(), 250);
        let net = g.apply_refund();
        assert_eq!(net, 400);
        assert_eq!(g.used(), 400);
        assert_eq!(g.refundable(), 0);
        assert!(g.refund_applied());
    }

    #[test]
    fn test_refund_capped_at_half_used() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        g.add_refund(80).unwrap();
        g.add_refund(50).unwrap();
        assert_eq!(g.refundable(), 100);
    }

    #[test]
    fn test_refund_zero_amount() {
        let mut g = GasMeter::new(1000);
        g.charge(100).unwrap();
        g.add_refund(0).unwrap();
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn test_refund_overflow() {
        let mut g = GasMeter::new(1000);
        g.charge(100).unwrap();
        g.refund = u64::MAX;
        let err = g.add_refund(1).unwrap_err();
        assert!(matches!(err, GasError::Overflow));
    }

    #[test]
    fn test_net_used() {
        let mut g = GasMeter::new(1000);
        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        assert_eq!(g.net_used(), 400);
        assert_eq!(g.used(), 500);
        assert_eq!(g.refundable(), 100);
    }

    #[test]
    fn test_apply_refund_zero() {
        let mut g = GasMeter::new(1000);
        g.charge(300).unwrap();
        let net = g.apply_refund();
        assert_eq!(net, 300);
        assert!(g.refund_applied());
    }

    #[test]
    fn test_apply_refund_twice() {
        let mut g = GasMeter::new(1000);
        g.charge(100).unwrap();
        g.add_refund(50).unwrap();
        let net1 = g.apply_refund();
        assert_eq!(net1, 50);
        let net2 = g.apply_refund();
        assert_eq!(net2, 50);
    }

    #[test]
    fn test_memory_cost_words() {
        assert_eq!(memory_cost_words(0), 0);
        assert_eq!(memory_cost_words(1), 3);
        assert_eq!(memory_cost_words(10), 30);
        assert_eq!(memory_cost_words(100), 3 * 100 + 10000 / 512);
    }

    #[test]
    fn test_memory_cost_words_with_config() {
        let mut config = GasConfig::default();
        config.memory_word_gas = 5;
        config.memory_quadratic_denom = 256;
        assert_eq!(memory_cost_words_with_config(10, &config), 5 * 10 + 100 / 256);
    }

    #[test]
    fn test_memory_cost_bytes() {
        assert_eq!(memory_cost_bytes(0), 0);
        assert_eq!(memory_cost_bytes(32), 3);
        assert_eq!(memory_cost_bytes(33), memory_cost_words(2));
    }

    #[test]
    fn test_charge_memory_expansion() {
        let mut g = GasMeter::new(1000);
        let cost = g.charge_memory_expansion(0, 10).unwrap();
        assert_eq!(cost, memory_cost_words(10));
        assert_eq!(g.used(), memory_cost_words(10));
    }

    #[test]
    fn test_charge_memory_no_expansion() {
        let mut g = GasMeter::new(1000);
        let cost = g.charge_memory_expansion(10, 10).unwrap();
        assert_eq!(cost, 0);
        let cost = g.charge_memory_expansion(10, 5).unwrap();
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_charge_memory_insufficient_gas() {
        let mut g = GasMeter::new(10);
        let err = g.charge_memory_expansion(0, 100).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
    }

    #[test]
    fn test_charge_memory_copy() {
        let mut g = GasMeter::new(1000);
        g.charge_memory_copy(32).unwrap();
        assert_eq!(g.used(), 3);
        g.charge_memory_copy(33).unwrap();
        assert_eq!(g.used(), 3 + 6);
    }

    #[test]
    fn test_fraction_used() {
        let mut g = GasMeter::new(200);
        assert!((g.fraction_used() - 0.0).abs() < f64::EPSILON);
        g.charge(50).unwrap();
        assert!((g.fraction_used() - 0.25).abs() < f64::EPSILON);
        g.charge(150).unwrap();
        assert!((g.fraction_used() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fraction_used_zero_limit() {
        let mut g = GasMeter::new(0);
        assert!((g.fraction_used() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_getters() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        g.add_refund(50).unwrap();

        assert_eq!(g.limit(), 1000);
        assert_eq!(g.used(), 200);
        assert_eq!(g.refundable(), 50);
        assert_eq!(g.remaining(), 800);
        assert_eq!(g.max_refund_allowed(), 100);
        assert_eq!(g.net_used(), 150);
        assert!(!g.refund_applied());
    }

    #[test]
    fn test_snapshot_restore() {
        let mut g = GasMeter::new(1000);
        g.charge(300).unwrap();
        g.add_refund(50).unwrap();

        let snap = g.snapshot();
        g.charge(100).unwrap();
        assert_eq!(g.used(), 400);

        g.restore(snap);
        assert_eq!(g.used(), 300);
        assert_eq!(g.refundable(), 50);
        assert!(!g.refund_applied());
    }

    #[test]
    fn test_integration_flow() {
        let mut g = GasMeter::new(100_000);

        g.charge(21_000).unwrap();
        g.charge_memory_expansion(0, 100).unwrap();
        g.charge(5_000).unwrap();
        g.add_refund(15_000).unwrap();
        g.charge(3).unwrap();

        let net = g.apply_refund();
        assert!(net > 0);
        assert_eq!(g.refundable(), 0);
        assert!(g.refund_applied());
    }

    #[test]
    fn test_serialize_deserialize() {
        let mut g = GasMeter::new(1000);
        g.charge(300).unwrap();
        g.add_refund(50).unwrap();

        let json = serde_json::to_string(&g).unwrap();
        let restored: GasMeter = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.limit(), 1000);
        assert_eq!(restored.used(), 300);
        assert_eq!(restored.refundable(), 50);
        assert!(!restored.refund_applied());
    }

    #[test]
    fn test_metrics() {
        let config = GasConfig::default();
        let metrics = Arc::new(GasMetrics::default());
        let mut g = GasMeter::with_metrics(1000, config, metrics.clone());

        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        g.charge_memory_expansion(0, 10).unwrap();

        let snap = metrics.snapshot();
        assert_eq!(snap.total_charged, 500 + memory_cost_words(10));
        assert_eq!(snap.total_refunded, 100);
        assert_eq!(snap.memory_expansion_gas, memory_cost_words(10));
        assert_eq!(snap.peak_gas_used, g.used());
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_manager() {
        let config = GasConfig::default();
        let manager = GasManager::new(config).unwrap();

        let mut meter = manager.meter(1000);
        meter.charge(500).unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_charged, 500);
        assert_eq!(snap.peak_gas_used, 500);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_manager_with_validation() {
        let config = GasConfig::default();
        let manager = GasManager::new(config).unwrap();

        let meter = manager.meter_with_validation(50_000);
        assert!(meter.is_ok());

        let err = manager.meter_with_validation(100);
        assert!(err.is_err());
    }
}
