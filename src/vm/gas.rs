//! Gas meter for the IONA VM.
//!
//! # Production Features
//! - Configurable via [`GasConfig`] (limits, refund quotient, memory cost
//!   parameters) with full validation.
//! - [`GasMetrics`] with atomic counters for charges, refunds, out‑of‑gas
//!   events, memory expansion, and forks.
//! - [`GasMeter`] is `Clone` but not `Copy` (it may hold an `Arc` to the
//!   metrics collector).
//! - [`GasManager`] as a thread‑safe wrapper suitable for a process‑wide
//!   singleton.
//! - Structured logging with `tracing` that includes the meter's current
//!   state and the operation that failed.
//! - Serialization captures the meter's mutable state but not the shared
//!   config/metrics handles; a deserialized meter is independent of any
//!   manager.
//! - Fork/snapshot support for sub‑calls and gas‑estimation rollback.
//! - Full test coverage, including regression tests for the refund and
//!   snapshot corner cases.
//!
//! # Concurrency
//!
//! A [`GasMeter`] is *not* internally synchronized: it is designed to be
//! owned by a single execution context. The [`GasManager`] is the shared,
//! thread‑safe object that hands out meters; it is `Send + Sync`.
//!
//! # Refund semantics
//!
//! Refunds are accrued separately from `used` and only applied at the end
//! of execution via [`GasMeter::apply_refund`]. This ensures the meter's
//! `used` value is monotonic during execution, which the VM relies on to
//! detect out‑of‑gas deterministically.
//!
//! The maximum refund is bounded by [`GasConfig::refund_quotient`] (EIP-3529
//! uses `2`, i.e. one half of `used`). Extra refund requests past the cap
//! are silently clamped and counted in the `refund_cap_events` metric.

use core::sync::atomic::{AtomicU64, Ordering};
use core::sync::OnceLock;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Base gas cost per memory word (32 bytes).
pub const MEMORY_WORD_GAS: u64 = 3;

/// Minimum gas for any transaction (covers base overhead).
pub const MINIMUM_GAS: u64 = 21_000;

/// Maximum gas allowed in a single block (per chain configuration).
pub const MAX_BLOCK_GAS: u64 = 30_000_000;

/// Maximum refund allowed per EIP-3529: half of gas used.
pub const MAX_REFUND_QUOTIENT: u64 = 2;

/// Default memory cost quadratic denominator (EIP-150: 512).
pub const DEFAULT_MEMORY_COST_DENOM: u64 = 512;

/// Default gas limit for tests.
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors produced by the gas metering subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GasError {
    #[error("out of gas: needed {needed}, remaining {remaining}")]
    OutOfGas { needed: u64, remaining: u64 },

    #[error("refund capped: attempted {attempted}, current {current}, max allowed {max_allowed}")]
    RefundCapped {
        attempted: u64,
        current: u64,
        max_allowed: u64,
    },

    #[error("gas limit {limit} exceeds block gas limit {block_limit}")]
    GasLimitTooHigh { limit: u64, block_limit: u64 },

    #[error("gas limit {limit} below minimum {minimum}")]
    GasLimitTooLow { limit: u64, minimum: u64 },

    #[error("gas calculation overflow")]
    Overflow,

    #[error("refund already applied")]
    RefundAlreadyApplied,

    #[error("cannot charge gas after refund was applied")]
    ChargeAfterRefund,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("cannot restore a snapshot from a meter with a different limit (current {current}, snapshot {snapshot})")]
    SnapshotMismatch { current: u64, snapshot: u64 },
}

pub type GasResult<T> = Result<T, GasError>;

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
    /// Refund quotient (denominator for max refund cap). EIP-3529 uses 2.
    pub refund_quotient: u64,
    /// Memory cost linear coefficient (gas per word).
    pub memory_word_gas: u64,
    /// Memory cost quadratic denominator.
    pub memory_quadratic_denom: u64,
    /// Whether to record metrics.
    pub track_metrics: bool,
    /// Whether to log gas operations (verbose; off in production).
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
    pub fn validate(&self) -> GasResult<()> {
        if self.max_gas_per_tx == 0 {
            return Err(GasError::Config("max_gas_per_tx must be > 0".into()));
        }
        if self.max_gas_per_block == 0 {
            return Err(GasError::Config("max_gas_per_block must be > 0".into()));
        }
        if self.min_gas_per_tx == 0 {
            return Err(GasError::Config("min_gas_per_tx must be > 0".into()));
        }
        if self.refund_quotient == 0 {
            return Err(GasError::Config("refund_quotient must be > 0".into()));
        }
        if self.memory_word_gas == 0 {
            return Err(GasError::Config("memory_word_gas must be > 0".into()));
        }
        if self.memory_quadratic_denom == 0 {
            return Err(GasError::Config("memory_quadratic_denom must be > 0".into()));
        }
        if self.min_gas_per_tx > self.max_gas_per_tx {
            return Err(GasError::Config(
                "min_gas_per_tx must be <= max_gas_per_tx".into(),
            ));
        }
        if self.max_gas_per_tx > self.max_gas_per_block {
            return Err(GasError::Config(
                "max_gas_per_tx must be <= max_gas_per_block".into(),
            ));
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Atomic counters for the gas meter subsystem.
///
/// All fields are `AtomicU64` so the collector can be shared across
/// concurrent meters without locking.
pub struct GasMetrics {
    pub total_charged: AtomicU64,
    pub total_refunded: AtomicU64,
    pub out_of_gas_events: AtomicU64,
    pub refund_cap_events: AtomicU64,
    pub memory_expansion_gas: AtomicU64,
    pub forks: AtomicU64,
    pub peak_gas_used: AtomicU64,
}

impl GasMetrics {
    pub const fn new() -> Self {
        Self {
            total_charged: AtomicU64::new(0),
            total_refunded: AtomicU64::new(0),
            out_of_gas_events: AtomicU64::new(0),
            refund_cap_events: AtomicU64::new(0),
            memory_expansion_gas: AtomicU64::new(0),
            forks: AtomicU64::new(0),
            peak_gas_used: AtomicU64::new(0),
        }
    }

    #[inline]
    pub fn record_charge(&self, amount: u64) {
        self.total_charged.fetch_add(amount, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_refund(&self, amount: u64) {
        self.total_refunded.fetch_add(amount, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_out_of_gas(&self) {
        self.out_of_gas_events.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_refund_cap(&self) {
        self.refund_cap_events.fetch_add(1, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_memory_expansion(&self, amount: u64) {
        self.memory_expansion_gas.fetch_add(amount, Ordering::Relaxed);
    }

    #[inline]
    pub fn record_fork(&self) {
        self.forks.fetch_add(1, Ordering::Relaxed);
    }

    /// Update peak gas used. Uses `fetch_max` so concurrent meters race
    /// safely without a `compare_exchange` loop.
    #[inline]
    pub fn update_peak(&self, used: u64) {
        self.peak_gas_used.fetch_max(used, Ordering::Relaxed);
    }

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

    /// Reset all counters.
    pub fn reset(&self) {
        self.total_charged.store(0, Ordering::Relaxed);
        self.total_refunded.store(0, Ordering::Relaxed);
        self.out_of_gas_events.store(0, Ordering::Relaxed);
        self.refund_cap_events.store(0, Ordering::Relaxed);
        self.memory_expansion_gas.store(0, Ordering::Relaxed);
        self.forks.store(0, Ordering::Relaxed);
        self.peak_gas_used.store(0, Ordering::Relaxed);
    }
}

impl Default for GasMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for GasMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GasMetrics")
            .field("total_charged", &self.total_charged.load(Ordering::Relaxed))
            .field("total_refunded", &self.total_refunded.load(Ordering::Relaxed))
            .field("out_of_gas_events", &self.out_of_gas_events.load(Ordering::Relaxed))
            .finish()
    }
}

/// Snapshot of gas metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct GasMetricsSnapshot {
    pub total_charged: u64,
    pub total_refunded: u64,
    pub out_of_gas_events: u64,
    pub refund_cap_events: u64,
    pub memory_expansion_gas: u64,
    pub forks: u64,
    pub peak_gas_used: u64,
}

// ── GasMeter ──────────────────────────────────────────────────────────────

/// Tracks gas consumption and refunds during a single execution context.
///
/// `GasMeter` is `Clone` but deliberately **not** `Copy`: it may hold an
/// `Arc<GasMetrics>` and duplicating it via `Copy` would silently double
/// the accounting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasMeter {
    /// Maximum gas allowed for this execution context.
    limit: u64,
    /// Gas consumed so far (monotonically non-decreasing until
    /// `apply_refund` runs).
    used: u64,
    /// Pending refund. Applied only at the end of execution.
    refund: u64,
    /// Cached `used / refund_quotient`. Recomputed on every charge.
    #[serde(skip)]
    max_refund_cache: u64,
    /// Whether `apply_refund` has already run.
    #[serde(skip)]
    refund_applied: bool,
    /// Configuration. Not serialized; a deserialized meter must be
    /// re-attached to a manager before use.
    #[serde(skip, default = "GasConfig::default")]
    config: GasConfig,
    /// Optional metrics collector. Not serialized.
    #[serde(skip)]
    metrics: Option<Arc<GasMetrics>>,
}

impl GasMeter {
    /// Create a new meter with the given limit and the default config.
    ///
    /// The limit is clamped to `[1, max_gas_per_tx]` from the default
    /// configuration. Use [`GasMeter::new_with_validation`] if you want
    /// the limit checked instead of clamped.
    pub fn new(limit: u64) -> Self {
        Self::with_config(limit, GasConfig::default())
    }

    /// Create a new meter with the given limit and configuration.
    ///
    /// The limit is clamped to `[1, config.max_gas_per_tx]`.
    pub fn with_config(limit: u64, config: GasConfig) -> Self {
        let clamped = limit.min(config.max_gas_per_tx).max(1);
        if clamped != limit {
            debug!(
                requested = limit,
                clamped,
                "GasMeter limit clamped to configuration bounds"
            );
        }
        Self {
            limit: clamped,
            used: 0,
            refund: 0,
            max_refund_cache: 0,
            refund_applied: false,
            config,
            metrics: None,
        }
    }

    /// Create a meter with the given config and metrics collector.
    pub fn with_metrics(limit: u64, config: GasConfig, metrics: Arc<GasMetrics>) -> Self {
        let mut m = Self::with_config(limit, config);
        m.metrics = Some(metrics);
        m
    }

    /// Create a meter, validating `limit` against `config`'s min/max bounds.
    pub fn new_with_validation(limit: u64, config: &GasConfig) -> GasResult<Self> {
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

    // ── Read-only accessors ─────────────────────────────────────────────

    #[inline]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    #[inline]
    pub fn used(&self) -> u64 {
        self.used
    }

    #[inline]
    pub fn refundable(&self) -> u64 {
        self.refund
    }

    #[inline]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    #[inline]
    pub fn max_refund_allowed(&self) -> u64 {
        self.max_refund_cache
    }

    /// Fraction of the limit that has been used, in `[0.0, 1.0]`.
    #[inline]
    pub fn fraction_used(&self) -> f64 {
        if self.limit == 0 {
            return 1.0;
        }
        (self.used as f64 / self.limit as f64).clamp(0.0, 1.0)
    }

    /// Net gas used after applying the pending refund. Does not mutate.
    #[inline]
    pub fn net_used(&self) -> u64 {
        self.used.saturating_sub(self.refund)
    }

    #[inline]
    pub fn refund_applied(&self) -> bool {
        self.refund_applied
    }

    pub fn config(&self) -> &GasConfig {
        &self.config
    }

    // ── Charging ────────────────────────────────────────────────────────

    /// Charge `amount` gas.
    ///
    /// On failure, `used` is set to `limit` (gas is fully consumed),
    /// matching EVM semantics so the caller cannot continue execution.
    pub fn charge(&mut self, amount: u64) -> GasResult<()> {
        if self.refund_applied {
            return Err(GasError::ChargeAfterRefund);
        }
        if amount == 0 {
            return Ok(());
        }

        let new_used = self.used.checked_add(amount).ok_or(GasError::Overflow)?;
        if new_used > self.limit {
            self.used = self.limit;
            self.refresh_refund_cache();
            if let Some(m) = &self.metrics {
                m.record_out_of_gas();
            }
            warn!(
                needed = amount,
                remaining = self.limit.saturating_sub(self.used),
                "GasMeter out of gas"
            );
            return Err(GasError::OutOfGas {
                needed: amount,
                remaining: self.limit.saturating_sub(self.used),
            });
        }

        if self.config.log_operations && amount > 1_000 {
            trace!(amount, new_used, "GasMeter charge");
        }
        self.used = new_used;
        self.refresh_refund_cache();

        if let Some(m) = &self.metrics {
            m.record_charge(amount);
            m.update_peak(new_used);
        }
        Ok(())
    }

    /// Whether `amount` gas can be charged without exceeding the limit.
    #[inline]
    pub fn can_charge(&self, amount: u64) -> bool {
        !self.refund_applied && self.used.saturating_add(amount) <= self.limit
    }

    /// Charge only if `condition` is true. Returns the amount charged.
    pub fn charge_if(&mut self, condition: bool, amount: u64) -> GasResult<u64> {
        if condition {
            self.charge(amount)?;
            Ok(amount)
        } else {
            Ok(0)
        }
    }

    /// Charge `base * multiplier`, rounding to the nearest integer.
    ///
    /// Uses `f64` only for the multiplication; the result is saturated to
    /// `u64::MAX` before the integer charge so a huge multiplier cannot
    /// wrap.
    pub fn charge_scaled(&mut self, base: u64, multiplier: f64) -> GasResult<u64> {
        let scaled_f = (base as f64) * multiplier;
        let scaled = if scaled_f.is_nan() || scaled_f < 0.0 {
            0
        } else if scaled_f >= u64::MAX as f64 {
            u64::MAX
        } else {
            scaled_f.round() as u64
        };
        self.charge(scaled)?;
        Ok(scaled)
    }

    // ── Refunds ─────────────────────────────────────────────────────────

    /// Add a refund request. The amount is clamped to `max_refund_allowed`.
    pub fn add_refund(&mut self, amount: u64) -> GasResult<()> {
        if self.refund_applied {
            return Err(GasError::RefundAlreadyApplied);
        }
        if amount == 0 {
            return Ok(());
        }

        let requested = self.refund.checked_add(amount).ok_or(GasError::Overflow)?;
        let cap = self.max_refund_cache;

        if requested > cap {
            // Compute how much of this request actually fits under the cap
            // so we can record the correct accepted amount in metrics.
            let accepted = cap.saturating_sub(self.refund);
            self.refund = cap;
            if let Some(m) = &self.metrics {
                m.record_refund(accepted);
                m.record_refund_cap();
            }
            debug!(
                requested,
                accepted,
                cap,
                "GasMeter refund clamped to cap"
            );
        } else {
            self.refund = requested;
            if let Some(m) = &self.metrics {
                m.record_refund(amount);
            }
        }
        Ok(())
    }

    /// Apply the pending refund, reducing `used`.
    ///
    /// Idempotent: a second call returns the same value and does nothing.
    /// Returns the meter's `used` value *after* the refund.
    pub fn apply_refund(&mut self) -> u64 {
        if self.refund_applied {
            return self.used;
        }
        let effective = self.refund.min(self.used);
        self.used = self.used.saturating_sub(effective);
        self.refund = 0;
        self.refund_applied = true;
        self.refresh_refund_cache();
        if self.config.log_operations {
            trace!(effective, net_used = self.used, "GasMeter refund applied");
        }
        self.used
    }

    // ── Memory ──────────────────────────────────────────────────────────

    /// Charge for memory expansion from `current_words` to `new_words`.
    pub fn charge_memory_expansion(
        &mut self,
        current_words: usize,
        new_words: usize,
    ) -> GasResult<u64> {
        if new_words <= current_words {
            return Ok(0);
        }
        let current_cost = memory_cost_words_with_config(current_words, &self.config);
        let new_cost = memory_cost_words_with_config(new_words, &self.config);
        let additional = new_cost
            .checked_sub(current_cost)
            .ok_or(GasError::Overflow)?;
        if additional > 0 {
            self.charge(additional)?;
            if let Some(m) = &self.metrics {
                m.record_memory_expansion(additional);
            }
        }
        Ok(additional)
    }

    /// Charge for memory expansion from `current_bytes` to `new_bytes`.
    pub fn charge_memory_expansion_bytes(
        &mut self,
        current_bytes: usize,
        new_bytes: usize,
    ) -> GasResult<u64> {
        let cur_words = bytes_to_words(current_bytes);
        let new_words = bytes_to_words(new_bytes);
        self.charge_memory_expansion(cur_words, new_words)
    }

    /// Charge for copying `size` bytes within memory.
    pub fn charge_memory_copy(&mut self, size: usize) -> GasResult<()> {
        let words = bytes_to_words(size) as u64;
        let cost = words.saturating_mul(self.config.memory_word_gas);
        self.charge(cost)
    }

    // ── Fork / snapshot ─────────────────────────────────────────────────

    /// Fork the meter with a new limit, preserving `used` and `refund`.
    ///
    /// Used by the VM when entering a sub-call: the sub-call inherits the
    /// parent's accounting so a revert restores the parent's pre-call
    /// state, but receives its own (smaller) `limit`.
    ///
    /// The new meter's `refund_applied` is always `false`; if the parent
    /// has already applied its refund the fork is a fresh accounting
    /// context for the sub-call.
    pub fn fork(&self, new_limit: u64) -> Self {
        if let Some(m) = &self.metrics {
            m.record_fork();
        }
        let clamped = new_limit.min(self.config.max_gas_per_tx).max(1);
        let mut forked = Self {
            limit: clamped,
            used: self.used,
            refund: self.refund,
            max_refund_cache: 0,
            refund_applied: false,
            config: self.config.clone(),
            metrics: self.metrics.clone(),
        };
        forked.refresh_refund_cache();
        forked
    }

    /// Snapshot the meter for a later `restore`.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Restore from a snapshot.
    ///
    /// Returns [`GasError::SnapshotMismatch`] if the snapshot's limit
    /// differs from this meter's limit, which would indicate the caller
    /// is restoring into the wrong context.
    pub fn restore(&mut self, snapshot: Self) -> GasResult<()> {
        if snapshot.limit != self.limit {
            return Err(GasError::SnapshotMismatch {
                current: self.limit,
                snapshot: snapshot.limit,
            });
        }
        // Preserve the current metrics handle and config: the snapshot may
        // have been taken before a manager re-attached them.
        let metrics = self.metrics.take();
        let config = std::mem::replace(&mut self.config, snapshot.config);
        *self = snapshot;
        self.metrics = metrics;
        self.config = config;
        self.refresh_refund_cache();
        Ok(())
    }

    /// Attach a metrics collector to this meter.
    pub fn set_metrics(&mut self, metrics: Arc<GasMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Reset to a fresh state with the same limit and config.
    pub fn reset(&mut self) {
        self.used = 0;
        self.refund = 0;
        self.max_refund_cache = 0;
        self.refund_applied = false;
    }

    // ── Internal ────────────────────────────────────────────────────────

    #[inline]
    fn refresh_refund_cache(&mut self) {
        self.max_refund_cache = self.used / self.config.refund_quotient;
    }
}

// ── Memory cost helpers ──────────────────────────────────────────────────

/// Number of 32-byte words needed for `bytes`.
#[inline]
pub const fn bytes_to_words(bytes: usize) -> usize {
    (bytes + 31) / 32
}

/// Gas cost of `words` memory words under the default configuration.
#[inline]
pub fn memory_cost_words(words: usize) -> u64 {
    memory_cost_words_with_config(words, &GasConfig::default())
}

/// Gas cost of `words` memory words under the given configuration.
///
/// Uses saturating arithmetic throughout: the quadratic term can exceed
/// `u64::MAX` only for pathological inputs, and saturating there is
/// preferable to wrapping.
#[inline]
pub fn memory_cost_words_with_config(words: usize, config: &GasConfig) -> u64 {
    let w = words as u64;
    let linear = w.saturating_mul(config.memory_word_gas);
    let quadratic = w
        .saturating_mul(w)
        .saturating_div(config.memory_quadratic_denom);
    linear.saturating_add(quadratic)
}

/// Gas cost of `bytes` memory bytes under the default configuration.
#[inline]
pub fn memory_cost_bytes(bytes: usize) -> u64 {
    memory_cost_words(bytes_to_words(bytes))
}

// ── Gas price provider ──────────────────────────────────────────────────

/// A trivial gas-price abstraction.
///
/// The VM accepts any type implementing this trait so that dynamic pricing
/// (EIP-1559) or oracle-based pricing can be plugged in without changing
/// the meter.
pub trait GasPriceProvider: Send + Sync {
    /// Current gas price in wei per gas.
    fn gas_price(&self) -> u64;
}

impl GasPriceProvider for u64 {
    fn gas_price(&self) -> u64 {
        *self
    }
}

impl GasPriceProvider for Arc<dyn GasPriceProvider> {
    fn gas_price(&self) -> u64 {
        (**self).gas_price()
    }
}

// ── GasManager ───────────────────────────────────────────────────────────

/// Thread-safe factory and metrics aggregator for [`GasMeter`]s.
#[derive(Clone)]
pub struct GasManager {
    config: Arc<GasConfig>,
    metrics: Arc<GasMetrics>,
}

impl GasManager {
    /// Create a manager with the given configuration.
    pub fn new(config: GasConfig) -> GasResult<Self> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(GasMetrics::new()),
        })
    }

    /// Create a meter with the configured limit clamped to `max_gas_per_tx`.
    pub fn meter(&self, limit: u64) -> GasMeter {
        GasMeter::with_metrics(limit, self.config.as_ref().clone(), self.metrics.clone())
    }

    /// Create a meter, validating `limit` against the configuration.
    pub fn meter_with_validation(&self, limit: u64) -> GasResult<GasMeter> {
        let mut m = GasMeter::new_with_validation(limit, &self.config)?;
        m.set_metrics(self.metrics.clone());
        Ok(m)
    }

    pub fn metrics_snapshot(&self) -> GasMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn config(&self) -> &GasConfig {
        &self.config
    }

    /// Reset all metric counters.
    pub fn reset_metrics(&self) {
        self.metrics.reset();
    }

    /// Direct access to the shared metrics handle (for tests/diagnostics).
    pub fn metrics(&self) -> &Arc<GasMetrics> {
        &self.metrics
    }
}

// ── Global singleton ────────────────────────────────────────────────────

static GLOBAL_MANAGER: OnceLock<GasManager> = OnceLock::new();

/// Initialize the global gas manager. Idempotent-safe: a second call
/// returns [`GasError::Config`] rather than silently ignoring the request.
pub fn init_gas_manager(config: GasConfig) -> GasResult<()> {
    let manager = GasManager::new(config)?;
    GLOBAL_MANAGER
        .set(manager)
        .map_err(|_| GasError::Config("gas manager already initialized".into()))
}

/// Access the global gas manager. Panics if [`init_gas_manager`] was never
/// called.
pub fn gas_manager() -> &'static GasManager {
    GLOBAL_MANAGER
        .get()
        .expect("gas manager not initialized; call init_gas_manager first")
}

/// Fallible variant for callers that want to handle the uninitialized case.
pub fn try_gas_manager() -> Option<&'static GasManager> {
    GLOBAL_MANAGER.get()
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config ─────────────────────────────────────────────────────────

    #[test]
    fn config_default_is_valid() {
        assert!(GasConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_fields() {
        let cfg = |f: fn(&mut GasConfig)| {
            let mut c = GasConfig::default();
            f(&mut c);
            c.validate()
        };
        assert!(cfg(|c| c.max_gas_per_tx = 0).is_err());
        assert!(cfg(|c| c.max_gas_per_block = 0).is_err());
        assert!(cfg(|c| c.min_gas_per_tx = 0).is_err());
        assert!(cfg(|c| c.refund_quotient = 0).is_err());
        assert!(cfg(|c| c.memory_word_gas = 0).is_err());
        assert!(cfg(|c| c.memory_quadratic_denom = 0).is_err());
    }

    #[test]
    fn config_rejects_min_above_max() {
        let mut c = GasConfig::default();
        c.min_gas_per_tx = 100;
        c.max_gas_per_tx = 50;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_tx_limit_above_block_limit() {
        let mut c = GasConfig::default();
        c.max_gas_per_tx = 100;
        c.max_gas_per_block = 50;
        assert!(c.validate().is_err());
    }

    // ── Construction ───────────────────────────────────────────────────

    #[test]
    fn new_clamps_zero_to_one() {
        let g = GasMeter::new(0);
        assert_eq!(g.limit(), 1);
    }

    #[test]
    fn new_clamps_above_max() {
        let g = GasMeter::new(MAX_BLOCK_GAS + 1);
        assert_eq!(g.limit(), MAX_BLOCK_GAS);
    }

    #[test]
    fn new_with_validation_accepts_valid_limit() {
        let cfg = GasConfig::default();
        assert!(GasMeter::new_with_validation(50_000, &cfg).is_ok());
    }

    #[test]
    fn new_with_validation_rejects_too_low() {
        let cfg = GasConfig::default();
        assert!(matches!(
            GasMeter::new_with_validation(100, &cfg),
            Err(GasError::GasLimitTooLow { .. })
        ));
    }

    #[test]
    fn new_with_validation_rejects_too_high() {
        let cfg = GasConfig::default();
        assert!(matches!(
            GasMeter::new_with_validation(MAX_BLOCK_GAS + 1, &cfg),
            Err(GasError::GasLimitTooHigh { .. })
        ));
    }

    // ── Charging ───────────────────────────────────────────────────────

    #[test]
    fn charge_accumulates() {
        let mut g = GasMeter::new(1_000);
        g.charge(500).unwrap();
        g.charge(100).unwrap();
        assert_eq!(g.used(), 600);
        assert_eq!(g.remaining(), 400);
    }

    #[test]
    fn charge_exact_limit_is_ok() {
        let mut g = GasMeter::new(100);
        g.charge(100).unwrap();
        assert_eq!(g.remaining(), 0);
    }

    #[test]
    fn charge_over_limit_sets_used_to_limit() {
        let mut g = GasMeter::new(100);
        g.charge(50).unwrap();
        let err = g.charge(60).unwrap_err();
        assert!(matches!(
            err,
            GasError::OutOfGas { needed: 60, remaining: 50 }
        ));
        assert_eq!(g.used(), 100);
    }

    #[test]
    fn charge_overflow_is_detected() {
        let mut g = GasMeter::new(u64::MAX);
        g.charge(1).unwrap();
        assert!(matches!(g.charge(u64::MAX), Err(GasError::Overflow)));
    }

    #[test]
    fn charge_after_refund_is_rejected() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.apply_refund();
        assert!(matches!(g.charge(10), Err(GasError::ChargeAfterRefund)));
    }

    #[test]
    fn charge_if_only_charges_when_true() {
        let mut g = GasMeter::new(1_000);
        assert_eq!(g.charge_if(true, 30).unwrap(), 30);
        assert_eq!(g.charge_if(false, 70).unwrap(), 0);
        assert_eq!(g.used(), 30);
    }

    #[test]
    fn charge_scaled_rounds_to_nearest() {
        let mut g = GasMeter::new(1_000);
        assert_eq!(g.charge_scaled(10, 1.5).unwrap(), 15);
        assert_eq!(g.charge_scaled(10, 1.4).unwrap(), 14);
    }

    #[test]
    fn charge_scaled_saturates_on_huge_multiplier() {
        let mut g = GasMeter::new(u64::MAX);
        // Should produce u64::MAX, not wrap.
        let _ = g.charge_scaled(10, 1e30);
        assert_eq!(g.used(), u64::MAX);
    }

    #[test]
    fn can_charge_reflects_limit() {
        let g = GasMeter::new(100);
        assert!(g.can_charge(100));
        assert!(!g.can_charge(101));
    }

    // ── Refunds ────────────────────────────────────────────────────────

    #[test]
    fn refund_reduces_net_used() {
        let mut g = GasMeter::new(1_000);
        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        assert_eq!(g.net_used(), 400);
        let net = g.apply_refund();
        assert_eq!(net, 400);
        assert!(g.refund_applied());
    }

    #[test]
    fn refund_is_clamped_to_half_of_used() {
        let mut g = GasMeter::new(1_000);
        g.charge(200).unwrap();
        g.add_refund(80).unwrap();
        g.add_refund(80).unwrap();
        // Half of 200 is 100.
        assert_eq!(g.refundable(), 100);
    }

    #[test]
    fn refund_zero_is_noop() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.add_refund(0).unwrap();
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn refund_overflow_is_detected() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.refund = u64::MAX;
        assert!(matches!(g.add_refund(1), Err(GasError::Overflow)));
    }

    #[test]
    fn refund_cap_is_recorded_in_metrics() {
        let metrics = Arc::new(GasMetrics::new());
        let mut g = GasMeter::with_metrics(1_000, GasConfig::default(), metrics.clone());
        g.charge(200).unwrap();
        // Half of 200 is 100; request 150, so 100 accepted, 50 rejected.
        g.add_refund(150).unwrap();
        let snap = metrics.snapshot();
        assert_eq!(snap.total_refunded, 100);
        assert_eq!(snap.refund_cap_events, 1);
    }

    #[test]
    fn apply_refund_is_idempotent() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.add_refund(50).unwrap();
        let a = g.apply_refund();
        let b = g.apply_refund();
        assert_eq!(a, b);
        assert_eq!(b, 50);
    }

    #[test]
    fn add_refund_after_apply_is_rejected() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.apply_refund();
        assert!(matches!(g.add_refund(50), Err(GasError::RefundAlreadyApplied)));
    }

    // ── Memory ─────────────────────────────────────────────────────────

    #[test]
    fn bytes_to_words_rounds_up() {
        assert_eq!(bytes_to_words(0), 0);
        assert_eq!(bytes_to_words(1), 1);
        assert_eq!(bytes_to_words(32), 1);
        assert_eq!(bytes_to_words(33), 2);
    }

    #[test]
    fn memory_cost_words_linear_plus_quadratic() {
        assert_eq!(memory_cost_words(0), 0);
        assert_eq!(memory_cost_words(1), 3);
        assert_eq!(memory_cost_words(10), 30);
        let expected = 3 * 100 + (100 * 100) / 512;
        assert_eq!(memory_cost_words(100), expected);
    }

    #[test]
    fn memory_cost_words_with_config_overrides() {
        let mut c = GasConfig::default();
        c.memory_word_gas = 5;
        c.memory_quadratic_denom = 256;
        assert_eq!(memory_cost_words_with_config(10, &c), 50 + 100 / 256);
    }

    #[test]
    fn charge_memory_expansion_charges_delta() {
        let mut g = GasMeter::new(10_000);
        let cost = g.charge_memory_expansion(0, 10).unwrap();
        assert_eq!(cost, memory_cost_words(10));
        assert_eq!(g.used(), memory_cost_words(10));
    }

    #[test]
    fn charge_memory_expansion_shrink_is_free() {
        let mut g = GasMeter::new(10_000);
        assert_eq!(g.charge_memory_expansion(10, 5).unwrap(), 0);
    }

    #[test]
    fn charge_memory_expansion_out_of_gas() {
        let mut g = GasMeter::new(10);
        assert!(matches!(
            g.charge_memory_expansion(0, 100),
            Err(GasError::OutOfGas { .. })
        ));
    }

    #[test]
    fn charge_memory_copy_uses_words() {
        let mut g = GasMeter::new(1_000);
        g.charge_memory_copy(32).unwrap();
        assert_eq!(g.used(), 3);
        g.charge_memory_copy(33).unwrap();
        assert_eq!(g.used(), 3 + 6);
    }

    // ── Fork / snapshot ────────────────────────────────────────────────

    #[test]
    fn fork_preserves_used_and_refund() {
        let mut g = GasMeter::new(1_000);
        g.charge(200).unwrap();
        g.add_refund(50).unwrap();
        let f = g.fork(500);
        assert_eq!(f.limit(), 500);
        assert_eq!(f.used(), 200);
        assert_eq!(f.refundable(), 50);
        assert!(!f.refund_applied());
    }

    #[test]
    fn fork_clears_refund_applied_flag() {
        let mut g = GasMeter::new(1_000);
        g.charge(100).unwrap();
        g.apply_refund();
        let f = g.fork(500);
        assert!(!f.refund_applied());
    }

    #[test]
    fn snapshot_restore_roundtrip() {
        let mut g = GasMeter::new(1_000);
        g.charge(300).unwrap();
        g.add_refund(50).unwrap();
        let snap = g.snapshot();

        g.charge(100).unwrap();
        assert_eq!(g.used(), 400);

        g.restore(snap).unwrap();
        assert_eq!(g.used(), 300);
        assert_eq!(g.refundable(), 50);
        assert!(!g.refund_applied());
    }

    #[test]
    fn restore_rejects_limit_mismatch() {
        let mut g = GasMeter::new(1_000);
        let snap = GasMeter::new(500);
        assert!(matches!(
            g.restore(snap),
            Err(GasError::SnapshotMismatch { .. })
        ));
    }

    // ── Serde ──────────────────────────────────────────────────────────

    #[test]
    fn serde_preserves_mutable_state() {
        let mut g = GasMeter::new(1_000);
        g.charge(300).unwrap();
        g.add_refund(50).unwrap();

        let json = serde_json::to_string(&g).unwrap();
        let restored: GasMeter = serde_json::from_str(&json).unwrap();

        assert_eq!(restored.limit(), 1_000);
        assert_eq!(restored.used(), 300);
        assert_eq!(restored.refundable(), 50);
        // refund_applied is not serialized (it is a per-execution flag),
        // and the deserialized meter starts with it cleared. That matches
        // the semantics of "load a checkpoint, resume execution".
        assert!(!restored.refund_applied());
    }

    // ── Metrics ────────────────────────────────────────────────────────

    #[test]
    fn metrics_track_every_operation() {
        let metrics = Arc::new(GasMetrics::new());
        let mut g = GasMeter::with_metrics(10_000, GasConfig::default(), metrics.clone());

        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        g.charge_memory_expansion(0, 10).unwrap();
        let _ = g.fork(1_000);

        let snap = metrics.snapshot();
        assert_eq!(snap.total_charged, 500 + memory_cost_words(10));
        assert_eq!(snap.total_refunded, 100);
        assert_eq!(snap.memory_expansion_gas, memory_cost_words(10));
        assert_eq!(snap.forks, 1);
        assert_eq!(snap.peak_gas_used, g.used());
    }

    #[test]
    fn metrics_reset_clears_all_counters() {
        let metrics = GasMetrics::new();
        metrics.record_charge(100);
        metrics.record_refund(50);
        metrics.record_out_of_gas();
        metrics.reset();
        let s = metrics.snapshot();
        assert_eq!(s.total_charged, 0);
        assert_eq!(s.total_refunded, 0);
        assert_eq!(s.out_of_gas_events, 0);
    }

    // ── Manager ────────────────────────────────────────────────────────

    #[test]
    fn manager_hands_out_meters_with_shared_metrics() {
        let manager = GasManager::new(GasConfig::default()).unwrap();
        let mut m1 = manager.meter(1_000);
        let mut m2 = manager.meter(1_000);
        m1.charge(500).unwrap();
        m2.charge(200).unwrap();
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_charged, 700);
        assert_eq!(snap.peak_gas_used, 500);
    }

    #[test]
    fn manager_rejects_invalid_config() {
        let mut cfg = GasConfig::default();
        cfg.max_gas_per_tx = 0;
        assert!(GasManager::new(cfg).is_err());
    }

    #[test]
    fn manager_meter_with_validation() {
        let manager = GasManager::new(GasConfig::default()).unwrap();
        assert!(manager.meter_with_validation(50_000).is_ok());
        assert!(manager.meter_with_validation(100).is_err());
    }

    // ── Integration ────────────────────────────────────────────────────

    #[test]
    fn realistic_execution_flow() {
        let mut g = GasMeter::new(100_000);
        g.charge(21_000).unwrap(); // intrinsic
        g.charge_memory_expansion_bytes(0, 256).unwrap();
        g.charge(5_000).unwrap(); // some opcodes
        g.add_refund(15_000).unwrap(); // storage clear
        g.charge(3).unwrap();
        let net = g.apply_refund();
        assert!(net > 0);
        assert!(g.refund_applied());
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn fraction_used_is_bounded() {
        let mut g = GasMeter::new(200);
        assert_eq!(g.fraction_used(), 0.0);
        g.charge(50).unwrap();
        assert!((g.fraction_used() - 0.25).abs() < f64::EPSILON);
        g.charge(150).unwrap();
        assert_eq!(g.fraction_used(), 1.0);
    }

    #[test]
    fn gas_price_provider_for_u64() {
        let p: u64 = 42;
        assert_eq!(GasPriceProvider::gas_price(&p), 42);
    }
}
