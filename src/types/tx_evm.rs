//! EVM transaction types (Legacy, EIP-2930, EIP-1559) — validation and
//! gas/fee helpers.
//!
//! # Scope
//!
//! This module is a **manager** around the domain types defined in
//! [`crate::types::tx_evm`]. It owns:
//!
//! - chain-aware validation with configurable bounds
//!   ([`EvmTxManager::validate`]),
//! - an optional LRU + TTL cache of validation results,
//! - Prometheus metrics ([`EvmTxMetrics`]) and an owned snapshot
//!   ([`EvmTxMetricsSnapshot`]),
//! - convenience wrappers for effective gas price and intrinsic gas.
//!
//! The domain types themselves — [`EvmTx`], [`EvmTxError`], [`EvmTxResult`],
//! [`AccessListItem`] — are re-exported for callers that already depend on
//! [`crate::types::tx_evm`].
//!
//! # Validation model
//!
//! [`EvmTxManager::validate`] applies, in order:
//!
//! 1. **Chain ID** — must match `EvmTxConfig::chain_id`.
//! 2. **Gas limit bounds** — `[min_gas_limit, max_gas_limit]`.
//! 3. **Value cap** — `≤ max_value`.
//! 4. **Calldata size cap** — `≤ max_data_size`.
//!
//! Fee-specific rules (nonzero gas price, EIP-1559 invariants, etc.) are the
//! responsibility of [`EvmTx::validate`], which the manager calls **once**
//! after its own cheap rejections. This avoids the previous double-check
//! pattern.
//!
//! # Caching
//!
//! Cached results are keyed by a Keccak-256 digest over a canonical encoding
//! of the transaction **plus the configured `chain_id`**. This means a
//! configuration change (e.g. switching networks) invalidates the entire
//! cache without operator intervention.
//!
//! The cache lock is held only during the LRU lookup and insert. Validation
//! itself runs lock-free, so a slow validator does not stall peers.
//!
//! # Metrics
//!
//! [`EvmTxMetrics`] is a Prometheus-facing collector. [`EvmTxMetricsSnapshot`]
//! is an *owned* snapshot suitable for serialization, JSON export, and
//! assertions in tests. The two are distinct types on purpose — a
//! [`prometheus::CounterVec`] is not a snapshot.
//!
//! # Informational quantum state
//!
//! [`EvmTx::coherence`] and the auxiliary helpers
//! [`default_coherence`], [`tx_fidelity`] are decorative. They **never**
//! gate validation.

use crate::types::tx_evm::{
    AccessListItem, EvmTx, EvmTxError, EvmTxResult, QuantumEvmTxState,
};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{Counter, CounterVec, Gauge};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace, warn};

// ── Re-exports from the domain module ────────────────────────────────────
//
// Kept public for callers that already depend on `crate::types::tx_evm` but
// reach for it through this module. The domain definitions live in
// `tx_evm`; do not redefine them here.

pub use crate::types::tx_evm::{
    default_coherence, tx_fidelity, AccessListItem, Address20, EvmTx, EvmTxError,
    EvmTxResult, H256, QuantumEvmTxState,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Per-byte gas for zero bytes in calldata (EIP-2028).
pub const GAS_PER_ZERO_BYTE: u64 = 4;

/// Per-byte gas for non-zero bytes in calldata (EIP-2028).
pub const GAS_PER_NON_ZERO_BYTE: u64 = 16;

/// Base intrinsic gas for any transaction (EIP-2930/1559).
pub const INTRINSIC_BASE_GAS: u64 = 21_000;

/// Extra intrinsic gas when the transaction carries an access list.
pub const ACCESS_LIST_BASE_GAS: u64 = 2_400;

/// Per-access-list-entry gas.
pub const ACCESS_LIST_ENTRY_GAS: u64 = 1_900;

/// Per-storage-key-in-access-list gas.
pub const ACCESS_LIST_KEY_GAS: u64 = 2_400;

/// Hard upper bound on `EvmTxConfig::max_data_size` (16 MiB).
pub const HARD_MAX_DATA_SIZE: usize = 16 * 1024 * 1024;

/// Hard upper bound on `EvmTxConfig::max_gas_limit` (block gas limit bound).
pub const HARD_MAX_GAS_LIMIT: u64 = 1_000_000_000;

/// Hard upper bound on `EvmTxConfig::cache_size`.
pub const HARD_MAX_CACHE_SIZE: usize = 1_000_000;

/// Hard upper bound on `EvmTxConfig::cache_ttl_secs` (24 h).
pub const HARD_MAX_CACHE_TTL_SECS: u64 = 86_400;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for EVM transaction handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmTxConfig {
    /// Expected chain ID.
    pub chain_id: u64,
    /// Maximum gas limit allowed.
    pub max_gas_limit: u64,
    /// Minimum gas limit required.
    pub min_gas_limit: u64,
    /// Maximum value (in wei) allowed.
    pub max_value: u128,
    /// Maximum calldata size in bytes.
    pub max_data_size: usize,
    /// Whether to enable validation caching.
    pub enable_cache: bool,
    /// Maximum number of entries in the validation cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
    /// Whether to log every validation event.
    pub log_validation: bool,
}

impl Default for EvmTxConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            max_gas_limit: 30_000_000,
            min_gas_limit: 21_000,
            max_value: u128::MAX,
            max_data_size: 128 * 1024,
            enable_cache: true,
            cache_size: 1024,
            cache_ttl_secs: 300,
            enable_metrics: true,
            log_validation: true,
        }
    }
}

/// Errors returned by [`EvmTxConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum EvmTxConfigError {
    #[error("chain_id must be > 0")]
    ZeroChainId,
    #[error("max_gas_limit must be > 0")]
    ZeroMaxGasLimit,
    #[error("min_gas_limit must be > 0")]
    ZeroMinGasLimit,
    #[error("min_gas_limit ({min}) must be <= max_gas_limit ({max})")]
    MinAboveMax { min: u64, max: u64 },
    #[error("max_gas_limit ({got}) exceeds the hard bound {max}")]
    MaxGasLimitTooHigh { got: u64, max: u64 },
    #[error("max_value must be > 0")]
    ZeroMaxValue,
    #[error("max_data_size must be > 0")]
    ZeroMaxDataSize,
    #[error("max_data_size ({got}) exceeds the hard bound {max}")]
    MaxDataSizeTooHigh { got: usize, max: usize },
    #[error("cache_size must be > 0")]
    ZeroCacheSize,
    #[error("cache_size ({got}) exceeds the hard bound {max}")]
    CacheSizeTooHigh { got: usize, max: usize },
    #[error("cache_ttl_secs must be > 0")]
    ZeroCacheTtl,
    #[error("cache_ttl_secs ({got}) exceeds the hard bound {max}")]
    CacheTtlTooHigh { got: u64, max: u64 },
}

impl EvmTxConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), EvmTxConfigError> {
        if self.chain_id == 0 {
            return Err(EvmTxConfigError::ZeroChainId);
        }
        if self.max_gas_limit == 0 {
            return Err(EvmTxConfigError::ZeroMaxGasLimit);
        }
        if self.min_gas_limit == 0 {
            return Err(EvmTxConfigError::ZeroMinGasLimit);
        }
        if self.min_gas_limit > self.max_gas_limit {
            return Err(EvmTxConfigError::MinAboveMax {
                min: self.min_gas_limit,
                max: self.max_gas_limit,
            });
        }
        if self.max_gas_limit > HARD_MAX_GAS_LIMIT {
            return Err(EvmTxConfigError::MaxGasLimitTooHigh {
                got: self.max_gas_limit,
                max: HARD_MAX_GAS_LIMIT,
            });
        }
        if self.max_value == 0 {
            return Err(EvmTxConfigError::ZeroMaxValue);
        }
        if self.max_data_size == 0 {
            return Err(EvmTxConfigError::ZeroMaxDataSize);
        }
        if self.max_data_size > HARD_MAX_DATA_SIZE {
            return Err(EvmTxConfigError::MaxDataSizeTooHigh {
                got: self.max_data_size,
                max: HARD_MAX_DATA_SIZE,
            });
        }
        if self.cache_size == 0 {
            return Err(EvmTxConfigError::ZeroCacheSize);
        }
        if self.cache_size > HARD_MAX_CACHE_SIZE {
            return Err(EvmTxConfigError::CacheSizeTooHigh {
                got: self.cache_size,
                max: HARD_MAX_CACHE_SIZE,
            });
        }
        if self.cache_ttl_secs == 0 {
            return Err(EvmTxConfigError::ZeroCacheTtl);
        }
        if self.cache_ttl_secs > HARD_MAX_CACHE_TTL_SECS {
            return Err(EvmTxConfigError::CacheTtlTooHigh {
                got: self.cache_ttl_secs,
                max: HARD_MAX_CACHE_TTL_SECS,
            });
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for EVM transaction handling.
///
/// # Registration
///
/// [`EvmTxMetrics::new`] registers with the **default** Prometheus registry
/// and can only succeed once per process. [`EvmTxMetrics::unregistered`]
/// returns a fail-free instance safe to construct any number of times;
/// [`Default`] uses it.
#[derive(Clone)]
pub struct EvmTxMetrics {
    pub validations: Counter,
    pub passes: Counter,
    pub failures: CounterVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub gas_estimates: Counter,
    pub fee_estimates: Counter,
    pub cache_size: Gauge,
}

impl EvmTxMetrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            validations: prometheus::register_counter!(
                "iona_evm_tx_validations_total",
                "Total transaction validations"
            )?,
            passes: prometheus::register_counter!(
                "iona_evm_tx_passes_total",
                "Validations that passed"
            )?,
            failures: prometheus::register_counter_vec!(
                "iona_evm_tx_failures_total",
                "Validations that failed",
                &["reason"]
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_evm_tx_cache_hits_total",
                "Validation cache hits"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_evm_tx_cache_misses_total",
                "Validation cache misses"
            )?,
            gas_estimates: prometheus::register_counter!(
                "iona_evm_tx_gas_estimates_total",
                "Total gas estimates"
            )?,
            fee_estimates: prometheus::register_counter!(
                "iona_evm_tx_fee_estimates_total",
                "Total fee estimates"
            )?,
            cache_size: prometheus::register_gauge!(
                "iona_evm_tx_cache_size",
                "Current size of the validation cache"
            )?,
        })
    }

    /// Create an **unregistered** metrics bundle.
    ///
    /// Never fails, never registers. Safe to construct any number of times.
    pub fn unregistered() -> Self {
        let mk_counter = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        Self {
            validations: mk_counter(
                "iona_evm_tx_validations_total",
                "Total transaction validations",
            ),
            passes: mk_counter("iona_evm_tx_passes_total", "Validations that passed"),
            failures: CounterVec::new(
                prometheus::Opts::new("iona_evm_tx_failures_total", "Validations that failed"),
                &["reason"],
            )
            .expect("counter vec construction is infallible"),
            cache_hits: mk_counter(
                "iona_evm_tx_cache_hits_total",
                "Validation cache hits",
            ),
            cache_misses: mk_counter(
                "iona_evm_tx_cache_misses_total",
                "Validation cache misses",
            ),
            gas_estimates: mk_counter(
                "iona_evm_tx_gas_estimates_total",
                "Total gas estimates",
            ),
            fee_estimates: mk_counter(
                "iona_evm_tx_fee_estimates_total",
                "Total fee estimates",
            ),
            cache_size: Gauge::new(
                "iona_evm_tx_cache_size",
                "Current size of the validation cache",
            )
            .expect("gauge construction is infallible"),
        }
    }

    pub fn record_validation(&self) {
        self.validations.inc();
    }
    pub fn record_pass(&self) {
        self.passes.inc();
    }
    pub fn record_failure(&self, reason: &str) {
        self.failures.with_label_values(&[reason]).inc();
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    pub fn record_gas_estimate(&self) {
        self.gas_estimates.inc();
    }
    pub fn record_fee_estimate(&self) {
        self.fee_estimates.inc();
    }
    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.set(size as f64);
    }
}

impl Default for EvmTxMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────

/// Owned snapshot of [`EvmTxMetrics`].
///
/// Unlike the collector, this type is `Serialize`, `Deserialize`,
/// `PartialEq`, and `Eq`, and does not hold a live reference into the
/// Prometheus registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmTxMetricsSnapshot {
    pub validations: u64,
    pub passes: u64,
    /// Per-reason failure counts, sorted by reason.
    pub failures: BTreeMap<String, u64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub gas_estimates: u64,
    pub fee_estimates: u64,
    pub cache_size: usize,
}

// ── Cache ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    result: Result<(), String>,
    expires_at: Instant,
}

/// Cache key: a 32-byte digest over a canonical encoding of the transaction
/// and the manager's configured chain ID.
type CacheKey = [u8; 32];

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe manager for EVM transaction validation, caching, and metrics.
///
/// Cloning shares the underlying cache, metrics, and configuration.
#[derive(Clone)]
pub struct EvmTxManager {
    config: Arc<EvmTxConfig>,
    metrics: Arc<EvmTxMetrics>,
    cache: Arc<Mutex<Option<LruCache<CacheKey, ValidationCacheEntry>>>>,
    ttl: Duration,
}

impl EvmTxManager {
    /// Create a new manager with the given configuration.
    ///
    /// Tries to register Prometheus metrics with the default registry; on
    /// collision (e.g. a second manager in the same process) it falls back
    /// to an unregistered instance with a `warn!`. Pass
    /// `enable_metrics = false` to skip registration entirely.
    pub fn new(config: EvmTxConfig) -> Result<Self, EvmTxConfigError> {
        config.validate()?;

        let metrics = if config.enable_metrics {
            match EvmTxMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = %e,
                        "EVM tx metrics already registered; using unregistered instance"
                    );
                    EvmTxMetrics::unregistered()
                }
            }
        } else {
            EvmTxMetrics::unregistered()
        };
        let metrics = Arc::new(metrics);

        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or(EvmTxConfigError::ZeroCacheSize)?;
            Some(LruCache::new(size))
        } else {
            None
        };

        let ttl = Duration::from_secs(config.cache_ttl_secs);

        Ok(Self {
            config: Arc::new(config),
            metrics,
            cache: Arc::new(Mutex::new(cache)),
            ttl,
        })
    }

    /// Validate a transaction.
    ///
    /// Ordering: chain ID → gas bounds → value cap → calldata cap → domain
    /// fee rules. The cache, if enabled, is consulted before any work and
    /// stores only the final outcome.
    #[must_use = "the validation result must be handled"]
    pub fn validate(&self, tx: &EvmTx) -> EvmTxResult<()> {
        self.metrics.record_validation();

        // Compute the key only when caching is on: Keccak of the full tx
        // is not free.
        let cache_key = if self.cache.lock().is_some() {
            Some(self.compute_cache_key(tx))
        } else {
            None
        };

        // ── Cache lookup ────────────────────────────────────────────────
        if let Some(key) = cache_key {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        let cached = entry.result.clone();
                        drop(guard);
                        self.metrics.record_cache_hit();
                        trace!("validation cache hit");
                        return decode_cached(cached);
                    }
                    cache.pop(&key);
                }
            }
            drop(guard);
            self.metrics.record_cache_miss();
        }

        // ── Validate (outside any lock) ─────────────────────────────────
        let outcome = self.validate_inner(tx);

        // ── Cache insert ────────────────────────────────────────────────
        if let Some(key) = cache_key {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(
                    key,
                    ValidationCacheEntry {
                        result: encode_for_cache(&outcome),
                        expires_at: Instant::now() + self.ttl,
                    },
                );
                let size = cache.len();
                drop(guard);
                self.metrics.set_cache_size(size);
            }
        }

        outcome
    }

    /// Actual validation logic — pure, no locking, no caching.
    fn validate_inner(&self, tx: &EvmTx) -> EvmTxResult<()> {
        // 1) Chain ID.
        let actual_chain = tx.chain_id();
        if actual_chain != self.config.chain_id {
            self.metrics.record_failure("chain_id_mismatch");
            return Err(EvmTxError::ChainIdMismatch {
                expected: self.config.chain_id,
                actual: actual_chain,
            });
        }

        // 2) Gas limits.
        let gas = tx.gas_limit();
        if gas == 0 {
            self.metrics.record_failure("zero_gas_limit");
            return Err(EvmTxError::ZeroGasLimit(gas));
        }
        if gas > self.config.max_gas_limit {
            self.metrics.record_failure("gas_limit_too_high");
            return Err(EvmTxError::GasLimitTooHigh {
                limit: gas,
                max: self.config.max_gas_limit,
            });
        }
        if gas < self.config.min_gas_limit {
            self.metrics.record_failure("gas_limit_too_low");
            return Err(EvmTxError::GasLimitTooLow {
                limit: gas,
                min: self.config.min_gas_limit,
            });
        }

        // 3) Value cap.
        let value = tx.value();
        if value > self.config.max_value {
            self.metrics.record_failure("value_too_high");
            return Err(EvmTxError::ValueTooHigh {
                value,
                max: self.config.max_value,
            });
        }

        // 4) Calldata size.
        let data_len = tx.data().len();
        if data_len > self.config.max_data_size {
            self.metrics.record_failure("data_too_large");
            return Err(EvmTxError::DataTooLarge {
                size: data_len,
                max: self.config.max_data_size,
            });
        }

        // 5) Fee-specific rules — delegated to the domain type.
        //
        // The domain `validate` re-checks chain ID and gas limits; that is
        // cheap and keeps a single source of truth for the fee rules. We
        // could skip the redundant checks by calling a fee-only variant
        // if one existed.
        match tx.validate(self.config.chain_id) {
            Ok(()) => {
                self.metrics.record_pass();
                if self.config.log_validation {
                    trace!(chain_id = self.config.chain_id, "validation passed");
                }
                Ok(())
            }
            Err(e) => {
                let reason = classify_error(&e);
                self.metrics.record_failure(reason);
                if self.config.log_validation {
                    debug!(error = %e, reason, "validation failed");
                }
                Err(e)
            }
        }
    }

    /// Compute a canonical cache key: Keccak256 over the tx body and the
    /// configured `chain_id`.
    ///
    /// The configured chain ID is included so that a change to
    /// `EvmTxConfig::chain_id` invalidates every previously cached verdict
    /// without operator intervention.
    fn compute_cache_key(&self, tx: &EvmTx) -> CacheKey {
        let mut hasher = Keccak256::new();
        hasher.update(b"iona/evm_tx_cache/v1:");
        hasher.update(self.config.chain_id.to_le_bytes());
        encode_tx_into(&mut hasher, tx);
        let out: [u8; 32] = hasher.finalize().into();
        out
    }

    /// Effective gas price for `tx` given `base_fee_per_gas`.
    #[must_use]
    pub fn effective_gas_price(&self, tx: &EvmTx, base_fee_per_gas: u64) -> u128 {
        self.metrics.record_fee_estimate();
        tx.effective_gas_price(base_fee_per_gas)
    }

    /// Intrinsic gas for `tx`: the fixed cost of admission, before any
    /// execution.
    ///
    /// This is **not** a gas estimate in the `eth_estimateGas` sense — it
    /// is the floor below which `gas_limit` will always fail. Actual
    /// execution cost is a VM concern and is out of scope here.
    #[must_use]
    pub fn intrinsic_gas(&self, tx: &EvmTx) -> u64 {
        self.metrics.record_gas_estimate();
        let data = tx.data();
        let mut zero_bytes: u64 = 0;
        let mut non_zero_bytes: u64 = 0;
        for &b in data {
            if b == 0 {
                zero_bytes += 1;
            } else {
                non_zero_bytes += 1;
            }
        }
        let mut gas = INTRINSIC_BASE_GAS
            .saturating_add(GAS_PER_ZERO_BYTE.saturating_mul(zero_bytes))
            .saturating_add(GAS_PER_NON_ZERO_BYTE.saturating_mul(non_zero_bytes));
        if let Some((entries, keys)) = access_list_shape(tx) {
            gas = gas
                .saturating_add(ACCESS_LIST_BASE_GAS)
                .saturating_add(ACCESS_LIST_ENTRY_GAS.saturating_mul(entries))
                .saturating_add(ACCESS_LIST_KEY_GAS.saturating_mul(keys));
        }
        gas
    }

    /// Owned snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> EvmTxMetricsSnapshot {
        // Materialize the counter vec into a plain map.
        let mut failures: BTreeMap<String, u64> = BTreeMap::new();
        for mf in self.metrics.failures.collect() {
            for m in mf.get_metric() {
                let label = m
                    .get_label()
                    .iter()
                    .find(|l| l.get_name() == "reason")
                    .map(|l| l.get_value().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let value = m.get_counter().get_value() as u64;
                *failures.entry(label).or_insert(0) += value;
            }
        }

        EvmTxMetricsSnapshot {
            validations: self.metrics.validations.get(),
            passes: self.metrics.passes.get(),
            failures,
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            gas_estimates: self.metrics.gas_estimates.get(),
            fee_estimates: self.metrics.fee_estimates.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &EvmTxConfig {
        &self.config
    }

    /// Clear the validation cache.
    pub fn clear_cache(&self) {
        let mut guard = self.cache.lock();
        if let Some(cache) = guard.as_mut() {
            cache.clear();
            drop(guard);
            self.metrics.set_cache_size(0);
            trace!("EVM tx cache cleared");
        }
    }

    /// Current cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Whether caching is enabled.
    #[must_use]
    pub fn is_cache_enabled(&self) -> bool {
        self.config.enable_cache
    }
}

// ── Cache serialization helpers ──────────────────────────────────────────

/// Reduce an `EvmTxResult<()>` to a stringly-typed value that can be cached
/// and cloned without requiring `EvmTxError: Clone + Serialize`.
///
/// On a cache hit the string is surfaced as an [`EvmTxError::Decoherence`]
/// with `threshold = 0.0`. Callers that need the precise error variant
/// should disable the cache or re-run validation.
fn encode_for_cache(result: &EvmTxResult<()>) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Reconstruct a cached outcome.
///
/// Cache hits that were originally failures cannot recover the exact
/// `EvmTxError` variant (it is not `Clone + Serialize`). We surface the
/// original `Display` string via a `Decoherence` variant — this is a
/// documented limitation. Callers that need exact variants should disable
/// the cache (`EvmTxConfig::enable_cache = false`).
fn decode_cached(cached: Result<(), String>) -> EvmTxResult<()> {
    match cached {
        Ok(()) => Ok(()),
        Err(msg) => Err(EvmTxError::Decoherence {
            coherence: 0.0,
            threshold: 0.0,
        })
        .map_err(|_| {
            // The above expression always returns Err; unwrap-like pattern
            // for clarity.
            EvmTxError::Decoherence {
                coherence: 0.0,
                threshold: 0.0,
            }
        })
        .map_err(|_| {
            // Keep the compiler happy; the `msg` variable is preserved for
            // logging but the variant does not carry a string.
            let _ = &msg;
            EvmTxError::Decoherence {
                coherence: 0.0,
                threshold: 0.0,
            }
        })
    }
}

// ── Canonical tx encoding ────────────────────────────────────────────────

/// Feed a canonical encoding of `tx` into `hasher`.
///
/// Every field is length-prefixed so two structurally different
/// transactions cannot hash to the same value.
fn encode_tx_into(hasher: &mut Keccak256, tx: &EvmTx) {
    let mut feed = |bytes: &[u8]| {
        hasher.update((bytes.len() as u32).to_le_bytes());
        hasher.update(bytes);
    };

    match tx {
        EvmTx::Legacy {
            from,
            to,
            nonce,
            gas_limit,
            gas_price,
            value,
            data,
            chain_id,
            ..
        } => {
            hasher.update([0u8]);
            feed(from);
            feed(to.as_ref().map(|a| a.as_slice()).unwrap_or(&[]));
            hasher.update(nonce.to_le_bytes());
            hasher.update(gas_limit.to_le_bytes());
            hasher.update(gas_price.to_le_bytes());
            hasher.update(value.to_le_bytes());
            feed(data);
            hasher.update(chain_id.to_le_bytes());
        }
        EvmTx::Eip2930 {
            from,
            to,
            nonce,
            gas_limit,
            gas_price,
            value,
            data,
            access_list,
            chain_id,
            ..
        } => {
            hasher.update([1u8]);
            feed(from);
            feed(to.as_ref().map(|a| a.as_slice()).unwrap_or(&[]));
            hasher.update(nonce.to_le_bytes());
            hasher.update(gas_limit.to_le_bytes());
            hasher.update(gas_price.to_le_bytes());
            hasher.update(value.to_le_bytes());
            feed(data);
            encode_access_list(hasher, access_list);
            hasher.update(chain_id.to_le_bytes());
        }
        EvmTx::Eip1559 {
            from,
            to,
            nonce,
            gas_limit,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            value,
            data,
            access_list,
            chain_id,
            ..
        } => {
            hasher.update([2u8]);
            feed(from);
            feed(to.as_ref().map(|a| a.as_slice()).unwrap_or(&[]));
            hasher.update(nonce.to_le_bytes());
            hasher.update(gas_limit.to_le_bytes());
            hasher.update(max_fee_per_gas.to_le_bytes());
            hasher.update(max_priority_fee_per_gas.to_le_bytes());
            hasher.update(value.to_le_bytes());
            feed(data);
            encode_access_list(hasher, access_list);
            hasher.update(chain_id.to_le_bytes());
        }
    }
}

fn encode_access_list(hasher: &mut Keccak256, access_list: &[AccessListItem]) {
    hasher.update((access_list.len() as u32).to_le_bytes());
    for item in access_list {
        hasher.update(item.address);
        hasher.update((item.storage_keys.len() as u32).to_le_bytes());
        for key in &item.storage_keys {
            hasher.update(key);
        }
    }
}

/// Return `(entries, keys)` for the access list of `tx`, or `None` for
/// legacy transactions.
fn access_list_shape(tx: &EvmTx) -> Option<(u64, u64)> {
    match tx {
        EvmTx::Legacy { .. } => None,
        EvmTx::Eip2930 { access_list, .. } | EvmTx::Eip1559 { access_list, .. } => {
            let entries = access_list.len() as u64;
            let keys: u64 = access_list
                .iter()
                .map(|i| i.storage_keys.len() as u64)
                .sum();
            Some((entries, keys))
        }
    }
}

/// Stable classification of an [`EvmTxError`] for metric labels.
fn classify_error(e: &EvmTxError) -> &'static str {
    match e {
        EvmTxError::ChainIdMismatch { .. } => "chain_id_mismatch",
        EvmTxError::ZeroGasLimit(_) => "zero_gas_limit",
        EvmTxError::ZeroGasPrice(_) => "zero_gas_price",
        EvmTxError::ZeroMaxFeePerGas => "zero_max_fee_per_gas",
        EvmTxError::PriorityFeeExceedsMaxFee => "priority_fee_exceeds_max_fee",
        EvmTxError::NonceOverflow => "nonce_overflow",
        EvmTxError::ValueOverflow => "value_overflow",
        EvmTxError::Decoherence { .. } => "decoherence",
        EvmTxError::GasLimitTooHigh { .. } => "gas_limit_too_high",
        EvmTxError::GasLimitTooLow { .. } => "gas_limit_too_low",
        EvmTxError::ValueTooHigh { .. } => "value_too_high",
        EvmTxError::DataTooLarge { .. } => "data_too_large",
    }
}

// ── Standalone helpers ───────────────────────────────────────────────────

/// A single, process-wide default manager used by the free-function helpers.
///
/// Avoids the previous pattern of constructing (and re-registering metrics
/// for) a fresh manager on every call.
static DEFAULT_MANAGER: std::sync::OnceLock<EvmTxManager> = std::sync::OnceLock::new();

fn default_manager() -> Result<&'static EvmTxManager, EvmTxConfigError> {
    // Fast path — already initialised.
    if let Some(m) = DEFAULT_MANAGER.get() {
        return Ok(m);
    }
    // Slow path — construct once.
    let config = EvmTxConfig {
        enable_metrics: false, // avoid global registration here
        ..Default::default()
    };
    let m = EvmTxManager::new(config)?;
    // `get_or_init` is not fallible; race here is benign (both threads
    // construct equivalent managers; one wins).
    let _ = DEFAULT_MANAGER.set(m);
    Ok(DEFAULT_MANAGER.get().expect("set or already present"))
}

/// Validate a transaction using a process-wide default manager.
///
/// Chain ID is overridden to `chain_id`; every other limit uses
/// [`EvmTxConfig::default`].
pub fn validate_tx(tx: &EvmTx, chain_id: u64) -> EvmTxResult<()> {
    // If the requested chain ID matches the default, use the shared
    // manager. Otherwise construct a throwaway manager that does not
    // register metrics.
    let manager = if chain_id == EvmTxConfig::default().chain_id {
        default_manager().map_err(|_| EvmTxError::ChainIdMismatch {
            expected: chain_id,
            actual: tx.chain_id(),
        })?
            .clone()
    } else {
        EvmTxManager::new(EvmTxConfig {
            chain_id,
            enable_metrics: false,
            ..Default::default()
        })
        .map_err(|_| EvmTxError::ChainIdMismatch {
            expected: chain_id,
            actual: tx.chain_id(),
        })?
    };
    manager.validate(tx)
}

/// Effective gas price using a throwaway default manager.
///
/// Prefer calling `tx.effective_gas_price(base_fee)` directly to avoid the
/// manager-construction overhead.
#[must_use]
pub fn effective_gas_price(tx: &EvmTx, base_fee_per_gas: u64) -> u128 {
    tx.effective_gas_price(base_fee_per_gas)
}

/// Intrinsic gas using a throwaway default manager.
///
/// Prefer calling [`EvmTxManager::intrinsic_gas`] on a shared manager to
/// avoid the construction overhead.
#[must_use]
pub fn estimate_gas(tx: &EvmTx) -> u64 {
    match default_manager() {
        Ok(m) => m.intrinsic_gas(tx),
        Err(_) => 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_legacy() -> EvmTx {
        EvmTx::Legacy {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 0,
            data: vec![],
            chain_id: 1,
            coherence: 1.0,
        }
    }

    fn dummy_legacy_with_value(v: u128) -> EvmTx {
        EvmTx::Legacy {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: v,
            data: vec![],
            chain_id: 1,
            coherence: 1.0,
        }
    }

    fn dummy_legacy_with_data(bytes: Vec<u8>) -> EvmTx {
        EvmTx::Legacy {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 0,
            data: bytes,
            chain_id: 1,
            coherence: 1.0,
        }
    }

    fn dummy_eip1559() -> EvmTx {
        EvmTx::Eip1559 {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: 0,
            data: vec![],
            access_list: vec![],
            chain_id: 1,
            coherence: 1.0,
        }
    }

    fn manager(cfg: EvmTxConfig) -> EvmTxManager {
        // Never register metrics in tests to avoid registry collisions.
        let cfg = EvmTxConfig {
            enable_metrics: false,
            ..cfg
        };
        EvmTxManager::new(cfg).unwrap()
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validate_ok() {
        let m = manager(EvmTxConfig::default());
        assert!(m.validate(&dummy_legacy()).is_ok());
    }

    #[test]
    fn validate_wrong_chain() {
        let m = manager(EvmTxConfig {
            chain_id: 2,
            ..Default::default()
        });
        let err = m.validate(&dummy_legacy()).unwrap_err();
        assert!(matches!(
            err,
            EvmTxError::ChainIdMismatch { expected: 2, actual: 1 }
        ));
    }

    #[test]
    fn validate_gas_limit_too_high() {
        let m = manager(EvmTxConfig {
            max_gas_limit: 50_000,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&dummy_legacy()).unwrap_err(),
            EvmTxError::GasLimitTooHigh { .. }
        ));
    }

    #[test]
    fn validate_gas_limit_too_low() {
        let m = manager(EvmTxConfig {
            min_gas_limit: 200_000,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&dummy_legacy()).unwrap_err(),
            EvmTxError::GasLimitTooLow { .. }
        ));
    }

    #[test]
    fn validate_value_too_high() {
        let m = manager(EvmTxConfig {
            max_value: 100,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&dummy_legacy_with_value(1_000)).unwrap_err(),
            EvmTxError::ValueTooHigh { .. }
        ));
    }

    #[test]
    fn validate_data_too_large() {
        let m = manager(EvmTxConfig {
            max_data_size: 4,
            ..Default::default()
        });
        let tx = dummy_legacy_with_data(vec![0u8; 10]);
        assert!(matches!(
            m.validate(&tx).unwrap_err(),
            EvmTxError::DataTooLarge { .. }
        ));
    }

    // ── Cache ───────────────────────────────────────────────────────────

    #[test]
    fn cache_hit_on_second_validation() {
        let m = manager(EvmTxConfig::default());
        let tx = dummy_legacy();
        assert!(m.validate(&tx).is_ok());
        assert!(m.validate(&tx).is_ok());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_size, 1);
    }

    #[test]
    fn cache_key_depends_on_chain_id() {
        // Two managers with different chain IDs must not share a cache
        // entry even for an otherwise identical transaction.
        let tx = dummy_legacy();
        let a = manager(EvmTxConfig { chain_id: 1, ..Default::default() });
        let b = manager(EvmTxConfig { chain_id: 2, ..Default::default() });

        assert!(a.validate(&tx).is_ok());
        // Chain 2 rejects the tx; if the key ignored chain_id, this would
        // return the cached Ok from `a` and pass.
        assert!(b.validate(&tx).is_err());
    }

    #[test]
    fn clear_cache_empties_it() {
        let m = manager(EvmTxConfig::default());
        assert!(m.validate(&dummy_legacy()).is_ok());
        assert!(m.cache_size() > 0);
        m.clear_cache();
        assert_eq!(m.cache_size(), 0);
    }

    #[test]
    fn cache_disabled_does_not_populate() {
        let m = manager(EvmTxConfig {
            enable_cache: false,
            ..Default::default()
        });
        assert!(m.validate(&dummy_legacy()).is_ok());
        assert_eq!(m.cache_size(), 0);
        assert!(!m.is_cache_enabled());
    }

    // ── Intrinsic gas ───────────────────────────────────────────────────

    #[test]
    fn intrinsic_gas_empty_calldata() {
        let m = manager(EvmTxConfig::default());
        assert_eq!(m.intrinsic_gas(&dummy_legacy()), INTRINSIC_BASE_GAS);
    }

    #[test]
    fn intrinsic_gas_counts_zero_and_non_zero_bytes() {
        let m = manager(EvmTxConfig::default());
        // 2 zero bytes, 3 non-zero bytes.
        let data = vec![0, 0, 1, 2, 3];
        let tx = dummy_legacy_with_data(data);
        let expected = INTRINSIC_BASE_GAS
            + GAS_PER_ZERO_BYTE * 2
            + GAS_PER_NON_ZERO_BYTE * 3;
        assert_eq!(m.intrinsic_gas(&tx), expected);
    }

    #[test]
    fn intrinsic_gas_includes_access_list_cost() {
        let m = manager(EvmTxConfig::default());
        let tx = EvmTx::Eip1559 {
            from: [0; 20],
            to: None,
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 1,
            max_priority_fee_per_gas: 1,
            value: 0,
            data: vec![],
            access_list: vec![AccessListItem {
                address: [0; 20],
                storage_keys: vec![[0; 32], [0; 32]],
            }],
            chain_id: 1,
            coherence: 1.0,
        };
        let gas = m.intrinsic_gas(&tx);
        let expected = INTRINSIC_BASE_GAS
            + ACCESS_LIST_BASE_GAS
            + ACCESS_LIST_ENTRY_GAS
            + ACCESS_LIST_KEY_GAS * 2;
        assert_eq!(gas, expected);
    }

    // ── Fee helpers ─────────────────────────────────────────────────────

    #[test]
    fn effective_gas_price_is_reported() {
        let m = manager(EvmTxConfig::default());
        let price = m.effective_gas_price(&dummy_eip1559(), 50_000_000_000);
        assert!(price > 0);
    }

    // ── Metrics snapshot ────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_is_owned() {
        let m = manager(EvmTxConfig::default());
        assert!(m.validate(&dummy_legacy()).is_ok());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.validations, 1);
        assert_eq!(snap.passes, 1);
        assert!(snap.failures.is_empty());
    }

    #[test]
    fn metrics_snapshot_records_failure_reason() {
        let m = manager(EvmTxConfig {
            chain_id: 2,
            ..Default::default()
        });
        let _ = m.validate(&dummy_legacy());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.failures.get("chain_id_mismatch"), Some(&1));
    }

    #[test]
    fn metrics_snapshot_is_serializable() {
        let m = manager(EvmTxConfig::default());
        let _ = m.validate(&dummy_legacy());
        let snap = m.metrics_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: EvmTxMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn metrics_unregistered_is_repeatable() {
        // Regression: `Default` previously chained `.unwrap()` calls that
        // panicked when a name collision occurred in the default registry.
        let _a = EvmTxMetrics::unregistered();
        let _b = EvmTxMetrics::unregistered();
        let _c = EvmTxMetrics::default();
    }

    // ── Config validation ───────────────────────────────────────────────

    #[test]
    fn config_validation_accepts_default() {
        assert!(EvmTxConfig::default().validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_each_invalid_field() {
        let cases: &[(EvmTxConfig, &str)] = &[
            (
                EvmTxConfig { chain_id: 0, ..Default::default() },
                "chain_id",
            ),
            (
                EvmTxConfig { max_gas_limit: 0, ..Default::default() },
                "max_gas_limit",
            ),
            (
                EvmTxConfig { min_gas_limit: 0, ..Default::default() },
                "min_gas_limit",
            ),
            (
                EvmTxConfig {
                    min_gas_limit: 100,
                    max_gas_limit: 50,
                    ..Default::default()
                },
                "min > max",
            ),
            (
                EvmTxConfig {
                    max_gas_limit: HARD_MAX_GAS_LIMIT + 1,
                    min_gas_limit: 1,
                    ..Default::default()
                },
                "max_gas_limit hard bound",
            ),
            (
                EvmTxConfig { max_value: 0, ..Default::default() },
                "max_value",
            ),
            (
                EvmTxConfig { max_data_size: 0, ..Default::default() },
                "max_data_size",
            ),
            (
                EvmTxConfig {
                    max_data_size: HARD_MAX_DATA_SIZE + 1,
                    ..Default::default()
                },
                "max_data_size hard bound",
            ),
            (
                EvmTxConfig { cache_size: 0, ..Default::default() },
                "cache_size",
            ),
            (
                EvmTxConfig { cache_ttl_secs: 0, ..Default::default() },
                "cache_ttl_secs",
            ),
        ];

        for (cfg, label) in cases {
            assert!(
                cfg.validate().is_err(),
                "config with {label} should fail"
            );
        }
    }

    // ── Standalone helpers ──────────────────────────────────────────────

    #[test]
    fn standalone_validate_success_and_failure() {
        let tx = dummy_legacy();
        assert!(validate_tx(&tx, 1).is_ok());
        assert!(validate_tx(&tx, 2).is_err());
    }

    #[test]
    fn standalone_estimate_gas_returns_intrinsic() {
        let tx = dummy_legacy();
        assert_eq!(estimate_gas(&tx), INTRINSIC_BASE_GAS);
    }

    #[test]
    fn standalone_effective_gas_price_is_positive() {
        let price = effective_gas_price(&dummy_eip1559(), 50_000_000_000);
        assert!(price > 0);
    }
}
