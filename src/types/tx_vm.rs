//! VM transaction types for the IONA custom VM — validation, gas helpers,
//! and caching.
//!
//! # Scope
//!
//! This module is a **manager** around the domain types defined in
//! [`crate::types::vm_tx`]. It provides:
//!
//! - configurable validation with bounds ([`VmTxManager::validate`]),
//! - an optional LRU + TTL cache of validation results,
//! - Prometheus metrics ([`VmTxMetrics`]) and an owned snapshot
//!   ([`VmTxMetricsSnapshot`]),
//! - a convenience intrinsic-gas helper ([`VmTxManager::intrinsic_gas`]),
//! - an informational quantum scoreboard
//!   ([`VmTxManager::validate_quantum`]).
//!
//! The domain types (`VmTx`, `VmTxError`, `VmTxResult`, `ContractAddr`,
//! `QuantumVmTxState`, `default_coherence`, `vm_tx_fidelity`) are re-exported
//! for callers that reach for them through this module.
//!
//! # Validation model
//!
//! [`VmTxManager::validate`] applies, in order:
//!
//! 1. Gas limit within `[min_gas_limit, max_gas_limit]`.
//! 2. Sender non-empty.
//! 3. Payload-specific:
//!    - `Deploy`: `init_code` non-empty and `≤ max_init_code_size`.
//!    - `Call`: contract address non-zero and `calldata ≤ max_calldata_size`.
//!
//! # Caching
//!
//! Cached results are keyed by a Keccak-256 digest over a canonical
//! encoding of the transaction **plus the validation-relevant fields of the
//! configuration**. Changing `min_gas_limit`, `max_gas_limit`,
//! `max_init_code_size`, or `max_calldata_size` invalidates the entire
//! cache without operator intervention.
//!
//! The cache lock is held only during the LRU lookup and insert; validation
//! itself runs lock-free.
//!
//! # Informational quantum state
//!
//! [`VmTx::coherence`] and the helpers `default_coherence`, `vm_tx_fidelity`
//! are decorative. They **never** gate validation. [`VmTxManager::validate_quantum`]
//! returns a side-channel scoreboard alongside the real result.

use crate::types::vm_tx::{QuantumVmTxState, VmTx, VmTxError, VmTxResult};
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

// ── Re-exports ────────────────────────────────────────────────────────────
//
// These are the domain types. Do not redefine them here; the module is a
// manager, not a definition site.

pub use crate::types::vm_tx::{
    default_coherence, vm_tx_fidelity, ContractAddr, QuantumVmTxState, VmTx, VmTxError,
    VmTxResult,
};

// ── Constants ─────────────────────────────────────────────────────────────

/// Base intrinsic gas (matches the VM's schedule).
pub const INTRINSIC_BASE_GAS: u64 = 21_000;

/// Per-byte gas applied to any payload byte.
pub const INTRINSIC_GAS_PER_BYTE: u64 = 4;

/// Additional gas reserved for the `Deploy` path (contract creation).
pub const DEPLOY_EXTRA_GAS: u64 = 32_000;

/// Hard upper bound on `VmTxConfig::max_gas_limit`.
pub const HARD_MAX_GAS_LIMIT: u64 = 1_000_000_000;

/// Hard upper bound on `VmTxConfig::max_init_code_size` (16 MiB).
pub const HARD_MAX_INIT_CODE_SIZE: usize = 16 * 1024 * 1024;

/// Hard upper bound on `VmTxConfig::max_calldata_size` (16 MiB).
pub const HARD_MAX_CALLDATA_SIZE: usize = 16 * 1024 * 1024;

/// Hard upper bound on `VmTxConfig::cache_size`.
pub const HARD_MAX_CACHE_SIZE: usize = 1_000_000;

/// Hard upper bound on `VmTxConfig::cache_ttl_secs` (24 h).
pub const HARD_MAX_CACHE_TTL_SECS: u64 = 86_400;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for VM transaction handling.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmTxConfig {
    /// Minimum gas limit required.
    pub min_gas_limit: u64,
    /// Maximum gas limit allowed.
    pub max_gas_limit: u64,
    /// Maximum size of init code (deploy), in bytes.
    pub max_init_code_size: usize,
    /// Maximum size of calldata (call), in bytes.
    pub max_calldata_size: usize,
    /// Whether to enable validation caching.
    pub enable_cache: bool,
    /// Maximum number of entries in the validation cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
    /// Whether to log validation events.
    pub log_validation: bool,
}

impl Default for VmTxConfig {
    fn default() -> Self {
        Self {
            min_gas_limit: 21_000,
            max_gas_limit: 30_000_000,
            max_init_code_size: 256 * 1024,
            max_calldata_size: 128 * 1024,
            enable_cache: true,
            cache_size: 1024,
            cache_ttl_secs: 300,
            enable_metrics: true,
            log_validation: true,
        }
    }
}

/// Errors returned by [`VmTxConfig::validate`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum VmTxConfigError {
    #[error("min_gas_limit must be > 0")]
    ZeroMinGasLimit,
    #[error("max_gas_limit must be > 0")]
    ZeroMaxGasLimit,
    #[error("min_gas_limit ({min}) must be <= max_gas_limit ({max})")]
    MinAboveMax { min: u64, max: u64 },
    #[error("max_gas_limit ({got}) exceeds the hard bound {max}")]
    MaxGasLimitTooHigh { got: u64, max: u64 },
    #[error("max_init_code_size must be > 0")]
    ZeroInitCodeSize,
    #[error("max_init_code_size ({got}) exceeds the hard bound {max}")]
    InitCodeSizeTooHigh { got: usize, max: usize },
    #[error("max_calldata_size must be > 0")]
    ZeroCalldataSize,
    #[error("max_calldata_size ({got}) exceeds the hard bound {max}")]
    CalldataSizeTooHigh { got: usize, max: usize },
    #[error("cache_size must be > 0")]
    ZeroCacheSize,
    #[error("cache_size ({got}) exceeds the hard bound {max}")]
    CacheSizeTooHigh { got: usize, max: usize },
    #[error("cache_ttl_secs must be > 0")]
    ZeroCacheTtl,
    #[error("cache_ttl_secs ({got}) exceeds the hard bound {max}")]
    CacheTtlTooHigh { got: u64, max: u64 },
}

impl VmTxConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), VmTxConfigError> {
        if self.min_gas_limit == 0 {
            return Err(VmTxConfigError::ZeroMinGasLimit);
        }
        if self.max_gas_limit == 0 {
            return Err(VmTxConfigError::ZeroMaxGasLimit);
        }
        if self.min_gas_limit > self.max_gas_limit {
            return Err(VmTxConfigError::MinAboveMax {
                min: self.min_gas_limit,
                max: self.max_gas_limit,
            });
        }
        if self.max_gas_limit > HARD_MAX_GAS_LIMIT {
            return Err(VmTxConfigError::MaxGasLimitTooHigh {
                got: self.max_gas_limit,
                max: HARD_MAX_GAS_LIMIT,
            });
        }
        if self.max_init_code_size == 0 {
            return Err(VmTxConfigError::ZeroInitCodeSize);
        }
        if self.max_init_code_size > HARD_MAX_INIT_CODE_SIZE {
            return Err(VmTxConfigError::InitCodeSizeTooHigh {
                got: self.max_init_code_size,
                max: HARD_MAX_INIT_CODE_SIZE,
            });
        }
        if self.max_calldata_size == 0 {
            return Err(VmTxConfigError::ZeroCalldataSize);
        }
        if self.max_calldata_size > HARD_MAX_CALLDATA_SIZE {
            return Err(VmTxConfigError::CalldataSizeTooHigh {
                got: self.max_calldata_size,
                max: HARD_MAX_CALLDATA_SIZE,
            });
        }
        if self.cache_size == 0 {
            return Err(VmTxConfigError::ZeroCacheSize);
        }
        if self.cache_size > HARD_MAX_CACHE_SIZE {
            return Err(VmTxConfigError::CacheSizeTooHigh {
                got: self.cache_size,
                max: HARD_MAX_CACHE_SIZE,
            });
        }
        if self.cache_ttl_secs == 0 {
            return Err(VmTxConfigError::ZeroCacheTtl);
        }
        if self.cache_ttl_secs > HARD_MAX_CACHE_TTL_SECS {
            return Err(VmTxConfigError::CacheTtlTooHigh {
                got: self.cache_ttl_secs,
                max: HARD_MAX_CACHE_TTL_SECS,
            });
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for VM transaction handling.
///
/// # Registration
///
/// [`VmTxMetrics::new`] registers with the **default** registry and can
/// only succeed once per process. [`VmTxMetrics::unregistered`] returns a
/// fail-free instance; [`Default`] uses it.
#[derive(Clone)]
pub struct VmTxMetrics {
    pub validations: Counter,
    pub passes: Counter,
    pub failures: CounterVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub gas_estimates: Counter,
    pub cache_size: Gauge,
}

impl VmTxMetrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            validations: prometheus::register_counter!(
                "iona_vmtx_validations_total",
                "Total VM transaction validations"
            )?,
            passes: prometheus::register_counter!(
                "iona_vmtx_passes_total",
                "Validations that passed"
            )?,
            failures: prometheus::register_counter_vec!(
                "iona_vmtx_failures_total",
                "Validations that failed",
                &["reason"]
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_vmtx_cache_hits_total",
                "Validation cache hits"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_vmtx_cache_misses_total",
                "Validation cache misses"
            )?,
            gas_estimates: prometheus::register_counter!(
                "iona_vmtx_gas_estimates_total",
                "Total gas estimates"
            )?,
            cache_size: prometheus::register_gauge!(
                "iona_vmtx_cache_size",
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
                "iona_vmtx_validations_total",
                "Total VM transaction validations",
            ),
            passes: mk_counter("iona_vmtx_passes_total", "Validations that passed"),
            failures: CounterVec::new(
                prometheus::Opts::new("iona_vmtx_failures_total", "Validations that failed"),
                &["reason"],
            )
            .expect("counter vec construction is infallible"),
            cache_hits: mk_counter("iona_vmtx_cache_hits_total", "Validation cache hits"),
            cache_misses: mk_counter(
                "iona_vmtx_cache_misses_total",
                "Validation cache misses",
            ),
            gas_estimates: mk_counter("iona_vmtx_gas_estimates_total", "Total gas estimates"),
            cache_size: Gauge::new(
                "iona_vmtx_cache_size",
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
    pub fn set_cache_size(&self, size: usize) {
        self.cache_size.set(size as f64);
    }
}

impl Default for VmTxMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── Snapshot ──────────────────────────────────────────────────────────────

/// Owned snapshot of [`VmTxMetrics`].
///
/// Unlike the collector, this type is `Serialize`, `Deserialize`,
/// `PartialEq`, and `Eq`, and does not hold a live reference into the
/// Prometheus registry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VmTxMetricsSnapshot {
    pub validations: u64,
    pub passes: u64,
    /// Per-reason failure counts, sorted by reason.
    pub failures: BTreeMap<String, u64>,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub gas_estimates: u64,
    pub cache_size: usize,
}

// ── Cache ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    result: Result<(), String>,
    expires_at: Instant,
}

/// Cache key: a 32-byte Keccak digest over the transaction's canonical
/// encoding plus the validation-relevant configuration fields.
type CacheKey = [u8; 32];

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe manager for VM transaction validation, caching, and metrics.
///
/// Cloning shares the underlying cache, metrics, and configuration.
#[derive(Clone)]
pub struct VmTxManager {
    config: Arc<VmTxConfig>,
    metrics: Arc<VmTxMetrics>,
    cache: Arc<Mutex<Option<LruCache<CacheKey, ValidationCacheEntry>>>>,
    ttl: Duration,
}

impl VmTxManager {
    /// Create a new manager with the given configuration.
    ///
    /// Tries to register Prometheus metrics with the default registry; on
    /// collision (e.g. a second manager in the same process) it falls back
    /// to an unregistered instance with a `warn!`.
    pub fn new(config: VmTxConfig) -> Result<Self, VmTxConfigError> {
        config.validate()?;

        let metrics = if config.enable_metrics {
            match VmTxMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = %e,
                        "VM tx metrics already registered; using unregistered instance"
                    );
                    VmTxMetrics::unregistered()
                }
            }
        } else {
            VmTxMetrics::unregistered()
        };
        let metrics = Arc::new(metrics);

        let cache = if config.enable_cache {
            let size =
                NonZeroUsize::new(config.cache_size).ok_or(VmTxConfigError::ZeroCacheSize)?;
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
    /// The cache, if enabled, is consulted before any work and stores only
    /// the final outcome.
    #[must_use = "the validation result must be handled"]
    pub fn validate(&self, tx: &VmTx) -> VmTxResult<()> {
        self.metrics.record_validation();

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
    fn validate_inner(&self, tx: &VmTx) -> VmTxResult<()> {
        // 1) Gas limits.
        let gas = tx.gas_limit();
        if gas == 0 {
            self.metrics.record_failure("zero_gas_limit");
            return Err(VmTxError::ZeroGasLimit(gas));
        }
        if gas > self.config.max_gas_limit {
            self.metrics.record_failure("gas_limit_too_high");
            return Err(VmTxError::GasLimitTooHigh {
                limit: gas,
                max: self.config.max_gas_limit,
            });
        }
        if gas < self.config.min_gas_limit {
            self.metrics.record_failure("gas_limit_too_low");
            return Err(VmTxError::GasLimitTooLow {
                limit: gas,
                min: self.config.min_gas_limit,
            });
        }

        // 2) Sender.
        if tx.sender().is_empty() {
            self.metrics.record_failure("empty_sender");
            return Err(VmTxError::EmptySender);
        }

        // 3) Payload.
        match tx {
            VmTx::Deploy { init_code, .. } => {
                if init_code.is_empty() {
                    self.metrics.record_failure("empty_init_code");
                    return Err(VmTxError::EmptyInitCode);
                }
                if init_code.len() > self.config.max_init_code_size {
                    self.metrics.record_failure("init_code_too_large");
                    return Err(VmTxError::InitCodeTooLarge {
                        size: init_code.len(),
                        max: self.config.max_init_code_size,
                    });
                }
            }
            VmTx::Call { contract, calldata, .. } => {
                if contract.iter().all(|&b| b == 0) {
                    self.metrics.record_failure("zero_contract_address");
                    return Err(VmTxError::ZeroContractAddress);
                }
                if calldata.len() > self.config.max_calldata_size {
                    self.metrics.record_failure("calldata_too_large");
                    return Err(VmTxError::CalldataTooLarge {
                        size: calldata.len(),
                        max: self.config.max_calldata_size,
                    });
                }
            }
        }

        self.metrics.record_pass();
        if self.config.log_validation {
            trace!("validation passed");
        }
        Ok(())
    }

    /// Validate and return an informational quantum scoreboard alongside
    /// the real result.
    ///
    /// **The scoreboard never gates a decision.** It is a diagnostic
    /// side-channel for observability.
    #[must_use = "both the result and the scoreboard should be handled"]
    pub fn validate_quantum(&self, tx: &VmTx) -> (VmTxResult<()>, QuantumVmTxState) {
        let result = self.validate(tx);
        let mut qstate = QuantumVmTxState::new();
        match &result {
            Ok(()) => {
                // Regression: the previous implementation recorded a pass
                // three times, over-counting every successful validation.
                qstate.record_pass();
                qstate.apply_payload_decoherence(tx.payload_size());
            }
            Err(_) => {
                qstate.record_failure();
            }
        }
        qstate.apply_vm_tx_channel();
        (result, qstate)
    }

    /// Canonical cache key: Keccak-256 over the transaction's body **and**
    /// the four validation-relevant config fields.
    ///
    /// Including the config means that changing `min_gas_limit` or a size
    /// bound invalidates the entire cache without operator intervention.
    fn compute_cache_key(&self, tx: &VmTx) -> CacheKey {
        let mut hasher = Keccak256::new();
        hasher.update(b"iona/vm_tx_cache/v1:");
        hasher.update(self.config.min_gas_limit.to_le_bytes());
        hasher.update(self.config.max_gas_limit.to_le_bytes());
        hasher.update((self.config.max_init_code_size as u64).to_le_bytes());
        hasher.update((self.config.max_calldata_size as u64).to_le_bytes());
        encode_tx_into(&mut hasher, tx);
        let out: [u8; 32] = hasher.finalize().into();
        out
    }

    /// Intrinsic gas for `tx`: the fixed cost of admission, before any VM
    /// execution.
    ///
    /// This is **not** an `estimate_gas` in the "predict execution" sense —
    /// it is the floor below which `gas_limit` will always fail. Actual
    /// execution cost is a VM concern and is out of scope here.
    #[must_use]
    pub fn intrinsic_gas(&self, tx: &VmTx) -> u64 {
        self.metrics.record_gas_estimate();

        let payload = tx.payload_size() as u64;
        let mut gas = INTRINSIC_BASE_GAS
            .saturating_add(INTRINSIC_GAS_PER_BYTE.saturating_mul(payload));
        if tx.is_deploy() {
            gas = gas.saturating_add(DEPLOY_EXTRA_GAS);
        }
        gas
    }

    /// Owned snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> VmTxMetricsSnapshot {
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

        VmTxMetricsSnapshot {
            validations: self.metrics.validations.get(),
            passes: self.metrics.passes.get(),
            failures,
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            gas_estimates: self.metrics.gas_estimates.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &VmTxConfig {
        &self.config
    }

    /// Clear the validation cache.
    pub fn clear_cache(&self) {
        let mut guard = self.cache.lock();
        if let Some(cache) = guard.as_mut() {
            cache.clear();
            drop(guard);
            self.metrics.set_cache_size(0);
            trace!("VM tx cache cleared");
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

/// Reduce an `VmTxResult<()>` to a stringly-typed value for caching.
fn encode_for_cache(result: &VmTxResult<()>) -> Result<(), String> {
    match result {
        Ok(()) => Ok(()),
        Err(e) => Err(e.to_string()),
    }
}

/// Reconstruct a cached outcome.
///
/// Cache hits for failures cannot recover the exact `VmTxError` variant
/// (it is not `Clone + Serialize`); the original `Display` string is
/// logged but the returned error is a `Decoherence` sentinel. Callers that
/// need exact variants should disable the cache
/// (`VmTxConfig::enable_cache = false`).
fn decode_cached(cached: Result<(), String>) -> VmTxResult<()> {
    match cached {
        Ok(()) => Ok(()),
        Err(msg) => {
            debug!(cached_error = %msg, "cache hit for a failed validation");
            Err(VmTxError::Decoherence {
                coherence: 0.0,
                threshold: 0.0,
            })
        }
    }
}

// ── Canonical tx encoding ────────────────────────────────────────────────

/// Feed a canonical, length-prefixed encoding of `tx` into `hasher`.
fn encode_tx_into(hasher: &mut Keccak256, tx: &VmTx) {
    let mut feed = |bytes: &[u8]| {
        hasher.update((bytes.len() as u64).to_le_bytes());
        hasher.update(bytes);
    };

    match tx {
        VmTx::Deploy {
            sender,
            init_code,
            gas_limit,
            ..
        } => {
            hasher.update([0u8]);
            feed(sender.as_bytes());
            hasher.update(gas_limit.to_le_bytes());
            feed(init_code);
        }
        VmTx::Call {
            sender,
            contract,
            calldata,
            gas_limit,
            ..
        } => {
            hasher.update([1u8]);
            feed(sender.as_bytes());
            hasher.update(contract);
            hasher.update(gas_limit.to_le_bytes());
            feed(calldata);
        }
    }
}

// ── Standalone helpers ───────────────────────────────────────────────────

/// Process-wide default manager for the free-function helpers.
static DEFAULT_MANAGER: std::sync::OnceLock<VmTxManager> = std::sync::OnceLock::new();

fn default_manager() -> Result<&'static VmTxManager, VmTxConfigError> {
    if let Some(m) = DEFAULT_MANAGER.get() {
        return Ok(m);
    }
    let config = VmTxConfig {
        enable_metrics: false,
        ..Default::default()
    };
    let m = VmTxManager::new(config)?;
    let _ = DEFAULT_MANAGER.set(m);
    Ok(DEFAULT_MANAGER.get().expect("set or already present"))
}

/// Validate a VM transaction using a process-wide default manager.
pub fn validate_vm_tx(tx: &VmTx) -> VmTxResult<()> {
    let manager = default_manager().map_err(|_| VmTxError::Decoherence {
        coherence: 0.0,
        threshold: 0.0,
    })?;
    manager.validate(tx)
}

/// Intrinsic gas using a process-wide default manager.
#[must_use]
pub fn estimate_vm_gas(tx: &VmTx) -> u64 {
    match default_manager() {
        Ok(m) => m.intrinsic_gas(tx),
        Err(_) => 0,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_deploy() -> VmTx {
        VmTx::Deploy {
            sender: "alice".into(),
            init_code: vec![0x60, 0x00, 0x00],
            gas_limit: 100_000,
            coherence: 1.0,
        }
    }

    fn valid_call() -> VmTx {
        VmTx::Call {
            sender: "bob".into(),
            contract: [1u8; 32],
            calldata: vec![0x01, 0x02],
            gas_limit: 200_000,
            coherence: 1.0,
        }
    }

    fn manager(cfg: VmTxConfig) -> VmTxManager {
        // Never register metrics in tests to avoid registry collisions.
        let cfg = VmTxConfig {
            enable_metrics: false,
            ..cfg
        };
        VmTxManager::new(cfg).unwrap()
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validate_ok() {
        let m = manager(VmTxConfig::default());
        assert!(m.validate(&valid_deploy()).is_ok());
        assert!(m.validate(&valid_call()).is_ok());
    }

    #[test]
    fn validate_gas_limit_too_high() {
        let m = manager(VmTxConfig {
            max_gas_limit: 50_000,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&valid_deploy()).unwrap_err(),
            VmTxError::GasLimitTooHigh { .. }
        ));
    }

    #[test]
    fn validate_gas_limit_too_low() {
        let m = manager(VmTxConfig {
            min_gas_limit: 200_000,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&valid_deploy()).unwrap_err(),
            VmTxError::GasLimitTooLow { .. }
        ));
    }

    #[test]
    fn validate_init_code_too_large() {
        let m = manager(VmTxConfig {
            max_init_code_size: 2,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&valid_deploy()).unwrap_err(),
            VmTxError::InitCodeTooLarge { .. }
        ));
    }

    #[test]
    fn validate_calldata_too_large() {
        let m = manager(VmTxConfig {
            max_calldata_size: 1,
            ..Default::default()
        });
        assert!(matches!(
            m.validate(&valid_call()).unwrap_err(),
            VmTxError::CalldataTooLarge { .. }
        ));
    }

    #[test]
    fn validate_empty_sender() {
        let m = manager(VmTxConfig::default());
        let mut tx = valid_deploy();
        if let VmTx::Deploy { sender, .. } = &mut tx {
            sender.clear();
        }
        assert!(matches!(m.validate(&tx).unwrap_err(), VmTxError::EmptySender));
    }

    #[test]
    fn validate_empty_init_code() {
        let m = manager(VmTxConfig::default());
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        assert!(matches!(
            m.validate(&tx).unwrap_err(),
            VmTxError::EmptyInitCode
        ));
    }

    #[test]
    fn validate_zero_contract() {
        let m = manager(VmTxConfig::default());
        let mut tx = valid_call();
        if let VmTx::Call { contract, .. } = &mut tx {
            *contract = [0u8; 32];
        }
        assert!(matches!(
            m.validate(&tx).unwrap_err(),
            VmTxError::ZeroContractAddress
        ));
    }

    // ── Quantum scoreboard ──────────────────────────────────────────────

    #[test]
    fn validate_quantum_records_pass_once() {
        // Regression: the previous implementation called `record_pass`
        // three times per successful validation.
        let m = manager(VmTxConfig::default());
        let (result, qstate) = m.validate_quantum(&valid_deploy());
        assert!(result.is_ok());
        assert_eq!(qstate.total_checks, 1);
        assert_eq!(qstate.total_failures, 0);
    }

    #[test]
    fn validate_quantum_records_failure_once() {
        let m = manager(VmTxConfig {
            max_init_code_size: 1,
            ..Default::default()
        });
        let (result, qstate) = m.validate_quantum(&valid_deploy());
        assert!(result.is_err());
        assert_eq!(qstate.total_checks, 1);
        assert_eq!(qstate.total_failures, 1);
    }

    // ── Gas ─────────────────────────────────────────────────────────────

    #[test]
    fn intrinsic_gas_deploy_includes_extra() {
        let m = manager(VmTxConfig::default());
        let gas = m.intrinsic_gas(&valid_deploy());
        let expected = INTRINSIC_BASE_GAS
            + INTRINSIC_GAS_PER_BYTE * 3
            + DEPLOY_EXTRA_GAS;
        assert_eq!(gas, expected);
    }

    #[test]
    fn intrinsic_gas_call_has_no_deploy_extra() {
        let m = manager(VmTxConfig::default());
        let gas = m.intrinsic_gas(&valid_call());
        let expected = INTRINSIC_BASE_GAS + INTRINSIC_GAS_PER_BYTE * 2;
        assert_eq!(gas, expected);
    }

    // ── Cache ───────────────────────────────────────────────────────────

    #[test]
    fn cache_hit_on_second_validation() {
        let m = manager(VmTxConfig::default());
        let tx = valid_deploy();
        assert!(m.validate(&tx).is_ok());
        assert!(m.validate(&tx).is_ok());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_size, 1);
    }

    #[test]
    fn cache_key_depends_on_limits() {
        // Two managers with different `max_gas_limit` must not share a
        // cache entry even for an identical tx.
        let tx = valid_call();
        let strict = manager(VmTxConfig {
            max_gas_limit: 100_000,
            min_gas_limit: 21_000,
            ..Default::default()
        });
        let permissive = manager(VmTxConfig {
            max_gas_limit: 1_000_000,
            min_gas_limit: 21_000,
            ..Default::default()
        });

        assert!(strict.validate(&tx).is_err()); // 200k > 100k
        assert!(permissive.validate(&tx).is_ok());
    }

    #[test]
    fn cache_disabled_does_not_populate() {
        let m = manager(VmTxConfig {
            enable_cache: false,
            ..Default::default()
        });
        assert!(m.validate(&valid_deploy()).is_ok());
        assert_eq!(m.cache_size(), 0);
        assert!(!m.is_cache_enabled());
    }

    #[test]
    fn clear_cache_empties_it() {
        let m = manager(VmTxConfig::default());
        assert!(m.validate(&valid_deploy()).is_ok());
        assert!(m.cache_size() > 0);
        m.clear_cache();
        assert_eq!(m.cache_size(), 0);
    }

    // ── Metrics snapshot ────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_is_owned() {
        let m = manager(VmTxConfig::default());
        assert!(m.validate(&valid_deploy()).is_ok());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.validations, 1);
        assert_eq!(snap.passes, 1);
        assert!(snap.failures.is_empty());
    }

    #[test]
    fn metrics_snapshot_records_failure_reason() {
        let m = manager(VmTxConfig {
            max_init_code_size: 1,
            ..Default::default()
        });
        let _ = m.validate(&valid_deploy());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.failures.get("init_code_too_large"), Some(&1));
    }

    #[test]
    fn metrics_snapshot_is_serializable() {
        let m = manager(VmTxConfig::default());
        let _ = m.validate(&valid_deploy());
        let snap = m.metrics_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: VmTxMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn metrics_unregistered_is_repeatable() {
        // Regression: `Default` previously chained `.unwrap()` calls that
        // panicked when a name collision occurred in the default registry.
        let _a = VmTxMetrics::unregistered();
        let _b = VmTxMetrics::unregistered();
        let _c = VmTxMetrics::default();
    }

    // ── Config validation ───────────────────────────────────────────────

    #[test]
    fn config_validation_accepts_default() {
        assert!(VmTxConfig::default().validate().is_ok());
    }

    #[test]
    fn config_validation_rejects_each_invalid_field() {
        let cases: &[(VmTxConfig, &str)] = &[
            (
                VmTxConfig { min_gas_limit: 0, ..Default::default() },
                "min_gas_limit",
            ),
            (
                VmTxConfig { max_gas_limit: 0, ..Default::default() },
                "max_gas_limit",
            ),
            (
                VmTxConfig {
                    min_gas_limit: 100,
                    max_gas_limit: 50,
                    ..Default::default()
                },
                "min > max",
            ),
            (
                VmTxConfig {
                    max_gas_limit: HARD_MAX_GAS_LIMIT + 1,
                    min_gas_limit: 1,
                    ..Default::default()
                },
                "max_gas_limit hard bound",
            ),
            (
                VmTxConfig { max_init_code_size: 0, ..Default::default() },
                "max_init_code_size",
            ),
            (
                VmTxConfig {
                    max_init_code_size: HARD_MAX_INIT_CODE_SIZE + 1,
                    ..Default::default()
                },
                "max_init_code_size hard bound",
            ),
            (
                VmTxConfig { max_calldata_size: 0, ..Default::default() },
                "max_calldata_size",
            ),
            (
                VmTxConfig {
                    max_calldata_size: HARD_MAX_CALLDATA_SIZE + 1,
                    ..Default::default()
                },
                "max_calldata_size hard bound",
            ),
            (
                VmTxConfig { cache_size: 0, ..Default::default() },
                "cache_size",
            ),
            (
                VmTxConfig { cache_ttl_secs: 0, ..Default::default() },
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
        assert!(validate_vm_tx(&valid_deploy()).is_ok());
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        assert!(validate_vm_tx(&tx).is_err());
    }

    #[test]
    fn standalone_estimate_gas_is_positive() {
        assert!(estimate_vm_gas(&valid_deploy()) > 0);
        assert!(estimate_vm_gas(&valid_call()) > 0);
    }
}
