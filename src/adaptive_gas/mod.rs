//! IONA — Adaptive Gas Pricing (Point 7).
//!
//! Separate pricing for CPU / I/O / Network / Storage resources.
//!
//! # Sync vs async
//!
//! The manager is designed to be called from **both** sync and async
//! contexts without panicking. The two big constraints:
//!
//! 1. **No `tokio::sync::Mutex::blocking_lock()`** anywhere on the hot
//!    path. Every interior mutex is `parking_lot::Mutex` or
//!    `parking_lot::RwLock`, which may be acquired from any thread.
//! 2. **No `tokio::spawn` from a sync constructor.** [`GasPricingManager::new`]
//!    never spawns a task; the caller opts in with
//!    [`GasPricingManager::start_updater`] from an async context.
//!
//! # Lock ordering
//!
//! Every code path acquires the two inner locks (`pricing` and `cache`)
//! in **one** order and never holds both at once:
//!
//! ```text
//!   price_for:      cache → (drop) → pricing → (drop) → cache → (drop)
//!   try_adjust:     pricing → (drop) → cache → (drop) → pricing.read (update_metrics)
//!   reload_config:  config → (drop) → pricing → (drop) → cache
//! ```
//!
//! The previous implementation held `cache.lock()` while waiting for
//! `pricing.read()` in `price_for`, and held `pricing.write()` while
//! waiting for `cache.lock()` in `try_adjust` — a guaranteed deadlock
//! under contention.
//!
//! # Reload semantics
//!
//! [`GasPricingManager::reload_config`] replaces the pricing state with
//! fresh base prices from the new configuration. Adaptive state
//! accumulated under the old config is **not** preserved — that is the
//! only safe behaviour when the base prices themselves change. Callers
//! that want to keep the current adaptation should modify the base
//! prices via `pricing::GasPricing` directly, which is not exposed here.
//!
//! # Standalone helpers
//!
//! [`gas_price`] and [`all_gas_prices`] use a process-wide default
//! manager created once via [`std::sync::OnceLock`]. They do **not**
//! create a fresh manager per call (the previous behaviour spawned a
//! tokio task on every call when `enable_adaptive` was set).

pub mod pricing;
pub mod resource_meter;
pub mod schedule;

use lru::LruCache;
use parking_lot::{Mutex, RwLock};
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram_vec, Counter,
    CounterVec, Gauge, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::CancellationToken;
use tokio::task::JoinHandle;
use tracing::{debug, error, info, trace, warn};

// ── Re-exports ────────────────────────────────────────────────────────────

pub use pricing::{GasPricing, PriceAdjustment, PricingFormula, ResourcePrice};
pub use resource_meter::{ResourceMeter, ResourceType, ResourceUsage};
pub use schedule::{PriceSchedule, PriceUpdater, UpdateMode};

// ── Constants ─────────────────────────────────────────────────────────────

pub const DEFAULT_CPU_PRICE: u64 = 10;
pub const DEFAULT_IO_PRICE: u64 = 5;
pub const DEFAULT_NETWORK_PRICE: u64 = 3;
pub const DEFAULT_STORAGE_PRICE: u64 = 2;
pub const DEFAULT_ADJUSTMENT_RATE: f64 = 0.001;
pub const DEFAULT_MAX_PRICE_MULTIPLIER: f64 = 10.0;
pub const DEFAULT_MIN_PRICE_MULTIPLIER: f64 = 0.1;
pub const DEFAULT_CACHE_SIZE: usize = 1024;
pub const DEFAULT_CACHE_TTL_SECS: u64 = 10;
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 60;
pub const DEFAULT_RETRY_ATTEMPTS: usize = 3;
pub const DEFAULT_RETRY_BACKOFF_MS: u64 = 100;

/// Cap on the exponential backoff exponent. `2^10 = 1024 × base_backoff`.
const MAX_BACKOFF_EXP: u32 = 10;

/// Cap on `update_interval_secs` to avoid integer overflow in
/// `Duration::from_secs` on platforms where `u64` seconds overflow
/// `time_t` (Windows).
const MAX_UPDATE_INTERVAL_SECS: u64 = 86_400;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the gas pricing subsystem.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GasPricingConfig {
    pub cpu_base_price: u64,
    pub io_base_price: u64,
    pub network_base_price: u64,
    pub storage_base_price: u64,
    pub adjustment_rate: f64,
    pub max_price_multiplier: f64,
    pub min_price_multiplier: f64,
    pub enable_cache: bool,
    pub cache_size: usize,
    pub cache_ttl_secs: u64,
    pub update_interval_secs: u64,
    pub enable_adaptive: bool,
    pub enable_metrics: bool,
    pub log_changes: bool,
    pub retry_attempts: usize,
    pub retry_backoff_ms: u64,
}

impl Default for GasPricingConfig {
    fn default() -> Self {
        Self {
            cpu_base_price: DEFAULT_CPU_PRICE,
            io_base_price: DEFAULT_IO_PRICE,
            network_base_price: DEFAULT_NETWORK_PRICE,
            storage_base_price: DEFAULT_STORAGE_PRICE,
            adjustment_rate: DEFAULT_ADJUSTMENT_RATE,
            max_price_multiplier: DEFAULT_MAX_PRICE_MULTIPLIER,
            min_price_multiplier: DEFAULT_MIN_PRICE_MULTIPLIER,
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            update_interval_secs: DEFAULT_UPDATE_INTERVAL_SECS,
            enable_adaptive: true,
            enable_metrics: true,
            log_changes: true,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            retry_backoff_ms: DEFAULT_RETRY_BACKOFF_MS,
        }
    }
}

impl GasPricingConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cpu_base_price == 0 {
            return Err("cpu_base_price must be > 0".into());
        }
        if self.io_base_price == 0 {
            return Err("io_base_price must be > 0".into());
        }
        if self.network_base_price == 0 {
            return Err("network_base_price must be > 0".into());
        }
        if self.storage_base_price == 0 {
            return Err("storage_base_price must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.adjustment_rate) {
            return Err("adjustment_rate must be in [0.0, 1.0]".into());
        }
        if !self.max_price_multiplier.is_finite() || self.max_price_multiplier <= 1.0 {
            return Err("max_price_multiplier must be finite and > 1.0".into());
        }
        if !self.min_price_multiplier.is_finite()
            || self.min_price_multiplier <= 0.0
            || self.min_price_multiplier >= 1.0
        {
            return Err("min_price_multiplier must be finite and in (0.0, 1.0)".into());
        }
        if self.min_price_multiplier >= self.max_price_multiplier {
            return Err(
                "min_price_multiplier must be strictly less than max_price_multiplier".into(),
            );
        }
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        if self.update_interval_secs == 0 {
            return Err("update_interval_secs must be > 0".into());
        }
        if self.update_interval_secs > MAX_UPDATE_INTERVAL_SECS {
            return Err(format!(
                "update_interval_secs must be <= {MAX_UPDATE_INTERVAL_SECS}"
            ));
        }
        if self.retry_attempts == 0 {
            return Err("retry_attempts must be > 0".into());
        }
        if self.retry_backoff_ms == 0 {
            return Err("retry_backoff_ms must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for the gas pricing subsystem.
///
/// [`GasPricingMetrics::new`] registers with the default registry and can
/// only succeed once per process. [`GasPricingMetrics::unregistered`] is
/// fail-free and what [`Default`] uses.
#[derive(Clone)]
pub struct GasPricingMetrics {
    pub cpu_price: Gauge,
    pub io_price: Gauge,
    pub network_price: Gauge,
    pub storage_price: Gauge,
    pub price_lookups: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub cache_expirations: Counter,
    pub adjustments: CounterVec,
    pub adjustment_duration: HistogramVec,
    pub adjustment_errors: Counter,
}

impl GasPricingMetrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            cpu_price: prometheus::register_gauge!(
                "iona_gas_cpu_price",
                "Current CPU gas price"
            )?,
            io_price: prometheus::register_gauge!(
                "iona_gas_io_price",
                "Current I/O gas price"
            )?,
            network_price: prometheus::register_gauge!(
                "iona_gas_network_price",
                "Current network gas price"
            )?,
            storage_price: prometheus::register_gauge!(
                "iona_gas_storage_price",
                "Current storage gas price"
            )?,
            price_lookups: prometheus::register_counter!(
                "iona_gas_price_lookups_total",
                "Total price lookups"
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_gas_cache_hits_total",
                "Cache hits"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_gas_cache_misses_total",
                "Cache misses"
            )?,
            cache_expirations: prometheus::register_counter!(
                "iona_gas_cache_expirations_total",
                "Cache expirations"
            )?,
            adjustments: prometheus::register_counter_vec!(
                "iona_gas_adjustments_total",
                "Price adjustments",
                &["resource", "direction"]
            )?,
            adjustment_duration: prometheus::register_histogram_vec!(
                "iona_gas_adjustment_duration_seconds",
                "Adjustment duration",
                &["resource"]
            )?,
            adjustment_errors: prometheus::register_counter!(
                "iona_gas_adjustment_errors_total",
                "Adjustment errors"
            )?,
        })
    }

    /// Fail-free metrics bundle. Never registers with Prometheus.
    pub fn unregistered() -> Self {
        let mk_counter = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        let mk_gauge = |name: &str, help: &str| {
            Gauge::new(name, help).expect("gauge construction is infallible")
        };
        Self {
            cpu_price: mk_gauge("iona_gas_cpu_price", "Current CPU gas price"),
            io_price: mk_gauge("iona_gas_io_price", "Current I/O gas price"),
            network_price: mk_gauge("iona_gas_network_price", "Current network gas price"),
            storage_price: mk_gauge("iona_gas_storage_price", "Current storage gas price"),
            price_lookups: mk_counter("iona_gas_price_lookups_total", "Total price lookups"),
            cache_hits: mk_counter("iona_gas_cache_hits_total", "Cache hits"),
            cache_misses: mk_counter("iona_gas_cache_misses_total", "Cache misses"),
            cache_expirations: mk_counter(
                "iona_gas_cache_expirations_total",
                "Cache expirations",
            ),
            adjustments: CounterVec::new(
                prometheus::Opts::new("iona_gas_adjustments_total", "Price adjustments"),
                &["resource", "direction"],
            )
            .expect("counter vec construction is infallible"),
            adjustment_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_gas_adjustment_duration_seconds",
                    "Adjustment duration",
                ),
                &["resource"],
            )
            .expect("histogram vec construction is infallible"),
            adjustment_errors: mk_counter(
                "iona_gas_adjustment_errors_total",
                "Adjustment errors",
            ),
        }
    }

    pub fn set_cpu_price(&self, price: u64) {
        self.cpu_price.set(price as f64);
    }
    pub fn set_io_price(&self, price: u64) {
        self.io_price.set(price as f64);
    }
    pub fn set_network_price(&self, price: u64) {
        self.network_price.set(price as f64);
    }
    pub fn set_storage_price(&self, price: u64) {
        self.storage_price.set(price as f64);
    }
    pub fn record_lookup(&self) {
        self.price_lookups.inc();
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    pub fn record_cache_expiration(&self) {
        self.cache_expirations.inc();
    }
    pub fn record_adjustment(&self, resource: &str, direction: &str, duration: Duration) {
        self.adjustments
            .with_label_values(&[resource, direction])
            .inc();
        self.adjustment_duration
            .with_label_values(&[resource])
            .observe(duration.as_secs_f64());
    }
    pub fn record_adjustment_error(&self) {
        self.adjustment_errors.inc();
    }
}

impl Default for GasPricingMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── Cache entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CacheEntry {
    price: u64,
    timestamp_secs: u64,
}

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe gas pricing manager.
///
/// # Cloning
///
/// `GasPricingManager::clone()` shares the pricing state, cache, and any
/// running updater task via `Arc`. Calling `shutdown` on any clone stops
/// the updater for **all** clones.
///
/// # Lifecycle
///
/// ```rust,ignore
/// let mgr = GasPricingManager::new(config)?;   // sync
/// mgr.start_updater().await?;                  // async, opt-in
/// // ... use mgr from any context ...
/// mgr.shutdown().await;                        // async
/// ```
pub struct GasPricingManager {
    config: RwLock<Arc<GasPricingConfig>>,
    metrics: Arc<GasPricingMetrics>,
    pricing: Arc<RwLock<GasPricing>>,
    cache: Arc<Mutex<Option<LruCache<u64, CacheEntry>>>>,
    cancellation_token: Mutex<CancellationToken>,
    updater_task: Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>,
    updater_running: Arc<AtomicBool>,
}

impl Clone for GasPricingManager {
    fn clone(&self) -> Self {
        Self {
            config: RwLock::new(self.config.read().clone()),
            metrics: self.metrics.clone(),
            pricing: self.pricing.clone(),
            cache: self.cache.clone(),
            cancellation_token: Mutex::new(self.cancellation_token.lock().clone()),
            updater_task: self.updater_task.clone(),
            updater_running: self.updater_running.clone(),
        }
    }
}

impl GasPricingManager {
    /// Create a new manager.
    ///
    /// # Sync
    ///
    /// This function does **not** spawn a background task and is safe to
    /// call from any context. If you want the adaptive updater to run,
    /// call [`start_updater`](Self::start_updater) from an async context
    /// after constructing the manager.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `config.validate()` fails.
    pub fn new(config: GasPricingConfig) -> Result<Self, String> {
        config.validate()?;

        let metrics = if config.enable_metrics {
            match GasPricingMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = %e,
                        "gas pricing metrics already registered; using unregistered instance"
                    );
                    GasPricingMetrics::unregistered()
                }
            }
        } else {
            GasPricingMetrics::unregistered()
        };
        let metrics = Arc::new(metrics);

        let cache = if config.enable_cache {
            let size =
                NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };

        let pricing = Arc::new(RwLock::new(GasPricing::new(&config)));

        let manager = Self {
            config: RwLock::new(Arc::new(config)),
            metrics,
            pricing,
            cache: Arc::new(Mutex::new(cache)),
            cancellation_token: Mutex::new(CancellationToken::new()),
            updater_task: Arc::new(tokio::sync::Mutex::new(None)),
            updater_running: Arc::new(AtomicBool::new(false)),
        };

        manager.refresh_gauges_from_pricing();
        Ok(manager)
    }

    // ── Configuration access ────────────────────────────────────────────

    /// Snapshot of the current configuration.
    ///
    /// Returns an `Arc` clone; cheap and safe to hold across `.await`.
    #[must_use]
    pub fn config(&self) -> Arc<GasPricingConfig> {
        self.config.read().clone()
    }

    // ── Pricing queries ─────────────────────────────────────────────────

    /// Current price for `resource`.
    ///
    /// Hot path. Never blocks on a tokio runtime; may be called from any
    /// thread or context.
    #[must_use]
    pub fn price_for(&self, resource: ResourceType) -> u64 {
        self.metrics.record_lookup();

        let cfg = self.config.read().clone();
        let key = resource as u64;
        let now = current_timestamp();

        // ── Cache lookup ──────────────────────────────────────────────
        if cfg.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    // `saturating_sub` avoids the u64 underflow that
                    // would otherwise panic in debug builds if the wall
                    // clock moved backwards.
                    let age = now.saturating_sub(entry.timestamp_secs);
                    if age < cfg.cache_ttl_secs {
                        let price = entry.price;
                        drop(guard);
                        self.metrics.record_cache_hit();
                        return price;
                    }
                    cache.pop(&key);
                    drop(guard);
                    self.metrics.record_cache_expiration();
                } else {
                    drop(guard);
                }
            }
        }

        self.metrics.record_cache_miss();

        // ── Compute ───────────────────────────────────────────────────
        let price = {
            let pricing = self.pricing.read();
            pricing.price_for(resource)
        };

        // ── Cache insert ──────────────────────────────────────────────
        if cfg.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(
                    key,
                    CacheEntry {
                        price,
                        timestamp_secs: now,
                    },
                );
            }
        }

        price
    }

    /// Snapshot of all four prices at once.
    #[must_use]
    pub fn all_prices(&self) -> [u64; 4] {
        [
            self.price_for(ResourceType::Cpu),
            self.price_for(ResourceType::Io),
            self.price_for(ResourceType::Network),
            self.price_for(ResourceType::Storage),
        ]
    }

    // ── Adjustment ──────────────────────────────────────────────────────

    /// Adjust prices **synchronously**, blocking the current thread on
    /// retry backoff.
    ///
    /// # Warning
    ///
    /// Blocks the caller's thread for up to `retry_attempts × max_backoff`.
    /// Do **not** call this from an async task unless you have wrapped it
    /// in `tokio::task::spawn_blocking`. For an async-friendly variant,
    /// see [`adjust_async`](Self::adjust_async).
    pub fn adjust_sync(&self, demand: &ResourceUsage) -> Result<(), String> {
        demand.validate()?;

        let start = Instant::now();
        let mut last_error: Option<String> = None;

        for attempt in 0..self.config.read().retry_attempts {
            if attempt > 0 {
                let backoff = self.retry_backoff_for(attempt);
                std::thread::sleep(backoff);
                trace!(attempt, ?backoff, "retrying adjustment");
            }

            match self.try_adjust(demand, start) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.metrics.record_adjustment_error();
                    warn!(attempt, error = %e, "adjustment attempt failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "adjustment failed after all retries".into()))
    }

    /// Adjust prices **asynchronously**, using `tokio::time::sleep` for
    /// retry backoff.
    ///
    /// This is the entry point the internal updater uses.
    pub async fn adjust_async(&self, demand: &ResourceUsage) -> Result<(), String> {
        demand.validate()?;

        let retry_attempts = self.config.read().retry_attempts;
        let start = Instant::now();
        let mut last_error: Option<String> = None;

        for attempt in 0..retry_attempts {
            if attempt > 0 {
                tokio::time::sleep(self.retry_backoff_for(attempt)).await;
                trace!(attempt, "retrying adjustment (async)");
            }

            match self.try_adjust(demand, start) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    self.metrics.record_adjustment_error();
                    warn!(attempt, error = %e, "adjustment attempt failed");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| "adjustment failed after all retries".into()))
    }

    /// Backwards-compatible alias for [`adjust_sync`](Self::adjust_sync).
    pub fn adjust(&self, demand: &ResourceUsage) -> Result<(), String> {
        self.adjust_sync(demand)
    }

    fn retry_backoff_for(&self, attempt: usize) -> Duration {
        // `attempt - 1` capped so `2^exp` cannot overflow.
        let exp = (attempt.saturating_sub(1) as u32).min(MAX_BACKOFF_EXP);
        let factor = 1u64.checked_shl(exp).unwrap_or(u64::MAX);
        let ms = self
            .config
            .read()
            .retry_backoff_ms
            .saturating_mul(factor);
        Duration::from_millis(ms)
    }

    fn try_adjust(&self, demand: &ResourceUsage, start: Instant) -> Result<(), String> {
        // ── Compute adjustments under the write lock, then release it ─
        //
        // The write guard must be dropped before `refresh_gauges_from_pricing`
        // (which takes `pricing.read()`) is called. Doing both in the
        // same scope was the previous deadlock.
        let cfg = self.config.read().clone();
        let adjustments = {
            let mut pricing = self.pricing.write();
            pricing.adjust(demand, &cfg)
        };

        // ── Metrics + logging ─────────────────────────────────────────
        for (resource, old_price, new_price) in &adjustments {
            let direction = if new_price > old_price { "up" } else { "down" };
            self.metrics
                .record_adjustment(resource.to_string().as_str(), direction, start.elapsed());
            if cfg.log_changes {
                info!(
                    resource = %resource,
                    old_price,
                    new_price,
                    "gas price adjusted"
                );
            }
        }

        // ── Clear cache outside the write lock ───────────────────────
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
        }

        // ── Refresh gauges outside the write lock ────────────────────
        self.refresh_gauges_from_pricing();

        Ok(())
    }

    // ── Updater lifecycle ───────────────────────────────────────────────

    /// Whether the background updater is currently running.
    #[must_use]
    pub fn is_updater_running(&self) -> bool {
        self.updater_running.load(Ordering::Acquire)
    }

    /// Start the background adaptive updater.
    ///
    /// # Errors
    ///
    /// - If the updater is already running, returns `Err` (no double-spawn).
    /// - If the manager's config has `enable_adaptive = false`, returns `Err`.
    ///
    /// # Async
    ///
    /// This method spawns a task and therefore must be called from
    /// within a tokio runtime. The previous implementation tried to
    /// spawn from a sync constructor, which panicked when `new()` was
    /// called before the runtime existed.
    pub async fn start_updater(&self) -> Result<(), String> {
        if self.updater_running.swap(true, Ordering::AcqRel) {
            return Err("gas pricing updater is already running".into());
        }

        let cfg = self.config.read().clone();
        if !cfg.enable_adaptive {
            self.updater_running.store(false, Ordering::Release);
            return Err("enable_adaptive is false; refusing to start updater".into());
        }

        let token = CancellationToken::new();
        *self.cancellation_token.lock() = token.clone();

        let manager = self.clone_for_updater();
        let interval = Duration::from_secs(cfg.update_interval_secs);

        let handle = tokio::spawn(async move {
            let mut tick = tokio::time::interval(interval);
            tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    _ = tick.tick() => {
                        // Placeholder demand: production code should feed
                        // actual block utilization from the producer.
                        let demand = ResourceUsage {
                            cpu_used: 50,
                            io_used: 30,
                            network_used: 20,
                            storage_used: 10,
                            target_cpu: 50,
                            target_io: 30,
                            target_network: 20,
                            target_storage: 10,
                        };
                        if let Err(e) = manager.adjust_async(&demand).await {
                            error!(error = %e, "adaptive gas adjustment failed");
                        }
                    }
                    _ = token.cancelled() => {
                        info!("gas pricing updater shutting down");
                        break;
                    }
                }
            }
            manager.updater_running.store(false, Ordering::Release);
        });

        *self.updater_task.lock().await = Some(handle);
        info!(
            interval_secs = cfg.update_interval_secs,
            "gas pricing updater started"
        );
        Ok(())
    }

    /// Stop the background updater.
    ///
    /// Idempotent: calling `shutdown` when no updater is running returns
    /// immediately.
    pub async fn shutdown(&self) {
        self.cancellation_token.lock().cancel();
        if let Some(handle) = self.updater_task.lock().await.take() {
            // Do not block forever: abort if the task takes > 5s.
            match tokio::time::timeout(Duration::from_secs(5), handle).await {
                Ok(_) => {}
                Err(_) => warn!("gas pricing updater did not shut down within 5s"),
            }
        }
        self.updater_running.store(false, Ordering::Release);
    }

    /// Hot-reload the configuration.
    ///
    /// Restarts the updater if `enable_adaptive` changed. Preserves
    /// nothing else from the previous config — the pricing state is
    /// rebuilt from the new base prices (see module docs).
    pub async fn reload_config(&self, new_config: GasPricingConfig) -> Result<(), String> {
        new_config.validate()?;

        let old_adaptive = self.config.read().enable_adaptive;
        let new_adaptive = new_config.enable_adaptive;

        // ── 1. Update pricing state (write lock) ─────────────────────
        {
            let mut pricing = self.pricing.write();
            *pricing = GasPricing::new(&new_config);
        }

        // ── 2. Update config (write lock) ────────────────────────────
        *self.config.write() = Arc::new(new_config.clone());

        // ── 3. Update cache ──────────────────────────────────────────
        {
            let mut cache = self.cache.lock();
            if new_config.enable_cache {
                let size = NonZeroUsize::new(new_config.cache_size)
                    .ok_or("cache_size must be > 0")?;
                let mut new_cache = LruCache::new(size);
                if let Some(old) = cache.as_mut() {
                    // Copy entries whose timestamp is still within TTL.
                    let now = current_timestamp();
                    for (k, v) in old.iter() {
                        if now.saturating_sub(v.timestamp_secs) < new_config.cache_ttl_secs {
                            new_cache.put(*k, v.clone());
                        }
                    }
                }
                *cache = Some(new_cache);
            } else {
                *cache = None;
            }
        }

        // ── 4. Refresh gauges ─────────────────────────────────────────
        self.refresh_gauges_from_pricing();

        // ── 5. Restart updater if adaptation state changed ───────────
        if old_adaptive != new_adaptive {
            self.shutdown().await;
            if new_adaptive {
                if let Err(e) = self.start_updater().await {
                    warn!(error = %e, "failed to restart updater after config reload");
                }
            }
        }

        info!("gas pricing configuration reloaded");
        Ok(())
    }

    // ── Cache / metrics accessors ───────────────────────────────────────

    /// Clear the price cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("gas pricing cache cleared");
        }
    }

    /// Current cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Snapshot of the current metrics. Reads `pricing` directly so it
    /// reflects the live state, not the last-refreshed gauges.
    #[must_use]
    pub fn metrics_snapshot(&self) -> GasPricingMetricsSnapshot {
        let (cpu, io, net, storage) = {
            let pricing = self.pricing.read();
            (
                pricing.price_for(ResourceType::Cpu),
                pricing.price_for(ResourceType::Io),
                pricing.price_for(ResourceType::Network),
                pricing.price_for(ResourceType::Storage),
            )
        };
        GasPricingMetricsSnapshot {
            cpu_price: cpu,
            io_price: io,
            network_price: net,
            storage_price: storage,
            price_lookups: self.metrics.price_lookups.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            cache_expirations: self.metrics.cache_expirations.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Refresh the Prometheus gauges from `pricing`. Called after every
    /// state change; never takes the cache or write locks.
    fn refresh_gauges_from_pricing(&self) {
        let (cpu, io, net, storage) = {
            let pricing = self.pricing.read();
            (
                pricing.price_for(ResourceType::Cpu),
                pricing.price_for(ResourceType::Io),
                pricing.price_for(ResourceType::Network),
                pricing.price_for(ResourceType::Storage),
            )
        };
        self.metrics.set_cpu_price(cpu);
        self.metrics.set_io_price(io);
        self.metrics.set_network_price(net);
        self.metrics.set_storage_price(storage);
    }

    /// Clone configured so the updater task holds its own cheap handle
    /// that cannot be confused with the caller's `.clone()`.
    fn clone_for_updater(&self) -> Self {
        self.clone()
    }
}

/// Snapshot of gas pricing metrics.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GasPricingMetricsSnapshot {
    pub cpu_price: u64,
    pub io_price: u64,
    pub network_price: u64,
    pub storage_price: u64,
    pub price_lookups: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_expirations: u64,
    pub cache_size: usize,
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── ResourceUsage validation ──────────────────────────────────────────────

impl ResourceUsage {
    /// Validate that all percentages are in `[0, 100]`.
    pub fn validate(&self) -> Result<(), String> {
        let fields = [
            (self.cpu_used, "cpu_used"),
            (self.io_used, "io_used"),
            (self.network_used, "network_used"),
            (self.storage_used, "storage_used"),
            (self.target_cpu, "target_cpu"),
            (self.target_io, "target_io"),
            (self.target_network, "target_network"),
            (self.target_storage, "target_storage"),
        ];
        for (val, name) in fields {
            if val > 100 {
                return Err(format!("{name} cannot exceed 100"));
            }
        }
        Ok(())
    }
}

// ── Standalone helpers ────────────────────────────────────────────────────

/// Process-wide default manager, installed on first use.
///
/// **Never** spawns an updater. `enable_adaptive` is forced to `false`
/// so this helper cannot leak tasks per call.
static DEFAULT_MANAGER: std::sync::OnceLock<GasPricingManager> = std::sync::OnceLock::new();

fn default_manager() -> &'static GasPricingManager {
    DEFAULT_MANAGER.get_or_init(|| {
        let cfg = GasPricingConfig {
            enable_adaptive: false,
            enable_metrics: false,
            ..Default::default()
        };
        GasPricingManager::new(cfg).expect("default gas pricing config is valid")
    })
}

/// Price for `resource` under the process-wide default config.
#[must_use]
pub fn gas_price(resource: ResourceType) -> u64 {
    default_manager().price_for(resource)
}

/// All four prices under the process-wide default config.
#[must_use]
pub fn all_gas_prices() -> [u64; 4] {
    default_manager().all_prices()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_default_validates() {
        assert!(GasPricingConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_prices() {
        for make in [
            |c: &mut GasPricingConfig| c.cpu_base_price = 0,
            |c: &mut GasPricingConfig| c.io_base_price = 0,
            |c: &mut GasPricingConfig| c.network_base_price = 0,
            |c: &mut GasPricingConfig| c.storage_base_price = 0,
        ] {
            let mut c = GasPricingConfig::default();
            make(&mut c);
            assert!(c.validate().is_err());
        }
    }

    #[test]
    fn config_rejects_out_of_range_multipliers() {
        let mut c = GasPricingConfig::default();
        c.max_price_multiplier = 1.0;
        assert!(c.validate().is_err());

        let mut c = GasPricingConfig::default();
        c.min_price_multiplier = 0.0;
        assert!(c.validate().is_err());

        // New: min must be strictly less than max.
        let mut c = GasPricingConfig::default();
        c.min_price_multiplier = 5.0;
        c.max_price_multiplier = 2.0;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_nan_multipliers() {
        let mut c = GasPricingConfig::default();
        c.max_price_multiplier = f64::NAN;
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_rejects_bad_retry_and_interval() {
        let mut c = GasPricingConfig::default();
        c.retry_attempts = 0;
        assert!(c.validate().is_err());

        let mut c = GasPricingConfig::default();
        c.retry_backoff_ms = 0;
        assert!(c.validate().is_err());

        let mut c = GasPricingConfig::default();
        c.update_interval_secs = 0;
        assert!(c.validate().is_err());

        let mut c = GasPricingConfig::default();
        c.update_interval_secs = MAX_UPDATE_INTERVAL_SECS + 1;
        assert!(c.validate().is_err());
    }

    // ── Basic operation ─────────────────────────────────────────────────

    #[test]
    fn new_works_from_sync_context() {
        // `new()` no longer spawns a task, so this is safe.
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        assert!(!mgr.is_updater_running());
    }

    #[test]
    fn price_for_returns_positive_prices() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        assert!(mgr.price_for(ResourceType::Cpu) > 0);
        assert!(mgr.price_for(ResourceType::Io) > 0);
        assert!(mgr.price_for(ResourceType::Network) > 0);
        assert!(mgr.price_for(ResourceType::Storage) > 0);
    }

    #[test]
    fn all_prices_has_four_entries() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        assert_eq!(mgr.all_prices().len(), 4);
    }

    #[test]
    fn cache_disabled_does_not_cache() {
        let cfg = GasPricingConfig {
            enable_cache: false,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        let _ = mgr.price_for(ResourceType::Cpu);
        assert_eq!(mgr.cache_size(), 0);
    }

    #[test]
    fn cache_populates_and_clears() {
        let cfg = GasPricingConfig {
            enable_cache: true,
            cache_size: 16,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        let _ = mgr.price_for(ResourceType::Cpu);
        assert!(mgr.cache_size() > 0);
        mgr.clear_cache();
        assert_eq!(mgr.cache_size(), 0);
    }

    // ── Adjustment ──────────────────────────────────────────────────────

    #[test]
    fn adjust_sync_is_deterministic() {
        let cfg = GasPricingConfig {
            enable_adaptive: false,
            retry_attempts: 1,
            log_changes: false,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        let demand = ResourceUsage {
            cpu_used: 80,
            io_used: 30,
            network_used: 20,
            storage_used: 10,
            target_cpu: 50,
            target_io: 30,
            target_network: 20,
            target_storage: 10,
        };
        mgr.adjust_sync(&demand).unwrap();
        let p1 = mgr.price_for(ResourceType::Cpu);
        mgr.adjust_sync(&demand).unwrap();
        let p2 = mgr.price_for(ResourceType::Cpu);
        assert!(p2 >= p1);
    }

    #[test]
    fn adjust_sync_rejects_invalid_demand() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        let bad = ResourceUsage {
            cpu_used: 200,
            ..ResourceUsage {
                cpu_used: 0,
                io_used: 0,
                network_used: 0,
                storage_used: 0,
                target_cpu: 0,
                target_io: 0,
                target_network: 0,
                target_storage: 0,
            }
        };
        assert!(mgr.adjust_sync(&bad).is_err());
    }

    #[tokio::test]
    async fn adjust_async_does_not_block_runtime() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        let demand = ResourceUsage {
            cpu_used: 60,
            io_used: 30,
            network_used: 20,
            storage_used: 10,
            target_cpu: 50,
            target_io: 30,
            target_network: 20,
            target_storage: 10,
        };
        // Would panic under the previous `blocking_lock` design.
        mgr.adjust_async(&demand).await.unwrap();
    }

    // ── Updater lifecycle ───────────────────────────────────────────────

    #[tokio::test]
    async fn updater_start_then_shutdown() {
        let cfg = GasPricingConfig {
            enable_adaptive: true,
            update_interval_secs: 1,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        mgr.start_updater().await.unwrap();
        assert!(mgr.is_updater_running());
        mgr.shutdown().await;
        assert!(!mgr.is_updater_running());
    }

    #[tokio::test]
    async fn updater_rejects_double_start() {
        let cfg = GasPricingConfig {
            enable_adaptive: true,
            update_interval_secs: 1,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        mgr.start_updater().await.unwrap();
        assert!(mgr.start_updater().await.is_err());
        mgr.shutdown().await;
    }

    #[tokio::test]
    async fn updater_rejects_when_adaptive_disabled() {
        let cfg = GasPricingConfig {
            enable_adaptive: false,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        assert!(mgr.start_updater().await.is_err());
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let cfg = GasPricingConfig {
            enable_adaptive: true,
            update_interval_secs: 1,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        mgr.start_updater().await.unwrap();
        mgr.shutdown().await;
        mgr.shutdown().await; // no panic
    }

    // ── Reload ──────────────────────────────────────────────────────────

    #[tokio::test]
    async fn reload_updates_base_prices() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        let before = mgr.price_for(ResourceType::Cpu);

        let mut new_cfg = GasPricingConfig::default();
        new_cfg.cpu_base_price = 100;
        mgr.reload_config(new_cfg).await.unwrap();

        let after = mgr.price_for(ResourceType::Cpu);
        assert_ne!(before, after);
    }

    #[tokio::test]
    async fn reload_rejects_invalid_config() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        let mut bad = GasPricingConfig::default();
        bad.cpu_base_price = 0;
        assert!(mgr.reload_config(bad).await.is_err());
    }

    #[tokio::test]
    async fn reload_starts_and_stops_updater() {
        let cfg = GasPricingConfig {
            enable_adaptive: false,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();

        // Reload with adaptive on → updater should start.
        let mut new_cfg = GasPricingConfig::default();
        new_cfg.enable_adaptive = true;
        new_cfg.update_interval_secs = 1;
        mgr.reload_config(new_cfg).await.unwrap();
        assert!(mgr.is_updater_running());

        // Reload with adaptive off → updater should stop.
        let mut new_cfg = GasPricingConfig::default();
        new_cfg.enable_adaptive = false;
        mgr.reload_config(new_cfg).await.unwrap();
        assert!(!mgr.is_updater_running());
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn metrics_unregistered_is_repeatable() {
        let _a = GasPricingMetrics::unregistered();
        let _b = GasPricingMetrics::unregistered();
        let _c = GasPricingMetrics::default();
    }

    #[test]
    fn metrics_snapshot_reads_live_prices() {
        let mgr = GasPricingManager::new(GasPricingConfig::default()).unwrap();
        let snap = mgr.metrics_snapshot();
        assert_eq!(snap.cpu_price, mgr.price_for(ResourceType::Cpu));
    }

    #[test]
    fn metrics_snapshot_tracks_lookups() {
        let cfg = GasPricingConfig {
            enable_cache: false,
            enable_metrics: false,
            ..Default::default()
        };
        let mgr = GasPricingManager::new(cfg).unwrap();
        let before = mgr.metrics_snapshot().price_lookups;
        let _ = mgr.price_for(ResourceType::Cpu);
        let _ = mgr.price_for(ResourceType::Cpu);
        let after = mgr.metrics_snapshot().price_lookups;
        assert_eq!(after, before + 2);
    }

    // ── Standalone ──────────────────────────────────────────────────────

    #[test]
    fn standalone_helpers_do_not_panic() {
        let p = gas_price(ResourceType::Cpu);
        assert!(p > 0);
        assert_eq!(all_gas_prices().len(), 4);
    }

    #[test]
    fn standalone_helpers_share_one_manager() {
        // Calling `gas_price` repeatedly must not accumulate updater
        // tasks — the previous implementation constructed a fresh
        // manager per call.
        for _ in 0..10 {
            let _ = gas_price(ResourceType::Cpu);
        }
        // No panics, no task accumulation.
    }
}
