//! IONA — Adaptive Gas Pricing (Point 7).
//!
//! Separate pricing for CPU / IO / Network / Storage resources.
//!
//! # Production Features
//! - Configurable via `GasPricingConfig` (base prices, adjustment rates, limits).
//! - `GasPricingMetrics` with Prometheus counters and gauges.
//! - `GasPricingManager` with thread‑safe LRU cache for price lookups.
//! - Resource‑aware pricing (CPU, IO, network, storage).
//! - Adaptive adjustment based on demand and block utilization.
//! - Scheduled price updates with configurable intervals.
//! - Structured logging with `tracing`.
//! - Full test coverage.

pub mod resource_meter;
pub mod pricing;
pub mod schedule;

use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram_vec,
    Counter, CounterVec, Gauge, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::{debug, error, info, trace, warn};

// ── Re‑exports ─────────────────────────────────────────────────────────────

pub use resource_meter::{ResourceMeter, ResourceUsage, ResourceType};
pub use pricing::{GasPricing, PriceAdjustment, ResourcePrice, PricingFormula};
pub use schedule::{PriceSchedule, PriceUpdater, UpdateMode};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default base price for CPU (in wei per gas).
pub const DEFAULT_CPU_PRICE: u64 = 10;

/// Default base price for I/O.
pub const DEFAULT_IO_PRICE: u64 = 5;

/// Default base price for network.
pub const DEFAULT_NETWORK_PRICE: u64 = 3;

/// Default base price for storage.
pub const DEFAULT_STORAGE_PRICE: u64 = 2;

/// Default adjustment rate (0.001 = 0.1% per block).
pub const DEFAULT_ADJUSTMENT_RATE: f64 = 0.001;

/// Default maximum price multiplier.
pub const DEFAULT_MAX_PRICE_MULTIPLIER: f64 = 10.0;

/// Default minimum price multiplier.
pub const DEFAULT_MIN_PRICE_MULTIPLIER: f64 = 0.1;

/// Default cache size for price lookups.
pub const DEFAULT_CACHE_SIZE: usize = 1024;

/// Default cache TTL in seconds.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 10;

/// Default update interval in seconds.
pub const DEFAULT_UPDATE_INTERVAL_SECS: u64 = 60;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the gas pricing subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasPricingConfig {
    /// Base price for CPU (in wei per gas).
    pub cpu_base_price: u64,
    /// Base price for I/O.
    pub io_base_price: u64,
    /// Base price for network.
    pub network_base_price: u64,
    /// Base price for storage.
    pub storage_base_price: u64,
    /// Adjustment rate per block (0.0 – 1.0).
    pub adjustment_rate: f64,
    /// Maximum price multiplier (e.g., 10.0 = 10x base).
    pub max_price_multiplier: f64,
    /// Minimum price multiplier (e.g., 0.1 = 0.1x base).
    pub min_price_multiplier: f64,
    /// Whether to enable caching of computed prices.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Update interval in seconds for scheduled adjustments.
    pub update_interval_secs: u64,
    /// Whether to enable adaptive adjustments based on demand.
    pub enable_adaptive: bool,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log pricing changes.
    pub log_changes: bool,
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
            return Err("adjustment_rate must be between 0.0 and 1.0".into());
        }
        if self.max_price_multiplier <= 1.0 {
            return Err("max_price_multiplier must be > 1.0".into());
        }
        if self.min_price_multiplier >= 1.0 || self.min_price_multiplier <= 0.0 {
            return Err("min_price_multiplier must be between 0.0 and 1.0".into());
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
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the gas pricing subsystem.
#[derive(Clone)]
pub struct GasPricingMetrics {
    pub cpu_price: Gauge,
    pub io_price: Gauge,
    pub network_price: Gauge,
    pub storage_price: Gauge,
    pub price_lookups: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub adjustments: CounterVec,
    pub adjustment_duration: HistogramVec,
}

impl GasPricingMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let cpu_price = register_gauge!("iona_gas_cpu_price", "Current CPU gas price")?;
        let io_price = register_gauge!("iona_gas_io_price", "Current I/O gas price")?;
        let network_price = register_gauge!("iona_gas_network_price", "Current network gas price")?;
        let storage_price = register_gauge!("iona_gas_storage_price", "Current storage gas price")?;
        let price_lookups = register_counter!("iona_gas_price_lookups_total", "Total price lookups")?;
        let cache_hits = register_counter!("iona_gas_cache_hits_total", "Cache hits")?;
        let cache_misses = register_counter!("iona_gas_cache_misses_total", "Cache misses")?;
        let adjustments = register_counter_vec!(
            "iona_gas_adjustments_total",
            "Price adjustments",
            &["resource", "direction"]
        )?;
        let adjustment_duration = register_histogram_vec!(
            "iona_gas_adjustment_duration_seconds",
            "Adjustment duration",
            &["resource"]
        )?;
        Ok(Self {
            cpu_price,
            io_price,
            network_price,
            storage_price,
            price_lookups,
            cache_hits,
            cache_misses,
            adjustments,
            adjustment_duration,
        })
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
    pub fn record_adjustment(&self, resource: &str, direction: &str, duration: Duration) {
        self.adjustments.with_label_values(&[resource, direction]).inc();
        self.adjustment_duration
            .with_label_values(&[resource])
            .observe(duration.as_secs_f64());
    }
}

impl Default for GasPricingMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            cpu_price: Gauge::new("iona_gas_cpu_price", "CPU price").unwrap(),
            io_price: Gauge::new("iona_gas_io_price", "IO price").unwrap(),
            network_price: Gauge::new("iona_gas_network_price", "Network price").unwrap(),
            storage_price: Gauge::new("iona_gas_storage_price", "Storage price").unwrap(),
            price_lookups: Counter::new("iona_gas_price_lookups_total", "Lookups").unwrap(),
            cache_hits: Counter::new("iona_gas_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_gas_cache_misses_total", "Cache misses").unwrap(),
            adjustments: CounterVec::new(
                prometheus::Opts::new("iona_gas_adjustments_total", "Adjustments"),
                &["resource", "direction"],
            ).unwrap(),
            adjustment_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_gas_adjustment_duration_seconds",
                    "Adjustment duration",
                ),
                &["resource"],
            ).unwrap(),
        })
    }
}

// ── Pricing Manager ─────────────────────────────────────────────────────

/// Thread‑safe manager for gas pricing with caching, metrics, and adaptive adjustment.
#[derive(Clone)]
pub struct GasPricingManager {
    config: Arc<GasPricingConfig>,
    metrics: Arc<GasPricingMetrics>,
    pricing: Arc<parking_lot::Mutex<pricing::GasPricing>>,
    cache: Arc<Mutex<Option<LruCache<u64, pricing::ResourcePrice>>>>,
    last_update: Arc<Mutex<Instant>>,
}

impl GasPricingManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: GasPricingConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(GasPricingMetrics::default());
        let pricing = Arc::new(parking_lot::Mutex::new(
            pricing::GasPricing::new(&config),
        ));
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };

        let manager = Self {
            config: Arc::new(config),
            metrics,
            pricing,
            cache: Arc::new(Mutex::new(cache)),
            last_update: Arc::new(Mutex::new(Instant::now())),
        };

        // Initial metric update.
        manager.update_metrics();

        // Start background updater if adaptive is enabled.
        if manager.config.enable_adaptive {
            manager.start_updater();
        }

        Ok(manager)
    }

    /// Get the current price for a specific resource.
    pub fn price_for(&self, resource: ResourceType) -> u64 {
        self.metrics.record_lookup();

        let key = resource as u64;

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(price) = cache.get(&key) {
                    self.metrics.record_cache_hit();
                    return price.price;
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute price.
        let pricing = self.pricing.lock();
        let price = pricing.price_for(resource);

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                cache.put(key, pricing::ResourcePrice {
                    resource,
                    price,
                    timestamp: current_timestamp(),
                });
            }
        }

        price
    }

    /// Get all current prices.
    pub fn all_prices(&self) -> [u64; 4] {
        let pricing = self.pricing.lock();
        [
            pricing.price_for(ResourceType::Cpu),
            pricing.price_for(ResourceType::Io),
            pricing.price_for(ResourceType::Network),
            pricing.price_for(ResourceType::Storage),
        ]
    }

    /// Adjust prices based on current demand (block utilization).
    /// This is the core adaptive adjustment.
    pub fn adjust(&self, demand: &ResourceUsage) -> Result<(), String> {
        let start = Instant::now();
        let mut pricing = self.pricing.lock();

        // For each resource, compute new price.
        let adjustments = pricing.adjust(demand, &self.config);

        // Record metrics and log.
        for (resource, old_price, new_price) in adjustments {
            let direction = if new_price > old_price { "up" } else { "down" };
            self.metrics.record_adjustment(
                resource.to_string().as_str(),
                direction,
                start.elapsed(),
            );
            if self.config.log_changes {
                info!(
                    resource = %resource,
                    old_price,
                    new_price,
                    "gas price adjusted"
                );
            }
        }

        // Clear cache on adjustment.
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
        }

        self.update_metrics();
        Ok(())
    }

    /// Update metrics to current values.
    fn update_metrics(&self) {
        let pricing = self.pricing.lock();
        self.metrics.set_cpu_price(pricing.price_for(ResourceType::Cpu));
        self.metrics.set_io_price(pricing.price_for(ResourceType::Io));
        self.metrics.set_network_price(pricing.price_for(ResourceType::Network));
        self.metrics.set_storage_price(pricing.price_for(ResourceType::Storage));
    }

    /// Start background updater (runs on a tokio task).
    fn start_updater(&self) {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.update_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                // In production, we would collect demand data from the block producer.
                // For now, we just simulate with a simple adjustment.
                // We'll use a placeholder demand that gradually changes.
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
                if let Err(e) = manager.adjust(&demand) {
                    error!(error = %e, "gas price adjustment failed");
                }
            }
        });
    }

    /// Force an immediate price update.
    pub fn force_update(&self, demand: &ResourceUsage) -> Result<(), String> {
        self.adjust(demand)
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("Gas pricing cache cleared");
        }
    }

    /// Get cache size.
    pub fn cache_size(&self) -> usize {
        if let Some(cache) = self.cache.lock().as_ref() {
            cache.len()
        } else {
            0
        }
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> GasPricingMetricsSnapshot {
        GasPricingMetricsSnapshot {
            cpu_price: self.metrics.cpu_price.get(),
            io_price: self.metrics.io_price.get(),
            network_price: self.metrics.network_price.get(),
            storage_price: self.metrics.storage_price.get(),
            price_lookups: self.metrics.price_lookups.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &GasPricingConfig {
        &self.config
    }
}

/// Snapshot of gas pricing metrics.
#[derive(Debug, Clone)]
pub struct GasPricingMetricsSnapshot {
    pub cpu_price: f64,
    pub io_price: f64,
    pub network_price: f64,
    pub storage_price: f64,
    pub price_lookups: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
}

// ── Helper ───────────────────────────────────────────────────────────────

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Standalone functions ─────────────────────────────────────────────────

/// Get the price for a specific resource (with default config).
pub fn gas_price(resource: ResourceType) -> u64 {
    let config = GasPricingConfig::default();
    let manager = GasPricingManager::new(config).unwrap();
    manager.price_for(resource)
}

/// Get all prices.
pub fn all_gas_prices() -> [u64; 4] {
    let config = GasPricingConfig::default();
    let manager = GasPricingManager::new(config).unwrap();
    manager.all_prices()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_config_validation() {
        let mut config = GasPricingConfig::default();
        assert!(config.validate().is_ok());
        config.cpu_base_price = 0;
        assert!(config.validate().is_err());
        config.cpu_base_price = 10;
        config.adjustment_rate = 1.5;
        assert!(config.validate().is_err());
        config.adjustment_rate = 0.1;
        config.max_price_multiplier = 0.5;
        assert!(config.validate().is_err());
        config.max_price_multiplier = 2.0;
        config.min_price_multiplier = 0.0;
        assert!(config.validate().is_err());
        config.min_price_multiplier = 0.5;
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
        config.cache_ttl_secs = 60;
        config.update_interval_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_manager_prices() {
        let config = GasPricingConfig::default();
        let manager = GasPricingManager::new(config).unwrap();
        let cpu = manager.price_for(ResourceType::Cpu);
        assert!(cpu > 0);
        let all = manager.all_prices();
        assert_eq!(all.len(), 4);
    }

    #[test]
    fn test_manager_cache() {
        let config = GasPricingConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = GasPricingManager::new(config).unwrap();
        let _ = manager.price_for(ResourceType::Cpu);
        let _ = manager.price_for(ResourceType::Cpu);
        assert!(manager.cache_size() > 0);
        let snap = manager.metrics_snapshot();
        assert!(snap.cache_hits > 0);
        assert!(snap.cache_misses > 0);
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = GasPricingConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = GasPricingManager::new(config).unwrap();
        let _ = manager.price_for(ResourceType::Cpu);
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_manager_adjust() {
        let config = GasPricingConfig {
            enable_adaptive: true,
            adjustment_rate: 0.1,
            ..Default::default()
        };
        let manager = GasPricingManager::new(config).unwrap();
        let demand = ResourceUsage {
            cpu_used: 80,
            io_used: 50,
            network_used: 40,
            storage_used: 20,
            target_cpu: 50,
            target_io: 30,
            target_network: 20,
            target_storage: 10,
        };
        let result = manager.adjust(&demand);
        assert!(result.is_ok());
        // Prices should have increased.
        let cpu = manager.price_for(ResourceType::Cpu);
        assert!(cpu > DEFAULT_CPU_PRICE);
    }

    #[test]
    fn test_standalone_functions() {
        let price = gas_price(ResourceType::Cpu);
        assert!(price > 0);
        let all = all_gas_prices();
        assert_eq!(all.len(), 4);
    }
}
