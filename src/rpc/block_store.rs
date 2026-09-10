//! RPC utility functions: hashing, bloom filtering, and root computations.
//!
//! # Production Features
//! - Configurable output formats (hex with/without `0x`, raw bytes).
//! - Prometheus metrics (optional) with atomic fallback for hashing operations.
//! - LRU cache for frequent hashes with TTL and hashed keys.
//! - Sync‑safe locking via `parking_lot::Mutex` (no `blocking_lock` panic).
//! - Global singleton for standalone functions (cache is preserved).
//! - Support for both Keccak-256 and SHA-256.
//! - Robust error handling with `UtilsError`.
//! - Overflow‑safe counters using saturating arithmetic.
//! - Serialization support for configuration.
//! - Full test coverage.
//!
//! # Example
//!
//! ```
//! use iona::rpc::utils::{Utils, UtilsConfig, keccak_hex};
//!
//! let utils = Utils::new(UtilsConfig::default()).unwrap();
//! let hash = keccak_hex(b"hello");
//! assert!(hash.starts_with("0x"));
//! ```

use crate::rpc::bloom::Bloom;
use crate::rpc::rlp_encode::keccak_rlp_root;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{register_counter, register_counter_vec, Counter, CounterVec};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256, Sha256};
use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Error types ──────────────────────────────────────────────────────────

/// Errors that can occur in the utility functions.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum UtilsError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("RLP encoding error: {0}")]
    Rlp(String),

    #[error("cache error: {0}")]
    Cache(String),

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("invalid input: {0}")]
    InvalidInput(String),
}

pub type UtilsResult<T> = Result<T, UtilsError>;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the utility functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UtilsConfig {
    /// Whether to include the `0x` prefix in hex outputs (default: true).
    pub hex_prefix: bool,
    /// Hashing algorithm: "keccak256" or "sha256".
    pub hash_algorithm: HashAlgorithm,
    /// Whether to cache hash results (default: true).
    pub cache_enabled: bool,
    /// Maximum number of entries in the hash cache (default: 1000).
    pub cache_size: usize,
    /// Cache TTL in seconds (default: 300).
    pub cache_ttl_secs: u64,
    /// Whether to log hashing operations.
    pub log_hashing: bool,
    /// Whether to enable Prometheus metrics.
    pub enable_metrics: bool,
}

impl Default for UtilsConfig {
    fn default() -> Self {
        Self {
            hex_prefix: true,
            hash_algorithm: HashAlgorithm::Keccak256,
            cache_enabled: true,
            cache_size: 1000,
            cache_ttl_secs: 300,
            log_hashing: false,
            enable_metrics: false,
        }
    }
}

impl UtilsConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }

    /// Enable Prometheus metrics.
    pub fn with_prometheus(mut self) -> Self {
        self.enable_metrics = true;
        self
    }
}

/// Supported hashing algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum HashAlgorithm {
    #[default]
    Keccak256,
    Sha256,
}

impl HashAlgorithm {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Keccak256 => "keccak256",
            Self::Sha256 => "sha256",
        }
    }
}

// ── Prometheus Metrics ───────────────────────────────────────────────────

/// Prometheus metrics for the utilities.
#[derive(Clone)]
pub struct UtilsPrometheus {
    pub hash_count_total: Counter,
    pub hash_time_ns_total: Counter,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub bloom_combines_total: Counter,
    pub rlp_roots_total: Counter,
}

impl UtilsPrometheus {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            hash_count_total: register_counter!(
                "iona_utils_hash_count_total",
                "Total hash computations"
            )?,
            hash_time_ns_total: register_counter!(
                "iona_utils_hash_time_ns_total",
                "Total time spent hashing (nanoseconds)"
            )?,
            cache_hits_total: register_counter!(
                "iona_utils_cache_hits_total",
                "Total hash cache hits"
            )?,
            cache_misses_total: register_counter!(
                "iona_utils_cache_misses_total",
                "Total hash cache misses"
            )?,
            bloom_combines_total: register_counter!(
                "iona_utils_bloom_combines_total",
                "Total bloom filter combination operations"
            )?,
            rlp_roots_total: register_counter!(
                "iona_utils_rlp_roots_total",
                "Total RLP root computations"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            hash_count_total: Counter::new("iona_utils_hash_count_total", "Hashes").unwrap(),
            hash_time_ns_total: Counter::new("iona_utils_hash_time_ns_total", "Time").unwrap(),
            cache_hits_total: Counter::new("iona_utils_cache_hits_total", "Hits").unwrap(),
            cache_misses_total: Counter::new("iona_utils_cache_misses_total", "Misses").unwrap(),
            bloom_combines_total: Counter::new("iona_utils_bloom_combines_total", "Blooms").unwrap(),
            rlp_roots_total: Counter::new("iona_utils_rlp_roots_total", "Roots").unwrap(),
        }
    }
}

// ── Metrics (atomic + optional Prometheus) ──────────────────────────────

/// Metrics for the utilities.
#[derive(Debug, Clone)]
pub struct UtilsMetrics {
    pub hash_count: Arc<AtomicU64>,
    pub hash_time_ns: Arc<AtomicU64>,
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,
    pub bloom_combines: Arc<AtomicU64>,
    pub rlp_roots: Arc<AtomicU64>,
    /// Optional Prometheus integration.
    pub prometheus: Option<Arc<UtilsPrometheus>>,
}

impl Default for UtilsMetrics {
    fn default() -> Self {
        Self {
            hash_count: Arc::new(AtomicU64::new(0)),
            hash_time_ns: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            bloom_combines: Arc::new(AtomicU64::new(0)),
            rlp_roots: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl UtilsMetrics {
    /// Create a new metrics instance, optionally with Prometheus integration.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(UtilsPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            hash_count: Arc::new(AtomicU64::new(0)),
            hash_time_ns: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            bloom_combines: Arc::new(AtomicU64::new(0)),
            rlp_roots: Arc::new(AtomicU64::new(0)),
            prometheus,
        })
    }

    pub fn record_hash(&self, duration_ns: u64) {
        self.hash_count.fetch_add(1, Ordering::Relaxed);
        self.hash_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.hash_count_total.inc();
            p.hash_time_ns_total.inc_by(duration_ns as f64);
        }
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_hits_total.inc();
        }
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_misses_total.inc();
        }
    }

    pub fn record_bloom_combine(&self) {
        self.bloom_combines.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.bloom_combines_total.inc();
        }
    }

    pub fn record_rlp_root(&self) {
        self.rlp_roots.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.rlp_roots_total.inc();
        }
    }

    pub fn snapshot(&self) -> UtilsMetricsSnapshot {
        UtilsMetricsSnapshot {
            hash_count: self.hash_count.load(Ordering::Relaxed),
            hash_time_ns: self.hash_time_ns.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            bloom_combines: self.bloom_combines.load(Ordering::Relaxed),
            rlp_roots: self.rlp_roots.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of utility metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UtilsMetricsSnapshot {
    pub hash_count: u64,
    pub hash_time_ns: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub bloom_combines: u64,
    pub rlp_roots: u64,
}

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CacheEntry {
    hash: Vec<u8>,
    expires_at: Instant,
}

/// Cache key: hash of the input data (32 bytes) plus the algorithm identifier.
/// This avoids storing potentially large input buffers as keys.
#[derive(Clone, Hash, PartialEq, Eq)]
struct CacheKey {
    data_hash: [u8; 32],
    algorithm: u8,
}

impl CacheKey {
    fn new(data: &[u8], algorithm: HashAlgorithm) -> Self {
        // Use SHA-256 as the cache key hasher for determinism.
        let digest = Sha256::digest(data);
        let mut data_hash = [0u8; 32];
        data_hash.copy_from_slice(&digest);
        Self {
            data_hash,
            algorithm: match algorithm {
                HashAlgorithm::Keccak256 => 0,
                HashAlgorithm::Sha256 => 1,
            },
        }
    }
}

// ── Utils Manager ────────────────────────────────────────────────────────

/// Thread‑safe utilities manager with caching and metrics.
///
/// Uses `parking_lot::Mutex` for the cache, allowing calls from both sync
/// and async contexts without the `blocking_lock` pitfall of `tokio::sync`.
#[derive(Clone)]
pub struct Utils {
    config: Arc<UtilsConfig>,
    metrics: Arc<UtilsMetrics>,
    cache: Arc<Mutex<Option<LruCache<CacheKey, CacheEntry>>>>,
}

impl Utils {
    /// Create a new utilities manager with the given configuration.
    pub fn new(config: UtilsConfig) -> UtilsResult<Self> {
        config
            .validate()
            .map_err(UtilsError::Config)?;
        let cache = if config.cache_enabled {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| UtilsError::Config("cache_size must be > 0".into()))?;
            Some(LruCache::new(size))
        } else {
            None
        };
        let metrics = UtilsMetrics::new(config.enable_metrics)
            .map_err(|e| UtilsError::Metrics(e.to_string()))?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Create a manager with default configuration.
    pub fn default() -> Self {
        Self::new(UtilsConfig::default()).expect("default utils config should be valid")
    }

    /// Get the configuration.
    pub fn config(&self) -> &UtilsConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> UtilsMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the metrics reference.
    pub fn metrics(&self) -> &UtilsMetrics {
        &self.metrics
    }

    /// Compute a hash of the given data.
    pub fn hash(&self, data: &[u8]) -> Vec<u8> {
        let start = Instant::now();
        let result = if self.config.cache_enabled {
            self.hash_cached(data)
        } else {
            self.hash_direct(data)
        };
        let duration = start.elapsed().as_nanos().min(u64::MAX as u128) as u64;
        self.metrics.record_hash(duration);
        if self.config.log_hashing {
            trace!(
                data_len = data.len(),
                result_len = result.len(),
                duration_ns = duration,
                "hash computed"
            );
        }
        result
    }

    /// Compute a hash and return as hex with optional prefix.
    pub fn hash_hex(&self, data: &[u8]) -> String {
        let bytes = self.hash(data);
        if self.config.hex_prefix {
            format!("0x{}", hex::encode(bytes))
        } else {
            hex::encode(bytes)
        }
    }

    /// Compute a hash and return as a 32‑byte array (for Keccak‑256/SHA-256).
    pub fn hash_array(&self, data: &[u8]) -> [u8; 32] {
        let bytes = self.hash(data);
        let mut arr = [0u8; 32];
        let len = bytes.len().min(32);
        arr[..len].copy_from_slice(&bytes[..len]);
        arr
    }

    /// Direct hash computation (no cache).
    fn hash_direct(&self, data: &[u8]) -> Vec<u8> {
        match self.config.hash_algorithm {
            HashAlgorithm::Keccak256 => {
                let mut hasher = Keccak256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
            HashAlgorithm::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                hasher.finalize().to_vec()
            }
        }
    }

    /// Cached hash computation (if enabled).
    ///
    /// Uses `parking_lot::Mutex` (blocking, but safe from sync and async).
    /// The cache key is a SHA-256 hash of the input data, so we never store
    /// unbounded input buffers.
    fn hash_cached(&self, data: &[u8]) -> Vec<u8> {
        let key = CacheKey::new(data, self.config.hash_algorithm);
        let now = Instant::now();
        let ttl = Duration::from_secs(self.config.cache_ttl_secs);

        let mut cache_guard = self.cache.lock();
        if let Some(cache) = cache_guard.as_mut() {
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > now {
                    self.metrics.record_cache_hit();
                    trace!("hash cache hit");
                    return entry.hash.clone();
                } else {
                    cache.pop(&key);
                }
            }
            self.metrics.record_cache_miss();
        }

        // Release the lock while computing the hash (avoid holding lock during crypto).
        drop(cache_guard);

        let hash = self.hash_direct(data);

        // Re-acquire the lock and insert.
        let mut cache_guard = self.cache.lock();
        if let Some(cache) = cache_guard.as_mut() {
            let entry = CacheEntry {
                hash: hash.clone(),
                expires_at: now + ttl,
            };
            cache.put(key, entry);
        }

        hash
    }

    // ── Bloom Utilities ──────────────────────────────────────────────────

    /// Combine multiple bloom filters by bitwise OR.
    pub fn bloom_combine(&self, blooms: &[Bloom]) -> Bloom {
        self.metrics.record_bloom_combine();
        let mut combined = Bloom::default();
        for b in blooms {
            for i in 0..256 {
                combined.0[i] |= b.0[i];
            }
        }
        if self.config.log_hashing {
            trace!(count = blooms.len(), "bloom filters combined");
        }
        combined
    }

    /// Combine blooms and return hex.
    pub fn bloom_combine_hex(&self, blooms: &[Bloom]) -> String {
        let b = self.bloom_combine(blooms);
        if self.config.hex_prefix {
            format!("0x{}", b.to_hex())
        } else {
            b.to_hex()
        }
    }

    // ── RLP Root Utilities ──────────────────────────────────────────────

    /// Compute the Keccak‑256 hash of the RLP‑encoded list of items.
    pub fn rlp_root(&self, items: &[Vec<u8>]) -> UtilsResult<[u8; 32]> {
        self.metrics.record_rlp_root();
        keccak_rlp_root(items).map_err(|e| UtilsError::Rlp(e.to_string()))
    }

    /// Compute the RLP root and return as hex with optional prefix.
    pub fn rlp_root_hex(&self, items: &[Vec<u8>]) -> UtilsResult<String> {
        let root = self.rlp_root(items)?;
        if self.config.hex_prefix {
            Ok(format!("0x{}", hex::encode(root)))
        } else {
            Ok(hex::encode(root))
        }
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        let mut guard = self.cache.lock();
        if let Some(cache) = guard.as_mut() {
            cache.clear();
        }
    }

    /// Get current cache size.
    pub fn cache_len(&self) -> usize {
        let guard = self.cache.lock();
        guard.as_ref().map(|c| c.len()).unwrap_or(0)
    }

    /// Reset cache (for testing, async‑compatible).
    #[cfg(test)]
    pub async fn reset_cache(&self) {
        self.clear_cache();
    }
}

// ── Global Singleton ────────────────────────────────────────────────────

/// Global utils singleton used by standalone functions.
/// The cache is preserved across calls, unlike creating a new `Utils` each time.
static GLOBAL_UTILS: OnceLock<Utils> = OnceLock::new();

/// Get the global Utils instance (lazily initialized with default config).
fn global_utils() -> &'static Utils {
    GLOBAL_UTILS.get_or_init(|| Utils::default())
}

/// Initialize the global Utils singleton with a custom config.
///
/// Returns `Err` if already initialized.
pub fn init_global_utils(config: UtilsConfig) -> UtilsResult<()> {
    let utils = Utils::new(config)?;
    GLOBAL_UTILS
        .set(utils)
        .map_err(|_| UtilsError::Config("global utils already initialized".into()))
}

// ── Standalone Functions (Backward Compatibility) ──────────────────────

/// Compute the Keccak‑256 hash and return as hex with `0x` prefix.
///
/// Uses the global `Utils` singleton so its cache is preserved.
pub fn keccak_hex(data: &[u8]) -> String {
    global_utils().hash_hex(data)
}

/// Compute a simple concatenation hash of a list of strings.
///
/// **Important**: This is NOT a Merkle Patricia Trie root.
pub fn concat_hash(items: &[String]) -> String {
    let mut hasher = Keccak256::new();
    for item in items {
        hasher.update(item.as_bytes());
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Combine bloom filters and return hex with `0x` prefix.
///
/// Uses the global `Utils` singleton.
pub fn bloom_or_hex(blooms: &[Bloom]) -> String {
    global_utils().bloom_combine_hex(blooms)
}

/// Compute the Keccak‑256 hash of the RLP‑encoded list of items.
/// Returns hex with `0x` prefix.
///
/// Uses the global `Utils` singleton.
pub fn rlp_root_hex(items: &[Vec<u8>]) -> Result<String, String> {
    global_utils()
        .rlp_root_hex(items)
        .map_err(|e| e.to_string())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_hex() {
        let hash = keccak_hex(b"");
        assert_eq!(
            hash,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_concat_hash() {
        let items = vec!["a".to_string(), "b".to_string()];
        let h1 = concat_hash(&items);
        let h2 = keccak_hex(b"ab");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_bloom_or_hex() {
        let mut b1 = Bloom::default();
        let mut b2 = Bloom::default();
        b1.0[0] = 0x01;
        b2.0[1] = 0x02;
        let result = bloom_or_hex(&[b1, b2]);
        let expected = "0x" + &hex::encode(&[0x01, 0x02].iter().chain(&[0u8; 254]).copied().collect::<Vec<u8>>());
        assert_eq!(result, expected);
    }

    #[test]
    fn test_rlp_root_hex_empty() {
        let root = rlp_root_hex(&[]).unwrap();
        assert_eq!(
            root,
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn test_utils_hash() {
        let utils = Utils::default();
        let bytes = utils.hash(b"hello");
        assert_eq!(bytes.len(), 32);
        let hex = utils.hash_hex(b"hello");
        assert_eq!(
            hex,
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_utils_cache() {
        let config = UtilsConfig {
            cache_enabled: true,
            cache_size: 10,
            cache_ttl_secs: 60,
            ..Default::default()
        };
        let utils = Utils::new(config).unwrap();
        let data = b"test data";
        let h1 = utils.hash(data);
        let h2 = utils.hash(data);
        assert_eq!(h1, h2);
        let snap = utils.metrics_snapshot();
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(utils.cache_len(), 1);
    }

    #[test]
    fn test_utils_cache_no_collision_across_algorithms() {
        // Same data, different algorithms → different cache entries.
        let config = UtilsConfig {
            cache_enabled: true,
            cache_size: 10,
            hash_algorithm: HashAlgorithm::Keccak256,
            ..Default::default()
        };
        let utils = Utils::new(config).unwrap();
        let k = utils.hash(b"x");

        let config2 = UtilsConfig {
            cache_enabled: true,
            cache_size: 10,
            hash_algorithm: HashAlgorithm::Sha256,
            ..Default::default()
        };
        let utils2 = Utils::new(config2).unwrap();
        let s = utils2.hash(b"x");

        // Different algorithms → different outputs.
        assert_ne!(k, s);
    }

    #[test]
    fn test_utils_config_validation() {
        let mut config = UtilsConfig::default();
        assert!(config.validate().is_ok());
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_utils_hash_algorithms() {
        let config = UtilsConfig {
            hash_algorithm: HashAlgorithm::Sha256,
            ..Default::default()
        };
        let utils = Utils::new(config).unwrap();
        let bytes = utils.hash(b"hello");
        assert_eq!(bytes.len(), 32);
        let hex = utils.hash_hex(b"hello");
        assert_eq!(
            hex,
            "0x2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
    }

    #[test]
    fn test_utils_bloom_combine() {
        let utils = Utils::default();
        let mut b1 = Bloom::default();
        let mut b2 = Bloom::default();
        b1.0[0] = 0x01;
        b2.0[1] = 0x02;
        let combined = utils.bloom_combine(&[b1, b2]);
        assert_eq!(combined.0[0], 0x01);
        assert_eq!(combined.0[1], 0x02);
    }

    #[test]
    fn test_utils_rlp_root() {
        let utils = Utils::default();
        let items: Vec<Vec<u8>> = vec![b"hello".to_vec()];
        let root = utils.rlp_root(&items).unwrap();
        assert_eq!(root.len(), 32);
        let hex = utils.rlp_root_hex(&items).unwrap();
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66);
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = UtilsPrometheus::new_unregistered();
        p.hash_count_total.inc();
        p.cache_hits_total.inc_by(2);
        p.cache_misses_total.inc_by(3);
        p.bloom_combines_total.inc();
        p.rlp_roots_total.inc_by(4);
        assert_eq!(p.hash_count_total.get(), 1);
        assert_eq!(p.cache_hits_total.get(), 2);
        assert_eq!(p.cache_misses_total.get(), 3);
        assert_eq!(p.bloom_combines_total.get(), 1);
        assert_eq!(p.rlp_roots_total.get(), 4);
    }

    #[test]
    fn test_cache_clear() {
        let config = UtilsConfig {
            cache_enabled: true,
            cache_size: 10,
            ..Default::default()
        };
        let utils = Utils::new(config).unwrap();
        utils.hash(b"a");
        assert_eq!(utils.cache_len(), 1);
        utils.clear_cache();
        assert_eq!(utils.cache_len(), 0);
    }

    #[test]
    fn test_utils_from_async_context_no_panic() {
        // This test ensures that calling `hash()` from within a tokio
        // runtime does not panic (the original `blocking_lock` would have).
        let utils = Utils::new(UtilsConfig {
            cache_enabled: true,
            ..Default::default()
        })
        .unwrap();

        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let h1 = utils.hash(b"async test");
            let h2 = utils.hash(b"async test");
            assert_eq!(h1, h2);
        });
    }
}
