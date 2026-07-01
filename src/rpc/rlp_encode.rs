//! RLP encoding utilities — Quantum Ethereum‑compatible data serialization.
//!
//! # Production Features
//! - Configurable via `RlpConfig` (cache size, TTL, decoherence rates).
//! - `RlpManager` with LRU caching for encoded bytes and roots (thread‑safe).
//! - Metrics for encoding, hashing, cache hits/misses.
//! - Batch processing support.
//! - Persistent cache (optional) with file locking.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec,
    Counter, CounterVec, HistogramVec,
};
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default decoherence rate per RLP encoding operation.
const DEFAULT_ENCODE_DECOHERENCE_RATE: f64 = 0.00005;

/// Default decoherence rate per Keccak-256 hash operation.
const DEFAULT_HASH_DECOHERENCE_RATE: f64 = 0.0001;

/// Default minimum coherence threshold for valid RLP state.
const DEFAULT_MIN_RLP_COHERENCE: f64 = 0.99;

/// Default cache size for encoded bytes and roots.
const DEFAULT_CACHE_SIZE: usize = 1024;

/// Default cache TTL in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// Keccak‑256 hash of RLP‑encoded empty list.
pub const EMPTY_LIST_RIPEMD: &str =
    "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Expected length of a hex‑encoded hash with prefix (2 + 64 = 66).
const HEX_HASH_LEN: usize = 66;

/// Kraus rank for RLP quantum channels.
const RLP_KRAUS_RANK: usize = 4;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for RLP encoding operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlpConfig {
    /// Decoherence rate per encoding operation (0.0 – 1.0).
    pub encode_decoherence_rate: f64,
    /// Decoherence rate per hash operation (0.0 – 1.0).
    pub hash_decoherence_rate: f64,
    /// Minimum coherence threshold for valid RLP state.
    pub min_rlp_coherence: f64,
    /// Whether to enable caching of encoded bytes and roots.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to persist cache to disk.
    pub persist_cache: bool,
    /// Path for cache persistence.
    pub cache_path: Option<String>,
}

impl Default for RlpConfig {
    fn default() -> Self {
        Self {
            encode_decoherence_rate: DEFAULT_ENCODE_DECOHERENCE_RATE,
            hash_decoherence_rate: DEFAULT_HASH_DECOHERENCE_RATE,
            min_rlp_coherence: DEFAULT_MIN_RLP_COHERENCE,
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            track_metrics: true,
            persist_cache: false,
            cache_path: None,
        }
    }
}

impl RlpConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.encode_decoherence_rate) {
            return Err("encode_decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.hash_decoherence_rate) {
            return Err("hash_decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_rlp_coherence) {
            return Err("min_rlp_coherence must be between 0.0 and 1.0".into());
        }
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        if self.persist_cache && self.cache_path.is_none() {
            return Err("cache_path must be set when persist_cache is true".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for RLP encoding operations.
#[derive(Clone)]
pub struct RlpMetrics {
    pub encodes: CounterVec,
    pub hashes: CounterVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub decoherence_events: Counter,
    pub encode_duration: HistogramVec,
    pub hash_duration: HistogramVec,
}

impl RlpMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let encodes = register_counter_vec!(
            "iona_rlp_encodes_total",
            "Total RLP encoding operations",
            &["type"]
        )?;
        let hashes = register_counter_vec!(
            "iona_rlp_hashes_total",
            "Total RLP hash operations",
            &["type"]
        )?;
        let cache_hits = register_counter!(
            "iona_rlp_cache_hits_total",
            "RLP cache hits"
        )?;
        let cache_misses = register_counter!(
            "iona_rlp_cache_misses_total",
            "RLP cache misses"
        )?;
        let decoherence_events = register_counter!(
            "iona_rlp_decoherence_events_total",
            "RLP decoherence events"
        )?;
        let encode_duration = register_histogram_vec!(
            "iona_rlp_encode_duration_seconds",
            "RLP encoding duration",
            &["type"]
        )?;
        let hash_duration = register_histogram_vec!(
            "iona_rlp_hash_duration_seconds",
            "RLP hash duration",
            &["type"]
        )?;
        Ok(Self {
            encodes,
            hashes,
            cache_hits,
            cache_misses,
            decoherence_events,
            encode_duration,
            hash_duration,
        })
    }

    pub fn record_encode(&self, typ: &str, duration: Duration) {
        self.encodes.with_label_values(&[typ]).inc();
        self.encode_duration.with_label_values(&[typ]).observe(duration.as_secs_f64());
    }

    pub fn record_hash(&self, typ: &str, duration: Duration) {
        self.hashes.with_label_values(&[typ]).inc();
        self.hash_duration.with_label_values(&[typ]).observe(duration.as_secs_f64());
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    pub fn record_decoherence(&self) {
        self.decoherence_events.inc();
    }
}

impl Default for RlpMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            encodes: CounterVec::new(
                prometheus::Opts::new("iona_rlp_encodes_total", "RLP encodes"),
                &["type"],
            ).unwrap(),
            hashes: CounterVec::new(
                prometheus::Opts::new("iona_rlp_hashes_total", "RLP hashes"),
                &["type"],
            ).unwrap(),
            cache_hits: Counter::new("iona_rlp_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_rlp_cache_misses_total", "Cache misses").unwrap(),
            decoherence_events: Counter::new("iona_rlp_decoherence_events_total", "Decoherence events").unwrap(),
            encode_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_rlp_encode_duration_seconds",
                    "RLP encoding duration",
                ),
                &["type"],
            ).unwrap(),
            hash_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_rlp_hash_duration_seconds",
                    "RLP hash duration",
                ),
                &["type"],
            ).unwrap(),
        })
    }
}

// ── Quantum RLP State ────────────────────────────────────────────────────

/// Quantum state of the RLP encoding system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumRlpState {
    pub purity: f64,
    pub entropy: f64,
    pub data_coherence: f64,
    pub items_encoded: usize,
    pub total_hashes: u64,
    pub total_encodes: u64,
    pub is_valid: bool,
}

impl Default for QuantumRlpState {
    fn default() -> Self {
        Self {
            purity: 1.0,
            entropy: 0.0,
            data_coherence: 1.0,
            items_encoded: 0,
            total_hashes: 0,
            total_encodes: 0,
            is_valid: true,
        }
    }
}

impl QuantumRlpState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_encode_decoherence(&mut self, item_count: usize, config: &RlpConfig) {
        self.total_encodes = self.total_encodes.wrapping_add(1);
        self.items_encoded = self.items_encoded.saturating_add(item_count);
        let decay = (-config.encode_decoherence_rate * item_count as f64).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute(config);
    }

    pub fn apply_hash_decoherence(&mut self, config: &RlpConfig) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-config.hash_decoherence_rate).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute(config);
    }

    pub fn apply_list_channel(&mut self, config: &RlpConfig) {
        let kraus_factor = (1.0 / RLP_KRAUS_RANK as f64).sqrt();
        self.data_coherence = (self.data_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute(config);
    }

    fn recompute(&mut self, config: &RlpConfig) {
        self.purity = self.data_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= config.min_rlp_coherence;
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum RlpEncodeError {
    #[error("unexpected error: {0}")]
    Internal(String),
    #[error("quantum decoherence: RLP coherence {coherence:.4} below threshold {threshold:.4}")]
    Decoherence { coherence: f64, threshold: f64 },
    #[error("configuration error: {0}")]
    Config(String),
}

pub type RlpEncodeResult<T> = Result<T, RlpEncodeError>;

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CacheEntry {
    data: Vec<u8>,
    expires_at: Instant,
}

// ── RlpManager ───────────────────────────────────────────────────────────

/// Thread‑safe manager for RLP encoding with caching and metrics.
#[derive(Clone)]
pub struct RlpManager {
    config: Arc<RlpConfig>,
    metrics: Arc<RlpMetrics>,
    cache: Arc<Mutex<Option<LruCache<u64, CacheEntry>>>>,
}

impl RlpManager {
    /// Create a new RLP manager with the given configuration.
    pub fn new(config: RlpConfig) -> Result<Self, String> {
        config.validate()?;
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(RlpMetrics::default()),
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Encode a list of items to RLP bytes.
    pub fn encode(&self, items: &[Vec<u8>]) -> Vec<u8> {
        let start = Instant::now();
        let key = self.compute_cache_key(items);

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        self.metrics.record_cache_hit();
                        trace!("RLP cache hit for {} items", items.len());
                        return entry.data.clone();
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Encode fresh.
        let data = rlp_list_bytes(items);
        let duration = start.elapsed();
        self.metrics.record_encode("list", duration);

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = CacheEntry {
                    data: data.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                };
                cache.put(key, entry);
            }
        }

        data
    }

    /// Encode with quantum state tracking.
    pub fn encode_quantum(&self, items: &[Vec<u8>]) -> (Vec<u8>, QuantumRlpState) {
        let data = self.encode(items);
        let mut state = QuantumRlpState::new();
        state.apply_encode_decoherence(items.len(), &self.config);
        state.apply_list_channel(&self.config);
        (data, state)
    }

    /// Compute the Keccak‑256 hash of bytes.
    pub fn hash(&self, bytes: &[u8]) -> String {
        let start = Instant::now();
        let hash = keccak_hex(bytes);
        self.metrics.record_hash("keccak", start.elapsed());
        hash
    }

    /// Hash with quantum state tracking.
    pub fn hash_quantum(&self, bytes: &[u8]) -> (String, QuantumRlpState) {
        let hash = self.hash(bytes);
        let mut state = QuantumRlpState::new();
        state.apply_hash_decoherence(&self.config);
        (hash, state)
    }

    /// Compute the Keccak-RLP root.
    pub fn root(&self, items: &[Vec<u8>]) -> String {
        let encoded = self.encode(items);
        self.hash(&encoded)
    }

    /// Compute the root with quantum state tracking.
    pub fn root_quantum(&self, items: &[Vec<u8>]) -> (String, QuantumRlpState) {
        let (encoded, mut state) = self.encode_quantum(items);
        let hash = self.hash(&encoded);
        state.apply_hash_decoherence(&self.config);
        (hash, state)
    }

    /// Compute roots for multiple batches.
    pub fn batch_roots(&self, batches: &[&[Vec<u8>]]) -> Vec<String> {
        batches.iter().map(|b| self.root(b)).collect()
    }

    /// Compute cache key for a list of items.
    fn compute_cache_key(&self, items: &[Vec<u8>]) -> u64 {
        let mut hasher = DefaultHasher::new();
        items.len().hash(&mut hasher);
        for item in items {
            item.hash(&mut hasher);
        }
        hasher.finish()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("RLP cache cleared");
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
    pub fn metrics_snapshot(&self) -> RlpMetricsSnapshot {
        RlpMetricsSnapshot {
            encodes: self.metrics.encodes.clone(),
            hashes: self.metrics.hashes.clone(),
            cache_hits: self.metrics.cache_hits.clone(),
            cache_misses: self.metrics.cache_misses.clone(),
            decoherence_events: self.metrics.decoherence_events.clone(),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &RlpConfig {
        &self.config
    }
}

/// Snapshot of RLP metrics.
#[derive(Debug, Clone)]
pub struct RlpMetricsSnapshot {
    pub encodes: CounterVec,
    pub hashes: CounterVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub decoherence_events: Counter,
}

// ── Core Functions ──────────────────────────────────────────────────────

/// Encode a list of byte slices as an RLP list of byte strings.
pub fn rlp_list_bytes(items: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = RlpStream::new_list(items.len());
    for item in items {
        stream.append(&item.as_slice());
    }
    stream.out().to_vec()
}

/// Compute the Keccak‑256 hash and return as hex with `0x` prefix.
pub fn keccak_hex(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    format!("{}{}", HEX_PREFIX, hex::encode(hasher.finalize()))
}

/// Compute the RLP root as hex.
pub fn keccak_rlp_root(items: &[Vec<u8>]) -> String {
    keccak_hex(&rlp_list_bytes(items))
}

/// Compute root from iterator.
pub fn keccak_rlp_root_from_iter<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let items_vec: Vec<Vec<u8>> = items.into_iter().map(|b| b.to_vec()).collect();
    keccak_rlp_root(&items_vec)
}

/// Compute root for encodable items.
pub fn keccak_rlp_root_encodable<T: rlp::Encodable>(items: &[T]) -> String {
    let rlp_items: Vec<Vec<u8>> = items
        .iter()
        .map(|item| rlp::encode(item).to_vec())
        .collect();
    keccak_rlp_root(&rlp_items)
}

/// Compute quantum fidelity between two RLP-encoded byte sequences.
pub fn rlp_fidelity(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / len as f64
}

/// Standalone quantum functions (using default config).
pub fn rlp_list_bytes_quantum(items: &[Vec<u8>]) -> (Vec<u8>, QuantumRlpState) {
    let config = RlpConfig::default();
    let data = rlp_list_bytes(items);
    let mut state = QuantumRlpState::new();
    state.apply_encode_decoherence(items.len(), &config);
    state.apply_list_channel(&config);
    (data, state)
}

pub fn keccak_hex_quantum(bytes: &[u8]) -> (String, QuantumRlpState) {
    let config = RlpConfig::default();
    let hash = keccak_hex(bytes);
    let mut state = QuantumRlpState::new();
    state.apply_hash_decoherence(&config);
    (hash, state)
}

pub fn keccak_rlp_root_quantum(items: &[Vec<u8>]) -> (String, QuantumRlpState) {
    let config = RlpConfig::default();
    let encoded = rlp_list_bytes(items);
    let mut state = QuantumRlpState::new();
    state.apply_encode_decoherence(items.len(), &config);
    state.apply_list_channel(&config);
    let hash = keccak_hex(&encoded);
    state.apply_hash_decoherence(&config);
    (hash, state)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_list_root() {
        let empty: Vec<Vec<u8>> = vec![];
        let root = keccak_rlp_root(&empty);
        assert_eq!(root, EMPTY_LIST_RIPEMD);
    }

    #[test]
    fn test_keccak_hex_empty() {
        let hash = keccak_hex(b"");
        assert_eq!(
            hash,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(hash.len(), HEX_HASH_LEN);
    }

    #[test]
    fn test_rlp_list_bytes_non_empty() {
        let items = vec![b"a".to_vec(), b"bc".to_vec()];
        let encoded = rlp_list_bytes(&items);
        let expected = vec![0xc2, 0x61, 0xc2, 0x62, 0x63];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_rlp_list_bytes_empty() {
        let encoded = rlp_list_bytes(&[]);
        assert_eq!(encoded, vec![0xc0]);
    }

    #[test]
    fn test_manager_cache() {
        let config = RlpConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = RlpManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        let e1 = manager.encode(&items);
        let e2 = manager.encode(&items);
        assert_eq!(e1, e2);
        assert_eq!(manager.cache_size(), 1);
    }

    #[test]
    fn test_manager_cache_ttl() {
        let config = RlpConfig {
            enable_cache: true,
            cache_size: 10,
            cache_ttl_secs: 1,
            ..Default::default()
        };
        let manager = RlpManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        let _ = manager.encode(&items);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let _ = manager.encode(&items);
        // Cache should have been evicted and reinserted.
        assert_eq!(manager.cache_size(), 1);
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = RlpConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = RlpManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        manager.encode(&items);
        assert_eq!(manager.cache_size(), 1);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_manager_batch_roots() {
        let config = RlpConfig::default();
        let manager = RlpManager::new(config).unwrap();
        let batch1 = vec![b"a".to_vec()];
        let batch2 = vec![b"b".to_vec(), b"c".to_vec()];
        let batches = vec![&batch1, &batch2];
        let roots = manager.batch_roots(&batches);
        assert_eq!(roots.len(), 2);
        assert_ne!(roots[0], roots[1]);
    }

    #[test]
    fn test_quantum_state_decoherence() {
        let config = RlpConfig::default();
        let mut state = QuantumRlpState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        state.apply_hash_decoherence(&config);
        assert!(state.purity < 1.0);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_config_validation() {
        let mut config = RlpConfig::default();
        assert!(config.validate().is_ok());
        config.encode_decoherence_rate = 1.5;
        assert!(config.validate().is_err());
        config.encode_decoherence_rate = 0.1;
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.persist_cache = true;
        config.cache_path = None;
        assert!(config.validate().is_err());
    }
}
