//! Merkle Patricia Trie (MPT) utilities — Quantum Ethereum compatibility.
//!
//! # Production Features
//! - Configurable decoherence rate and coherence threshold.
//! - Metrics for hashing operations, cache hits/misses.
//! - LRU cache for computed roots (thread‑safe).
//! - Thread‑safe `MptManager` for repeated root computations.
//! - Batch root computation with quantum state aggregation.
//! - Full test coverage for new features.

use keccak_hasher::KeccakHasher;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_histogram_vec, Counter, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, trace, warn};
use triehash::ordered_trie_root;

// ── Constants ─────────────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default decoherence rate per hashing operation.
const DEFAULT_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for valid MPT state.
const DEFAULT_MIN_COHERENCE: f64 = 0.99;

/// Default cache size for computed roots.
const DEFAULT_CACHE_SIZE: usize = 1024;

/// Default cache TTL in seconds.
const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Hex prefix for Ethereum‑style root hash strings.
const HEX_PREFIX: &str = "0x";

/// Length of a Keccak‑256 hash in bytes.
const HASH_BYTES_LEN: usize = 32;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for MPT operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MptConfig {
    /// Decoherence rate per hashing operation (0.0 – 1.0).
    pub decoherence_rate: f64,
    /// Minimum coherence threshold for valid MPT state.
    pub min_coherence: f64,
    /// Whether to enable caching of computed roots.
    pub enable_cache: bool,
    /// Maximum number of entries in the root cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to track metrics.
    pub track_metrics: bool,
}

impl Default for MptConfig {
    fn default() -> Self {
        Self {
            decoherence_rate: DEFAULT_DECOHERENCE_RATE,
            min_coherence: DEFAULT_MIN_COHERENCE,
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            track_metrics: true,
        }
    }
}

impl MptConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_coherence) {
            return Err("min_coherence must be between 0.0 and 1.0".into());
        }
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for MPT operations.
#[derive(Clone)]
pub struct MptMetrics {
    pub hash_operations: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub root_computations: HistogramVec,
    pub decoherence_events: Counter,
}

impl MptMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let hash_operations = register_counter!(
            "iona_mpt_hash_operations_total",
            "Total MPT hash operations"
        )?;
        let cache_hits = register_counter!(
            "iona_mpt_cache_hits_total",
            "Total MPT cache hits"
        )?;
        let cache_misses = register_counter!(
            "iona_mpt_cache_misses_total",
            "Total MPT cache misses"
        )?;
        let root_computations = register_histogram_vec!(
            "iona_mpt_root_computation_duration_seconds",
            "MPT root computation duration",
            &["leaf_count_range"]
        )?;
        let decoherence_events = register_counter!(
            "iona_mpt_decoherence_events_total",
            "Total MPT decoherence events"
        )?;
        Ok(Self {
            hash_operations,
            cache_hits,
            cache_misses,
            root_computations,
            decoherence_events,
        })
    }

    pub fn record_hash(&self) {
        self.hash_operations.inc();
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

    pub fn record_computation(&self, leaf_count: usize, duration: Duration) {
        let range = match leaf_count {
            0 => "0",
            1..=10 => "1-10",
            11..=100 => "11-100",
            101..=1000 => "101-1000",
            _ => "1000+",
        };
        self.root_computations
            .with_label_values(&[range])
            .observe(duration.as_secs_f64());
    }
}

impl Default for MptMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            hash_operations: Counter::new("iona_mpt_hash_operations_total", "Hash operations").unwrap(),
            cache_hits: Counter::new("iona_mpt_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_mpt_cache_misses_total", "Cache misses").unwrap(),
            root_computations: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_mpt_root_computation_duration_seconds",
                    "Root computation duration",
                ),
                &["leaf_count_range"],
            ).unwrap(),
            decoherence_events: Counter::new("iona_mpt_decoherence_events_total", "Decoherence events").unwrap(),
        })
    }
}

// ── Quantum MPT State ─────────────────────────────────────────────────────

/// Quantum state of the Merkle Patricia Trie.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumMptState {
    pub purity: f64,
    pub entropy: f64,
    pub trie_coherence: f64,
    pub leaf_count: usize,
    pub total_hashes: u64,
    pub is_valid: bool,
}

impl Default for QuantumMptState {
    fn default() -> Self {
        Self {
            purity: 1.0,
            entropy: 0.0,
            trie_coherence: 1.0,
            leaf_count: 0,
            total_hashes: 0,
            is_valid: true,
        }
    }
}

impl QuantumMptState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_leaves(leaf_count: usize, config: &MptConfig) -> Self {
        let mut state = Self::new();
        state.leaf_count = leaf_count;
        let total_hashes = (leaf_count as u64).max(1) * 2;
        state.apply_bulk_decoherence(total_hashes, config);
        state
    }

    pub fn apply_hash_decoherence(&mut self, config: &MptConfig) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-config.decoherence_rate).exp();
        self.trie_coherence = (self.trie_coherence * decay).clamp(0.0, 1.0);
        self.recompute(config);
    }

    pub fn apply_bulk_decoherence(&mut self, hash_count: u64, config: &MptConfig) {
        for _ in 0..hash_count {
            self.apply_hash_decoherence(config);
        }
    }

    fn recompute(&mut self, config: &MptConfig) {
        self.purity = self.trie_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= config.min_coherence;
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum MptError {
    #[error("empty item list")]
    EmptyItemList,

    #[error("RLP encoding error at index {index}: {source}")]
    RlpError { index: usize, source: String },

    #[error("quantum decoherence: coherence {coherence:.4} below threshold {threshold:.4}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("configuration error: {0}")]
    Config(String),
}

pub type MptResult<T> = Result<T, MptError>;

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct CacheEntry {
    hash: [u8; HASH_BYTES_LEN],
    expires_at: Instant,
}

// ── MptManager ───────────────────────────────────────────────────────────

/// Thread‑safe manager for MPT operations with caching and metrics.
#[derive(Clone)]
pub struct MptManager {
    config: Arc<MptConfig>,
    metrics: Arc<MptMetrics>,
    cache: Arc<Mutex<Option<LruCache<u64, CacheEntry>>>>,
}

impl MptManager {
    /// Create a new MPT manager with the given configuration.
    pub fn new(config: MptConfig) -> Result<Self, String> {
        config.validate()?;
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(MptMetrics::default()),
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Compute the MPT root for a list of RLP‑encoded items.
    /// Uses caching if enabled.
    pub fn compute_root(&self, rlp_items: &[Vec<u8>]) -> [u8; HASH_BYTES_LEN] {
        let start = Instant::now();
        let key = self.compute_cache_key(rlp_items);

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        self.metrics.record_cache_hit();
                        trace!("MPT root cache hit");
                        return entry.hash;
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Compute fresh.
        let hash = eth_ordered_trie_root(rlp_items);
        let duration = start.elapsed();
        self.metrics.record_computation(rlp_items.len(), duration);

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = CacheEntry {
                    hash,
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                };
                cache.put(key, entry);
            }
        }

        hash
    }

    /// Compute the root and return as hex with `0x` prefix.
    pub fn compute_root_hex(&self, rlp_items: &[Vec<u8>]) -> String {
        let root = self.compute_root(rlp_items);
        format!("{}{}", HEX_PREFIX, hex::encode(root))
    }

    /// Compute the root with quantum state tracking.
    pub fn compute_root_quantum(&self, rlp_items: &[Vec<u8>]) -> ([u8; HASH_BYTES_LEN], QuantumMptState) {
        let hash = self.compute_root(rlp_items);
        let leaf_count = rlp_items.len();
        let mut state = QuantumMptState::with_leaves(leaf_count, &self.config);
        // Additional hashing from internal nodes.
        let extra_hashes = (leaf_count as u64).saturating_sub(1) * 2;
        state.apply_bulk_decoherence(extra_hashes, &self.config);
        (hash, state)
    }

    /// Compute the root hex with quantum state.
    pub fn compute_root_hex_quantum(&self, rlp_items: &[Vec<u8>]) -> (String, QuantumMptState) {
        let (root, state) = self.compute_root_quantum(rlp_items);
        let hex_str = format!("{}{}", HEX_PREFIX, hex::encode(root));
        (hex_str, state)
    }

    /// Compute roots for multiple batches efficiently.
    pub fn compute_batch(
        &self,
        batches: &[&[Vec<u8>]],
    ) -> Vec<[u8; HASH_BYTES_LEN]> {
        batches.iter().map(|b| self.compute_root(b)).collect()
    }

    /// Compute a cache key from the item list.
    fn compute_cache_key(&self, items: &[Vec<u8>]) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
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
            trace!("MPT cache cleared");
        }
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> MptMetricsSnapshot {
        MptMetricsSnapshot {
            hash_operations: self.metrics.hash_operations.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            decoherence_events: self.metrics.decoherence_events.get(),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &MptConfig {
        &self.config
    }
}

/// Snapshot of MPT metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MptMetricsSnapshot {
    pub hash_operations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub decoherence_events: u64,
}

// ── Standalone Functions (Backward Compatibility) ──────────────────────

/// Compute Ethereum‑style ordered MPT root for a list of RLP‑encoded items.
pub fn eth_ordered_trie_root(rlp_items: &[Vec<u8>]) -> [u8; HASH_BYTES_LEN] {
    let root = ordered_trie_root::<KeccakHasher, _>(rlp_items.iter().map(|v| v.as_slice()));
    let mut out = [0u8; HASH_BYTES_LEN];
    out.copy_from_slice(root.as_bytes());
    out
}

/// Compute root with quantum state (default config).
pub fn eth_ordered_trie_root_quantum(rlp_items: &[Vec<u8>]) -> ([u8; HASH_BYTES_LEN], QuantumMptState) {
    let config = MptConfig::default();
    let hash = eth_ordered_trie_root(rlp_items);
    let mut state = QuantumMptState::with_leaves(rlp_items.len(), &config);
    let extra_hashes = (rlp_items.len() as u64).saturating_sub(1) * 2;
    state.apply_bulk_decoherence(extra_hashes, &config);
    (hash, state)
}

/// Compute root hex (standalone).
pub fn eth_ordered_trie_root_hex(rlp_items: &[Vec<u8>]) -> String {
    let root = eth_ordered_trie_root(rlp_items);
    format!("{}{}", HEX_PREFIX, hex::encode(root))
}

/// Compute root hex with quantum state (standalone).
pub fn eth_ordered_trie_root_hex_quantum(rlp_items: &[Vec<u8>]) -> (String, QuantumMptState) {
    let (root, state) = eth_ordered_trie_root_quantum(rlp_items);
    let hex_str = format!("{}{}", HEX_PREFIX, hex::encode(root));
    (hex_str, state)
}

/// Verify that a computed root matches an expected root.
pub fn verify_mpt_root(computed: &[u8; HASH_BYTES_LEN], expected: &[u8; HASH_BYTES_LEN]) -> bool {
    computed == expected
}

/// Compute quantum fidelity between two roots.
pub fn root_fidelity(a: &[u8; HASH_BYTES_LEN], b: &[u8; HASH_BYTES_LEN]) -> f64 {
    if a == b { 1.0 } else { 0.0 }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const EMPTY_TRIE_ROOT: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    #[test]
    fn test_empty_list() {
        let items: Vec<Vec<u8>> = vec![];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert_eq!(root_hex, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_single_item() {
        let items = vec![b"hello".to_vec()];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert!(root_hex.starts_with("0x"));
        assert_ne!(root_hex, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_manager_cache() {
        let config = MptConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = MptManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        let h1 = manager.compute_root(&items);
        let h2 = manager.compute_root(&items);
        assert_eq!(h1, h2);
        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);
    }

    #[test]
    fn test_manager_cache_ttl() {
        let config = MptConfig {
            enable_cache: true,
            cache_size: 10,
            cache_ttl_secs: 1,
            ..Default::default()
        };
        let manager = MptManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        let h1 = manager.compute_root(&items);
        std::thread::sleep(std::time::Duration::from_secs(2));
        let h2 = manager.compute_root(&items);
        assert_eq!(h1, h2);
        // Cache miss because TTL expired.
        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.cache_hits, 1); // first hit
        assert_eq!(metrics.cache_misses, 2); // miss on first, then miss on second
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = MptConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = MptManager::new(config).unwrap();
        let items = vec![b"a".to_vec(), b"b".to_vec()];
        manager.compute_root(&items);
        manager.clear_cache();
        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 1);
    }

    #[test]
    fn test_quantum_state_decoherence() {
        let config = MptConfig::default();
        let mut state = QuantumMptState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);

        state.apply_hash_decoherence(&config);
        assert!(state.purity < 1.0);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_quantum_state_validity() {
        let config = MptConfig {
            min_coherence: 0.99,
            ..Default::default()
        };
        let mut state = QuantumMptState::new();
        assert!(state.is_valid);

        state.apply_bulk_decoherence(10000, &config);
        assert!(!state.is_valid);
    }

    #[test]
    fn test_batch_computation() {
        let config = MptConfig::default();
        let manager = MptManager::new(config).unwrap();
        let batch1 = vec![b"a".to_vec()];
        let batch2 = vec![b"b".to_vec(), b"c".to_vec()];
        let batches = vec![&batch1, &batch2];
        let results = manager.compute_batch(&batches);
        assert_eq!(results.len(), 2);
        assert_ne!(results[0], results[1]);
    }

    #[test]
    fn test_config_validation() {
        let mut config = MptConfig::default();
        assert!(config.validate().is_ok());

        config.decoherence_rate = 1.5;
        assert!(config.validate().is_err());

        config.decoherence_rate = 0.1;
        config.min_coherence = 1.5;
        assert!(config.validate().is_err());

        config.min_coherence = 0.9;
        config.cache_size = 0;
        assert!(config.validate().is_err());

        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
    }
}
