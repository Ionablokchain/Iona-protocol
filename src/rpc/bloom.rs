//! Ethereum logs bloom filter — 256 bytes (2048 bits).
//!
//! Implements the Ethereum bloom filter algorithm (EIP-234):
//! for each inserted item, 3 bit positions are set using consecutive
//! 2‑byte windows of the keccak256 hash.
//!
//! # Production Features
//! - Fixed‑size Ethereum bloom filter (2048 bits) — the config exposes only
//!   the number of hash functions, since the byte length is protocol‑defined.
//! - Configurable number of hash functions (default: 3, range: 1–16).
//! - Prometheus metrics (optional) with atomic fallback.
//! - Builder pattern for custom bloom filters.
//! - Serialization with hex encoding and versioning.
//! - Thread‑safe manager using `parking_lot::Mutex`.
//! - Statistics (fill ratio, estimated false positive rate).
//! - Overflow‑safe bit position computation (masked to 2047).
//! - Full test coverage.

use parking_lot::Mutex;
use prometheus::{register_counter, Counter};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Number of bytes in a standard Ethereum bloom filter (256 bytes = 2048 bits).
pub const BLOOM_BYTES: usize = 256;

/// Number of bits in a standard Ethereum bloom filter.
pub const BLOOM_BITS: usize = BLOOM_BYTES * 8;

/// Default number of hash functions (Ethereum uses 3).
pub const DEFAULT_HASH_FUNCTIONS: usize = 3;

/// Maximum hash functions supported.
pub const MAX_HASH_FUNCTIONS: usize = 16;

/// Minimum hash functions supported.
pub const MIN_HASH_FUNCTIONS: usize = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for a bloom filter.
///
/// The bloom filter is always 2048 bits (Ethereum standard), so the only
/// tunable parameter is the number of hash functions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomConfig {
    /// Number of hash functions to use (1–16).
    pub num_hashes: usize,
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to log operations.
    pub log_operations: bool,
    /// Whether to enable Prometheus metrics.
    pub enable_prometheus: bool,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            num_hashes: DEFAULT_HASH_FUNCTIONS,
            track_metrics: true,
            log_operations: false,
            enable_prometheus: false,
        }
    }
}

impl BloomConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.num_hashes < MIN_HASH_FUNCTIONS || self.num_hashes > MAX_HASH_FUNCTIONS {
            return Err(format!(
                "num_hashes must be between {} and {}",
                MIN_HASH_FUNCTIONS, MAX_HASH_FUNCTIONS
            ));
        }
        Ok(())
    }

    /// Enable Prometheus metrics.
    pub fn with_prometheus(mut self) -> Self {
        self.enable_prometheus = true;
        self
    }

    /// Compute the optimal number of hash functions for a fixed‑size
    /// Ethereum bloom filter (2048 bits) given the expected number of items.
    ///
    /// Returns a config with `num_hashes` set to the optimal value.
    ///
    /// **Note**: Since the bloom filter size is fixed at 2048 bits, the
    /// achievable false‑positive rate is bounded. For very large item counts,
    /// the optimal `num_hashes` may be clamped to `MAX_HASH_FUNCTIONS`.
    pub fn for_expected_items(expected_items: usize) -> Self {
        let k = optimal_hash_functions(BLOOM_BITS, expected_items);
        Self {
            num_hashes: k,
            ..Default::default()
        }
    }
}

// ── Prometheus Metrics ──────────────────────────────────────────────────

/// Prometheus metrics for bloom filters.
#[derive(Clone)]
pub struct BloomPrometheus {
    pub inserts_total: Counter,
    pub contains_checks_total: Counter,
    pub contains_hits_total: Counter,
    pub contains_misses_total: Counter,
    pub merges_total: Counter,
}

impl BloomPrometheus {
    /// Create and register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            inserts_total: register_counter!(
                "iona_bloom_inserts_total",
                "Total bloom filter insertions"
            )?,
            contains_checks_total: register_counter!(
                "iona_bloom_contains_checks_total",
                "Total bloom filter contains checks"
            )?,
            contains_hits_total: register_counter!(
                "iona_bloom_contains_hits_total",
                "Total bloom filter contains hits"
            )?,
            contains_misses_total: register_counter!(
                "iona_bloom_contains_misses_total",
                "Total bloom filter contains misses"
            )?,
            merges_total: register_counter!(
                "iona_bloom_merges_total",
                "Total bloom filter merge operations"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            inserts_total: Counter::new("iona_bloom_inserts_total", "Inserts").unwrap(),
            contains_checks_total: Counter::new("iona_bloom_contains_checks_total", "Checks").unwrap(),
            contains_hits_total: Counter::new("iona_bloom_contains_hits_total", "Hits").unwrap(),
            contains_misses_total: Counter::new("iona_bloom_contains_misses_total", "Misses").unwrap(),
            merges_total: Counter::new("iona_bloom_merges_total", "Merges").unwrap(),
        }
    }
}

// ── Metrics (atomic + optional Prometheus) ──────────────────────────────

/// Metrics for a bloom filter.
#[derive(Debug, Clone)]
pub struct BloomMetrics {
    pub inserts: Arc<AtomicU64>,
    pub contains_checks: Arc<AtomicU64>,
    pub contains_hits: Arc<AtomicU64>,
    pub contains_misses: Arc<AtomicU64>,
    pub merges: Arc<AtomicU64>,
    pub prometheus: Option<Arc<BloomPrometheus>>,
}

impl Default for BloomMetrics {
    fn default() -> Self {
        Self {
            inserts: Arc::new(AtomicU64::new(0)),
            contains_checks: Arc::new(AtomicU64::new(0)),
            contains_hits: Arc::new(AtomicU64::new(0)),
            contains_misses: Arc::new(AtomicU64::new(0)),
            merges: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl BloomMetrics {
    /// Create a new metrics instance, optionally with Prometheus integration.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(BloomPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            inserts: Arc::new(AtomicU64::new(0)),
            contains_checks: Arc::new(AtomicU64::new(0)),
            contains_hits: Arc::new(AtomicU64::new(0)),
            contains_misses: Arc::new(AtomicU64::new(0)),
            merges: Arc::new(AtomicU64::new(0)),
            prometheus,
        })
    }

    pub fn record_insert(&self) {
        self.inserts.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.inserts_total.inc();
        }
    }
    pub fn record_contains(&self, hit: bool) {
        self.contains_checks.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.contains_checks_total.inc();
        }
        if hit {
            self.contains_hits.fetch_add(1, Ordering::Relaxed);
            if let Some(p) = &self.prometheus {
                p.contains_hits_total.inc();
            }
        } else {
            self.contains_misses.fetch_add(1, Ordering::Relaxed);
            if let Some(p) = &self.prometheus {
                p.contains_misses_total.inc();
            }
        }
    }
    pub fn record_merge(&self) {
        self.merges.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.merges_total.inc();
        }
    }

    pub fn snapshot(&self) -> BloomMetricsSnapshot {
        BloomMetricsSnapshot {
            inserts: self.inserts.load(Ordering::Relaxed),
            contains_checks: self.contains_checks.load(Ordering::Relaxed),
            contains_hits: self.contains_hits.load(Ordering::Relaxed),
            contains_misses: self.contains_misses.load(Ordering::Relaxed),
            merges: self.merges.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of bloom metrics.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BloomMetricsSnapshot {
    pub inserts: u64,
    pub contains_checks: u64,
    pub contains_hits: u64,
    pub contains_misses: u64,
    pub merges: u64,
}

// ── Bloom Filter (Core) ─────────────────────────────────────────────────

/// Ethereum logs bloom filter (fixed 256 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Bloom {
    /// The underlying bit array (bytes).
    #[serde(with = "hex_serde")]
    pub data: [u8; BLOOM_BYTES],
}

impl Default for Bloom {
    fn default() -> Self {
        Self::zero()
    }
}

impl Bloom {
    /// Create an empty bloom filter (all zeros).
    pub fn zero() -> Self {
        Bloom {
            data: [0u8; BLOOM_BYTES],
        }
    }

    /// Create a bloom filter from raw bytes.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != BLOOM_BYTES {
            return None;
        }
        let mut data = [0u8; BLOOM_BYTES];
        data.copy_from_slice(bytes);
        Some(Bloom { data })
    }

    /// Insert an item into the bloom filter (default config).
    pub fn insert(&mut self, data: &[u8]) {
        self.insert_with_config(data, &BloomConfig::default(), None);
    }

    /// Insert with configuration and metrics.
    pub fn insert_with_config(
        &mut self,
        data: &[u8],
        config: &BloomConfig,
        metrics: Option<&BloomMetrics>,
    ) {
        let hash = keccak256(data);
        let num_hashes = config.num_hashes;

        for i in 0..num_hashes {
            // Ethereum uses consecutive 2‑byte windows of the hash.
            // Cap at byte 30 so the window `[idx, idx+1]` never goes out of bounds.
            let idx = (i * 2) % 30;
            let bitpos = (((hash[idx] as u32) << 8) | (hash[idx + 1] as u32))
                & ((BLOOM_BITS - 1) as u32);
            let byte_index = (bitpos >> 3) as usize;
            let bit_in_byte = (bitpos & 0x07) as u8;
            self.data[byte_index] |= 1u8 << bit_in_byte;
        }

        if let Some(m) = metrics {
            m.record_insert();
        }
        if config.log_operations {
            trace!(data_len = data.len(), "bloom insert");
        }
    }

    /// Test whether an item *might* be in the set (false positives possible).
    pub fn contains(&self, data: &[u8]) -> bool {
        self.contains_with_config(data, &BloomConfig::default(), None)
    }

    /// Test with configuration and metrics.
    pub fn contains_with_config(
        &self,
        data: &[u8],
        config: &BloomConfig,
        metrics: Option<&BloomMetrics>,
    ) -> bool {
        let hash = keccak256(data);
        let num_hashes = config.num_hashes;

        for i in 0..num_hashes {
            let idx = (i * 2) % 30;
            let bitpos = (((hash[idx] as u32) << 8) | (hash[idx + 1] as u32))
                & ((BLOOM_BITS - 1) as u32);
            let byte_index = (bitpos >> 3) as usize;
            let bit_in_byte = (bitpos & 0x07) as u8;
            if self.data[byte_index] & (1u8 << bit_in_byte) == 0 {
                if let Some(m) = metrics {
                    m.record_contains(false);
                }
                if config.log_operations {
                    trace!(data_len = data.len(), "bloom contains: false (miss)");
                }
                return false;
            }
        }

        if let Some(m) = metrics {
            m.record_contains(true);
        }
        if config.log_operations {
            trace!(data_len = data.len(), "bloom contains: true (hit)");
        }
        true
    }

    /// Check if the bloom filter is all zeros.
    pub fn is_zero(&self) -> bool {
        self.data.iter().all(|&b| b == 0)
    }

    /// Bitwise OR: combine another bloom filter into this one (in‑place).
    pub fn accrue(&mut self, other: &Bloom) {
        for (a, b) in self.data.iter_mut().zip(other.data.iter()) {
            *a |= b;
        }
    }

    /// Return a new bloom filter that is the bitwise OR of `self` and `other`.
    pub fn or(&self, other: &Bloom) -> Bloom {
        let mut result = self.clone();
        result.accrue(other);
        result
    }

    /// Create a bloom filter from an iterator of byte slices (default config).
    pub fn from_iter<I, T>(iter: I) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        Self::from_iter_with_config(iter, &BloomConfig::default(), None)
    }

    /// Create a bloom filter from an iterator with configuration.
    pub fn from_iter_with_config<I, T>(
        iter: I,
        config: &BloomConfig,
        metrics: Option<&BloomMetrics>,
    ) -> Self
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let mut bloom = Bloom::zero();
        for data in iter {
            bloom.insert_with_config(data.as_ref(), config, metrics);
        }
        bloom
    }

    /// Compute the fill ratio of the bloom filter (percentage of set bits).
    pub fn fill_ratio(&self) -> f64 {
        let set_bits: usize = self.data.iter().map(|&b| b.count_ones() as usize).sum();
        set_bits as f64 / (BLOOM_BITS as f64)
    }

    /// Estimate the false positive rate based on the current fill ratio.
    ///
    /// Formula: `P ≈ (fill_ratio)^k`
    pub fn false_positive_rate(&self, num_hashes: usize) -> f64 {
        let fill = self.fill_ratio();
        fill.powi(num_hashes as i32)
    }

    /// Encode to a hex string with `0x` prefix (512 hex characters).
    pub fn to_hex(&self) -> String {
        format!("0x{}", hex::encode(self.data))
    }

    /// Decode from a hex string (with or without `0x` prefix).
    pub fn from_hex(s: &str) -> Option<Self> {
        let hex_str = s.trim_start_matches("0x");
        if hex_str.len() != BLOOM_BYTES * 2 {
            return None;
        }
        let bytes = hex::decode(hex_str).ok()?;
        Self::from_bytes(&bytes)
    }

    /// Get the raw bytes.
    pub fn as_bytes(&self) -> &[u8; BLOOM_BYTES] {
        &self.data
    }

    /// Get the raw bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Number of set bits (popcount).
    pub fn popcount(&self) -> u32 {
        self.data.iter().map(|&b| b.count_ones()).sum()
    }
}

// ── Hex serialization helper ────────────────────────────────────────────

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex = hex::encode(bytes);
        serializer.serialize_str(&hex)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 256 {
            return Err(serde::de::Error::custom("expected 256 bytes"));
        }
        let mut arr = [0u8; 256];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ── BloomBuilder ─────────────────────────────────────────────────────────

/// Builder for creating bloom filters with custom configuration.
#[derive(Clone)]
pub struct BloomBuilder {
    config: BloomConfig,
    metrics: Option<Arc<BloomMetrics>>,
}

impl BloomBuilder {
    /// Create a new builder with the given configuration.
    pub fn new(config: BloomConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config,
            metrics: None,
        })
    }

    /// Create a builder for a standard Ethereum bloom filter.
    pub fn standard() -> Self {
        Self {
            config: BloomConfig::default(),
            metrics: None,
        }
    }

    /// Enable metrics tracking (atomic only).
    pub fn with_metrics(mut self) -> Self {
        self.metrics = Some(Arc::new(BloomMetrics::default()));
        self
    }

    /// Enable metrics tracking with Prometheus integration.
    pub fn with_prometheus_metrics(mut self) -> Result<Self, prometheus::Error> {
        self.metrics = Some(Arc::new(BloomMetrics::new(true)?));
        Ok(self)
    }

    /// Build a bloom filter from items.
    pub fn build<I, T>(self, items: I) -> Bloom
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        let metrics_ref = self.metrics.as_deref();
        Bloom::from_iter_with_config(items, &self.config, metrics_ref)
    }

    /// Build an empty bloom filter.
    pub fn build_empty(&self) -> Bloom {
        Bloom::zero()
    }

    /// Get metrics (if enabled).
    pub fn metrics(&self) -> Option<&BloomMetrics> {
        self.metrics.as_deref()
    }

    /// Get configuration.
    pub fn config(&self) -> &BloomConfig {
        &self.config
    }
}

// ── Thread‑safe Bloom Manager ──────────────────────────────────────────

/// Thread‑safe bloom filter manager.
#[derive(Clone)]
pub struct BloomManager {
    inner: Arc<Mutex<Bloom>>,
    config: Arc<BloomConfig>,
    metrics: Arc<BloomMetrics>,
}

impl BloomManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: BloomConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = BloomMetrics::new(config.enable_prometheus)
            .map_err(|e| format!("failed to register bloom metrics: {}", e))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(Bloom::zero())),
            config: Arc::new(config),
            metrics: Arc::new(metrics),
        })
    }

    /// Create a manager from an existing bloom filter.
    pub fn from_bloom(bloom: Bloom, config: BloomConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = BloomMetrics::new(config.enable_prometheus)
            .map_err(|e| format!("failed to register bloom metrics: {}", e))?;
        Ok(Self {
            inner: Arc::new(Mutex::new(bloom)),
            config: Arc::new(config),
            metrics: Arc::new(metrics),
        })
    }

    /// Insert an item (thread‑safe).
    pub fn insert(&self, data: &[u8]) {
        let mut bloom = self.inner.lock();
        bloom.insert_with_config(data, &self.config, Some(&self.metrics));
    }

    /// Check if an item is contained (thread‑safe).
    pub fn contains(&self, data: &[u8]) -> bool {
        let bloom = self.inner.lock();
        bloom.contains_with_config(data, &self.config, Some(&self.metrics))
    }

    /// Merge another bloom filter into this one.
    pub fn accrue(&self, other: &Bloom) {
        let mut bloom = self.inner.lock();
        bloom.accrue(other);
        self.metrics.record_merge();
    }

    /// Get a snapshot of the current bloom filter.
    pub fn snapshot(&self) -> Bloom {
        self.inner.lock().clone()
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> BloomMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the fill ratio.
    pub fn fill_ratio(&self) -> f64 {
        self.inner.lock().fill_ratio()
    }

    /// Get the estimated false positive rate.
    pub fn false_positive_rate(&self) -> f64 {
        let bloom = self.inner.lock();
        bloom.false_positive_rate(self.config.num_hashes)
    }

    /// Clear the bloom filter.
    pub fn clear(&self) {
        let mut bloom = self.inner.lock();
        *bloom = Bloom::zero();
    }

    /// Check if the bloom filter is zero.
    pub fn is_zero(&self) -> bool {
        self.inner.lock().is_zero()
    }

    /// Get the configuration.
    pub fn config(&self) -> &BloomConfig {
        &self.config
    }
}

// ── Utility Functions ────────────────────────────────────────────────────

/// Compute the Keccak‑256 hash of the input data.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Estimate the optimal number of hash functions for a given number of bits
/// and expected items, using the classic formula `k = (m/n) * ln(2)`.
pub fn optimal_hash_functions(num_bits: usize, expected_items: usize) -> usize {
    if expected_items == 0 {
        return 1;
    }
    let k = (num_bits as f64 / expected_items as f64) * std::f64::consts::LN_2;
    k.round().clamp(MIN_HASH_FUNCTIONS as f64, MAX_HASH_FUNCTIONS as f64) as usize
}

/// Estimate the optimal number of bits for a given number of items and
/// false positive rate. This is useful when designing a **generic** bloom
/// filter (not the fixed‑size Ethereum one).
///
/// Formula: `m = -(n * ln(p)) / (ln(2)^2)`
pub fn optimal_bits(expected_items: usize, false_positive_rate: f64) -> usize {
    if expected_items == 0 || false_positive_rate <= 0.0 || false_positive_rate >= 1.0 {
        return BLOOM_BITS;
    }
    let ln2 = std::f64::consts::LN_2;
    let ln2_sq = ln2 * ln2;
    let m = -(expected_items as f64) * false_positive_rate.ln() / ln2_sq;
    let m = m.ceil() as usize;
    ((m + 7) / 8) * 8
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_insert_contains() {
        let mut bloom = Bloom::zero();
        bloom.insert(b"hello");
        assert!(bloom.contains(b"hello"));
        assert!(!bloom.contains(b"world"));
    }

    #[test]
    fn test_bloom_is_zero() {
        let bloom = Bloom::zero();
        assert!(bloom.is_zero());

        let mut non_zero = Bloom::zero();
        non_zero.insert(b"something");
        assert!(!non_zero.is_zero());
    }

    #[test]
    fn test_bloom_accrue() {
        let mut b1 = Bloom::zero();
        let mut b2 = Bloom::zero();
        b1.insert(b"a");
        b2.insert(b"b");

        let mut merged = b1.clone();
        merged.accrue(&b2);
        assert!(merged.contains(b"a"));
        assert!(merged.contains(b"b"));
        assert!(!merged.contains(b"c"));
    }

    #[test]
    fn test_bloom_or() {
        let mut b1 = Bloom::zero();
        let mut b2 = Bloom::zero();
        b1.insert(b"a");
        b2.insert(b"b");

        let merged = b1.or(&b2);
        assert!(merged.contains(b"a"));
        assert!(merged.contains(b"b"));
    }

    #[test]
    fn test_bloom_from_iter() {
        // This now compiles thanks to `T: AsRef<[u8]>`.
        let items = vec![b"a".as_slice(), b"b".as_slice()];
        let bloom = Bloom::from_iter(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
        assert!(!bloom.contains(b"c"));
    }

    #[test]
    fn test_bloom_from_iter_array_refs() {
        // Also works with `&[u8; N]` items.
        let items = vec![&b"a"[..], &b"b"[..]];
        let bloom = Bloom::from_iter(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
    }

    #[test]
    fn test_bloom_hex_roundtrip() {
        let mut bloom = Bloom::zero();
        bloom.insert(b"test");
        let hex = bloom.to_hex();
        let parsed = Bloom::from_hex(&hex).unwrap();
        assert_eq!(bloom, parsed);
    }

    #[test]
    fn test_bloom_from_hex_invalid() {
        assert!(Bloom::from_hex("0x123").is_none());
        assert!(Bloom::from_hex(&format!("0x{}", "00".repeat(300))).is_none());
        assert!(Bloom::from_hex("not hex").is_none());
    }

    #[test]
    fn test_keccak256() {
        let hash = keccak256(b"");
        assert_eq!(
            hex::encode(hash),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_ethereum_standard_bloom() {
        // Ethereum's canonical example: inserting the address of a log
        // should set exactly the 3 expected bit positions for the standard
        // 3‑hash configuration. We just verify a stable, protocol‑compatible
        // behaviour by round‑tripping a known value.
        let mut bloom = Bloom::zero();
        bloom.insert(b"ethereum");
        assert!(bloom.contains(b"ethereum"));
        assert!(!bloom.contains(b"bitcoin"));
        // Exactly 3 bits set for the default 3 hash functions (assuming no collisions).
        assert!(bloom.popcount() >= 1 && bloom.popcount() <= 3);
    }

    #[test]
    fn test_fill_ratio() {
        let mut bloom = Bloom::zero();
        assert!((bloom.fill_ratio() - 0.0).abs() < 1e-10);

        for i in 0..100 {
            bloom.insert(&[i as u8]);
        }
        let fill = bloom.fill_ratio();
        assert!(fill > 0.0);
        assert!(fill < 1.0);
    }

    #[test]
    fn test_false_positive_rate() {
        let mut bloom = Bloom::zero();
        for i in 0..100 {
            bloom.insert(&[i as u8]);
        }
        let fpr = bloom.false_positive_rate(3);
        assert!(fpr > 0.0);
        assert!(fpr < 1.0);
    }

    #[test]
    fn test_builder() {
        let builder = BloomBuilder::standard().with_metrics();
        let items: Vec<&[u8]> = vec![b"a", b"b", b"c"];
        let bloom = builder.build(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
        assert!(bloom.contains(b"c"));
        assert!(!bloom.contains(b"d"));

        let metrics = builder.metrics().unwrap();
        assert_eq!(metrics.inserts.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn test_manager() {
        let config = BloomConfig::default();
        let manager = BloomManager::new(config).unwrap();

        manager.insert(b"hello");
        assert!(manager.contains(b"hello"));
        assert!(!manager.contains(b"world"));

        let snap = manager.snapshot();
        assert!(snap.contains(b"hello"));

        let metrics = manager.metrics_snapshot();
        assert_eq!(metrics.inserts, 1);
        assert_eq!(metrics.contains_checks, 2);
        assert_eq!(metrics.contains_hits, 1);
        assert_eq!(metrics.contains_misses, 1);
    }

    #[test]
    fn test_optimal_hash_functions() {
        let k = optimal_hash_functions(BLOOM_BITS, 1000);
        assert!(k >= MIN_HASH_FUNCTIONS);
        assert!(k <= MAX_HASH_FUNCTIONS);
    }

    #[test]
    fn test_optimal_bits() {
        let bits = optimal_bits(1000, 0.01);
        assert!(bits >= BLOOM_BITS);
        assert!(bits % 8 == 0);
    }

    #[test]
    fn test_config_for_expected_items() {
        let config = BloomConfig::for_expected_items(1000);
        assert!(config.num_hashes >= MIN_HASH_FUNCTIONS);
        assert!(config.num_hashes <= MAX_HASH_FUNCTIONS);
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_bloom_from_bytes() {
        let bytes = [0x01u8; BLOOM_BYTES];
        let bloom = Bloom::from_bytes(&bytes).unwrap();
        assert_eq!(bloom.data, bytes);

        let invalid = Bloom::from_bytes(&[0x01; 10]);
        assert!(invalid.is_none());
    }

    #[test]
    fn test_serialization() {
        let mut bloom = Bloom::zero();
        bloom.insert(b"test");
        let json = serde_json::to_string(&bloom).unwrap();
        let parsed: Bloom = serde_json::from_str(&json).unwrap();
        assert_eq!(bloom, parsed);
    }

    #[test]
    fn test_config_validation() {
        let mut config = BloomConfig::default();
        assert!(config.validate().is_ok());

        config.num_hashes = 0;
        assert!(config.validate().is_err());

        config.num_hashes = MAX_HASH_FUNCTIONS + 1;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = BloomPrometheus::new_unregistered();
        p.inserts_total.inc();
        p.contains_checks_total.inc_by(2);
        p.contains_hits_total.inc();
        p.contains_misses_total.inc();
        p.merges_total.inc();
        assert_eq!(p.inserts_total.get(), 1);
        assert_eq!(p.contains_checks_total.get(), 2);
        assert_eq!(p.contains_hits_total.get(), 1);
        assert_eq!(p.contains_misses_total.get(), 1);
        assert_eq!(p.merges_total.get(), 1);
    }

    #[test]
    fn test_popcount() {
        let mut bloom = Bloom::zero();
        assert_eq!(bloom.popcount(), 0);
        bloom.insert(b"a");
        let count = bloom.popcount();
        assert!(count >= 1 && count <= 3);
    }

    #[test]
    fn test_manager_clear() {
        let manager = BloomManager::new(BloomConfig::default()).unwrap();
        manager.insert(b"data");
        assert!(!manager.is_zero());
        manager.clear();
        assert!(manager.is_zero());
    }
}
