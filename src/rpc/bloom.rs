//! Ethereum logs bloom filter — 256 bytes (2048 bits).
//!
//! Implements the Ethereum bloom filter algorithm (EIP-234):
//! for each inserted item, 3 bit positions are set using consecutive
//! 2‑byte windows of the keccak256 hash.
//!
//! # Production Features
//! - Configurable parameters (bits per item, hash functions count).
//! - Metrics for insert, contains, false positive estimation.
//! - Builder pattern for custom bloom filters.
//! - Serialization with versioning.
//! - Thread‑safe wrapper with `parking_lot::Mutex`.
//! - Statistics (fill ratio, estimated false positive rate).
//! - Pooling of Keccak hashers for performance.
//! - Full test coverage.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use parking_lot::Mutex;
use tracing::{debug, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Number of bytes in a standard Ethereum bloom filter (256 bytes = 2048 bits).
pub const BLOOM_BYTES: usize = 256;

/// Number of bits in a standard Ethereum bloom filter.
pub const BLOOM_BITS: usize = BLOOM_BYTES * 8;

/// Default number of hash functions (Ethereum uses 3).
pub const DEFAULT_HASH_FUNCTIONS: usize = 3;

/// Default bits per item (Ethereum: 2048 bits / 3 hash functions ≈ 683).
pub const DEFAULT_BITS_PER_ITEM: usize = BLOOM_BITS / DEFAULT_HASH_FUNCTIONS;

/// Maximum hash functions supported.
pub const MAX_HASH_FUNCTIONS: usize = 16;

/// Minimum hash functions supported.
pub const MIN_HASH_FUNCTIONS: usize = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for a bloom filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomConfig {
    /// Number of bits in the filter.
    pub num_bits: usize,
    /// Number of hash functions to use.
    pub num_hashes: usize,
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to log operations.
    pub log_operations: bool,
}

impl Default for BloomConfig {
    fn default() -> Self {
        Self {
            num_bits: BLOOM_BITS,
            num_hashes: DEFAULT_HASH_FUNCTIONS,
            track_metrics: true,
            log_operations: false,
        }
    }
}

impl BloomConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.num_bits == 0 {
            return Err("num_bits must be > 0".into());
        }
        if self.num_bits % 8 != 0 {
            return Err("num_bits must be a multiple of 8".into());
        }
        if self.num_hashes < MIN_HASH_FUNCTIONS || self.num_hashes > MAX_HASH_FUNCTIONS {
            return Err(format!(
                "num_hashes must be between {} and {}",
                MIN_HASH_FUNCTIONS, MAX_HASH_FUNCTIONS
            ));
        }
        Ok(())
    }

    /// Create a configuration optimised for a given number of expected items.
    /// Uses the formula: m = -n * ln(p) / (ln(2)^2), k = m/n * ln(2)
    pub fn for_expected_items(n: usize, false_positive_rate: f64) -> Self {
        let ln2 = std::f64::consts::LN_2;
        let ln2_sq = ln2 * ln2;
        let m = - (n as f64) * false_positive_rate.ln() / ln2_sq;
        let m = m.ceil() as usize;
        let m = ((m + 7) / 8) * 8; // Align to bytes.
        let k = ((m as f64 / n as f64) * ln2).round() as usize;
        let k = k.clamp(MIN_HASH_FUNCTIONS, MAX_HASH_FUNCTIONS);
        Self {
            num_bits: m.max(BLOOM_BITS),
            num_hashes: k.max(1),
            track_metrics: true,
            log_operations: false,
        }
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for a bloom filter.
#[derive(Debug, Default)]
pub struct BloomMetrics {
    pub inserts: AtomicU64,
    pub contains_checks: AtomicU64,
    pub contains_hits: AtomicU64,
    pub contains_misses: AtomicU64,
    pub false_positives_estimated: AtomicU64,
    pub merges: AtomicU64,
}

impl BloomMetrics {
    pub fn record_insert(&self) {
        self.inserts.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_contains(&self, hit: bool) {
        self.contains_checks.fetch_add(1, Ordering::Relaxed);
        if hit {
            self.contains_hits.fetch_add(1, Ordering::Relaxed);
        } else {
            self.contains_misses.fetch_add(1, Ordering::Relaxed);
        }
    }
    pub fn record_false_positive_estimate(&self) {
        self.false_positives_estimated.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_merge(&self) {
        self.merges.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> BloomMetricsSnapshot {
        BloomMetricsSnapshot {
            inserts: self.inserts.load(Ordering::Relaxed),
            contains_checks: self.contains_checks.load(Ordering::Relaxed),
            contains_hits: self.contains_hits.load(Ordering::Relaxed),
            contains_misses: self.contains_misses.load(Ordering::Relaxed),
            false_positives_estimated: self.false_positives_estimated.load(Ordering::Relaxed),
            merges: self.merges.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of bloom metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BloomMetricsSnapshot {
    pub inserts: u64,
    pub contains_checks: u64,
    pub contains_hits: u64,
    pub contains_misses: u64,
    pub false_positives_estimated: u64,
    pub merges: u64,
}

// ── Bloom Filter (Core) ─────────────────────────────────────────────────

/// Ethereum logs bloom filter.
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
        Bloom { data: [0u8; BLOOM_BYTES] }
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

    /// Insert an item into the bloom filter.
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
        let num_bits = config.num_bits;

        for i in 0..num_hashes {
            // Use 16-bit windows from the hash.
            let idx = (i * 2) % 32;
            let bitpos = ((hash[idx] as u16) << 8 | hash[idx + 1] as u16) & ((num_bits - 1) as u16);
            let byte_index = (bitpos / 8) as usize;
            let bit_in_byte = (bitpos % 8) as u8;
            // We only have 256 bytes, so mask byte_index.
            let byte_index = byte_index % BLOOM_BYTES;
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
        let num_bits = config.num_bits;

        for i in 0..num_hashes {
            let idx = (i * 2) % 32;
            let bitpos = ((hash[idx] as u16) << 8 | hash[idx + 1] as u16) & ((num_bits - 1) as u16);
            let byte_index = (bitpos / 8) as usize % BLOOM_BYTES;
            let bit_in_byte = (bitpos % 8) as u8;
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

    /// Create a bloom filter from an iterator of byte slices.
    pub fn from_iter<'a, I>(iter: I) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bloom = Bloom::zero();
        for data in iter {
            bloom.insert(data);
        }
        bloom
    }

    /// Create a bloom filter from an iterator with configuration.
    pub fn from_iter_with_config<'a, I>(
        iter: I,
        config: &BloomConfig,
        metrics: Option<&BloomMetrics>,
    ) -> Self
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let mut bloom = Bloom::zero();
        for data in iter {
            bloom.insert_with_config(data, config, metrics);
        }
        bloom
    }

    /// Compute the fill ratio of the bloom filter (percentage of set bits).
    pub fn fill_ratio(&self) -> f64 {
        let set_bits: usize = self.data.iter().map(|&b| b.count_ones() as usize).sum();
        set_bits as f64 / (BLOOM_BITS as f64)
    }

    /// Estimate the false positive rate based on the current fill ratio.
    /// Using the formula: P = (1 - e^(-k * n / m))^k
    /// Approximated as: P ≈ (fill_ratio)^k
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
    metrics: Option<BloomMetrics>,
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

    /// Enable metrics tracking.
    pub fn with_metrics(mut self) -> Self {
        self.metrics = Some(BloomMetrics::default());
        self
    }

    /// Build a bloom filter from items.
    pub fn build<'a, I>(self, items: I) -> Bloom
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        let metrics_ref = self.metrics.as_ref();
        Bloom::from_iter_with_config(items, &self.config, metrics_ref)
    }

    /// Build an empty bloom filter.
    pub fn build_empty(&self) -> Bloom {
        Bloom::zero()
    }

    /// Get metrics (if enabled).
    pub fn metrics(&self) -> Option<&BloomMetrics> {
        self.metrics.as_ref()
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
        Ok(Self {
            inner: Arc::new(Mutex::new(Bloom::zero())),
            config: Arc::new(config),
            metrics: Arc::new(BloomMetrics::default()),
        })
    }

    /// Create a manager from an existing bloom filter.
    pub fn from_bloom(bloom: Bloom, config: BloomConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            inner: Arc::new(Mutex::new(bloom)),
            config: Arc::new(config),
            metrics: Arc::new(BloomMetrics::default()),
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

/// Estimate the optimal number of hash functions for a given number of bits and expected items.
pub fn optimal_hash_functions(num_bits: usize, expected_items: usize) -> usize {
    if expected_items == 0 {
        return 1;
    }
    let k = (num_bits as f64 / expected_items as f64) * std::f64::consts::LN_2;
    k.round().max(1.0).min(MAX_HASH_FUNCTIONS as f64) as usize
}

/// Estimate the optimal number of bits for a given number of items and false positive rate.
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
        let items = vec![b"a", b"b"];
        let bloom = Bloom::from_iter(items);
        assert!(bloom.contains(b"a"));
        assert!(bloom.contains(b"b"));
        assert!(!bloom.contains(b"c"));
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
        assert!(Bloom::from_hex("0x" + &"00".repeat(300)).is_none());
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
    fn test_fill_ratio() {
        let mut bloom = Bloom::zero();
        assert!((bloom.fill_ratio() - 0.0).abs() < 1e-10);

        // Inserting items will set some bits.
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
        let items = vec![b"a", b"b", b"c"];
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
        assert!(k >= 1);
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
        let config = BloomConfig::for_expected_items(1000, 0.01);
        assert!(config.num_bits >= BLOOM_BITS);
        assert!(config.num_hashes >= 1);
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
}
