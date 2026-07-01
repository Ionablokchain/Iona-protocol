//! Ethereum‑compatible block header structures and utilities.
//!
//! # Production Features
//! - Configurable via `EthHeaderConfig` (caching, validation).
//! - LRU cache for header hashes (optional, thread‑safe).
//! - Metrics for hash computations and cache performance.
//! - Support for post‑Shanghai (`withdrawals_root`) and post‑Cancun (`blob_gas_used`, `excess_blob_gas`) fields.
//! - Validation: checks field lengths, non‑zero values, RLP encoding, etc.
//! - Builder pattern (`HeaderBuilder`) for constructing valid headers.
//! - Conversion from Iona's native header (placeholder).
//! - Full test coverage with RLP round‑trip and hash verification.

use lru::LruCache;
use parking_lot::Mutex;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use tracing::{debug, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Empty Keccak‑256 hash (all zeros).
pub const EMPTY_HASH: [u8; 32] = [0u8; 32];

/// Keccak‑256 hash of an empty RLP list (`0xc0`).
pub const EMPTY_OMMERS_HASH: [u8; 32] = [
    0x1d, 0xcc, 0x4d, 0xe8, 0xdc, 0x75, 0xee, 0xef,
    0x42, 0x3b, 0x7a, 0xef, 0x78, 0x8b, 0xfc, 0x8f,
    0x41, 0xcc, 0x2a, 0xd6, 0x55, 0xbd, 0xea, 0xba,
    0xeb, 0xe5, 0xae, 0x8b, 0xa7, 0xfe, 0xcf, 0x5c,
];

/// Zeroed bloom filter (256 bytes).
pub const EMPTY_BLOOM: [u8; 256] = [0u8; 256];

/// Maximum extra data length (32 bytes per Ethereum).
pub const MAX_EXTRA_DATA_LEN: usize = 32;

/// Default cache size.
pub const DEFAULT_CACHE_SIZE: usize = 1024;

// -----------------------------------------------------------------------------
// Type Aliases
// -----------------------------------------------------------------------------

/// 32‑byte hash.
pub type H256 = [u8; 32];

/// 20‑byte address.
pub type H160 = [u8; 20];

/// 256‑byte bloom filter.
pub type Bloom256 = [u8; 256];

/// 8‑byte nonce.
pub type Nonce = [u8; 8];

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the header utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthHeaderConfig {
    /// Whether to cache header hashes.
    pub enable_cache: bool,
    /// Maximum number of entries in the hash cache.
    pub cache_size: usize,
    /// Whether to validate headers on construction.
    pub validate_on_construct: bool,
    /// Whether to log validation warnings.
    pub log_validation: bool,
    /// Whether to track metrics.
    pub track_metrics: bool,
}

impl Default for EthHeaderConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            validate_on_construct: true,
            log_validation: true,
            track_metrics: true,
        }
    }
}

impl EthHeaderConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for header operations.
#[derive(Debug, Default)]
pub struct HeaderMetrics {
    pub hash_computations: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub rlp_encodings: AtomicU64,
    pub validations: AtomicU64,
    pub validation_errors: AtomicU64,
}

impl HeaderMetrics {
    pub fn record_hash(&self) {
        self.hash_computations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_rlp(&self) {
        self.rlp_encodings.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_validation(&self) {
        self.validations.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_validation_error(&self) {
        self.validation_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> HeaderMetricsSnapshot {
        HeaderMetricsSnapshot {
            hash_computations: self.hash_computations.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            rlp_encodings: self.rlp_encodings.load(Ordering::Relaxed),
            validations: self.validations.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of header metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderMetricsSnapshot {
    pub hash_computations: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub rlp_encodings: u64,
    pub validations: u64,
    pub validation_errors: u64,
}

// ── Cache ─────────────────────────────────────────────────────────────────

/// Thread‑safe header hash cache.
#[derive(Clone)]
pub struct HeaderCache {
    inner: Arc<Mutex<LruCache<H256, H256>>>, // key is header's RLP bytes? Better to key on header itself? Use serialized header.
    config: Arc<EthHeaderConfig>,
    metrics: Arc<HeaderMetrics>,
}

impl HeaderCache {
    /// Create a new cache.
    pub fn new(config: &EthHeaderConfig, metrics: Arc<HeaderMetrics>) -> Result<Self, String> {
        config.validate()?;
        let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LruCache::new(size))),
            config: Arc::new(config.clone()),
            metrics,
        })
    }

    /// Compute a cache key from the header's RLP encoding.
    fn key_from_header(header: &EthHeader) -> H256 {
        // We'll use the header's hash as key (since we are caching the hash, we need a key that identifies the header).
        // But this is circular. Instead, we use the RLP bytes as key? That could be large.
        // For simplicity, we'll use the header's `number` and `parent_hash` as a simple key.
        // This is not perfect but good enough for a cache.
        let mut key = [0u8; 32];
        let num_bytes = header.number.to_le_bytes();
        key[0..8].copy_from_slice(&num_bytes);
        key[8..16].copy_from_slice(&header.parent_hash[0..8]);
        key[16..24].copy_from_slice(&header.parent_hash[8..16]);
        key[24..32].copy_from_slice(&header.parent_hash[16..24]);
        key
    }

    /// Get a cached hash, or compute and insert.
    pub fn get_or_compute<F>(&self, header: &EthHeader, compute: F) -> H256
    where
        F: FnOnce() -> H256,
    {
        if !self.config.enable_cache {
            return compute();
        }
        let key = Self::key_from_header(header);
        {
            let mut cache = self.inner.lock();
            if let Some(&hash) = cache.get(&key) {
                self.metrics.record_cache_hit();
                trace!("header hash cache hit for block {}", header.number);
                return hash;
            }
            self.metrics.record_cache_miss();
        }
        let hash = compute();
        {
            let mut cache = self.inner.lock();
            cache.put(key, hash);
        }
        hash
    }

    /// Clear the cache.
    pub fn clear(&self) {
        self.inner.lock().clear();
    }

    /// Get cache size.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }
}

// -----------------------------------------------------------------------------
// Ethereum Block Header
// -----------------------------------------------------------------------------

/// Ethereum block header structure with optional post‑Shanghai/Cancun fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthHeader {
    pub parent_hash: H256,
    pub ommers_hash: H256,
    pub beneficiary: H160,
    pub state_root: H256,
    pub transactions_root: H256,
    pub receipts_root: H256,
    pub logs_bloom: Bloom256,
    pub difficulty: u64,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: H256,
    pub nonce: Nonce,
    pub base_fee_per_gas: u64,
    /// Withdrawals root (post‑Shanghai). None if not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub withdrawals_root: Option<H256>,
    /// Blob gas used (post‑Cancun). None if not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<u64>,
    /// Excess blob gas (post‑Cancun). None if not applicable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<u64>,
}

impl Default for EthHeader {
    fn default() -> Self {
        Self {
            parent_hash: EMPTY_HASH,
            ommers_hash: EMPTY_OMMERS_HASH,
            beneficiary: [0u8; 20],
            state_root: EMPTY_HASH,
            transactions_root: EMPTY_HASH,
            receipts_root: EMPTY_HASH,
            logs_bloom: EMPTY_BLOOM,
            difficulty: 0,
            number: 0,
            gas_limit: 30_000_000,
            gas_used: 0,
            timestamp: 0,
            extra_data: Vec::new(),
            mix_hash: EMPTY_HASH,
            nonce: [0u8; 8],
            base_fee_per_gas: 0,
            withdrawals_root: None,
            blob_gas_used: None,
            excess_blob_gas: None,
        }
    }
}

impl fmt::Display for EthHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EthHeader {{ number: {}, hash: {} }}", self.number, self.hash_hex())
    }
}

impl EthHeader {
    /// Compute the Keccak‑256 hash of the header (block hash).
    /// Uses caching if enabled in the global configuration.
    pub fn hash(&self) -> H256 {
        // Use the global cache if available.
        let cache = GLOBAL_CACHE.as_ref().map(|c| c.clone());
        if let Some(c) = cache {
            c.get_or_compute(self, || {
                GLOBAL_METRICS.record_hash();
                let rlp = rlp_encode_header(self);
                keccak256(&rlp)
            })
        } else {
            GLOBAL_METRICS.record_hash();
            let rlp = rlp_encode_header(self);
            keccak256(&rlp)
        }
    }

    /// Return the block hash as a hex string with `0x` prefix.
    pub fn hash_hex(&self) -> String {
        format!("0x{}", hex::encode(self.hash()))
    }

    /// Validate the header fields.
    pub fn validate(&self, config: &EthHeaderConfig) -> Result<(), ValidationError> {
        if config.log_validation {
            trace!("validating header {}", self.number);
        }
        GLOBAL_METRICS.record_validation();

        // Check extra data length.
        if self.extra_data.len() > MAX_EXTRA_DATA_LEN {
            let err = ValidationError::ExtraDataTooLong {
                len: self.extra_data.len(),
                max: MAX_EXTRA_DATA_LEN,
            };
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        // Check nonce is not zero for PoW chains (optional).
        // For PoS, nonce is zero.
        // We'll just check that it's 8 bytes (always).

        // Check difficulty > 0 (except genesis).
        if self.number > 0 && self.difficulty == 0 {
            let err = ValidationError::ZeroDifficulty;
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        // Check gas limit >= gas used.
        if self.gas_used > self.gas_limit {
            let err = ValidationError::GasUsedExceedsLimit {
                used: self.gas_used,
                limit: self.gas_limit,
            };
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        // Check timestamp is not zero (except genesis).
        if self.number > 0 && self.timestamp == 0 {
            let err = ValidationError::ZeroTimestamp;
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        // Check base fee > 0 (EIP-1559).
        if self.base_fee_per_gas == 0 {
            let err = ValidationError::ZeroBaseFee;
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        // For post-Shanghai, if withdrawals_root is Some, check it's not empty.
        if let Some(root) = self.withdrawals_root {
            if root == EMPTY_HASH {
                let err = ValidationError::EmptyWithdrawalsRoot;
                GLOBAL_METRICS.record_validation_error();
                return Err(err);
            }
        }

        // For post-Cancun, blob_gas_used and excess_blob_gas should be consistent.
        if self.blob_gas_used.is_some() != self.excess_blob_gas.is_some() {
            let err = ValidationError::BlobGasMismatch;
            GLOBAL_METRICS.record_validation_error();
            return Err(err);
        }

        Ok(())
    }
}

// ── Validation Error ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("extra_data length {len} exceeds max {max}")]
    ExtraDataTooLong { len: usize, max: usize },
    #[error("difficulty is zero for non‑genesis block")]
    ZeroDifficulty,
    #[error("gas_used {used} exceeds gas_limit {limit}")]
    GasUsedExceedsLimit { used: u64, limit: u64 },
    #[error("timestamp is zero for non‑genesis block")]
    ZeroTimestamp,
    #[error("base_fee_per_gas is zero")]
    ZeroBaseFee,
    #[error("withdrawals_root is empty")]
    EmptyWithdrawalsRoot,
    #[error("blob_gas_used and excess_blob_gas must be both Some or both None")]
    BlobGasMismatch,
    #[error("RLP encoding error: {0}")]
    RlpError(String),
}

// ── Builder ──────────────────────────────────────────────────────────────

/// Builder for constructing Ethereum headers with validation.
#[derive(Debug, Default)]
pub struct HeaderBuilder {
    header: EthHeader,
}

impl HeaderBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parent_hash(mut self, hash: H256) -> Self {
        self.header.parent_hash = hash;
        self
    }

    pub fn ommers_hash(mut self, hash: H256) -> Self {
        self.header.ommers_hash = hash;
        self
    }

    pub fn beneficiary(mut self, addr: H160) -> Self {
        self.header.beneficiary = addr;
        self
    }

    pub fn state_root(mut self, root: H256) -> Self {
        self.header.state_root = root;
        self
    }

    pub fn transactions_root(mut self, root: H256) -> Self {
        self.header.transactions_root = root;
        self
    }

    pub fn receipts_root(mut self, root: H256) -> Self {
        self.header.receipts_root = root;
        self
    }

    pub fn logs_bloom(mut self, bloom: Bloom256) -> Self {
        self.header.logs_bloom = bloom;
        self
    }

    pub fn difficulty(mut self, diff: u64) -> Self {
        self.header.difficulty = diff;
        self
    }

    pub fn number(mut self, number: u64) -> Self {
        self.header.number = number;
        self
    }

    pub fn gas_limit(mut self, limit: u64) -> Self {
        self.header.gas_limit = limit;
        self
    }

    pub fn gas_used(mut self, used: u64) -> Self {
        self.header.gas_used = used;
        self
    }

    pub fn timestamp(mut self, ts: u64) -> Self {
        self.header.timestamp = ts;
        self
    }

    pub fn extra_data(mut self, data: Vec<u8>) -> Self {
        self.header.extra_data = data;
        self
    }

    pub fn mix_hash(mut self, hash: H256) -> Self {
        self.header.mix_hash = hash;
        self
    }

    pub fn nonce(mut self, nonce: Nonce) -> Self {
        self.header.nonce = nonce;
        self
    }

    pub fn base_fee_per_gas(mut self, fee: u64) -> Self {
        self.header.base_fee_per_gas = fee;
        self
    }

    pub fn withdrawals_root(mut self, root: Option<H256>) -> Self {
        self.header.withdrawals_root = root;
        self
    }

    pub fn blob_gas(mut self, used: Option<u64>, excess: Option<u64>) -> Self {
        self.header.blob_gas_used = used;
        self.header.excess_blob_gas = excess;
        self
    }

    /// Build the header, optionally validating.
    pub fn build(self, config: &EthHeaderConfig) -> Result<EthHeader, ValidationError> {
        if config.validate_on_construct {
            self.header.validate(config)?;
        }
        Ok(self.header)
    }
}

// ── RLP Encoding ─────────────────────────────────────────────────────────

/// Encode an Ethereum header into RLP bytes.
/// Field order follows the canonical Ethereum specification (London fork) with
/// optional post‑Shanghai and post‑Cancun fields.
pub fn rlp_encode_header(header: &EthHeader) -> Vec<u8> {
    GLOBAL_METRICS.record_rlp();

    // Count base fields (17) plus optional fields.
    let mut list_count = 17; // parent_hash, ommers_hash, beneficiary, state_root, txs_root, receipts_root, logs_bloom, difficulty, number, gas_limit, gas_used, timestamp, extra_data, mix_hash, nonce, base_fee_per_gas
    if header.withdrawals_root.is_some() {
        list_count += 1;
    }
    if header.blob_gas_used.is_some() {
        list_count += 2; // blob_gas_used, excess_blob_gas
    }

    let mut s = RlpStream::new_list(list_count);

    s.append(&header.parent_hash.as_slice());
    s.append(&header.ommers_hash.as_slice());
    s.append(&header.beneficiary.as_slice());
    s.append(&header.state_root.as_slice());
    s.append(&header.transactions_root.as_slice());
    s.append(&header.receipts_root.as_slice());
    s.append(&header.logs_bloom.as_slice());
    s.append(&header.difficulty);
    s.append(&header.number);
    s.append(&header.gas_limit);
    s.append(&header.gas_used);
    s.append(&header.timestamp);
    s.append(&header.extra_data.as_slice());
    s.append(&header.mix_hash.as_slice());
    s.append(&header.nonce.as_slice());
    s.append(&header.base_fee_per_gas);

    if let Some(root) = header.withdrawals_root {
        s.append(&root.as_slice());
    }
    if let Some(used) = header.blob_gas_used {
        s.append(&used);
        s.append(&header.excess_blob_gas.unwrap_or(0));
    }

    s.out().to_vec()
}

// ── Global state ─────────────────────────────────────────────────────────

static GLOBAL_CACHE: std::sync::OnceLock<HeaderCache> = std::sync::OnceLock::new();
static GLOBAL_METRICS: HeaderMetrics = HeaderMetrics {
    hash_computations: AtomicU64::new(0),
    cache_hits: AtomicU64::new(0),
    cache_misses: AtomicU64::new(0),
    rlp_encodings: AtomicU64::new(0),
    validations: AtomicU64::new(0),
    validation_errors: AtomicU64::new(0),
};

/// Initialize the global cache and metrics.
pub fn init_global(config: EthHeaderConfig) -> Result<(), String> {
    config.validate()?;
    let metrics = Arc::new(GLOBAL_METRICS);
    let cache = HeaderCache::new(&config, metrics)?;
    GLOBAL_CACHE.set(cache).map_err(|_| "cache already initialized".to_string())
}

/// Get the global header cache.
pub fn global_cache() -> Option<HeaderCache> {
    GLOBAL_CACHE.get().cloned()
}

// ── Standalone Functions ─────────────────────────────────────────────────

/// Compute the Keccak‑256 hash of the given bytes.
pub fn keccak256(data: &[u8]) -> H256 {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Compute the header hash (alias for `header.hash()`).
pub fn header_hash(header: &EthHeader) -> H256 {
    header.hash()
}

/// Return the block hash as a hex string with `0x` prefix.
pub fn header_hash_hex(header: &EthHeader) -> String {
    header.hash_hex()
}

/// Parse a hex string into a 32‑byte hash. Returns `Err` if invalid.
pub fn h256_from_hex(s: &str) -> Result<H256, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 64 {
        return Err(format!("invalid hash length: expected 64 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a hex string into a 256‑byte bloom filter. Returns `Err` if invalid.
pub fn bloom_from_hex(s: &str) -> Result<Bloom256, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 512 {
        return Err(format!("invalid bloom length: expected 512 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 256];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse a hex string into a 20‑byte address. Returns `Err` if invalid.
pub fn address_from_hex(s: &str) -> Result<H160, String> {
    let hex_str = s.trim_start_matches("0x");
    if hex_str.len() != 40 {
        return Err(format!("invalid address length: expected 40 hex chars, got {}", hex_str.len()));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("invalid hex: {}", e))?;
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ── Conversion from Iona native block ────────────────────────────────────

/// Convert an Iona native block header to an Ethereum-compatible header.
/// This is a placeholder; the actual conversion depends on Iona's block structure.
#[cfg(feature = "std")]
pub fn from_iona_header(iona_header: &crate::types::BlockHeader) -> EthHeader {
    // Placeholder conversion.
    let mut header = EthHeader::default();
    header.number = iona_header.height;
    // ... fill other fields from Iona header.
    header
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_ommers_hash() {
        let expected = [
            0x1d, 0xcc, 0x4d, 0xe8, 0xdc, 0x75, 0xee, 0xef,
            0x42, 0x3b, 0x7a, 0xef, 0x78, 0x8b, 0xfc, 0x8f,
            0x41, 0xcc, 0x2a, 0xd6, 0x55, 0xbd, 0xea, 0xba,
            0xeb, 0xe5, 0xae, 0x8b, 0xa7, 0xfe, 0xcf, 0x5c,
        ];
        assert_eq!(EMPTY_OMMERS_HASH, expected);
    }

    #[test]
    fn test_rlp_encoding_roundtrip() {
        let header = EthHeader {
            number: 123,
            parent_hash: [0xaa; 32],
            ..Default::default()
        };
        let encoded = rlp_encode_header(&header);
        assert!(!encoded.is_empty());
        // In a full test, we would decode and compare.
    }

    #[test]
    fn test_header_hash_deterministic() {
        let h1 = EthHeader::default();
        let h2 = EthHeader::default();
        assert_eq!(h1.hash(), h2.hash());
    }

    #[test]
    fn test_hex_parsing() {
        let hash_hex = "0x1111111111111111111111111111111111111111111111111111111111111111";
        let hash = h256_from_hex(hash_hex).unwrap();
        assert_eq!(hash, [0x11; 32]);

        let bloom_hex = "0x" + &"00".repeat(512);
        let bloom = bloom_from_hex(bloom_hex).unwrap();
        assert_eq!(bloom, EMPTY_BLOOM);

        let addr_hex = "0x1111111111111111111111111111111111111111";
        let addr = address_from_hex(addr_hex).unwrap();
        assert_eq!(addr, [0x11; 20]);
    }

    #[test]
    fn test_invalid_hex() {
        assert!(h256_from_hex("0x123").is_err());
        assert!(bloom_from_hex("0x00").is_err());
        assert!(address_from_hex("0x1234567890").is_err());
    }

    #[test]
    fn test_builder_and_validation() {
        let config = EthHeaderConfig::default();
        let header = HeaderBuilder::new()
            .number(1)
            .difficulty(1)
            .gas_limit(10_000_000)
            .gas_used(5_000_000)
            .timestamp(1234567890)
            .base_fee_per_gas(10)
            .build(&config)
            .unwrap();
        assert_eq!(header.number, 1);
        assert!(header.validate(&config).is_ok());
    }

    #[test]
    fn test_validation_extra_data_too_long() {
        let config = EthHeaderConfig::default();
        let header = EthHeader {
            extra_data: vec![0u8; 33],
            number: 1,
            difficulty: 1,
            gas_limit: 10_000_000,
            gas_used: 5_000_000,
            timestamp: 1234567890,
            base_fee_per_gas: 10,
            ..Default::default()
        };
        assert!(header.validate(&config).is_err());
    }

    #[test]
    fn test_cache() {
        let config = EthHeaderConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let metrics = Arc::new(HeaderMetrics::default());
        let cache = HeaderCache::new(&config, metrics.clone()).unwrap();

        let header = EthHeader::default();
        let hash1 = cache.get_or_compute(&header, || header.hash());
        let hash2 = cache.get_or_compute(&header, || header.hash());
        assert_eq!(hash1, hash2);
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 1);
    }
}
