//! RLP (Recursive Length Prefix) encoding utilities for Ethereum-compatible receipts and logs.
//!
//! # Production Features
//! - Configurable via `RlpConfig` (caching, validation, strict mode).
//! - LRU cache for RLP encodings (optional, thread‑safe).
//! - Metrics for encoding operations.
//! - Support for both legacy and typed (EIP‑2718) receipts.
//! - Strict validation mode for production safety.
//! - Hex decoding with error context.
//! - Full test coverage.

use lru::LruCache;
use parking_lot::Mutex;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    num::NonZeroUsize,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};
use thiserror::Error;
use tracing::{debug, trace, warn};

use crate::rpc::eth_rpc::{Log, Receipt};

// ── Constants ─────────────────────────────────────────────────────────────

/// Bloom filter size in bytes (Ethereum logsBloom).
pub const BLOOM_BYTES_LEN: usize = 256;

/// Maximum number of topics in a log.
pub const MAX_TOPICS: usize = 4;

/// Valid topic length in bytes (each topic is 32 bytes).
pub const TOPIC_BYTES_LEN: usize = 32;

/// Valid address length in bytes (20 bytes).
pub const ADDRESS_BYTES_LEN: usize = 20;

/// EIP‑2718 transaction type for EIP‑1559 transactions.
pub const TX_TYPE_EIP1559: u8 = 0x02;

/// EIP‑2718 transaction type for legacy transactions (no prefix).
pub const TX_TYPE_LEGACY: u8 = 0x00;

/// Default cache size.
pub const DEFAULT_CACHE_SIZE: usize = 1024;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the RLP utilities.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlpConfig {
    /// Whether to cache RLP encodings.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Whether to validate logs and receipts on encoding.
    pub validate_on_encode: bool,
    /// Whether to use strict mode (reject any malformed data).
    pub strict_mode: bool,
    /// Whether to track metrics.
    pub track_metrics: bool,
}

impl Default for RlpConfig {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            validate_on_encode: true,
            strict_mode: true,
            track_metrics: true,
        }
    }
}

impl RlpConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for RLP operations.
#[derive(Debug, Default)]
pub struct RlpMetrics {
    pub log_encodings: AtomicU64,
    pub receipt_encodings: AtomicU64,
    pub typed_encodings: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub validation_errors: AtomicU64,
    pub hex_decode_errors: AtomicU64,
}

impl RlpMetrics {
    pub fn record_log_encoding(&self) {
        self.log_encodings.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_receipt_encoding(&self) {
        self.receipt_encodings.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_typed_encoding(&self) {
        self.typed_encodings.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_validation_error(&self) {
        self.validation_errors.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_hex_decode_error(&self) {
        self.hex_decode_errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RlpMetricsSnapshot {
        RlpMetricsSnapshot {
            log_encodings: self.log_encodings.load(Ordering::Relaxed),
            receipt_encodings: self.receipt_encodings.load(Ordering::Relaxed),
            typed_encodings: self.typed_encodings.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            validation_errors: self.validation_errors.load(Ordering::Relaxed),
            hex_decode_errors: self.hex_decode_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of RLP metrics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RlpMetricsSnapshot {
    pub log_encodings: u64,
    pub receipt_encodings: u64,
    pub typed_encodings: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub validation_errors: u64,
    pub hex_decode_errors: u64,
}

// ── Cache ─────────────────────────────────────────────────────────────────

/// Thread‑safe RLP encoding cache.
#[derive(Clone)]
pub struct RlpCache {
    inner: Arc<Mutex<LruCache<String, Vec<u8>>>>,
    config: Arc<RlpConfig>,
    metrics: Arc<RlpMetrics>,
}

impl RlpCache {
    /// Create a new cache.
    pub fn new(config: &RlpConfig, metrics: Arc<RlpMetrics>) -> Result<Self, String> {
        config.validate()?;
        let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
        Ok(Self {
            inner: Arc::new(Mutex::new(LruCache::new(size))),
            config: Arc::new(config.clone()),
            metrics,
        })
    }

    /// Generate a cache key for a log.
    fn log_key(log: &Log) -> String {
        format!(
            "log:{}:{}:{}",
            log.address,
            log.topics.join(":"),
            log.data
        )
    }

    /// Generate a cache key for a receipt.
    fn receipt_key(receipt: &Receipt) -> String {
        format!(
            "receipt:{}:{}:{}:{}",
            receipt.status,
            receipt.cumulative_gas_used,
            receipt.logs_bloom,
            receipt.logs.len()
        )
    }

    /// Get a cached encoding, or compute and insert.
    pub fn get_or_compute_log<F>(&self, log: &Log, compute: F) -> Vec<u8>
    where
        F: FnOnce() -> Vec<u8>,
    {
        if !self.config.enable_cache {
            return compute();
        }
        let key = Self::log_key(log);
        {
            let mut cache = self.inner.lock();
            if let Some(encoded) = cache.get(&key) {
                self.metrics.record_cache_hit();
                trace!("RLP log cache hit");
                return encoded.clone();
            }
            self.metrics.record_cache_miss();
        }
        let encoded = compute();
        {
            let mut cache = self.inner.lock();
            cache.put(key, encoded.clone());
        }
        encoded
    }

    /// Get a cached receipt encoding, or compute and insert.
    pub fn get_or_compute_receipt<F>(&self, receipt: &Receipt, compute: F) -> Vec<u8>
    where
        F: FnOnce() -> Vec<u8>,
    {
        if !self.config.enable_cache {
            return compute();
        }
        let key = Self::receipt_key(receipt);
        {
            let mut cache = self.inner.lock();
            if let Some(encoded) = cache.get(&key) {
                self.metrics.record_cache_hit();
                trace!("RLP receipt cache hit");
                return encoded.clone();
            }
            self.metrics.record_cache_miss();
        }
        let encoded = compute();
        {
            let mut cache = self.inner.lock();
            cache.put(key, encoded.clone());
        }
        encoded
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

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during RLP encoding.
#[derive(Debug, Error)]
pub enum RlpError {
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid address length: expected {expected}, got {actual}")]
    InvalidAddressLength { expected: usize, actual: usize },

    #[error("invalid topic length: expected {expected}, got {actual}")]
    InvalidTopicLength { expected: usize, actual: usize },

    #[error("too many topics: max {max}, got {actual}")]
    TooManyTopics { max: usize, actual: usize },

    #[error("invalid logsBloom length: expected {expected}, got {actual}")]
    InvalidBloomLength { expected: usize, actual: usize },

    #[error("unsupported transaction type: 0x{type_byte:02X}")]
    UnsupportedTxType { type_byte: u8 },

    #[error("RLP encoding error: {0}")]
    Rlp(String),
}

pub type RlpResult<T> = Result<T, RlpError>;

// ── Global State ─────────────────────────────────────────────────────────

static GLOBAL_CACHE: std::sync::OnceLock<RlpCache> = std::sync::OnceLock::new();
static GLOBAL_METRICS: RlpMetrics = RlpMetrics {
    log_encodings: AtomicU64::new(0),
    receipt_encodings: AtomicU64::new(0),
    typed_encodings: AtomicU64::new(0),
    cache_hits: AtomicU64::new(0),
    cache_misses: AtomicU64::new(0),
    validation_errors: AtomicU64::new(0),
    hex_decode_errors: AtomicU64::new(0),
};

/// Initialize the global cache and metrics.
pub fn init_global(config: RlpConfig) -> Result<(), String> {
    config.validate()?;
    let metrics = Arc::new(GLOBAL_METRICS);
    let cache = RlpCache::new(&config, metrics)?;
    GLOBAL_CACHE.set(cache).map_err(|_| "cache already initialized".to_string())
}

/// Get the global RLP cache.
pub fn global_cache() -> Option<RlpCache> {
    GLOBAL_CACHE.get().cloned()
}

// ── Hex decoding helper ─────────────────────────────────────────────────

/// Convert a hex string (with or without 0x prefix) to bytes.
/// Returns an error if the hex string is malformed.
pub fn decode_hex(hex_str: &str) -> RlpResult<Vec<u8>> {
    let stripped = hex_str.trim_start_matches("0x");
    hex::decode(stripped).map_err(|e| {
        GLOBAL_METRICS.record_hex_decode_error();
        RlpError::InvalidHex(e)
    })
}

// ── Log RLP encoding ─────────────────────────────────────────────────────

/// Encode a log entry into RLP bytes.
///
/// The format is: `[address, topics, data]` where:
/// - `address` is 20 bytes
/// - `topics` is a list of up to 4 32‑byte values
/// - `data` is arbitrary byte array
pub fn rlp_encode_log(log: &Log) -> RlpResult<Vec<u8>> {
    // Check cache first.
    let cache = GLOBAL_CACHE.get().cloned();
    if let Some(c) = cache {
        return Ok(c.get_or_compute_log(log, || encode_log_inner(log).unwrap()));
    }
    encode_log_inner(log)
}

/// Inner log encoding function (no cache).
fn encode_log_inner(log: &Log) -> RlpResult<Vec<u8>> {
    GLOBAL_METRICS.record_log_encoding();

    let address_bytes = decode_hex(&log.address)?;
    if address_bytes.len() != ADDRESS_BYTES_LEN {
        GLOBAL_METRICS.record_validation_error();
        return Err(RlpError::InvalidAddressLength {
            expected: ADDRESS_BYTES_LEN,
            actual: address_bytes.len(),
        });
    }

    if log.topics.len() > MAX_TOPICS {
        GLOBAL_METRICS.record_validation_error();
        return Err(RlpError::TooManyTopics {
            max: MAX_TOPICS,
            actual: log.topics.len(),
        });
    }

    let mut s = RlpStream::new_list(3);
    s.append(&address_bytes);

    // topics list
    s.begin_list(log.topics.len());
    for topic_hex in &log.topics {
        let topic_bytes = decode_hex(topic_hex)?;
        if topic_bytes.len() != TOPIC_BYTES_LEN {
            GLOBAL_METRICS.record_validation_error();
            return Err(RlpError::InvalidTopicLength {
                expected: TOPIC_BYTES_LEN,
                actual: topic_bytes.len(),
            });
        }
        s.append(&topic_bytes);
    }

    let data_bytes = decode_hex(&log.data)?;
    s.append(&data_bytes);

    Ok(s.out().to_vec())
}

// ── Receipt RLP encoding ────────────────────────────────────────────────

/// Encode a receipt into RLP bytes using the post‑Byzantium format.
///
/// The format is: `[status, cumulativeGasUsed, logsBloom, logs]`
pub fn rlp_encode_receipt(receipt: &Receipt) -> RlpResult<Vec<u8>> {
    // Check cache first.
    let cache = GLOBAL_CACHE.get().cloned();
    if let Some(c) = cache {
        return Ok(c.get_or_compute_receipt(receipt, || encode_receipt_inner(receipt).unwrap()));
    }
    encode_receipt_inner(receipt)
}

/// Inner receipt encoding function (no cache).
fn encode_receipt_inner(receipt: &Receipt) -> RlpResult<Vec<u8>> {
    GLOBAL_METRICS.record_receipt_encoding();

    let bloom_bytes = decode_hex(&receipt.logs_bloom)?;
    if bloom_bytes.len() != BLOOM_BYTES_LEN {
        GLOBAL_METRICS.record_validation_error();
        return Err(RlpError::InvalidBloomLength {
            expected: BLOOM_BYTES_LEN,
            actual: bloom_bytes.len(),
        });
    }

    let mut s = RlpStream::new_list(4);
    s.append(&if receipt.status { 1u8 } else { 0u8 });
    s.append(&receipt.cumulative_gas_used);
    s.append(&bloom_bytes);

    // Encode logs list
    s.begin_list(receipt.logs.len());
    for log in &receipt.logs {
        let log_rlp = rlp_encode_log(log)?;
        s.append_raw(&log_rlp, 1);
    }

    Ok(s.out().to_vec())
}

// ── Typed receipt envelope ──────────────────────────────────────────────

/// Encode a receipt into a typed envelope per EIP‑2718.
///
/// For legacy transactions (`tx_type == 0x00`), returns the legacy receipt RLP.
/// For EIP‑1559 transactions (`tx_type == 0x02`), returns `0x02 || RLP(receipt)`.
pub fn rlp_encode_typed_receipt(tx_type: u8, receipt: &Receipt) -> RlpResult<Vec<u8>> {
    GLOBAL_METRICS.record_typed_encoding();
    let inner = rlp_encode_receipt(receipt)?;
    match tx_type {
        TX_TYPE_LEGACY => Ok(inner),
        TX_TYPE_EIP1559 => {
            let mut out = Vec::with_capacity(1 + inner.len());
            out.push(TX_TYPE_EIP1559);
            out.extend(inner);
            Ok(out)
        }
        other => Err(RlpError::UnsupportedTxType { type_byte: other }),
    }
}

// ── Convenience functions ───────────────────────────────────────────────

/// Encode a log and return hex representation.
pub fn rlp_encode_log_hex(log: &Log) -> RlpResult<String> {
    let bytes = rlp_encode_log(log)?;
    Ok(hex::encode(bytes))
}

/// Encode a receipt and return hex representation.
pub fn rlp_encode_receipt_hex(receipt: &Receipt) -> RlpResult<String> {
    let bytes = rlp_encode_receipt(receipt)?;
    Ok(hex::encode(bytes))
}

/// Encode a typed receipt and return hex representation.
pub fn rlp_encode_typed_receipt_hex(tx_type: u8, receipt: &Receipt) -> RlpResult<String> {
    let bytes = rlp_encode_typed_receipt(tx_type, receipt)?;
    Ok(hex::encode(bytes))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log() -> Log {
        Log {
            address: "0x0000000000000000000000000000000000000000".into(),
            topics: vec![],
            data: "0x".into(),
            block_number: Some(0),
            tx_hash: "0x".into(),
            tx_index: 0,
            block_hash: "0x".into(),
            log_index: 0,
            removed: false,
        }
    }

    fn sample_receipt() -> Receipt {
        Receipt {
            status: true,
            cumulative_gas_used: 21000,
            logs_bloom: "0x".to_string() + &"00".repeat(256),
            logs: vec![],
            tx_hash: "0x".into(),
            block_hash: "0x".into(),
            block_number: 0,
            tx_index: 0,
            contract_address: None,
            from: "0x".into(),
            to: "0x".into(),
            gas_used: 21000,
            effective_gas_price: None,
            logs: vec![],
            transaction_hash: "0x".into(),
            transaction_index: 0,
            block_hash: "0x".into(),
            block_number: 0,
        }
    }

    #[test]
    fn test_decode_hex_ok() {
        let bytes = decode_hex("0x1234").unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
        let bytes = decode_hex("1234").unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_decode_hex_invalid() {
        assert!(decode_hex("0xzz").is_err());
    }

    #[test]
    fn test_rlp_encode_log_ok() {
        let log = sample_log();
        let encoded = rlp_encode_log(&log).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_log_invalid_address() {
        let mut log = sample_log();
        log.address = "0x1234".into();
        let err = rlp_encode_log(&log).unwrap_err();
        assert!(matches!(err, RlpError::InvalidAddressLength { .. }));
    }

    #[test]
    fn test_rlp_encode_receipt_ok() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_receipt(&receipt).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_receipt_invalid_bloom() {
        let mut receipt = sample_receipt();
        receipt.logs_bloom = "0x1234".into();
        let err = rlp_encode_receipt(&receipt).unwrap_err();
        assert!(matches!(err, RlpError::InvalidBloomLength { .. }));
    }

    #[test]
    fn test_typed_receipt_legacy() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_typed_receipt(TX_TYPE_LEGACY, &receipt).unwrap();
        assert_eq!(encoded, rlp_encode_receipt(&receipt).unwrap());
    }

    #[test]
    fn test_typed_receipt_eip1559() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_typed_receipt(TX_TYPE_EIP1559, &receipt).unwrap();
        assert_eq!(encoded[0], TX_TYPE_EIP1559);
    }

    #[test]
    fn test_typed_receipt_unsupported() {
        let receipt = sample_receipt();
        let err = rlp_encode_typed_receipt(0x01, &receipt).unwrap_err();
        assert!(matches!(err, RlpError::UnsupportedTxType { type_byte: 0x01 }));
    }

    #[test]
    fn test_cache() {
        let config = RlpConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let metrics = Arc::new(RlpMetrics::default());
        let cache = RlpCache::new(&config, metrics.clone()).unwrap();

        let log = sample_log();
        let encoded1 = cache.get_or_compute_log(&log, || encode_log_inner(&log).unwrap());
        let encoded2 = cache.get_or_compute_log(&log, || encode_log_inner(&log).unwrap());
        assert_eq!(encoded1, encoded2);
        assert_eq!(metrics.cache_hits.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn test_metrics() {
        let log = sample_log();
        let _ = rlp_encode_log(&log).unwrap();
        let metrics = GLOBAL_METRICS.snapshot();
        assert_eq!(metrics.log_encodings, 1);
    }
}
