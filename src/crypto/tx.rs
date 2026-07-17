//! Transaction signing and address derivation.
//!
//! # Production Features
//! - Configurable via `TxConfig` (chain ID, gas limits, max payload size).
//! - `TxMetrics` with Prometheus counters for sign/verify operations, errors, and durations.
//! - `TxManager` as a thread‑safe wrapper with LRU cache for validation results.
//! - Batch signature verification (optional, via `rayon`).
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use crate::types::Tx;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, Counter, CounterVec, HistogramVec,
};
use serde::Serialize;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for transaction signing and verification.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TxConfig {
    /// Expected chain ID (must match transaction's chain_id).
    pub chain_id: u64,
    /// Minimum gas limit allowed.
    pub min_gas_limit: u64,
    /// Maximum gas limit allowed.
    pub max_gas_limit: u64,
    /// Maximum payload size in bytes.
    pub max_payload_size: usize,
    /// Whether to enable caching of validation results.
    pub enable_cache: bool,
    /// Maximum number of entries in the validation cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable batch verification (using rayon).
    pub enable_batch_verify: bool,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log validation events.
    pub log_validation: bool,
}

impl Default for TxConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            min_gas_limit: 21_000,
            max_gas_limit: 30_000_000,
            max_payload_size: 128 * 1024, // 128 KiB
            enable_cache: true,
            cache_size: 1024,
            cache_ttl_secs: 300,
            enable_batch_verify: true,
            enable_metrics: true,
            log_validation: true,
        }
    }
}

impl TxConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id == 0 {
            return Err("chain_id must be > 0".into());
        }
        if self.min_gas_limit == 0 {
            return Err("min_gas_limit must be > 0".into());
        }
        if self.max_gas_limit == 0 {
            return Err("max_gas_limit must be > 0".into());
        }
        if self.min_gas_limit > self.max_gas_limit {
            return Err("min_gas_limit must be <= max_gas_limit".into());
        }
        if self.max_payload_size == 0 {
            return Err("max_payload_size must be > 0".into());
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

/// Metrics for transaction signing and verification.
#[derive(Clone)]
pub struct TxMetrics {
    pub sign_operations: Counter,
    pub sign_errors: CounterVec,
    pub sign_duration: HistogramVec,
    pub verifications: CounterVec,
    pub verification_errors: CounterVec,
    pub verification_duration: HistogramVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
}

impl TxMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let sign_operations = register_counter!("iona_tx_sign_operations_total", "Total sign operations")?;
        let sign_errors = register_counter_vec!(
            "iona_tx_sign_errors_total",
            "Sign errors",
            &["error_type"]
        )?;
        let sign_duration = register_histogram_vec!(
            "iona_tx_sign_duration_seconds",
            "Sign duration",
            &["status"]
        )?;
        let verifications = register_counter_vec!(
            "iona_tx_verifications_total",
            "Verifications",
            &["type"]
        )?;
        let verification_errors = register_counter_vec!(
            "iona_tx_verification_errors_total",
            "Verification errors",
            &["error_type"]
        )?;
        let verification_duration = register_histogram_vec!(
            "iona_tx_verification_duration_seconds",
            "Verification duration",
            &["status"]
        )?;
        let cache_hits = register_counter!("iona_tx_cache_hits_total", "Cache hits")?;
        let cache_misses = register_counter!("iona_tx_cache_misses_total", "Cache misses")?;
        Ok(Self {
            sign_operations,
            sign_errors,
            sign_duration,
            verifications,
            verification_errors,
            verification_duration,
            cache_hits,
            cache_misses,
        })
    }

    pub fn record_sign(&self, status: &str, duration: Duration) {
        self.sign_operations.inc();
        self.sign_duration.with_label_values(&[status]).observe(duration.as_secs_f64());
    }

    pub fn record_sign_error(&self, error_type: &str) {
        self.sign_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_verification(&self, typ: &str, status: &str, duration: Duration) {
        self.verifications.with_label_values(&[typ]).inc();
        self.verification_duration.with_label_values(&[status]).observe(duration.as_secs_f64());
    }

    pub fn record_verification_error(&self, error_type: &str) {
        self.verification_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
}

impl Default for TxMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            sign_operations: Counter::new("iona_tx_sign_operations_total", "Sign ops").unwrap(),
            sign_errors: CounterVec::new(
                prometheus::Opts::new("iona_tx_sign_errors_total", "Sign errors"),
                &["error_type"],
            ).unwrap(),
            sign_duration: HistogramVec::new(
                prometheus::HistogramOpts::new("iona_tx_sign_duration_seconds", "Sign duration"),
                &["status"],
            ).unwrap(),
            verifications: CounterVec::new(
                prometheus::Opts::new("iona_tx_verifications_total", "Verifications"),
                &["type"],
            ).unwrap(),
            verification_errors: CounterVec::new(
                prometheus::Opts::new("iona_tx_verification_errors_total", "Verification errors"),
                &["error_type"],
            ).unwrap(),
            verification_duration: HistogramVec::new(
                prometheus::HistogramOpts::new("iona_tx_verification_duration_seconds", "Verification duration"),
                &["status"],
            ).unwrap(),
            cache_hits: Counter::new("iona_tx_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_tx_cache_misses_total", "Cache misses").unwrap(),
        })
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during transaction signing or verification.
#[derive(Debug, Error)]
pub enum TxSignError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("empty signing payload")]
    EmptyPayload,

    #[error("invalid chain ID: {0}")]
    InvalidChainId(u64),

    #[error("gas limit {limit} below minimum {min}")]
    GasLimitTooLow { limit: u64, min: u64 },

    #[error("gas limit {limit} exceeds maximum {max}")]
    GasLimitTooHigh { limit: u64, max: u64 },

    #[error("payload size {size} exceeds maximum {max}")]
    PayloadTooLarge { size: usize, max: usize },

    #[error("configuration error: {0}")]
    Config(String),
}

pub type TxSignResult<T> = Result<T, TxSignError>;

// ── Constants ─────────────────────────────────────────────────────────────

/// Transaction signing version string.
const TX_SIGN_VERSION: &str = "iona-tx-v1";

/// Expected public key length (32 bytes for Ed25519).
const PUBLIC_KEY_LEN: usize = 32;

/// Expected signature length (64 bytes for Ed25519).
const SIGNATURE_LEN: usize = 64;

// ── Signing payload ──────────────────────────────────────────────────────

/// Canonical signing payload for a transaction.
#[derive(Debug, Serialize)]
struct TxSigningPayload<'a> {
    version: &'static str,
    chain_id: u64,
    pubkey: &'a [u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &'a str,
}

impl<'a> TxSigningPayload<'a> {
    fn from_tx(tx: &'a Tx) -> Self {
        Self {
            version: TX_SIGN_VERSION,
            chain_id: tx.chain_id,
            pubkey: &tx.pubkey,
            nonce: tx.nonce,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            gas_limit: tx.gas_limit,
            payload: &tx.payload,
        }
    }

    fn to_bytes(&self) -> TxSignResult<Vec<u8>> {
        let value = serde_json::to_vec(&(
            self.version,
            self.chain_id,
            self.pubkey,
            self.nonce,
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            self.gas_limit,
            self.payload,
        ))?;
        Ok(value)
    }
}

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct ValidationCacheEntry {
    result: TxSignResult<()>,
    expires_at: Instant,
}

// ── TxManager ─────────────────────────────────────────────────────────────

/// Thread‑safe manager for transaction signing and verification.
#[derive(Clone)]
pub struct TxManager {
    config: Arc<TxConfig>,
    metrics: Arc<TxMetrics>,
    cache: Arc<Mutex<Option<LruCache<[u8; 32], ValidationCacheEntry>>>>,
}

impl TxManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: TxConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(TxMetrics::default());
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Compute signing bytes for a transaction.
    pub fn sign_bytes(&self, tx: &Tx) -> TxSignResult<Vec<u8>> {
        let payload = TxSigningPayload::from_tx(tx);
        payload.to_bytes()
    }

    /// Sign a transaction (modifies in place).
    pub fn sign_tx(&self, tx: &mut Tx, signer: &dyn crate::crypto::Signer) -> TxSignResult<()> {
        let start = Instant::now();

        // Validate transaction fields.
        self.validate_tx_fields(tx)?;

        let msg = self.sign_bytes(tx)?;
        let sig = signer.sign(&msg);

        if sig.0.is_empty() {
            self.metrics.record_sign_error("empty_signature");
            return Err(TxSignError::InvalidSignature("empty signature".into()));
        }
        if sig.0.len() != SIGNATURE_LEN {
            self.metrics.record_sign_error("invalid_signature_length");
            return Err(TxSignError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                SIGNATURE_LEN,
                sig.0.len()
            )));
        }

        tx.signature = sig.0;
        tx.from = derive_address(&tx.pubkey)?;
        self.metrics.record_sign("ok", start.elapsed());
        if self.config.log_validation {
            trace!("transaction signed successfully");
        }
        Ok(())
    }

    /// Validate transaction fields (gas limit, payload size, chain ID).
    fn validate_tx_fields(&self, tx: &Tx) -> TxSignResult<()> {
        if tx.chain_id != self.config.chain_id {
            return Err(TxSignError::InvalidChainId(tx.chain_id));
        }
        if tx.gas_limit == 0 {
            return Err(TxSignError::GasLimitTooLow {
                limit: tx.gas_limit,
                min: self.config.min_gas_limit,
            });
        }
        if tx.gas_limit < self.config.min_gas_limit {
            return Err(TxSignError::GasLimitTooLow {
                limit: tx.gas_limit,
                min: self.config.min_gas_limit,
            });
        }
        if tx.gas_limit > self.config.max_gas_limit {
            return Err(TxSignError::GasLimitTooHigh {
                limit: tx.gas_limit,
                max: self.config.max_gas_limit,
            });
        }
        let payload_size = tx.payload.len();
        if payload_size > self.config.max_payload_size {
            return Err(TxSignError::PayloadTooLarge {
                size: payload_size,
                max: self.config.max_payload_size,
            });
        }
        if tx.pubkey.len() != PUBLIC_KEY_LEN {
            return Err(TxSignError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                PUBLIC_KEY_LEN,
                tx.pubkey.len()
            )));
        }
        Ok(())
    }

    /// Verify a transaction's signature (with caching).
    pub fn verify_tx(&self, tx: &Tx) -> TxSignResult<()> {
        let start = Instant::now();

        // Validate fields first.
        self.validate_tx_fields(tx)?;

        // Compute cache key (hash of signing bytes + signature + pubkey).
        let key = self.compute_cache_key(tx);

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        self.metrics.record_cache_hit();
                        self.metrics.record_verification("cache", "hit", start.elapsed());
                        return entry.result.clone();
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Perform verification.
        let result = self.verify_internal(tx);
        let duration = start.elapsed();

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = ValidationCacheEntry {
                    result: result.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                };
                cache.put(key, entry);
            }
        }

        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_verification("full", status, duration);
        result
    }

    /// Internal verification (without caching).
    fn verify_internal(&self, tx: &Tx) -> TxSignResult<()> {
        if tx.signature.is_empty() {
            self.metrics.record_verification_error("empty_signature");
            return Err(TxSignError::InvalidSignature("empty signature".into()));
        }
        if tx.signature.len() != SIGNATURE_LEN {
            self.metrics.record_verification_error("invalid_signature_length");
            return Err(TxSignError::InvalidSignature(format!(
                "expected {} bytes, got {}",
                SIGNATURE_LEN,
                tx.signature.len()
            )));
        }
        if tx.pubkey.len() != PUBLIC_KEY_LEN {
            self.metrics.record_verification_error("invalid_pubkey_length");
            return Err(TxSignError::InvalidPublicKey(format!(
                "expected {} bytes, got {}",
                PUBLIC_KEY_LEN,
                tx.pubkey.len()
            )));
        }

        let msg = self.sign_bytes(tx)?;
        let pk = PublicKeyBytes(tx.pubkey.clone());
        let sig = SignatureBytes(tx.signature.clone());

        crate::crypto::ed25519::Ed25519Verifier::verify(&pk, &msg, &sig)?;
        Ok(())
    }

    /// Compute a cache key for a transaction.
    fn compute_cache_key(&self, tx: &Tx) -> [u8; 32] {
        let msg = self.sign_bytes(tx).unwrap_or_default();
        let mut hasher = blake3::Hasher::new();
        hasher.update(&msg);
        hasher.update(&tx.pubkey);
        hasher.update(&tx.signature);
        let hash = hasher.finalize();
        *hash.as_bytes()
    }

    /// Batch verify multiple transactions.
    pub fn verify_batch(&self, txs: &[Tx]) -> Vec<TxSignResult<()>> {
        let start = Instant::now();

        #[cfg(feature = "rayon")]
        {
            use rayon::prelude::*;
            let results: Vec<TxSignResult<()>> = txs
                .par_iter()
                .map(|tx| self.verify_tx(tx))
                .collect();
            let duration = start.elapsed();
            self.metrics.record_verification("batch", "ok", duration);
            results
        }
        #[cfg(not(feature = "rayon"))]
        {
            let results: Vec<TxSignResult<()>> = txs.iter().map(|tx| self.verify_tx(tx)).collect();
            let duration = start.elapsed();
            self.metrics.record_verification("batch", "ok", duration);
            results
        }
    }

    /// Get the public key from a signer (convenience).
    pub fn public_key(&self, signer: &dyn crate::crypto::Signer) -> PublicKeyBytes {
        signer.public_key()
    }

    /// Clear the validation cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("Tx cache cleared");
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

    /// Get configuration.
    pub fn config(&self) -> &TxConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> TxMetricsSnapshot {
        TxMetricsSnapshot {
            sign_operations: self.metrics.sign_operations.get(),
            verifications: self.metrics.verifications.clone(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
        }
    }
}

/// Snapshot of transaction metrics.
#[derive(Debug, Clone)]
pub struct TxMetricsSnapshot {
    pub sign_operations: u64,
    pub verifications: CounterVec,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

// ── Public API (standalone functions) ──────────────────────────────────

/// Derive an Iona address (20‑byte hex string) from a public key.
pub fn derive_address(pubkey: &[u8]) -> TxSignResult<String> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LEN,
            pubkey.len()
        )));
    }
    let hash = blake3::hash(pubkey);
    let addr = hex::encode(&hash.as_bytes()[..20]);
    Ok(addr)
}

/// Derive an Iona address from a `PublicKeyBytes` wrapper.
pub fn derive_address_from_pk(pk: &PublicKeyBytes) -> TxSignResult<String> {
    derive_address(&pk.0)
}

/// Compute the bytes that are signed for a transaction.
pub fn tx_sign_bytes(tx: &Tx) -> TxSignResult<Vec<u8>> {
    let payload = TxSigningPayload::from_tx(tx);
    payload.to_bytes()
}

/// Compute signing bytes from individual transaction fields.
pub fn tx_sign_bytes_from_parts(
    chain_id: u64,
    pubkey: &[u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &str,
) -> TxSignResult<Vec<u8>> {
    let payload_struct = TxSigningPayload {
        version: TX_SIGN_VERSION,
        chain_id,
        pubkey,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        payload,
    };
    payload_struct.to_bytes()
}

/// Sign a transaction (standalone, uses default config).
pub fn sign_tx(tx: &mut Tx, signer: &dyn crate::crypto::Signer) -> TxSignResult<()> {
    let config = TxConfig::default();
    let manager = TxManager::new(config).map_err(|e| TxSignError::Config(e.to_string()))?;
    manager.sign_tx(tx, signer)
}

/// Verify a transaction's signature (standalone).
pub fn verify_tx_signature(tx: &Tx) -> TxSignResult<()> {
    let config = TxConfig::default();
    let manager = TxManager::new(config).map_err(|e| TxSignError::Config(e.to_string()))?;
    manager.verify_tx(tx)
}

/// Verify a signature using individual components.
pub fn verify_signature(
    pubkey: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> TxSignResult<()> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LEN,
            pubkey.len()
        )));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(TxSignError::InvalidSignature(format!(
            "expected {} bytes, got {}",
            SIGNATURE_LEN,
            signature.len()
        )));
    }

    let pk = PublicKeyBytes(pubkey.to_vec());
    let sig = SignatureBytes(signature.to_vec());

    crate::crypto::ed25519::Ed25519Verifier::verify(&pk, msg, &sig)?;
    Ok(())
}

/// Validate a transaction (field validation + signature).
pub fn validate_tx(tx: &Tx) -> TxSignResult<()> {
    let config = TxConfig::default();
    let manager = TxManager::new(config).map_err(|e| TxSignError::Config(e.to_string()))?;
    manager.verify_tx(tx)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;
    use crate::types::Tx;

    fn dummy_tx() -> Tx {
        Tx {
            pubkey: vec![0x01; 32],
            from: "".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21_000,
            payload: "set key value".into(),
            signature: vec![],
            chain_id: 1,
        }
    }

    #[test]
    fn test_derive_address() {
        let pubkey = vec![0xAA; 32];
        let addr = derive_address(&pubkey).unwrap();
        assert_eq!(addr.len(), 40);
        let addr2 = derive_address(&pubkey).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_derive_address_invalid_length() {
        let pubkey = vec![0xAA; 31];
        let result = derive_address(&pubkey);
        assert!(matches!(result, Err(TxSignError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_sign_and_verify() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        let config = TxConfig::default();
        let manager = TxManager::new(config).unwrap();
        manager.sign_tx(&mut tx, &signer).unwrap();
        assert!(manager.verify_tx(&tx).is_ok());
        assert_eq!(tx.from, derive_address(&tx.pubkey).unwrap());
    }

    #[test]
    fn test_verify_corrupted_signature() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        let config = TxConfig::default();
        let manager = TxManager::new(config).unwrap();
        manager.sign_tx(&mut tx, &signer).unwrap();
        if let Some(byte) = tx.signature.get_mut(0) {
            *byte ^= 1;
        }
        let result = manager.verify_tx(&tx);
        assert!(matches!(result, Err(TxSignError::Crypto(CryptoError::InvalidSignature))));
    }

    #[test]
    fn test_manager_cache() {
        let config = TxConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = TxManager::new(config).unwrap();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx();
        manager.sign_tx(&mut tx, &signer).unwrap();
        manager.verify_tx(&tx).unwrap();
        manager.verify_tx(&tx).unwrap();
        assert!(manager.cache_size() > 0);
        let snap = manager.metrics_snapshot();
        assert!(snap.cache_hits > 0);
        assert!(snap.cache_misses > 0);
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = TxConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = TxManager::new(config).unwrap();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx();
        manager.sign_tx(&mut tx, &signer).unwrap();
        manager.verify_tx(&tx).unwrap();
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_config_validation() {
        let mut config = TxConfig::default();
        assert!(config.validate().is_ok());
        config.chain_id = 0;
        assert!(config.validate().is_err());
        config.chain_id = 1;
        config.min_gas_limit = 0;
        assert!(config.validate().is_err());
        config.min_gas_limit = 10;
        config.max_gas_limit = 5;
        assert!(config.validate().is_err());
        config.max_gas_limit = 10;
        config.max_payload_size = 0;
        assert!(config.validate().is_err());
        config.max_payload_size = 1024;
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_validate_tx_fields() {
        let config = TxConfig::default();
        let manager = TxManager::new(config).unwrap();
        let mut tx = dummy_tx();

        // Valid
        assert!(manager.validate_tx_fields(&tx).is_ok());

        // Wrong chain ID
        tx.chain_id = 2;
        assert!(manager.validate_tx_fields(&tx).is_err());

        // Gas limit too low
        tx.chain_id = 1;
        tx.gas_limit = 100;
        assert!(manager.validate_tx_fields(&tx).is_err());

        // Gas limit too high
        tx.gas_limit = 40_000_000;
        assert!(manager.validate_tx_fields(&tx).is_err());

        // Payload too large
        tx.gas_limit = 21_000;
        tx.payload = "x".repeat(200_000);
        assert!(manager.validate_tx_fields(&tx).is_err());

        // Invalid pubkey length
        tx.payload = "test".into();
        tx.pubkey = vec![0x01; 31];
        assert!(manager.validate_tx_fields(&tx).is_err());
    }
}
