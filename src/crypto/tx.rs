//! Transaction signing and address derivation.
//!
//! # Signing model
//!
//! A transaction is signed over a canonical encoding of every field that
//! affects state, **except** `signature` and `from`:
//!
//! ```text
//! version | chain_id | pubkey | nonce | max_fee | max_priority | gas_limit | payload
//! ```
//!
//! `from` is **derived** from `pubkey` ([`derive_address`]) and is not part
//! of the signed payload. [`TxManager::verify_tx`] rejects a transaction
//! whose `from` does not match the address derived from its `pubkey`,
//! closing an authorization-confusion bug where a signature-valid
//! transaction could claim any sender.
//!
//! # `sign_tx` contract
//!
//! [`TxManager::sign_tx`] **overwrites** `tx.pubkey` with
//! `signer.public_key().0` before computing the signing bytes, then
//! derives and sets `tx.from`. A caller cannot end up with a transaction
//! whose signature verifies against a different key than the one it
//! declares.
//!
//! # Cache correctness
//!
//! The verification cache is keyed on `BLAKE3-256(pubkey || signature)`
//! over the canonical tx fields, computed **without** calling
//! `sign_bytes`. Two transactions that differ in any signed field — or in
//! `pubkey` or `signature` — map to distinct cache keys.
//!
//! The cache stores `Result<(), CachedVerifyError>` where
//! `CachedVerifyError` is a `Clone + PartialEq + Eq` enum. The full
//! `TxSignError` cannot be cached because `serde_json::Error` is not
//! `Clone`; the cache stores the failure *category* and a message, and
//! reconstructs the error on hit.
//!
//! # Batch verification
//!
//! [`TxManager::verify_batch`] honours [`TxConfig::enable_batch_verify`]:
//! when `true` **and** the `rayon` feature is compiled in, uncached
//! verifications run in parallel. Cache lookups and inserts happen under
//! the same mutex the parallel verifiers would otherwise contend on, so
//! the implementation performs them **sequentially** (lookup, then
//! parallel verify of misses, then sequential insert). This is faster
//! than serializing every verifier on the cache lock, and correct.
//!
//! # Serialization format
//!
//! The signing payload is a JSON array of the eight fields listed above.
//! Field order is load-bearing: reordering or inserting a field breaks
//! every existing signature. Bump [`TX_SIGN_VERSION`] when the payload
//! changes, and accept both versions during the migration window.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer};
use crate::types::Tx;
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{Counter, CounterVec, HistogramVec};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::trace;

// ── Constants ─────────────────────────────────────────────────────────────

const TX_SIGN_VERSION: &str = "iona-tx-v1";
const PUBLIC_KEY_LEN: usize = 32;
const SIGNATURE_LEN: usize = 64;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for transaction signing and verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TxConfig {
    pub chain_id: u64,
    pub min_gas_limit: u64,
    pub max_gas_limit: u64,
    pub max_payload_size: usize,
    pub enable_cache: bool,
    pub cache_size: usize,
    pub cache_ttl_secs: u64,
    /// Whether [`TxManager::verify_batch`] may use `rayon` parallelism.
    /// Only takes effect when the `rayon` feature is compiled in.
    pub enable_batch_verify: bool,
    pub enable_metrics: bool,
    pub log_validation: bool,
}

impl Default for TxConfig {
    fn default() -> Self {
        Self {
            chain_id: 1,
            min_gas_limit: 21_000,
            max_gas_limit: 30_000_000,
            max_payload_size: 128 * 1024,
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
    pub fn validate(&self) -> Result<(), TxSignError> {
        if self.chain_id == 0 {
            return Err(TxSignError::Config("chain_id must be > 0".into()));
        }
        if self.min_gas_limit == 0 {
            return Err(TxSignError::Config("min_gas_limit must be > 0".into()));
        }
        if self.max_gas_limit == 0 {
            return Err(TxSignError::Config("max_gas_limit must be > 0".into()));
        }
        if self.min_gas_limit > self.max_gas_limit {
            return Err(TxSignError::Config(
                "min_gas_limit must be <= max_gas_limit".into(),
            ));
        }
        if self.max_payload_size == 0 {
            return Err(TxSignError::Config("max_payload_size must be > 0".into()));
        }
        if self.cache_size == 0 {
            return Err(TxSignError::Config("cache_size must be > 0".into()));
        }
        if self.cache_ttl_secs == 0 {
            return Err(TxSignError::Config("cache_ttl_secs must be > 0".into()));
        }
        Ok(())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can occur during transaction signing or verification.
///
/// The `Serialization` variant wraps a `String` (not a
/// `serde_json::Error`) so the enum derives `Clone + PartialEq + Eq` and
/// can be cached. `From<serde_json::Error>` is implemented manually.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum TxSignError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("`from` does not match address derived from pubkey")]
    FromMismatch,

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

impl From<serde_json::Error> for TxSignError {
    fn from(e: serde_json::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

pub type TxSignResult<T> = Result<T, TxSignError>;

/// Compact, `Clone + Eq` error category for the verification cache.
///
/// A cache hit reconstructs a `TxSignError` from this — callers that
/// need the exact error should verify again with caching disabled.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CachedVerifyError {
    InvalidSignature(String),
    InvalidPublicKey(String),
    FromMismatch,
    Other(String),
}

impl CachedVerifyError {
    fn from_tx_error(e: &TxSignError) -> Self {
        match e {
            TxSignError::InvalidSignature(m) => Self::InvalidSignature(m.clone()),
            TxSignError::InvalidPublicKey(m) => Self::InvalidPublicKey(m.clone()),
            TxSignError::FromMismatch => Self::FromMismatch,
            other => Self::Other(other.to_string()),
        }
    }

    fn into_tx_error(self) -> TxSignError {
        match self {
            Self::InvalidSignature(m) => TxSignError::InvalidSignature(m),
            Self::InvalidPublicKey(m) => TxSignError::InvalidPublicKey(m),
            Self::FromMismatch => TxSignError::FromMismatch,
            Self::Other(m) => TxSignError::Config(m),
        }
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for transaction signing and verification.
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
    /// Register with the default Prometheus registry. Succeeds at most
    /// once per process.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            sign_operations: prometheus::register_counter!(
                "iona_tx_sign_operations_total",
                "Total sign operations"
            )?,
            sign_errors: prometheus::register_counter_vec!(
                "iona_tx_sign_errors_total",
                "Sign errors",
                &["error_type"]
            )?,
            sign_duration: prometheus::register_histogram_vec!(
                "iona_tx_sign_duration_seconds",
                "Sign duration",
                &["status"]
            )?,
            verifications: prometheus::register_counter_vec!(
                "iona_tx_verifications_total",
                "Verifications",
                &["type", "status"]
            )?,
            verification_errors: prometheus::register_counter_vec!(
                "iona_tx_verification_errors_total",
                "Verification errors",
                &["error_type"]
            )?,
            verification_duration: prometheus::register_histogram_vec!(
                "iona_tx_verification_duration_seconds",
                "Verification duration",
                &["status"]
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_tx_cache_hits_total",
                "Cache hits"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_tx_cache_misses_total",
                "Cache misses"
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        Self {
            sign_operations: Counter::new("iona_tx_sign_operations_total", "Sign ops")
                .expect("counter construction is infallible"),
            sign_errors: CounterVec::new(
                prometheus::Opts::new("iona_tx_sign_errors_total", "Sign errors"),
                &["error_type"],
            )
            .expect("counter vec construction is infallible"),
            sign_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_tx_sign_duration_seconds",
                    "Sign duration",
                ),
                &["status"],
            )
            .expect("histogram vec construction is infallible"),
            verifications: CounterVec::new(
                prometheus::Opts::new("iona_tx_verifications_total", "Verifications"),
                &["type", "status"],
            )
            .expect("counter vec construction is infallible"),
            verification_errors: CounterVec::new(
                prometheus::Opts::new(
                    "iona_tx_verification_errors_total",
                    "Verification errors",
                ),
                &["error_type"],
            )
            .expect("counter vec construction is infallible"),
            verification_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_tx_verification_duration_seconds",
                    "Verification duration",
                ),
                &["status"],
            )
            .expect("histogram vec construction is infallible"),
            cache_hits: Counter::new("iona_tx_cache_hits_total", "Cache hits")
                .expect("counter construction is infallible"),
            cache_misses: Counter::new("iona_tx_cache_misses_total", "Cache misses")
                .expect("counter construction is infallible"),
        }
    }

    pub fn record_sign(&self, status: &str, duration: Duration) {
        self.sign_operations.inc();
        self.sign_duration
            .with_label_values(&[status])
            .observe(duration.as_secs_f64());
    }

    pub fn record_sign_error(&self, error_type: &str) {
        self.sign_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_verification(&self, typ: &str, status: &str, duration: Duration) {
        self.verifications
            .with_label_values(&[typ, status])
            .inc();
        self.verification_duration
            .with_label_values(&[status])
            .observe(duration.as_secs_f64());
    }

    pub fn record_verification_error(&self, error_type: &str) {
        self.verification_errors
            .with_label_values(&[error_type])
            .inc();
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    /// Owned, serializable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> TxMetricsSnapshot {
        TxMetricsSnapshot {
            sign_operations: self.sign_operations.get(),
            verifications: collect(&self.verifications),
            cache_hits: self.cache_hits.get(),
            cache_misses: self.cache_misses.get(),
        }
    }
}

impl Default for TxMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

/// Owned snapshot of one counter family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub labels: BTreeMap<String, String>,
    pub value: u64,
}

/// Owned snapshot of [`TxMetrics`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxMetricsSnapshot {
    pub sign_operations: u64,
    pub verifications: Vec<CounterSnapshot>,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

fn collect(vec: &CounterVec) -> Vec<CounterSnapshot> {
    let mut out = Vec::new();
    for mf in vec.collect() {
        for m in mf.get_metric() {
            let mut labels = BTreeMap::new();
            for l in m.get_label() {
                labels.insert(l.get_name().to_string(), l.get_value().to_string());
            }
            out.push(CounterSnapshot {
                labels,
                value: m.get_counter().get_value() as u64,
            });
        }
    }
    out.sort_by(|a, b| a.labels.cmp(&b.labels));
    out
}

// ── Signing payload ──────────────────────────────────────────────────────

/// Canonical tuple of the fields covered by the signature.
///
/// **Order is load-bearing.** Reordering, adding, or removing a field
/// invalidates every signature produced by an older binary. Bump
/// [`TX_SIGN_VERSION`] when this changes and accept both versions during
/// the migration window.
fn canonical_payload<'a>(
    version: &'static str,
    chain_id: u64,
    pubkey: &'a [u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &'a str,
) -> TxSignResult<Vec<u8>> {
    // JSON-array encoding. Slow compared to bincode but stable across
    // serde_json versions; the field order is the wire format.
    Ok(serde_json::to_vec(&(
        version,
        chain_id,
        pubkey,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        payload,
    ))?)
}

// ── Cache entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct ValidationCacheEntry {
    result: Result<(), CachedVerifyError>,
    expires_at: Instant,
}

type CacheKey = [u8; 32];

// ── TxManager ─────────────────────────────────────────────────────────────

/// Thread-safe manager for transaction signing and verification.
#[derive(Clone)]
pub struct TxManager {
    config: Arc<TxConfig>,
    metrics: Arc<TxMetrics>,
    cache: Arc<Mutex<Option<LruCache<CacheKey, ValidationCacheEntry>>>>,
}

impl TxManager {
    /// Construct a manager.
    pub fn new(config: TxConfig) -> TxSignResult<Self> {
        config.validate()?;
        let metrics = if config.enable_metrics {
            match TxMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "tx metrics already registered; using unregistered"
                    );
                    TxMetrics::unregistered()
                }
            }
        } else {
            TxMetrics::unregistered()
        };

        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| TxSignError::Config("cache_size must be > 0".into()))?;
            Some(LruCache::new(size))
        } else {
            None
        };

        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Construct with a caller-supplied metrics handle.
    pub fn with_metrics(config: TxConfig, metrics: TxMetrics) -> TxSignResult<Self> {
        config.validate()?;
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or_else(|| TxSignError::Config("cache_size must be > 0".into()))?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Compute the canonical signing bytes for a transaction.
    ///
    /// This is a pure function of the fields listed in the module doc;
    /// it does not depend on `signature` or `from`.
    pub fn sign_bytes(&self, tx: &Tx) -> TxSignResult<Vec<u8>> {
        canonical_payload(
            TX_SIGN_VERSION,
            tx.chain_id,
            &tx.pubkey,
            tx.nonce,
            tx.max_fee_per_gas,
            tx.max_priority_fee_per_gas,
            tx.gas_limit,
            &tx.payload,
        )
    }

    /// Sign a transaction in place.
    ///
    /// # Contract
    ///
    /// - Overwrites `tx.pubkey` with `signer.public_key().0`.
    /// - Overwrites `tx.signature`.
    /// - Overwrites `tx.from` with the address derived from `tx.pubkey`.
    ///
    /// After success, `verify_tx(&tx)` is guaranteed to return `Ok(())`
    /// unless the transaction is later mutated.
    pub fn sign_tx(&self, tx: &mut Tx, signer: &dyn Signer) -> TxSignResult<()> {
        let start = Instant::now();

        // Sync pubkey to the signer. The signature is over the payload
        // containing `pubkey`, and verification uses `pubkey` as the
        // verifying key — they must be the same key.
        tx.pubkey = signer.public_key().0;

        self.validate_tx_fields(tx)?;

        let msg = self.sign_bytes(tx)?;
        let sig = signer.sign(&msg);

        if sig.0.len() != SIGNATURE_LEN {
            self.metrics.record_sign_error("invalid_signature_length");
            return Err(TxSignError::InvalidSignature(format!(
                "expected {SIGNATURE_LEN} bytes, got {}",
                sig.0.len()
            )));
        }

        tx.signature = sig.0;
        tx.from = derive_address(&tx.pubkey)?;

        self.metrics.record_sign("ok", start.elapsed());
        if self.config.log_validation {
            trace!("transaction signed");
        }
        Ok(())
    }

    fn validate_tx_fields(&self, tx: &Tx) -> TxSignResult<()> {
        if tx.chain_id != self.config.chain_id {
            return Err(TxSignError::InvalidChainId(tx.chain_id));
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
        if tx.payload.len() > self.config.max_payload_size {
            return Err(TxSignError::PayloadTooLarge {
                size: tx.payload.len(),
                max: self.config.max_payload_size,
            });
        }
        if tx.pubkey.len() != PUBLIC_KEY_LEN {
            return Err(TxSignError::InvalidPublicKey(format!(
                "expected {PUBLIC_KEY_LEN} bytes, got {}",
                tx.pubkey.len()
            )));
        }
        Ok(())
    }

    /// Verify a transaction's signature. Uses the cache when enabled.
    pub fn verify_tx(&self, tx: &Tx) -> TxSignResult<()> {
        let start = Instant::now();

        self.validate_tx_fields(tx)?;

        let key = self.compute_cache_key(tx);

        // ── Cache lookup ──────────────────────────────────────────────
        if let Some(cache) = self.cache.lock().as_mut() {
            if let Some(entry) = cache.get(&key) {
                if entry.expires_at > Instant::now() {
                    self.metrics.record_cache_hit();
                    self.metrics
                        .record_verification("cache", if entry.result.is_ok() { "ok" } else { "error" }, start.elapsed());
                    return entry.result.clone().map_err(CachedVerifyError::into_tx_error);
                }
                cache.pop(&key);
            }
            self.metrics.record_cache_miss();
        }

        // ── Full verify ───────────────────────────────────────────────
        let result = self.verify_internal(tx);
        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };

        // ── Cache insert ──────────────────────────────────────────────
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.put(
                key,
                ValidationCacheEntry {
                    result: result
                        .as_ref()
                        .map(|_| ())
                        .map_err(CachedVerifyError::from_tx_error),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                },
            );
        }

        self.metrics.record_verification("full", status, duration);
        result
    }

    fn verify_internal(&self, tx: &Tx) -> TxSignResult<()> {
        if tx.signature.len() != SIGNATURE_LEN {
            self.metrics.record_verification_error("invalid_signature_length");
            return Err(TxSignError::InvalidSignature(format!(
                "expected {SIGNATURE_LEN} bytes, got {}",
                tx.signature.len()
            )));
        }

        // `validate_tx_fields` already enforced `tx.pubkey.len() == PUBLIC_KEY_LEN`.

        // Authenticate `from` against `pubkey`. This is not part of the
        // signed payload, so it must be checked explicitly — otherwise a
        // signature-valid transaction could claim any sender.
        let derived_from = derive_address(&tx.pubkey)?;
        if !tx.from.eq_ignore_ascii_case(&derived_from) {
            self.metrics.record_verification_error("from_mismatch");
            return Err(TxSignError::FromMismatch);
        }

        let msg = self.sign_bytes(tx)?;
        let pk = PublicKeyBytes(tx.pubkey.clone());
        let sig = SignatureBytes(tx.signature.clone());
        crate::crypto::ed25519::Ed25519Verifier::verify(&pk, &msg, &sig)?;
        Ok(())
    }

    /// Compute the cache key.
    ///
    /// Hashes every field that determines the verification result:
    /// chain_id, pubkey, nonce, the two fee fields, gas_limit, payload,
    /// **and** the signature. Two transactions that differ in any of
    /// these produce distinct keys.
    fn compute_cache_key(&self, tx: &Tx) -> CacheKey {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"iona/tx_cache/v1:");
        hasher.update(&tx.chain_id.to_le_bytes());
        hasher.update(&(tx.pubkey.len() as u32).to_le_bytes());
        hasher.update(&tx.pubkey);
        hasher.update(&tx.nonce.to_le_bytes());
        hasher.update(&tx.max_fee_per_gas.to_le_bytes());
        hasher.update(&tx.max_priority_fee_per_gas.to_le_bytes());
        hasher.update(&tx.gas_limit.to_le_bytes());
        hasher.update(&(tx.payload.len() as u64).to_le_bytes());
        hasher.update(tx.payload.as_bytes());
        hasher.update(&(tx.signature.len() as u32).to_le_bytes());
        hasher.update(&tx.signature);
        *hasher.finalize().as_bytes()
    }

    /// Verify a batch of transactions.
    ///
    /// Returns a per-transaction result. When
    /// [`TxConfig::enable_batch_verify`] is `true` **and** the `rayon`
    /// feature is compiled in, uncached verifications run in parallel.
    /// Cache lookups and inserts happen sequentially to avoid
    /// serializing every verifier on the cache lock.
    #[must_use]
    pub fn verify_batch(&self, txs: &[Tx]) -> Vec<TxSignResult<()>> {
        let start = Instant::now();

        // Phase 1: cache lookups (sequential — cheap, avoids lock contention).
        let mut results: Vec<Option<TxSignResult<()>>> = Vec::with_capacity(txs.len());
        let mut misses: Vec<(usize, CacheKey)> = Vec::new();
        {
            let mut cache_guard = self.cache.lock();
            for (i, tx) in txs.iter().enumerate() {
                if let Err(e) = self.validate_tx_fields(tx) {
                    results.push(Some(Err(e)));
                    continue;
                }
                let key = self.compute_cache_key(tx);
                if let Some(cache) = cache_guard.as_mut() {
                    if let Some(entry) = cache.get(&key) {
                        if entry.expires_at > Instant::now() {
                            self.metrics.record_cache_hit();
                            results.push(Some(
                                entry.result.clone().map_err(CachedVerifyError::into_tx_error),
                            ));
                            continue;
                        }
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
                results.push(None);
                misses.push((i, key));
            }
        }

        // Phase 2: verify misses (parallel when enabled).
        #[cfg(feature = "rayon")]
        if self.config.enable_batch_verify {
            use rayon::prelude::*;
            let verified: Vec<(usize, CacheKey, TxSignResult<()>)> = misses
                .par_iter()
                .map(|(i, key)| {
                    let r = self.verify_internal(&txs[*i]);
                    (*i, *key, r)
                })
                .collect();
            for (i, _, r) in verified {
                results[i] = Some(r);
            }
        }
        #[cfg(not(feature = "rayon"))]
        {
            for (i, _) in &misses {
                results[*i] = Some(self.verify_internal(&txs[*i]));
            }
        }

        // Phase 3: cache inserts (sequential).
        {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let ttl = Duration::from_secs(self.config.cache_ttl_secs);
                let now = Instant::now();
                for (i, key) in &misses {
                    if let Some(Some(ref r)) = results.get(*i) {
                        cache.put(
                            *key,
                            ValidationCacheEntry {
                                result: r
                                    .as_ref()
                                    .map(|_| ())
                                    .map_err(CachedVerifyError::from_tx_error),
                                expires_at: now + ttl,
                            },
                        );
                    }
                }
            }
        }

        let status = if results
            .iter()
            .all(|r| matches!(r, Some(Ok(_))))
        {
            "ok"
        } else {
            "error"
        };
        self.metrics
            .record_verification("batch", status, start.elapsed());

        results
            .into_iter()
            .map(|r| r.unwrap_or(Err(TxSignError::Config("batch slot empty".into()))))
            .collect()
    }

    /// Signer's public key as `PublicKeyBytes`. Convenience wrapper.
    #[must_use]
    pub fn public_key(&self, signer: &dyn Signer) -> PublicKeyBytes {
        signer.public_key()
    }

    /// Clear the validation cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("tx cache cleared");
        }
    }

    /// Current cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    #[must_use]
    pub fn config(&self) -> &TxConfig {
        &self.config
    }

    /// Owned snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> TxMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ── Standalone helpers ────────────────────────────────────────────────────

/// Derive an IONA address (40-char hex string) from a 32-byte public key.
///
/// `BLAKE3(pubkey)[0..20]`, lowercase hex.
pub fn derive_address(pubkey: &[u8]) -> TxSignResult<String> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {PUBLIC_KEY_LEN} bytes, got {}",
            pubkey.len()
        )));
    }
    let hash = blake3::hash(pubkey);
    Ok(hex::encode(&hash.as_bytes()[..20]))
}

/// Derive an IONA address from a [`PublicKeyBytes`] wrapper.
pub fn derive_address_from_pk(pk: &PublicKeyBytes) -> TxSignResult<String> {
    derive_address(&pk.0)
}

/// Canonical signing bytes for a transaction.
pub fn tx_sign_bytes(tx: &Tx) -> TxSignResult<Vec<u8>> {
    canonical_payload(
        TX_SIGN_VERSION,
        tx.chain_id,
        &tx.pubkey,
        tx.nonce,
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        tx.gas_limit,
        &tx.payload,
    )
}

/// Canonical signing bytes from individual fields.
#[allow(clippy::too_many_arguments)]
pub fn tx_sign_bytes_from_parts(
    chain_id: u64,
    pubkey: &[u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &str,
) -> TxSignResult<Vec<u8>> {
    canonical_payload(
        TX_SIGN_VERSION,
        chain_id,
        pubkey,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        payload,
    )
}

/// Sign a transaction using a throwaway manager with default config.
///
/// Prefer constructing a [`TxManager`] once and reusing it — this helper
/// builds a fresh manager (and tries to register Prometheus metrics) per
/// call.
pub fn sign_tx(tx: &mut Tx, signer: &dyn Signer) -> TxSignResult<()> {
    let manager = TxManager::new(TxConfig::default())?;
    manager.sign_tx(tx, signer)
}

/// Verify a transaction using a throwaway manager with default config.
///
/// Prefer constructing a [`TxManager`] once and reusing it.
pub fn verify_tx_signature(tx: &Tx) -> TxSignResult<()> {
    let manager = TxManager::new(TxConfig::default())?;
    manager.verify_tx(tx)
}

/// Verify a raw signature (no transaction structure).
pub fn verify_signature(pubkey: &[u8], msg: &[u8], signature: &[u8]) -> TxSignResult<()> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {PUBLIC_KEY_LEN} bytes, got {}",
            pubkey.len()
        )));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(TxSignError::InvalidSignature(format!(
            "expected {SIGNATURE_LEN} bytes, got {}",
            signature.len()
        )));
    }
    let pk = PublicKeyBytes(pubkey.to_vec());
    let sig = SignatureBytes(signature.to_vec());
    crate::crypto::ed25519::Ed25519Verifier::verify(&pk, msg, &sig)?;
    Ok(())
}

/// Validate a transaction (field + signature checks) with default config.
pub fn validate_tx(tx: &Tx) -> TxSignResult<()> {
    verify_tx_signature(tx)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;

    fn manager() -> TxManager {
        TxManager::with_metrics(
            TxConfig {
                enable_metrics: false,
                ..Default::default()
            },
            TxMetrics::unregistered(),
        )
        .unwrap()
    }

    fn dummy_tx(chain_id: u64) -> Tx {
        Tx {
            pubkey: vec![0u8; 32],
            from: String::new(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21_000,
            payload: "set key value".into(),
            signature: vec![],
            chain_id,
        }
    }

    // ── Address derivation ──────────────────────────────────────────────

    #[test]
    fn derive_address_is_deterministic() {
        let pk = vec![0xAA; 32];
        let a = derive_address(&pk).unwrap();
        let b = derive_address(&pk).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 40);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn derive_address_rejects_wrong_length() {
        assert!(matches!(
            derive_address(&[0u8; 31]),
            Err(TxSignError::InvalidPublicKey(_))
        ));
    }

    // ── sign_tx contract ────────────────────────────────────────────────

    #[test]
    fn sign_tx_overwrites_pubkey_and_from() {
        // Regression: the previous implementation left `tx.pubkey`
        // unchanged, so a transaction signed by `signer` but declaring
        // a different `pubkey` produced a signature that failed
        // verification.
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let signer_pk = signer.public_key().0;

        let mut tx = dummy_tx(1);
        // Deliberately wrong pubkey.
        tx.pubkey = vec![0xFF; 32];

        m.sign_tx(&mut tx, &signer).unwrap();

        assert_eq!(tx.pubkey, signer_pk, "pubkey must be the signer's");
        assert_eq!(tx.from, derive_address(&signer_pk).unwrap());
        m.verify_tx(&tx).unwrap();
    }

    #[test]
    fn verify_rejects_from_mismatch() {
        // Regression: a signature-valid transaction used to pass
        // verification even when `from` was arbitrary.
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx(1);
        m.sign_tx(&mut tx, &signer).unwrap();
        tx.from = "0".repeat(40); // tamper
        assert!(matches!(
            m.verify_tx(&tx),
            Err(TxSignError::FromMismatch)
        ));
    }

    #[test]
    fn verify_rejects_corrupted_signature() {
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx(1);
        m.sign_tx(&mut tx, &signer).unwrap();
        tx.signature[0] ^= 1;
        assert!(matches!(
            m.verify_tx(&tx),
            Err(TxSignError::Crypto(CryptoError::InvalidSignature))
        ));
    }

    // ── Cache ───────────────────────────────────────────────────────────

    #[test]
    fn cache_populates_and_clears() {
        let m = TxManager::with_metrics(
            TxConfig {
                enable_metrics: false,
                enable_cache: true,
                cache_size: 16,
                ..Default::default()
            },
            TxMetrics::unregistered(),
        )
        .unwrap();

        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx(1);
        m.sign_tx(&mut tx, &signer).unwrap();
        m.verify_tx(&tx).unwrap();
        m.verify_tx(&tx).unwrap();
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
        m.clear_cache();
        assert_eq!(m.cache_size(), 0);
    }

    #[test]
    fn cache_key_distinguishes_signatures() {
        // Two transactions identical except for signature must not share
        // a cache entry — one is valid, one is not.
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx(1);
        m.sign_tx(&mut tx, &signer).unwrap();
        m.verify_tx(&tx).unwrap();

        let mut bad = tx.clone();
        bad.signature[0] ^= 1;
        assert!(m.verify_tx(&bad).is_err());
        // Cache miss for the bad signature, and the good one is still
        // cached.
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 2);
    }

    // ── Batch ───────────────────────────────────────────────────────────

    #[test]
    fn verify_batch_reports_per_tx_results() {
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let mut good = dummy_tx(1);
        m.sign_tx(&mut good, &signer).unwrap();

        let mut bad = good.clone();
        bad.payload = "tampered".into();

        let results = m.verify_batch(&[good, bad]);
        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert!(results[1].is_err());
    }

    // ── Metrics ─────────────────────────────────────────────────────────

    #[test]
    fn metrics_default_does_not_panic() {
        let _a = TxMetrics::unregistered();
        let _b = TxMetrics::unregistered();
        let _c = TxMetrics::default();
    }

    #[test]
    fn metrics_snapshot_is_serializable() {
        let m = manager();
        let signer = Ed25519Keypair::generate();
        let mut tx = dummy_tx(1);
        m.sign_tx(&mut tx, &signer).unwrap();
        m.verify_tx(&tx).unwrap();
        let snap = m.metrics_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: TxMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_validation_matrix() {
        assert!(TxConfig::default().validate().is_ok());

        let mut c = TxConfig::default();
        c.chain_id = 0;
        assert!(c.validate().is_err());

        let mut c = TxConfig::default();
        c.min_gas_limit = 0;
        assert!(c.validate().is_err());

        let mut c = TxConfig::default();
        c.min_gas_limit = 100;
        c.max_gas_limit = 50;
        assert!(c.validate().is_err());

        let mut c = TxConfig::default();
        c.max_payload_size = 0;
        assert!(c.validate().is_err());

        let mut c = TxConfig::default();
        c.cache_size = 0;
        assert!(c.validate().is_err());

        let mut c = TxConfig::default();
        c.cache_ttl_secs = 0;
        assert!(c.validate().is_err());
    }

    // ── Field validation ────────────────────────────────────────────────

    #[test]
    fn validate_tx_fields_cases() {
        let m = manager();
        let mut tx = dummy_tx(1);
        tx.pubkey = vec![0u8; 32];
        assert!(m.validate_tx_fields(&tx).is_ok());

        tx.chain_id = 2;
        assert!(matches!(m.validate_tx_fields(&tx), Err(TxSignError::InvalidChainId(_))));
        tx.chain_id = 1;

        tx.gas_limit = 100;
        assert!(matches!(m.validate_tx_fields(&tx), Err(TxSignError::GasLimitTooLow { .. })));
        tx.gas_limit = 21_000;

        tx.gas_limit = 100_000_000;
        assert!(matches!(m.validate_tx_fields(&tx), Err(TxSignError::GasLimitTooHigh { .. })));
        tx.gas_limit = 21_000;

        tx.payload = "x".repeat(200_000);
        assert!(matches!(m.validate_tx_fields(&tx), Err(TxSignError::PayloadTooLarge { .. })));
        tx.payload = "ok".into();

        tx.pubkey = vec![0u8; 31];
        assert!(matches!(m.validate_tx_fields(&tx), Err(TxSignError::InvalidPublicKey(_))));
    }
}
