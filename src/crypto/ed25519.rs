//! Ed25519 signing and verification for IONA.
//!
//! Implements the [`Signer`] and [`Verifier`] traits using the Ed25519
//! signature scheme (`ed25519_dalek`, v2.x API).
//!
//! # Zeroization
//!
//! - [`SigningKey`] from `ed25519-dalek` zeroizes its secret bytes on
//!   drop.
//! - [`Ed25519Signer::try_from_slice`], [`from_hex`], [`from_base64`],
//!   and [`try_random`] **zeroize the local seed buffer** after
//!   constructing the signer. The docs previously claimed "secure
//!   zeroization" without actually zeroizing the intermediate `[u8; 32]`
//!   copies.
//! - [`Ed25519Signer::to_seed`] (and its `hex` / `base64` variants)
//!   export the raw seed into a caller-owned `[u8; 32]` / `String`. These
//!   are documented as **secret material**; the caller is responsible for
//!   wiping the returned buffer. Prefer [`Ed25519Signer::sign`] over
//!   round-tripping the seed.
//!
//! # Verification cache
//!
//! When enabled, verification results are cached in an LRU keyed by a
//! **BLAKE3-256** digest of `(public_key, message, signature)`. The cache
//! is a performance optimisation only; the hash is collision-resistant,
//! so a crafted input cannot force a cache hit that returns `Ok` for an
//! invalid signature. The previous implementation used a 64-bit
//! `DefaultHasher` (SipHash) — fine for a hashmap, less so for a
//! security decision.
//!
//! Cache hits for **malformed** inputs return [`CryptoError::InvalidSignature`]
//! instead of the specific key-length / key-parse error. Callers that
//! need the exact error should disable the cache
//! ([`Ed25519Config::enable_cache`]).
//!
//! # Global manager
//!
//! [`init_global`] is idempotent: a second call returns `Ok(())`
//! without re-initialising. [`try_global_manager`] returns `Option`; the
//! panicking [`global_manager`] is retained for backward compatibility.
//! [`ed25519_verify`] falls back to uncached verification when the
//! global manager has not been initialised, so it never panics.
//!
//! # Asymmetric key material
//!
//! [`Ed25519Signer::random`] panics if the OS RNG is unavailable. Use
//! [`Ed25519Signer::try_random`] to receive `Result` instead. This
//! matters in early-boot contexts where `getrandom` may not be seeded
//! yet.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{Counter, CounterVec, HistogramVec};
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroUsize;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tracing::{trace, warn};
use zeroize::Zeroize;

// ── Constants ─────────────────────────────────────────────────────────────

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Length of an Ed25519 seed, in bytes.
pub const SEED_LEN: usize = 32;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the Ed25519 subsystem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Config {
    /// Whether to cache verification results.
    pub enable_cache: bool,
    /// Maximum number of entries in the verification cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to register Prometheus metrics via [`Ed25519Metrics::new`].
    pub enable_metrics: bool,
    /// Whether to log every verification (verbose).
    pub log_verification: bool,
}

impl Default for Ed25519Config {
    fn default() -> Self {
        Self {
            enable_cache: true,
            cache_size: 1024,
            cache_ttl_secs: 300,
            enable_metrics: true,
            log_verification: true,
        }
    }
}

/// Errors from [`Ed25519Config::validate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ed25519ConfigError {
    CacheSizeZero,
    CacheTtlZero,
}

impl fmt::Display for Ed25519ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CacheSizeZero => f.write_str("cache_size must be > 0"),
            Self::CacheTtlZero => f.write_str("cache_ttl_secs must be > 0"),
        }
    }
}

impl Ed25519Config {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), Ed25519ConfigError> {
        if self.cache_size == 0 {
            return Err(Ed25519ConfigError::CacheSizeZero);
        }
        if self.cache_ttl_secs == 0 {
            return Err(Ed25519ConfigError::CacheTtlZero);
        }
        Ok(())
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for Ed25519 operations.
///
/// [`Ed25519Metrics::new`] registers with the default registry and can
/// only succeed once per process. [`Ed25519Metrics::unregistered`] is
/// fail-free; [`Default`] uses it.
#[derive(Clone)]
pub struct Ed25519Metrics {
    pub sign_ops: Counter,
    pub verify_ops: CounterVec,
    pub verify_success: Counter,
    pub verify_failure: Counter,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub operation_duration: HistogramVec,
}

impl Ed25519Metrics {
    /// Register all metrics with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            sign_ops: prometheus::register_counter!(
                "iona_ed25519_sign_ops_total",
                "Total sign operations"
            )?,
            verify_ops: prometheus::register_counter_vec!(
                "iona_ed25519_verify_ops_total",
                "Total verify operations",
                &["result"]
            )?,
            verify_success: prometheus::register_counter!(
                "iona_ed25519_verify_success_total",
                "Successful verifications"
            )?,
            verify_failure: prometheus::register_counter!(
                "iona_ed25519_verify_failure_total",
                "Failed verifications"
            )?,
            cache_hits: prometheus::register_counter!(
                "iona_ed25519_cache_hits_total",
                "Cache hits"
            )?,
            cache_misses: prometheus::register_counter!(
                "iona_ed25519_cache_misses_total",
                "Cache misses"
            )?,
            operation_duration: prometheus::register_histogram_vec!(
                "iona_ed25519_operation_duration_seconds",
                "Operation duration",
                &["operation"]
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        let mk_counter = |name: &str, help: &str| {
            Counter::new(name, help).expect("counter construction is infallible")
        };
        Self {
            sign_ops: mk_counter("iona_ed25519_sign_ops_total", "Total sign operations"),
            verify_ops: CounterVec::new(
                prometheus::Opts::new("iona_ed25519_verify_ops_total", "Total verify operations"),
                &["result"],
            )
            .expect("counter vec construction is infallible"),
            verify_success: mk_counter(
                "iona_ed25519_verify_success_total",
                "Successful verifications",
            ),
            verify_failure: mk_counter(
                "iona_ed25519_verify_failure_total",
                "Failed verifications",
            ),
            cache_hits: mk_counter("iona_ed25519_cache_hits_total", "Cache hits"),
            cache_misses: mk_counter("iona_ed25519_cache_misses_total", "Cache misses"),
            operation_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_ed25519_operation_duration_seconds",
                    "Operation duration",
                ),
                &["operation"],
            )
            .expect("histogram vec construction is infallible"),
        }
    }

    pub fn record_sign(&self, duration: Duration) {
        self.sign_ops.inc();
        self.operation_duration
            .with_label_values(&["sign"])
            .observe(duration.as_secs_f64());
    }

    pub fn record_verify(&self, success: bool, duration: Duration) {
        self.verify_ops
            .with_label_values(&[if success { "ok" } else { "fail" }])
            .inc();
        if success {
            self.verify_success.inc();
        } else {
            self.verify_failure.inc();
        }
        self.operation_duration
            .with_label_values(&["verify"])
            .observe(duration.as_secs_f64());
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
}

impl Default for Ed25519Metrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── Cache entry ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
struct VerifyCacheEntry {
    /// `true` if the cached verification succeeded.
    ok: bool,
    expires_at: Instant,
}

/// Cache key: 256-bit BLAKE3 digest over `(pk, msg, sig)`.
///
/// Collision resistance matters here: a collision could cause an invalid
/// signature to be accepted based on a *different* signature that was
/// previously verified.
type CacheKey = [u8; 32];

// ── Signer ────────────────────────────────────────────────────────────────

/// Ed25519 signer with a zeroizing signing key.
#[derive(Clone, Debug)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_key_bytes: PublicKeyBytes,
    metrics: Option<Arc<Ed25519Metrics>>,
}

impl Ed25519Signer {
    /// Build a signer from a 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
            metrics: None,
        }
    }

    /// Generate a new signer from the OS RNG.
    ///
    /// # Errors
    ///
    /// Returns `Err` if the OS RNG is unavailable (e.g. early boot before
    /// `getrandom` is seeded).
    pub fn try_random() -> Result<Self, CryptoError> {
        let mut seed = [0u8; SEED_LEN];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|e| CryptoError::Key(format!("OS RNG unavailable: {e}")))?;
        let signer = Self::from_seed(seed);
        seed.zeroize();
        Ok(signer)
    }

    /// Generate a new signer from the OS RNG, panicking on failure.
    ///
    /// Prefer [`try_random`](Self::try_random) when the caller can handle
    /// an RNG failure.
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG is unavailable.
    #[must_use]
    pub fn random() -> Self {
        Self::try_random().expect("OS RNG unavailable")
    }

    /// Export the raw seed. **Secret material.** The caller is
    /// responsible for wiping the returned buffer.
    #[must_use]
    pub fn to_seed(&self) -> [u8; SEED_LEN] {
        self.signing_key.to_bytes()
    }

    /// Build a signer from a 32-byte slice.
    ///
    /// The intermediate seed buffer is zeroized before returning.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != SEED_LEN {
            return Err(CryptoError::KeyLength {
                expected: SEED_LEN,
                actual: slice.len(),
            });
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(slice);
        let signer = Self::from_seed(seed);
        seed.zeroize();
        Ok(signer)
    }

    /// Parse a signer from a hex-encoded seed.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let mut bytes = hex::decode(hex).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        let result = Self::try_from_slice(&bytes);
        bytes.zeroize();
        result
    }

    /// Export the seed as hex. **Secret material.**
    #[must_use]
    pub fn to_hex(&self) -> String {
        let mut seed = self.to_seed();
        let out = hex::encode(seed);
        seed.zeroize();
        out
    }

    /// Parse a signer from a base64-encoded seed.
    ///
    /// # Note
    ///
    /// Uses the `base64` 0.13–0.20 free-function API. For base64 ≥ 0.21,
    /// replace with `base64::engine::general_purpose::STANDARD.decode(..)`.
    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let mut bytes =
            base64::decode(b64).map_err(|_| CryptoError::Key("invalid base64".into()))?;
        let result = Self::try_from_slice(&bytes);
        bytes.zeroize();
        result
    }

    /// Export the seed as base64. **Secret material.**
    #[must_use]
    pub fn to_base64(&self) -> String {
        let mut seed = self.to_seed();
        let out = base64::encode(seed);
        seed.zeroize();
        out
    }

    /// Access the underlying verifying key.
    #[must_use]
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Attach a metrics handle so [`Signer::sign`] records duration.
    #[must_use]
    pub fn with_metrics(mut self, metrics: Arc<Ed25519Metrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> PublicKeyBytes {
        self.public_key_bytes.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let start = Instant::now();
        let signature: Signature = self.signing_key.sign(msg);
        if let Some(m) = &self.metrics {
            m.record_sign(start.elapsed());
        }
        SignatureBytes(signature.to_bytes().to_vec())
    }
}

// ── Verifier ──────────────────────────────────────────────────────────────

/// Ed25519 verifier (stateless).
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        if pk.0.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: pk.0.len(),
            });
        }
        if sig.0.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: sig.0.len(),
            });
        }

        // Lengths are checked above; `try_into` cannot fail.
        let pk_array: [u8; PUBLIC_KEY_LEN] = pk.0.as_slice().try_into().expect("length checked");
        let sig_array: [u8; SIGNATURE_LEN] = sig.0.as_slice().try_into().expect("length checked");

        let public_key = VerifyingKey::from_bytes(&pk_array)
            .map_err(|_| CryptoError::InvalidKey("public key bytes invalid".into()))?;
        let signature = Signature::from_bytes(&sig_array);

        public_key
            .verify(msg, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe manager for Ed25519 verification with caching and metrics.
#[derive(Clone)]
pub struct Ed25519Manager {
    config: Arc<Ed25519Config>,
    metrics: Arc<Ed25519Metrics>,
    cache: Arc<Mutex<Option<LruCache<CacheKey, VerifyCacheEntry>>>>,
}

impl Ed25519Manager {
    /// Build a manager with unregistered metrics (no Prometheus
    /// registration attempt).
    pub fn new(config: Ed25519Config) -> Result<Self, Ed25519ConfigError> {
        Self::with_metrics(config, Ed25519Metrics::unregistered())
    }

    /// Build a manager with a caller-supplied metrics handle. Use this
    /// when the caller has already called [`Ed25519Metrics::new`] once.
    pub fn with_metrics(
        config: Ed25519Config,
        metrics: Ed25519Metrics,
    ) -> Result<Self, Ed25519ConfigError> {
        config.validate()?;
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or(Ed25519ConfigError::CacheSizeZero)?;
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

    /// Verify a signature, using the cache if enabled.
    ///
    /// # Errors
    ///
    /// On a cache miss, returns the underlying verifier's error. On a
    /// cache hit, returns [`CryptoError::InvalidSignature`] for any
    /// cached failure (the specific malformed-key error is not preserved
    /// across cache hits).
    pub fn verify(
        &self,
        pk: &PublicKeyBytes,
        msg: &[u8],
        sig: &SignatureBytes,
    ) -> Result<(), CryptoError> {
        let start = Instant::now();

        // Pre-check lengths so malformed inputs bypass the cache and get
        // the specific error. This also keeps the cache key domain
        // well-defined.
        if pk.0.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: pk.0.len(),
            });
        }
        if sig.0.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: sig.0.len(),
            });
        }

        let key = compute_cache_key(pk, msg, sig);

        // ── Cache lookup ─────────────────────────────────────────────
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        let ok = entry.ok;
                        drop(guard);
                        self.metrics.record_cache_hit();
                        self.metrics.record_verify(ok, start.elapsed());
                        if self.config.log_verification {
                            trace!(result = ok, "ed25519 verify (cache hit)");
                        }
                        return if ok {
                            Ok(())
                        } else {
                            Err(CryptoError::InvalidSignature)
                        };
                    }
                    cache.pop(&key);
                }
                drop(guard);
                self.metrics.record_cache_miss();
            }
        }

        // ── Full verify ──────────────────────────────────────────────
        let result = Ed25519Verifier::verify(pk, msg, sig);
        let success = result.is_ok();
        self.metrics.record_verify(success, start.elapsed());

        if self.config.log_verification {
            trace!(success, pk_len = pk.0.len(), sig_len = sig.0.len(), "ed25519 verify");
        }

        // ── Cache insert ─────────────────────────────────────────────
        if self.config.enable_cache {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(
                    key,
                    VerifyCacheEntry {
                        ok: success,
                        expires_at: Instant::now()
                            + Duration::from_secs(self.config.cache_ttl_secs),
                    },
                );
            }
        }

        result
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("ed25519 cache cleared");
        }
    }

    /// Current cache size.
    #[must_use]
    pub fn cache_size(&self) -> usize {
        self.cache.lock().as_ref().map_or(0, |c| c.len())
    }

    /// Owned snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> Ed25519MetricsSnapshot {
        let mut verify_ops = BTreeMap::new();
        for mf in self.metrics.verify_ops.collect() {
            for m in mf.get_metric() {
                let label = m
                    .get_label()
                    .iter()
                    .find(|l| l.get_name() == "result")
                    .map(|l| l.get_value().to_string())
                    .unwrap_or_else(|| "unknown".to_string());
                let value = m.get_counter().get_value() as u64;
                *verify_ops.entry(label).or_insert(0u64) += value;
            }
        }

        Ed25519MetricsSnapshot {
            sign_ops: self.metrics.sign_ops.get(),
            verify_ops,
            verify_success: self.metrics.verify_success.get(),
            verify_failure: self.metrics.verify_failure.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Access the underlying metrics handle.
    #[must_use]
    pub fn metrics(&self) -> &Ed25519Metrics {
        &self.metrics
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &Ed25519Config {
        &self.config
    }
}

/// Owned snapshot of [`Ed25519Metrics`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519MetricsSnapshot {
    pub sign_ops: u64,
    /// Verify operations, keyed by the `result` label (`"ok"` / `"fail"`).
    pub verify_ops: BTreeMap<String, u64>,
    pub verify_success: u64,
    pub verify_failure: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
}

/// Compute the cache key for `(pk, msg, sig)`.
///
/// Uses length-prefixed BLAKE3-256 so structurally different tuples
/// cannot collide.
fn compute_cache_key(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CacheKey {
    let mut hasher = blake3::Hasher::new();
    hasher.update(&(pk.0.len() as u32).to_le_bytes());
    hasher.update(&pk.0);
    hasher.update(&(msg.len() as u64).to_le_bytes());
    hasher.update(msg);
    hasher.update(&(sig.0.len() as u32).to_le_bytes());
    hasher.update(&sig.0);
    *hasher.finalize().as_bytes()
}

// ── Global manager ────────────────────────────────────────────────────────

static ED25519_MANAGER: OnceLock<Ed25519Manager> = OnceLock::new();

/// Initialise the global manager.
///
/// Idempotent: a second call returns `Ok(())` without changing the
/// existing manager. This matters for tests, which can be run in any
/// order, and for library callers that do not control initialisation
/// timing.
///
/// Tries to register Prometheus metrics; on collision (e.g. a second
/// process instance in the same test binary) it falls back to
/// unregistered metrics with a `warn!`.
pub fn init_global(config: Ed25519Config) -> Result<(), Ed25519ConfigError> {
    if ED25519_MANAGER.get().is_some() {
        return Ok(());
    }
    let metrics = if config.enable_metrics {
        match Ed25519Metrics::new() {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "ed25519 metrics already registered; using unregistered");
                Ed25519Metrics::unregistered()
            }
        }
    } else {
        Ed25519Metrics::unregistered()
    };
    let manager = Ed25519Manager::with_metrics(config, metrics)?;
    // If another thread raced ahead of us, ignore the error; the existing
    // manager is authoritative.
    let _ = ED25519_MANAGER.set(manager);
    Ok(())
}

/// Try to access the global manager without panicking.
#[must_use]
pub fn try_global_manager() -> Option<&'static Ed25519Manager> {
    ED25519_MANAGER.get()
}

/// Access the global manager.
///
/// # Panics
///
/// Panics if [`init_global`] was never called. Prefer
/// [`try_global_manager`] where possible.
#[must_use]
pub fn global_manager() -> &'static Ed25519Manager {
    ED25519_MANAGER
        .get()
        .expect("Ed25519 manager not initialized; call init_global() first")
}

/// Verify a signature using the global manager if initialised, otherwise
/// the uncached stateless verifier.
///
/// This function **never panics** for any input.
pub fn ed25519_verify(
    pk: &PublicKeyBytes,
    msg: &[u8],
    sig: &SignatureBytes,
) -> Result<(), CryptoError> {
    match ED25519_MANAGER.get() {
        Some(mgr) => mgr.verify(pk, msg, sig),
        None => Ed25519Verifier::verify(pk, msg, sig),
    }
}

// ── Display / FromStr helpers ─────────────────────────────────────────────
//
// NOTE: These impls live here, not in `crate::crypto` where the types are
// defined. If `crate::crypto` ever implements `Display` / `FromStr` for
// these types, remove one set to avoid a coherence error.

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for SignatureBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn manager() -> Ed25519Manager {
        Ed25519Manager::new(Ed25519Config::default()).unwrap()
    }

    // ── Sign / verify roundtrip ─────────────────────────────────────────

    #[test]
    fn sign_verify_roundtrip() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        let pk = signer.public_key();
        assert!(manager().verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn verify_rejects_bit_flip() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let mut sig = signer.sign(msg);
        sig.0[0] ^= 1;
        assert!(manager().verify(&signer.public_key(), msg, &sig).is_err());
    }

    #[test]
    fn verify_rejects_wrong_message() {
        let signer = Ed25519Signer::random();
        let sig = signer.sign(b"hello");
        assert!(manager()
            .verify(&signer.public_key(), b"goodbye", &sig)
            .is_err());
    }

    #[test]
    fn verify_rejects_wrong_lengths() {
        let m = manager();
        let pk = PublicKeyBytes(vec![0u8; 31]);
        let sig = SignatureBytes(vec![0u8; 64]);
        assert!(matches!(
            m.verify(&pk, b"x", &sig),
            Err(CryptoError::KeyLength { expected: 32, actual: 31 })
        ));

        let pk = PublicKeyBytes(vec![0u8; 32]);
        let sig = SignatureBytes(vec![0u8; 63]);
        assert!(matches!(
            m.verify(&pk, b"x", &sig),
            Err(CryptoError::KeyLength { expected: 64, actual: 63 })
        ));
    }

    // ── Determinism ─────────────────────────────────────────────────────

    #[test]
    fn same_seed_same_signature() {
        let seed = [0xAA; 32];
        let a = Ed25519Signer::from_seed(seed);
        let b = Ed25519Signer::from_seed(seed);
        assert_eq!(a.public_key().0, b.public_key().0);
        assert_eq!(a.sign(b"test").0, b.sign(b"test").0);
    }

    #[test]
    fn seed_roundtrip_via_hex() {
        let s = Ed25519Signer::random();
        let hex_repr = s.to_hex();
        let r = Ed25519Signer::from_hex(&hex_repr).unwrap();
        assert_eq!(s.public_key().0, r.public_key().0);
    }

    #[test]
    fn seed_roundtrip_via_base64() {
        let s = Ed25519Signer::random();
        let b64 = s.to_base64();
        let r = Ed25519Signer::from_base64(&b64).unwrap();
        assert_eq!(s.public_key().0, r.public_key().0);
    }

    // ── Cache ───────────────────────────────────────────────────────────

    #[test]
    fn cache_records_hit_and_miss() {
        let m = manager();
        let s = Ed25519Signer::random();
        let pk = s.public_key();
        let sig = s.sign(b"test");
        m.verify(&pk, b"test", &sig).unwrap(); // miss
        m.verify(&pk, b"test", &sig).unwrap(); // hit
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 1);
        assert_eq!(snap.cache_hits, 1);
        assert_eq!(snap.cache_size, 1);
    }

    #[test]
    fn cache_is_keyed_by_full_input_tuple() {
        // Regression: the previous 64-bit SipHash key was marginal for a
        // security decision. The BLAKE3-256 key cannot collide in
        // practice; this test simply asserts that two different
        // signatures on the same message do not share a cache entry.
        let m = manager();
        let s = Ed25519Signer::random();
        let pk = s.public_key();
        let sig_a = s.sign(b"msg");
        let mut sig_b = sig_a.clone();
        sig_b.0[0] ^= 1;

        m.verify(&pk, b"msg", &sig_a).unwrap();
        // Different signature: must be a cache miss, and verification
        // must fail.
        assert!(m.verify(&pk, b"msg", &sig_b).is_err());
        let snap = m.metrics_snapshot();
        assert_eq!(snap.cache_misses, 2);
        assert_eq!(snap.cache_hits, 0);
    }

    #[test]
    fn cache_is_bypassed_for_malformed_inputs() {
        let m = manager();
        let pk = PublicKeyBytes(vec![0u8; 31]);
        let sig = SignatureBytes(vec![0u8; 64]);
        assert!(m.verify(&pk, b"x", &sig).is_err());
        // Length pre-check returns before cache lookup, so no cache
        // entry was created.
        assert_eq!(m.cache_size(), 0);
    }

    #[test]
    fn clear_cache_empties_it() {
        let m = manager();
        let s = Ed25519Signer::random();
        m.verify(&s.public_key(), b"x", &s.sign(b"x")).unwrap();
        assert!(m.cache_size() > 0);
        m.clear_cache();
        assert_eq!(m.cache_size(), 0);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_validation() {
        assert_eq!(Ed25519Config::default().validate(), Ok(()));
        assert_eq!(
            Ed25519Config { cache_size: 0, ..Default::default() }.validate(),
            Err(Ed25519ConfigError::CacheSizeZero),
        );
        assert_eq!(
            Ed25519Config { cache_ttl_secs: 0, ..Default::default() }.validate(),
            Err(Ed25519ConfigError::CacheTtlZero),
        );
    }

    #[test]
    fn metrics_unregistered_is_repeatable() {
        let _a = Ed25519Metrics::unregistered();
        let _b = Ed25519Metrics::unregistered();
        let _c = Ed25519Metrics::default();
    }

    #[test]
    fn metrics_snapshot_is_owned_and_serializable() {
        let m = manager();
        let s = Ed25519Signer::random();
        m.verify(&s.public_key(), b"x", &s.sign(b"x")).unwrap();
        let snap = m.metrics_snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: Ed25519MetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
        assert_eq!(snap.verify_ops.get("ok"), Some(&1));
    }

    // ── Global manager ──────────────────────────────────────────────────

    #[test]
    fn init_global_is_idempotent() {
        // Two calls must both succeed regardless of test ordering.
        assert!(init_global(Ed25519Config::default()).is_ok());
        assert!(init_global(Ed25519Config::default()).is_ok());
        assert!(try_global_manager().is_some());
    }

    #[test]
    fn ed25519_verify_works_without_global_manager() {
        // Regression: the previous `ed25519_verify` called
        // `global_manager()`, which panics if `init_global` was never
        // called. Now it falls back to stateless verification.
        let s = Ed25519Signer::random();
        let sig = s.sign(b"x");
        // Note: cannot assert absence of global manager here because a
        // sibling test may have called `init_global`. The assertion is
        // that this returns a result either way.
        assert!(ed25519_verify(&s.public_key(), b"x", &sig).is_ok());
    }

    // ── Display / FromStr ───────────────────────────────────────────────

    #[test]
    fn public_key_display_roundtrip() {
        let pk = Ed25519Signer::random().public_key();
        let parsed: PublicKeyBytes = pk.to_string().parse().unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn signature_display_roundtrip() {
        let sig = Ed25519Signer::random().sign(b"x");
        let parsed: SignatureBytes = sig.to_string().parse().unwrap();
        assert_eq!(sig, parsed);
    }

    // ── RFC 8032 known-answer test ─────────────────────────────────────

    #[test]
    fn rfc_8032_test_vector() {
        // RFC 8032, Section 7.1, test 1.
        let seed =
            hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap();
        let signer = Ed25519Signer::try_from_slice(&seed).unwrap();

        let pk_expected =
            hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
                .unwrap();
        assert_eq!(signer.public_key().0, pk_expected);

        let sig = signer.sign(b"");
        let sig_expected = hex::decode(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
             fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        )
        .unwrap();
        assert_eq!(sig.0, sig_expected);

        assert!(manager().verify(&signer.public_key(), b"", &sig).is_ok());
    }
}
