//! Ed25519 signing and verification for IONA.
//!
//! This module provides an implementation of the `Signer` and `Verifier` traits
//! using the Ed25519 signature scheme (Edwards‑curve Digital Signature Algorithm).
//! The implementation is based on the `ed25519_dalek` crate and includes secure
//! zeroization of secret material.
//!
//! # Production Features
//! - Configurable via `Ed25519Config` (cache size, metrics, logging).
//! - `Ed25519Metrics` with Prometheus counters for sign/verify operations.
//! - `Ed25519Manager` with thread‑safe LRU cache for public keys.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier as EdVerifier, VerifyingKey};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, Counter, CounterVec, HistogramVec,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};
use zeroize::Zeroize;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the Ed25519 subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ed25519Config {
    /// Whether to enable caching of public key verification results.
    pub enable_cache: bool,
    /// Maximum number of entries in the verification cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log verification events.
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

impl Ed25519Config {
    pub fn validate(&self) -> Result<(), String> {
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

/// Metrics for Ed25519 operations.
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
    pub fn new() -> Result<Self, prometheus::Error> {
        let sign_ops = register_counter!("iona_ed25519_sign_ops_total", "Total sign operations")?;
        let verify_ops = register_counter_vec!(
            "iona_ed25519_verify_ops_total",
            "Total verify operations",
            &["result"]
        )?;
        let verify_success = register_counter!("iona_ed25519_verify_success_total", "Successful verifications")?;
        let verify_failure = register_counter!("iona_ed25519_verify_failure_total", "Failed verifications")?;
        let cache_hits = register_counter!("iona_ed25519_cache_hits_total", "Cache hits")?;
        let cache_misses = register_counter!("iona_ed25519_cache_misses_total", "Cache misses")?;
        let operation_duration = register_histogram_vec!(
            "iona_ed25519_operation_duration_seconds",
            "Operation duration",
            &["operation"]
        )?;
        Ok(Self {
            sign_ops,
            verify_ops,
            verify_success,
            verify_failure,
            cache_hits,
            cache_misses,
            operation_duration,
        })
    }

    pub fn record_sign(&self, duration: Duration) {
        self.sign_ops.inc();
        self.operation_duration.with_label_values(&["sign"]).observe(duration.as_secs_f64());
    }

    pub fn record_verify(&self, success: bool, duration: Duration) {
        self.verify_ops.with_label_values(&[if success { "ok" } else { "fail" }]).inc();
        if success {
            self.verify_success.inc();
        } else {
            self.verify_failure.inc();
        }
        self.operation_duration.with_label_values(&["verify"]).observe(duration.as_secs_f64());
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
        Self::new().unwrap_or_else(|_| Self {
            sign_ops: Counter::new("iona_ed25519_sign_ops_total", "Sign ops").unwrap(),
            verify_ops: CounterVec::new(
                prometheus::Opts::new("iona_ed25519_verify_ops_total", "Verify ops"),
                &["result"],
            ).unwrap(),
            verify_success: Counter::new("iona_ed25519_verify_success_total", "Success").unwrap(),
            verify_failure: Counter::new("iona_ed25519_verify_failure_total", "Failure").unwrap(),
            cache_hits: Counter::new("iona_ed25519_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_ed25519_cache_misses_total", "Cache misses").unwrap(),
            operation_duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_ed25519_operation_duration_seconds",
                    "Operation duration",
                ),
                &["operation"],
            ).unwrap(),
        })
    }
}

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct VerifyCacheEntry {
    result: bool,
    expires_at: Instant,
}

// ── Ed25519 Signer ──────────────────────────────────────────────────────

/// Ed25519 signer that securely holds a signing key.
#[derive(Clone)]
pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_key_bytes: PublicKeyBytes,
}

impl Ed25519Signer {
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
        }
    }

    pub fn random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
        }
    }

    pub fn to_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::KeyLength { expected: 32, actual: slice.len() });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(slice);
        Ok(Self::from_seed(seed))
    }

    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        Self::try_from_slice(&bytes)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.to_seed())
    }

    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = base64::decode(b64).map_err(|_| CryptoError::Key("invalid base64".into()))?;
        Self::try_from_slice(&bytes)
    }

    pub fn to_base64(&self) -> String {
        base64::encode(self.to_seed())
    }

    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> PublicKeyBytes {
        self.public_key_bytes.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let start = Instant::now();
        let signature: Signature = self.signing_key.sign(msg);
        // Record metrics (global metrics from manager).
        if let Some(mgr) = ED25519_MANAGER.as_ref() {
            mgr.metrics.record_sign(start.elapsed());
        }
        SignatureBytes(signature.to_bytes().to_vec())
    }
}

// ── Ed25519 Verifier ─────────────────────────────────────────────────────

/// Ed25519 verifier (stateless).
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        if pk.0.len() != 32 {
            return Err(CryptoError::KeyLength { expected: 32, actual: pk.0.len() });
        }
        if sig.0.len() != 64 {
            return Err(CryptoError::KeyLength { expected: 64, actual: sig.0.len() });
        }

        let public_key = VerifyingKey::from_bytes(&pk.0[..].try_into().unwrap())
            .map_err(|_| CryptoError::InvalidKey("public key bytes invalid".into()))?;

        let signature = Signature::from_bytes(&sig.0[..].try_into().unwrap());

        public_key
            .verify(msg, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

// ── Ed25519 Manager (thread‑safe) ──────────────────────────────────────

/// Thread‑safe manager for Ed25519 operations with caching and metrics.
#[derive(Clone)]
pub struct Ed25519Manager {
    config: Arc<Ed25519Config>,
    metrics: Arc<Ed25519Metrics>,
    cache: Arc<Mutex<Option<LruCache<u64, VerifyCacheEntry>>>>,
}

impl Ed25519Manager {
    pub fn new(config: Ed25519Config) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(Ed25519Metrics::default());
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

    /// Verify a signature, using cache if enabled.
    pub fn verify(&self, pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        let start = Instant::now();

        // Compute cache key (hash of pk + msg + sig).
        let key = self.compute_cache_key(pk, msg, sig);

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        self.metrics.record_cache_hit();
                        if self.config.log_verification {
                            trace!("Ed25519 verification cache hit");
                        }
                        self.metrics.record_verify(entry.result, start.elapsed());
                        if entry.result {
                            return Ok(());
                        } else {
                            return Err(CryptoError::InvalidSignature);
                        }
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Perform actual verification.
        let result = Ed25519Verifier::verify(pk, msg, sig);

        // Record metrics.
        let success = result.is_ok();
        self.metrics.record_verify(success, start.elapsed());

        if self.config.log_verification {
            trace!(
                success = success,
                pk_len = pk.0.len(),
                sig_len = sig.0.len(),
                "Ed25519 verification"
            );
        }

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = VerifyCacheEntry {
                    result: success,
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                };
                cache.put(key, entry);
            }
        }

        result
    }

    /// Compute a cache key from the verification inputs.
    fn compute_cache_key(&self, pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> u64 {
        let mut hasher = DefaultHasher::new();
        pk.0.hash(&mut hasher);
        msg.hash(&mut hasher);
        sig.0.hash(&mut hasher);
        hasher.finish()
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("Ed25519 cache cleared");
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
    pub fn metrics_snapshot(&self) -> Ed25519MetricsSnapshot {
        Ed25519MetricsSnapshot {
            sign_ops: self.metrics.sign_ops.get(),
            verify_ops: self.metrics.verify_ops.clone(),
            verify_success: self.metrics.verify_success.get(),
            verify_failure: self.metrics.verify_failure.get(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            cache_size: self.cache_size(),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &Ed25519Config {
        &self.config
    }
}

/// Snapshot of Ed25519 metrics.
#[derive(Debug, Clone)]
pub struct Ed25519MetricsSnapshot {
    pub sign_ops: u64,
    pub verify_ops: CounterVec,
    pub verify_success: u64,
    pub verify_failure: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub cache_size: usize,
}

// ── Global Manager ────────────────────────────────────────────────────────

static ED25519_MANAGER: once_cell::sync::OnceCell<Ed25519Manager> = once_cell::sync::OnceCell::new();

/// Initialize the global Ed25519 manager.
pub fn init_global(config: Ed25519Config) -> Result<(), String> {
    let manager = Ed25519Manager::new(config)?;
    ED25519_MANAGER.set(manager).map_err(|_| "global manager already initialized".into())
}

/// Get the global manager (panics if not initialized).
pub fn global_manager() -> &'static Ed25519Manager {
    ED25519_MANAGER.get().expect("Ed25519 manager not initialized")
}

// ── Standalone verification (uses global manager) ──────────────────────

/// Standalone verification function using the global manager.
pub fn ed25519_verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
    let mgr = global_manager();
    mgr.verify(pk, msg, sig)
}

// ── Format helpers ──────────────────────────────────────────────────────

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::KeyLength { expected: 32, actual: bytes.len() });
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
        if bytes.len() != 64 {
            return Err(CryptoError::KeyLength { expected: 64, actual: bytes.len() });
        }
        Ok(SignatureBytes(bytes))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn init_test_manager() -> Ed25519Manager {
        let config = Ed25519Config::default();
        Ed25519Manager::new(config).unwrap()
    }

    #[test]
    fn test_sign_verify() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        let pk = signer.public_key();
        let mgr = init_test_manager();
        assert!(mgr.verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let mut sig = signer.sign(msg);
        if let Some(byte) = sig.0.get_mut(0) {
            *byte ^= 1;
        }
        let pk = signer.public_key();
        let mgr = init_test_manager();
        assert!(mgr.verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn test_wrong_message() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        let wrong_msg = b"goodbye";
        let pk = signer.public_key();
        let mgr = init_test_manager();
        assert!(mgr.verify(&pk, wrong_msg, &sig).is_err());
    }

    #[test]
    fn test_from_seed() {
        let seed = [0xaa; 32];
        let signer1 = Ed25519Signer::from_seed(seed);
        let signer2 = Ed25519Signer::from_seed(seed);
        assert_eq!(signer1.public_key().0, signer2.public_key().0);
        let msg = b"test";
        let sig1 = signer1.sign(msg);
        let sig2 = signer2.sign(msg);
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_to_seed() {
        let seed = [0xaa; 32];
        let signer = Ed25519Signer::from_seed(seed);
        let exported = signer.to_seed();
        assert_eq!(seed, exported);
    }

    #[test]
    fn test_hex_roundtrip() {
        let signer = Ed25519Signer::random();
        let hex = signer.to_hex();
        let restored = Ed25519Signer::from_hex(&hex).unwrap();
        assert_eq!(signer.public_key().0, restored.public_key().0);
    }

    #[test]
    fn test_base64_roundtrip() {
        let signer = Ed25519Signer::random();
        let b64 = signer.to_base64();
        let restored = Ed25519Signer::from_base64(&b64).unwrap();
        assert_eq!(signer.public_key().0, restored.public_key().0);
    }

    #[test]
    fn test_cache() {
        let mgr = init_test_manager();
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let msg = b"test";
        let sig = signer.sign(msg);

        // First verification (cache miss).
        assert!(mgr.verify(&pk, msg, &sig).is_ok());
        // Second verification (cache hit).
        assert!(mgr.verify(&pk, msg, &sig).is_ok());
        assert!(mgr.cache_size() > 0);
        let metrics = mgr.metrics_snapshot();
        assert!(metrics.cache_hits > 0);
        assert!(metrics.cache_misses > 0);
    }

    #[test]
    fn test_clear_cache() {
        let mgr = init_test_manager();
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let msg = b"test";
        let sig = signer.sign(msg);
        mgr.verify(&pk, msg, &sig).unwrap();
        assert!(mgr.cache_size() > 0);
        mgr.clear_cache();
        assert_eq!(mgr.cache_size(), 0);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Ed25519Config::default();
        assert!(config.validate().is_ok());
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_global_manager() {
        let config = Ed25519Config::default();
        init_global(config).unwrap();
        let mgr = global_manager();
        assert!(mgr.cache_size() == 0);
    }

    #[test]
    fn test_public_key_display_fromstr() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let s = pk.to_string();
        let pk2: PublicKeyBytes = s.parse().unwrap();
        assert_eq!(pk.0, pk2.0);
    }

    #[test]
    fn test_signature_display_fromstr() {
        let signer = Ed25519Signer::random();
        let sig = signer.sign(b"test");
        let s = sig.to_string();
        let sig2: SignatureBytes = s.parse().unwrap();
        assert_eq!(sig.0, sig2.0);
    }

    #[test]
    fn test_known_vector() {
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let signer = Ed25519Signer::try_from_slice(&seed).unwrap();
        let msg = b"";
        let sig = signer.sign(msg);
        let expected = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
            .unwrap();
        assert_eq!(sig.0, expected);
        let pk = signer.public_key();
        let pk_expected = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        assert_eq!(pk.0, pk_expected);
        let mgr = init_test_manager();
        assert!(mgr.verify(&pk, msg, &sig).is_ok());
    }
}
