//! Cryptographic primitives for IONA.
//!
//! This module provides:
//! - Public key and signature type wrappers with hex and base64 serialisation.
//! - Traits `Signer` and `Verifier` for pluggable signing backends.
//! - Ed25519 implementation (ed25519 module).
//! - Transaction signing utilities (tx module).
//! - Encrypted keystore (keystore module).
//! - Remote signer client (remote_signer module).
//! - HSM support (hsm module, optional).
//!
//! # Production Features
//! - Unified `CryptoConfig` for all cryptographic subsystems.
//! - `CryptoManager` as a thread‑safe container for signers and verifiers.
//! - `CryptoMetrics` for monitoring signing operations, errors, and latency.
//! - Support for key backup and restoration.
//! - Comprehensive validation and error handling.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Submodules ────────────────────────────────────────────────────────────

pub mod ed25519;
pub mod tx;
pub mod keystore;
pub mod remote_signer;
pub mod hsm;

// ── Re‑exports ───────────────────────────────────────────────────────────

pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use tx::{derive_address, tx_sign_bytes, tx_verify_signature};
pub use keystore::{KeystoreConfig, KeystoreManager, KeystoreOptions, SecretString};
pub use remote_signer::{RemoteSigner, RemoteSignerConfig};
#[cfg(feature = "hsm")]
pub use hsm::{HsmManager, HsmSigner, KeyBackendConfig};

// ── Constants ─────────────────────────────────────────────────────────────

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

/// Default network timeout in seconds.
pub const DEFAULT_NETWORK_TIMEOUT_SECS: u64 = 10;

/// Default retry attempts for crypto operations.
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default initial backoff in milliseconds.
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;

/// Default maximum backoff in milliseconds.
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 5000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Unified configuration for cryptographic subsystems.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Network timeout in seconds.
    pub network_timeout_secs: u64,
    /// Retry attempts for operations.
    pub retry_attempts: u32,
    /// Initial backoff in milliseconds.
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds.
    pub max_backoff_ms: u64,
    /// Keystore configuration.
    pub keystore: keystore::KeystoreConfig,
    /// Remote signer configuration (optional).
    #[serde(default)]
    pub remote_signer: Option<remote_signer::RemoteSignerConfig>,
    /// HSM configuration (optional).
    #[serde(default)]
    pub hsm: Option<hsm::KeyBackendConfig>,
    /// Whether to enable metrics.
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    /// Whether to log operations.
    #[serde(default = "default_true")]
    pub log_operations: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            network_timeout_secs: DEFAULT_NETWORK_TIMEOUT_SECS,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            keystore: keystore::KeystoreConfig::default(),
            remote_signer: None,
            hsm: None,
            enable_metrics: default_true(),
            log_operations: default_true(),
        }
    }
}

impl CryptoConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.network_timeout_secs == 0 {
            return Err("network_timeout_secs must be > 0".into());
        }
        if self.retry_attempts == 0 {
            return Err("retry_attempts must be > 0".into());
        }
        if self.initial_backoff_ms == 0 {
            return Err("initial_backoff_ms must be > 0".into());
        }
        if self.max_backoff_ms == 0 {
            return Err("max_backoff_ms must be > 0".into());
        }
        self.keystore.validate()
            .map_err(|e| format!("keystore validation: {}", e))?;
        if let Some(ref rs) = self.remote_signer {
            rs.validate()
                .map_err(|e| format!("remote signer validation: {}", e))?;
        }
        if let Some(ref hsm) = self.hsm {
            hsm.validate()
                .map_err(|e| format!("HSM validation: {}", e))?;
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Cryptographic errors that can occur during signature verification or key handling.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid key.
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Key length mismatch.
    #[error("invalid key length: expected {expected}, got {actual}")]
    KeyLength { expected: usize, actual: usize },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Network error.
    #[error("network error: {0}")]
    Network(String),

    /// Timeout error.
    #[error("timeout")]
    Timeout,

    /// Backend‑specific error.
    #[error("backend error: {0}")]
    Backend(String),

    /// Internal error.
    #[error("internal error: {0}")]
    Internal(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// ── PublicKeyBytes ───────────────────────────────────────────────────────

/// Public key bytes wrapper with hex and base64 serialisation.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl PublicKeyBytes {
    /// Create a new public key from a hex string.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }

    /// Create a new public key from a base64 string.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = base64::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }

    /// Encode the public key as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Encode the public key as a base64 string.
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Check if the public key is empty.
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }

    /// Get the public key as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ── SignatureBytes ──────────────────────────────────────────────────────

/// Signature bytes wrapper (usually 64 bytes for Ed25519).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureBytes(pub Vec<u8>);

impl SignatureBytes {
    /// Create a new signature from a hex string.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
    }

    /// Create a new signature from a base64 string.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = base64::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
    }

    /// Encode the signature as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Encode the signature as a base64 string.
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Get the signature as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for SignatureBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// ── Signer trait ─────────────────────────────────────────────────────────

/// A signer that can produce signatures for arbitrary messages.
pub trait Signer: Send + Sync {
    /// Return the public key corresponding to this signer.
    fn public_key(&self) -> PublicKeyBytes;

    /// Sign the given message and return the signature.
    fn sign(&self, msg: &[u8]) -> SignatureBytes;

    /// Return a human‑readable name of the signing backend.
    fn backend_name(&self) -> &str {
        "unknown"
    }

    /// Check if the signer is healthy / reachable.
    fn health_check(&self) -> CryptoResult<()> {
        Ok(())
    }
}

// ── Verifier trait ──────────────────────────────────────────────────────

/// A stateless verifier that can validate signatures against public keys.
pub trait Verifier: Send + Sync {
    /// Verify that `sig` is a valid signature for `msg` under `pk`.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()>;

    /// Verify a batch of signatures (same key, multiple messages).
    fn verify_batch(
        pk: &PublicKeyBytes,
        msgs: &[&[u8]],
        sigs: &[SignatureBytes],
    ) -> CryptoResult<()> {
        if msgs.len() != sigs.len() {
            return Err(CryptoError::KeyLength {
                expected: msgs.len(),
                actual: sigs.len(),
            });
        }
        for (msg, sig) in msgs.iter().zip(sigs.iter()) {
            Self::verify(pk, msg, sig)?;
        }
        Ok(())
    }
}

// ── CryptoManager ──────────────────────────────────────────────────────

/// Thread‑safe manager for cryptographic operations.
#[derive(Clone)]
pub struct CryptoManager {
    config: Arc<CryptoConfig>,
    signer: Arc<Box<dyn Signer>>,
    verifier: Arc<dyn Verifier>,
    metrics: Arc<CryptoMetrics>,
}

impl CryptoManager {
    /// Create a new manager with the given signer and verifier.
    pub fn new(
        config: CryptoConfig,
        signer: Box<dyn Signer>,
        verifier: Arc<dyn Verifier>,
    ) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(CryptoMetrics::default());
        Ok(Self {
            config: Arc::new(config),
            signer: Arc::new(signer),
            verifier,
            metrics,
        })
    }

    /// Get the public key.
    pub fn public_key(&self) -> PublicKeyBytes {
        self.signer.public_key()
    }

    /// Sign a message, recording metrics.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let start = Instant::now();
        let result = self.signer.sign(msg);
        let duration = start.elapsed();
        self.metrics.record_sign(self.signer.backend_name(), duration);
        if self.config.log_operations {
            trace!(
                backend = self.signer.backend_name(),
                msg_len = msg.len(),
                duration_ms = duration.as_millis(),
                "signature generated"
            );
        }
        result
    }

    /// Verify a signature.
    pub fn verify(&self, pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
        let start = Instant::now();
        let result = self.verifier.verify(pk, msg, sig);
        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_verify(status, duration);
        if self.config.log_operations {
            trace!(
                status = status,
                duration_ms = duration.as_millis(),
                "signature verification"
            );
        }
        result
    }

    /// Verify a batch of signatures.
    pub fn verify_batch(
        &self,
        pk: &PublicKeyBytes,
        msgs: &[&[u8]],
        sigs: &[SignatureBytes],
    ) -> CryptoResult<()> {
        self.verifier.verify_batch(pk, msgs, sigs)
    }

    /// Health check.
    pub fn health_check(&self) -> CryptoResult<()> {
        self.signer.health_check()
    }

    /// Get the backend name.
    pub fn backend_name(&self) -> &str {
        self.signer.backend_name()
    }

    /// Get configuration.
    pub fn config(&self) -> &CryptoConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> CryptoMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ── CryptoMetrics ──────────────────────────────────────────────────────

/// Metrics for cryptographic operations.
#[derive(Clone)]
pub struct CryptoMetrics {
    pub sign_operations: prometheus::CounterVec,
    pub sign_latency: prometheus::HistogramVec,
    pub verify_operations: prometheus::CounterVec,
    pub verify_latency: prometheus::HistogramVec,
}

impl CryptoMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let sign_operations = prometheus::register_counter_vec!(
            "iona_crypto_sign_operations_total",
            "Total sign operations",
            &["backend"]
        )?;
        let sign_latency = prometheus::register_histogram_vec!(
            "iona_crypto_sign_latency_seconds",
            "Sign latency",
            &["backend"]
        )?;
        let verify_operations = prometheus::register_counter_vec!(
            "iona_crypto_verify_operations_total",
            "Total verify operations",
            &["status"]
        )?;
        let verify_latency = prometheus::register_histogram_vec!(
            "iona_crypto_verify_latency_seconds",
            "Verify latency",
            &["status"]
        )?;
        Ok(Self {
            sign_operations,
            sign_latency,
            verify_operations,
            verify_latency,
        })
    }

    pub fn record_sign(&self, backend: &str, duration: Duration) {
        self.sign_operations.with_label_values(&[backend]).inc();
        self.sign_latency.with_label_values(&[backend]).observe(duration.as_secs_f64());
    }

    pub fn record_verify(&self, status: &str, duration: Duration) {
        self.verify_operations.with_label_values(&[status]).inc();
        self.verify_latency.with_label_values(&[status]).observe(duration.as_secs_f64());
    }

    pub fn snapshot(&self) -> CryptoMetricsSnapshot {
        CryptoMetricsSnapshot {
            sign_operations: self.sign_operations.clone(),
            verify_operations: self.verify_operations.clone(),
        }
    }
}

impl Default for CryptoMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            sign_operations: prometheus::CounterVec::new(
                prometheus::Opts::new("iona_crypto_sign_operations_total", "Sign ops"),
                &["backend"],
            ).unwrap(),
            sign_latency: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_crypto_sign_latency_seconds",
                    "Sign latency",
                ),
                &["backend"],
            ).unwrap(),
            verify_operations: prometheus::CounterVec::new(
                prometheus::Opts::new("iona_crypto_verify_operations_total", "Verify ops"),
                &["status"],
            ).unwrap(),
            verify_latency: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_crypto_verify_latency_seconds",
                    "Verify latency",
                ),
                &["status"],
            ).unwrap(),
        })
    }
}

/// Snapshot of crypto metrics.
#[derive(Debug, Clone)]
pub struct CryptoMetricsSnapshot {
    pub sign_operations: prometheus::CounterVec,
    pub verify_operations: prometheus::CounterVec,
}

// ── Convenience functions ──────────────────────────────────────────────

/// Verify an Ed25519 signature.
pub fn verify_ed25519(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    ed25519::Ed25519Verifier::verify(pk, msg, sig)
}

/// Create a public key from a hex string.
pub fn public_key_from_hex(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_hex(s)
}

/// Create a public key from a base64 string.
pub fn public_key_from_base64(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_base64(s)
}

/// Create a signature from a hex string.
pub fn signature_from_hex(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_hex(s)
}

/// Create a signature from a base64 string.
pub fn signature_from_base64(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_base64(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
    use std::sync::Arc;

    #[test]
    fn test_public_key_bytes_hex_roundtrip() {
        let orig = PublicKeyBytes(vec![0xAA; 32]);
        let hex = orig.to_hex();
        let restored = PublicKeyBytes::from_hex(&hex).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_base64_roundtrip() {
        let orig = PublicKeyBytes(vec![0xBB; 32]);
        let b64 = orig.to_base64();
        let restored = PublicKeyBytes::from_base64(&b64).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_display_fromstr() {
        let orig = PublicKeyBytes(vec![0xCC; 32]);
        let s = orig.to_string();
        let restored: PublicKeyBytes = s.parse().unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_serialize() {
        let pk = PublicKeyBytes(vec![0xDD; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains(&pk.to_hex()));
        let restored: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn test_signature_bytes_hex_roundtrip() {
        let orig = SignatureBytes(vec![0xEE; 64]);
        let hex = orig.to_hex();
        let restored = SignatureBytes::from_hex(&hex).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_signature_bytes_display_fromstr() {
        let orig = SignatureBytes(vec![0xFF; 64]);
        let s = orig.to_string();
        let restored: SignatureBytes = s.parse().unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_crypto_manager() {
        let signer = Box::new(Ed25519Signer::random());
        let verifier = Arc::new(Ed25519Verifier);
        let config = CryptoConfig::default();
        let manager = CryptoManager::new(config, signer, verifier).unwrap();

        let pk = manager.public_key();
        let msg = b"hello world";
        let sig = manager.sign(msg);
        assert!(manager.verify(&pk, msg, &sig).is_ok());
        assert!(manager.health_check().is_ok());
        assert_eq!(manager.backend_name(), "local");
    }

    #[test]
    fn test_config_validation() {
        let mut config = CryptoConfig::default();
        assert!(config.validate().is_ok());
        config.network_timeout_secs = 0;
        assert!(config.validate().is_err());
        config.network_timeout_secs = 10;
        config.retry_attempts = 0;
        assert!(config.validate().is_err());
        config.retry_attempts = 3;
        config.initial_backoff_ms = 0;
        assert!(config.validate().is_err());
        config.initial_backoff_ms = 100;
        config.max_backoff_ms = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::InvalidSignature;
        assert_eq!(err.to_string(), "invalid signature");
        let err = CryptoError::KeyLength { expected: 32, actual: 16 };
        assert!(err.to_string().contains("32"));
        assert!(err.to_string().contains("16"));
    }
}
