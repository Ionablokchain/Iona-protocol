//! Cryptographic primitives for IONA.
//!
//! Provides:
//! - [`PublicKeyBytes`] and [`SignatureBytes`] type wrappers with hex
//!   and base64 serialization.
//! - The infallible [`Signer`] trait for **local** signing backends, and
//!   the (separate, fallible) `HsmSigner` trait for remote/HSM backends
//!   — see the [`hsm`] module.
//! - [`Verifier`], a stateless trait for signature validation.
//! - [`CryptoManager`], a thread-safe container that binds a signer, a
//!   verifier, and a metrics bundle.
//!
//! # Which trait do I want?
//!
//! | Backend                  | Trait       | Failure mode            |
//! |--------------------------|-------------|-------------------------|
//! | Local Ed25519 keypair    | [`Signer`]  | infallible (`SignatureBytes`) |
//! | Remote signer / HSM/KMS  | `HsmSigner` | fallible (`Result<SignatureBytes, CryptoError>`) |
//!
//! `CryptoManager` wraps a `Signer` and is intended for the local case.
//! For a remote/HSM backend, construct an `HsmManager` directly — the
//! two managers are distinct because their failure models differ, and a
//! uniform "signature or error" return type would force every local-only
//! caller to `.expect()` on every signature.
//!
//! # Base64
//!
//! This module targets the `base64` 0.13–0.20 free-function API
//! (`base64::encode` / `base64::decode`). For `base64 >= 0.21`, replace
//! with `base64::engine::general_purpose::STANDARD.encode / decode`.
//!
//! # Hex
//!
//! Hex input accepts an optional `0x`/`0X` prefix, matching the rest of
//! the codebase. Output is always lowercase, unprefixed hex.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::trace;

// ── Submodules ────────────────────────────────────────────────────────────

pub mod ed25519;
pub mod hsm;
pub mod keystore;
pub mod remote_signer;
pub mod tx;

// ── Re-exports ────────────────────────────────────────────────────────────

pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use keystore::{KeystoreConfig, KeystoreManager, KeystoreOptions, SecretString};
pub use remote_signer::{RemoteSigner, RemoteSignerConfig};
pub use tx::{derive_address, tx_sign_bytes, tx_verify_signature};

#[cfg(feature = "hsm")]
pub use hsm::{HsmManager, HsmSigner, KeyBackendConfig};

// ── Constants ─────────────────────────────────────────────────────────────

/// Length of an Ed25519 public key, in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature, in bytes.
pub const SIGNATURE_LEN: usize = 64;

pub const DEFAULT_NETWORK_TIMEOUT_SECS: u64 = 10;
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 100;
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 5_000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Unified configuration for the cryptographic subsystems.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CryptoConfig {
    pub network_timeout_secs: u64,
    pub retry_attempts: u32,
    pub initial_backoff_ms: u64,
    pub max_backoff_ms: u64,
    pub keystore: keystore::KeystoreConfig,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_signer: Option<remote_signer::RemoteSignerConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hsm: Option<hsm::KeyBackendConfig>,
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
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
            enable_metrics: true,
            log_operations: true,
        }
    }
}

impl CryptoConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), CryptoError> {
        if self.network_timeout_secs == 0 {
            return Err(CryptoError::Config("network_timeout_secs must be > 0".into()));
        }
        if self.retry_attempts == 0 {
            return Err(CryptoError::Config("retry_attempts must be > 0".into()));
        }
        if self.initial_backoff_ms == 0 {
            return Err(CryptoError::Config("initial_backoff_ms must be > 0".into()));
        }
        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(CryptoError::Config(
                "max_backoff_ms must be >= initial_backoff_ms".into(),
            ));
        }
        self.keystore
            .validate()
            .map_err(|e| CryptoError::Config(format!("keystore: {e}")))?;
        if let Some(rs) = &self.remote_signer {
            rs.validate()
                .map_err(|e| CryptoError::Config(format!("remote signer: {e}")))?;
        }
        if let Some(hsm) = &self.hsm {
            hsm.validate()
                .map_err(|e| CryptoError::Config(format!("hsm: {e}")))?;
        }
        Ok(())
    }
}

fn default_true() -> bool {
    true
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Cryptographic errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid key: {0}")]
    InvalidKey(String),

    #[error("invalid key length: expected {expected}, got {actual}")]
    KeyLength { expected: usize, actual: usize },

    #[error("key not found")]
    KeyNotFound,

    #[error("backend unsupported: {0}")]
    BackendUnsupported(String),

    #[error("batch length mismatch: {msgs} messages, {sigs} signatures")]
    BatchLengthMismatch { msgs: usize, sigs: usize },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("network error: {0}")]
    Network(String),

    #[error("timeout")]
    Timeout,

    #[error("backend error: {0}")]
    Backend(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// ── Hex / base64 helpers ──────────────────────────────────────────────────

/// Decode hex, tolerating an optional `0x`/`0X` prefix.
fn decode_hex(s: &str) -> CryptoResult<Vec<u8>> {
    let trimmed = s
        .strip_prefix("0x")
        .or_else(|| s.strip_prefix("0X"))
        .unwrap_or(s);
    hex::decode(trimmed).map_err(|e| CryptoError::InvalidKey(format!("hex: {e}")))
}

/// Decode base64. See the module doc for the base64 version note.
fn decode_base64(s: &str) -> CryptoResult<Vec<u8>> {
    base64::decode(s).map_err(|e| CryptoError::InvalidKey(format!("base64: {e}")))
}

fn encode_base64(bytes: &[u8]) -> String {
    base64::encode(bytes)
}

// ── PublicKeyBytes ────────────────────────────────────────────────────────

/// Public key bytes with hex/base64 serialization.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl PublicKeyBytes {
    /// Parse from a hex string (optional `0x` prefix). Enforces
    /// [`PUBLIC_KEY_LEN`].
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = decode_hex(s)?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Parse from a base64 string. Enforces [`PUBLIC_KEY_LEN`].
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = decode_base64(s)?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Build from a raw byte slice. Enforces [`PUBLIC_KEY_LEN`].
    pub fn try_from_slice(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    /// Lowercase, unprefixed hex.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Standard base64. See the module doc for the version note.
    #[must_use]
    pub fn to_base64(&self) -> String {
        encode_base64(&self.0)
    }

    /// Whether every byte is zero.
    ///
    /// **Not** the same as "empty": an all-zero 32-byte Ed25519 key is a
    /// syntactically valid key that will never verify a signature. The
    /// previous `is_empty()` name was misleading — this method has been
    /// renamed.
    #[must_use]
    pub fn is_all_zero(&self) -> bool {
        !self.0.is_empty() && self.0.iter().all(|&b| b == 0)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether the byte vector is empty (length 0). Valid keys are never
    /// empty; this exists for `is_empty`/`len` symmetry.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for PublicKeyBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// ── SignatureBytes ────────────────────────────────────────────────────────

/// Signature bytes (64 bytes for Ed25519).
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

impl SignatureBytes {
    /// Parse from a hex string (optional `0x` prefix). Enforces
    /// [`SIGNATURE_LEN`].
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = decode_hex(s)?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Parse from a base64 string. Enforces [`SIGNATURE_LEN`].
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = decode_base64(s)?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes))
    }

    /// Build from a raw byte slice. Enforces [`SIGNATURE_LEN`].
    pub fn try_from_slice(bytes: &[u8]) -> CryptoResult<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(Self(bytes.to_vec()))
    }

    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    #[must_use]
    pub fn to_base64(&self) -> String {
        encode_base64(&self.0)
    }

    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl AsRef<[u8]> for SignatureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl FromStr for SignatureBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// ── Signer trait (infallible, local) ──────────────────────────────────────

/// Infallible signer for **local** keypairs.
///
/// A `Signer` must be able to produce a signature without any I/O. That
/// is true for in-memory Ed25519 keys and false for remote signers, HSMs,
/// and cloud KMS — those use the separate (fallible) `HsmSigner` trait in
/// the [`hsm`] module.
///
/// If you find yourself wanting to return an error from `sign`, you
/// probably want `HsmSigner`, not this trait.
pub trait Signer: Send + Sync {
    fn public_key(&self) -> PublicKeyBytes;
    fn sign(&self, msg: &[u8]) -> SignatureBytes;

    /// Human-readable backend name for logs and metrics labels.
    fn backend_name(&self) -> &'static str {
        "unknown"
    }

    /// Liveness probe. For a local signer this returns `Ok(())`.
    fn health_check(&self) -> CryptoResult<()> {
        Ok(())
    }
}

// ── Verifier trait ────────────────────────────────────────────────────────

/// Stateless signature verifier.
pub trait Verifier: Send + Sync {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()>;

    /// Verify a batch. The default implementation loops over `verify`.
    ///
    /// # Errors
    ///
    /// - [`CryptoError::BatchLengthMismatch`] if `msgs.len() != sigs.len()`.
    /// - Any error returned by [`verify`](Self::verify).
    fn verify_batch(
        pk: &PublicKeyBytes,
        msgs: &[&[u8]],
        sigs: &[SignatureBytes],
    ) -> CryptoResult<()> {
        if msgs.len() != sigs.len() {
            return Err(CryptoError::BatchLengthMismatch {
                msgs: msgs.len(),
                sigs: sigs.len(),
            });
        }
        for (msg, sig) in msgs.iter().zip(sigs.iter()) {
            Self::verify(pk, msg, sig)?;
        }
        Ok(())
    }
}

// ── CryptoManager ─────────────────────────────────────────────────────────

/// Thread-safe container for a signer, a verifier, and metrics.
///
/// Cloning shares state via `Arc`. `CryptoManager` wraps the infallible
/// [`Signer`] trait, so it is intended for **local** keypairs. For a
/// remote/HSM backend, use `HsmManager` directly.
#[derive(Clone)]
pub struct CryptoManager {
    config: Arc<CryptoConfig>,
    signer: Arc<dyn Signer>,
    verifier: Arc<dyn Verifier>,
    metrics: Arc<CryptoMetrics>,
}

impl CryptoManager {
    /// Construct a manager with unregistered metrics.
    ///
    /// `enable_metrics` in the config is honoured: when `true`, the
    /// constructor tries to register with the default Prometheus
    /// registry and falls back to unregistered metrics on a name
    /// collision (a very common test-suite situation).
    ///
    /// # Errors
    ///
    /// Returns `Err(CryptoError::Config)` if `config.validate()` fails.
    pub fn new(
        config: CryptoConfig,
        signer: Box<dyn Signer>,
        verifier: Arc<dyn Verifier>,
    ) -> CryptoResult<Self> {
        config.validate()?;
        let metrics = if config.enable_metrics {
            match CryptoMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "crypto metrics already registered; using unregistered instance"
                    );
                    CryptoMetrics::unregistered()
                }
            }
        } else {
            CryptoMetrics::unregistered()
        };
        Ok(Self {
            config: Arc::new(config),
            signer: Arc::from(signer),
            verifier,
            metrics: Arc::new(metrics),
        })
    }

    /// Construct with a caller-supplied metrics handle. Use this when
    /// the caller has already registered metrics once at startup.
    pub fn with_metrics(
        config: CryptoConfig,
        signer: Box<dyn Signer>,
        verifier: Arc<dyn Verifier>,
        metrics: CryptoMetrics,
    ) -> CryptoResult<Self> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            signer: Arc::from(signer),
            verifier,
            metrics: Arc::new(metrics),
        })
    }

    #[must_use]
    pub fn public_key(&self) -> PublicKeyBytes {
        self.signer.public_key()
    }

    /// Sign a message.
    ///
    /// This method is infallible because it wraps a [`Signer`], which is
    /// the infallible (local) trait. For remote/HSM signing, use
    /// `HsmManager::sign` instead.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let start = Instant::now();
        let sig = self.signer.sign(msg);
        let duration = start.elapsed();
        self.metrics.record_sign(self.signer.backend_name(), duration);
        if self.config.log_operations {
            trace!(
                backend = self.signer.backend_name(),
                msg_len = msg.len(),
                duration_us = duration.as_micros() as u64,
                "signature generated"
            );
        }
        sig
    }

    /// Verify a signature.
    pub fn verify(
        &self,
        pk: &PublicKeyBytes,
        msg: &[u8],
        sig: &SignatureBytes,
    ) -> CryptoResult<()> {
        let start = Instant::now();
        let result = self.verifier.verify(pk, msg, sig);
        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_verify(status, duration);
        if self.config.log_operations {
            trace!(
                status,
                duration_us = duration.as_micros() as u64,
                "signature verification"
            );
        }
        result
    }

    pub fn verify_batch(
        &self,
        pk: &PublicKeyBytes,
        msgs: &[&[u8]],
        sigs: &[SignatureBytes],
    ) -> CryptoResult<()> {
        self.verifier.verify_batch(pk, msgs, sigs)
    }

    pub fn health_check(&self) -> CryptoResult<()> {
        self.signer.health_check()
    }

    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.signer.backend_name()
    }

    #[must_use]
    pub fn config(&self) -> &CryptoConfig {
        &self.config
    }

    /// Owned snapshot of the current metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> CryptoMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ── CryptoMetrics ────────────────────────────────────────────────────────

/// Prometheus metrics for cryptographic operations.
///
/// [`new`](Self::new) registers with the default registry and can only
/// succeed once per process. [`unregistered`](Self::unregistered) is
/// fail-free; [`Default`] uses it.
#[derive(Clone)]
pub struct CryptoMetrics {
    pub sign_operations: prometheus::CounterVec,
    pub sign_latency: prometheus::HistogramVec,
    pub verify_operations: prometheus::CounterVec,
    pub verify_latency: prometheus::HistogramVec,
}

impl CryptoMetrics {
    /// Register with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            sign_operations: prometheus::register_counter_vec!(
                "iona_crypto_sign_operations_total",
                "Sign operations",
                &["backend"]
            )?,
            sign_latency: prometheus::register_histogram_vec!(
                "iona_crypto_sign_latency_seconds",
                "Sign latency",
                &["backend"]
            )?,
            verify_operations: prometheus::register_counter_vec!(
                "iona_crypto_verify_operations_total",
                "Verify operations",
                &["status"]
            )?,
            verify_latency: prometheus::register_histogram_vec!(
                "iona_crypto_verify_latency_seconds",
                "Verify latency",
                &["status"]
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        Self {
            sign_operations: prometheus::CounterVec::new(
                prometheus::Opts::new("iona_crypto_sign_operations_total", "Sign operations"),
                &["backend"],
            )
            .expect("counter vec construction is infallible"),
            sign_latency: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_crypto_sign_latency_seconds",
                    "Sign latency",
                ),
                &["backend"],
            )
            .expect("histogram vec construction is infallible"),
            verify_operations: prometheus::CounterVec::new(
                prometheus::Opts::new(
                    "iona_crypto_verify_operations_total",
                    "Verify operations",
                ),
                &["status"],
            )
            .expect("counter vec construction is infallible"),
            verify_latency: prometheus::HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_crypto_verify_latency_seconds",
                    "Verify latency",
                ),
                &["status"],
            )
            .expect("histogram vec construction is infallible"),
        }
    }

    pub fn record_sign(&self, backend: &str, duration: Duration) {
        self.sign_operations
            .with_label_values(&[backend])
            .inc();
        self.sign_latency
            .with_label_values(&[backend])
            .observe(duration.as_secs_f64());
    }

    pub fn record_verify(&self, status: &str, duration: Duration) {
        self.verify_operations
            .with_label_values(&[status])
            .inc();
        self.verify_latency
            .with_label_values(&[status])
            .observe(duration.as_secs_f64());
    }

    /// Owned, serializable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> CryptoMetricsSnapshot {
        CryptoMetricsSnapshot {
            sign_operations: collect(&self.sign_operations),
            verify_operations: collect(&self.verify_operations),
        }
    }
}

impl Default for CryptoMetrics {
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

/// Owned snapshot of [`CryptoMetrics`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoMetricsSnapshot {
    pub sign_operations: Vec<CounterSnapshot>,
    pub verify_operations: Vec<CounterSnapshot>,
}

fn collect(vec: &prometheus::CounterVec) -> Vec<CounterSnapshot> {
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

// ── Convenience helpers ──────────────────────────────────────────────────

/// Verify an Ed25519 signature.
pub fn verify_ed25519(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    ed25519::Ed25519Verifier::verify(pk, msg, sig)
}

pub fn public_key_from_hex(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_hex(s)
}

pub fn public_key_from_base64(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_base64(s)
}

pub fn signature_from_hex(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_hex(s)
}

pub fn signature_from_base64(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_base64(s)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── PublicKeyBytes ──────────────────────────────────────────────────

    #[test]
    fn public_key_hex_roundtrip() {
        let orig = PublicKeyBytes(vec![0xAA; 32]);
        assert_eq!(PublicKeyBytes::from_hex(&orig.to_hex()).unwrap(), orig);
    }

    #[test]
    fn public_key_hex_accepts_0x_prefix() {
        let orig = PublicKeyBytes(vec![0x11; 32]);
        let with_prefix = format!("0x{}", orig.to_hex());
        assert_eq!(PublicKeyBytes::from_hex(&with_prefix).unwrap(), orig);
    }

    #[test]
    fn public_key_base64_roundtrip() {
        let orig = PublicKeyBytes(vec![0xBB; 32]);
        assert_eq!(
            PublicKeyBytes::from_base64(&orig.to_base64()).unwrap(),
            orig
        );
    }

    #[test]
    fn public_key_rejects_wrong_length() {
        let hex = "00".repeat(31);
        let err = PublicKeyBytes::from_hex(&hex).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::KeyLength { expected: 32, actual: 31 }
        ));
    }

    #[test]
    fn public_key_rejects_non_hex() {
        assert!(matches!(
            PublicKeyBytes::from_hex("not-hex"),
            Err(CryptoError::InvalidKey(_))
        ));
    }

    #[test]
    fn is_all_zero_distinguishes_from_empty() {
        // Regression: the previous `is_empty()` returned true for any
        // all-zero key, which is a *valid* (if useless) Ed25519 key.
        let zero = PublicKeyBytes(vec![0u8; 32]);
        let empty = PublicKeyBytes(vec![]);
        assert!(zero.is_all_zero());
        assert!(!zero.is_empty());
        assert!(!empty.is_all_zero());
        assert!(empty.is_empty());
    }

    #[test]
    fn public_key_display_and_fromstr() {
        let pk = PublicKeyBytes(vec![0xCC; 32]);
        let parsed: PublicKeyBytes = pk.to_string().parse().unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn public_key_serde_roundtrip() {
        let pk = PublicKeyBytes(vec![0xDD; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains(&pk.to_hex()));
        let back: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, back);
    }

    // ── SignatureBytes ──────────────────────────────────────────────────

    #[test]
    fn signature_hex_roundtrip() {
        let s = SignatureBytes(vec![0xEE; 64]);
        assert_eq!(SignatureBytes::from_hex(&s.to_hex()).unwrap(), s);
    }

    #[test]
    fn signature_base64_roundtrip() {
        let s = SignatureBytes(vec![0xFF; 64]);
        assert_eq!(SignatureBytes::from_base64(&s.to_base64()).unwrap(), s);
    }

    #[test]
    fn signature_rejects_wrong_length() {
        let hex = "00".repeat(63);
        let err = SignatureBytes::from_hex(&hex).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::KeyLength { expected: 64, actual: 63 }
        ));
    }

    // ── Verifier::verify_batch ─────────────────────────────────────────

    #[test]
    fn verify_batch_reports_length_mismatch() {
        // Regression: the previous implementation returned
        // `KeyLength { expected: msgs.len(), actual: sigs.len() }`, which
        // was semantically wrong (a count, not a byte length) and
        // indistinguishable from a malformed key length.
        let signer = ed25519::Ed25519Signer::random();
        let pk = signer.public_key();
        let sigs = vec![signer.sign(b"a"), signer.sign(b"b")];
        let err =
            ed25519::Ed25519Verifier::verify_batch(&pk, &[b"a".as_slice()], &sigs).unwrap_err();
        assert!(matches!(
            err,
            CryptoError::BatchLengthMismatch { msgs: 1, sigs: 2 }
        ));
    }

    // ── CryptoManager ──────────────────────────────────────────────────

    #[test]
    fn manager_roundtrip() {
        let signer = Box::new(ed25519::Ed25519Signer::random());
        let verifier = Arc::new(ed25519::Ed25519Verifier);
        let mut config = CryptoConfig::default();
        config.enable_metrics = false; // avoid global registry in tests
        let m = CryptoManager::new(config, signer, verifier).unwrap();

        let pk = m.public_key();
        let sig = m.sign(b"hello");
        m.verify(&pk, b"hello", &sig).unwrap();
        assert_eq!(m.backend_name(), "local");
        assert!(m.health_check().is_ok());
    }

    #[test]
    fn manager_verify_rejects_wrong_message() {
        let signer = Box::new(ed25519::Ed25519Signer::random());
        let verifier = Arc::new(ed25519::Ed25519Verifier);
        let mut config = CryptoConfig::default();
        config.enable_metrics = false;
        let m = CryptoManager::new(config, signer, verifier).unwrap();

        let pk = m.public_key();
        let sig = m.sign(b"hello");
        assert!(matches!(
            m.verify(&pk, b"goodbye", &sig),
            Err(CryptoError::InvalidSignature)
        ));
    }

    #[test]
    fn manager_metrics_are_recorded_and_snapshotted() {
        let signer = Box::new(ed25519::Ed25519Signer::random());
        let verifier = Arc::new(ed25519::Ed25519Verifier);
        let mut config = CryptoConfig::default();
        config.enable_metrics = false;
        let m = CryptoManager::new(config, signer, verifier).unwrap();

        let pk = m.public_key();
        let sig = m.sign(b"x");
        m.verify(&pk, b"x", &sig).unwrap();
        m.verify(&pk, b"y", &sig).unwrap_err();

        let snap = m.metrics_snapshot();
        let ok = snap
            .verify_operations
            .iter()
            .find(|c| c.labels.get("status").map(String::as_str) == Some("ok"));
        let err = snap
            .verify_operations
            .iter()
            .find(|c| c.labels.get("status").map(String::as_str) == Some("error"));
        assert_eq!(ok.map(|c| c.value), Some(1));
        assert_eq!(err.map(|c| c.value), Some(1));
    }

    // ── Metrics default ────────────────────────────────────────────────

    #[test]
    fn metrics_default_does_not_panic() {
        // Regression: the previous `Default::default()` chained `.unwrap()`
        // inside `unwrap_or_else`, so a second instantiation in the same
        // process panicked on the Prometheus name collision.
        let _a = CryptoMetrics::unregistered();
        let _b = CryptoMetrics::unregistered();
        let _c = CryptoMetrics::default();
    }

    #[test]
    fn metrics_snapshot_is_serializable() {
        let m = CryptoMetrics::unregistered();
        m.record_sign("local", Duration::from_micros(123));
        m.record_verify("ok", Duration::from_micros(45));
        let snap = m.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: CryptoMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // ── Config ─────────────────────────────────────────────────────────

    #[test]
    fn config_default_validates() {
        assert!(CryptoConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_bad_values() {
        let mut c = CryptoConfig::default();
        c.network_timeout_secs = 0;
        assert!(c.validate().is_err());

        let mut c = CryptoConfig::default();
        c.retry_attempts = 0;
        assert!(c.validate().is_err());

        let mut c = CryptoConfig::default();
        c.initial_backoff_ms = 1000;
        c.max_backoff_ms = 100;
        assert!(c.validate().is_err());
    }

    // ── Errors ─────────────────────────────────────────────────────────

    #[test]
    fn error_display() {
        assert_eq!(CryptoError::InvalidSignature.to_string(), "invalid signature");
        assert_eq!(
            CryptoError::KeyLength { expected: 32, actual: 16 }.to_string(),
            "invalid key length: expected 32, got 16"
        );
        assert_eq!(
            CryptoError::BatchLengthMismatch { msgs: 3, sigs: 4 }.to_string(),
            "batch length mismatch: 3 messages, 4 signatures"
        );
    }
}
