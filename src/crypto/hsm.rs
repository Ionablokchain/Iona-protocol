//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Trait-based abstraction for signing operations, backed by:
//!
//! - **Local keystore** (default; Ed25519 keypair on disk, AES-encrypted).
//! - **Remote signer** (HTTPS service; mTLS + optional API key).
//! - **PKCS#11 HSM** (feature-gated; YubiHSM, Thales Luna, etc.).
//! - **Cloud KMS** (AWS / Azure / GCP) — declared in config, **not
//!   implemented**. `create_signer` returns `Err(BackendUnsupported)` for
//!   these instead of an unreachable stub.
//!
//! # Security model
//!
//! ## Fail-closed key loading
//!
//! [`create_signer`] **never generates a key silently**. A missing
//! keystore with a `Local` backend returns
//! [`CryptoError::KeyNotFound`] unless the config explicitly sets
//! `Local::allow_generate = true`. This closes the previous bug where a
//! node restarted without `IONA_KEYSTORE_PASSWORD` in its environment
//! would generate a *new* validator key and start signing with it —
//! producing slashable equivocation on the very next block.
//!
//! When `allow_generate` is set, the freshly generated key is **persisted
//! to the keystore before `create_signer` returns**. If persistence
//! fails, the key is discarded and an error is returned; the node does
//! not start with an unpersisted key.
//!
//! ## Secret handling
//!
//! [`SecretString`] renders as `[REDACTED]` in `Debug` and `Serialize`,
//! and **refuses to deserialize** the `[REDACTED]` literal. Any field
//! that needs a secret at runtime should pull it from the environment (or
//! a file with restricted permissions), not from the JSON config. Any
//! field carrying a `SecretString` that needs to survive a
//! serialize/deserialize round trip will **not** — that is intentional.
//!
//! ## Zeroization
//!
//! - `SigningKey` (`ed25519-dalek` 2.x) zeroizes on drop.
//! - [`LocalSigner::try_from_slice`], [`try_from_keystore`],
//!   [`try_from_hex`], [`try_from_base64`], and the keystore-write path
//!   in [`create_signer`] zeroize intermediate seed buffers before
//!   returning.
//! - [`SecretString::drop`] zeroizes the underlying `String`.
//!
//! ## Remote signer
//!
//! The signer fetches the public key at construction and rejects a
//! response whose length is not exactly 32 bytes. The HTTP client is
//! configured with an explicit timeout; **there is no automatic retry**.
//! A transient network failure at startup aborts construction, and the
//! caller decides whether to retry, back off, or fall back to another
//! backend.
//!
//! ## PKCS#11 caveats
//!
//! The `pkcs11` feature targets `cryptoki` 0.7 (or a compatible fork).
//! `Session::sign` takes `&mut self` in most versions; `Session` is not
//! `Sync` on all platforms. This module serializes signing through a
//! [`parking_lot::Mutex`] and documents the requirement. **None of the
//! PKCS#11 code is exercised by the default test suite** — it is gated
//! behind `#[cfg(feature = "pkcs11")]`.
//!
//! ## Base64
//!
//! The remote signer uses the `base64` 0.13–0.20 free-function API
//! (`base64::encode` / `base64::decode`). For `base64 >= 0.21`, replace
//! with
//! `base64::engine::general_purpose::STANDARD.encode / decode`.
//!
//! # Metrics
//!
//! [`HsmMetrics::new`] registers with the default Prometheus registry and
//! can only succeed once per process. [`HsmMetrics::unregistered`] is
//! fail-free; [`Default`] uses it. [`HsmManager::with_metrics`] accepts
//! a caller-supplied handle.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use ed25519_dalek::{Signer as EdSigner, SigningKey, VerifyingKey};
use prometheus::{CounterVec, HistogramVec};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, trace, warn};
use zeroize::Zeroize;

// ── Constants ─────────────────────────────────────────────────────────────

pub const PUBLIC_KEY_LEN: usize = 32;
pub const SIGNATURE_LEN: usize = 64;
pub const SEED_LEN: usize = 32;

const LOCAL_BACKEND: &str = "local";
const REMOTE_BACKEND: &str = "remote";
const PKCS11_BACKEND: &str = "pkcs11";

// ── SecretString ──────────────────────────────────────────────────────────

/// A string that renders as `[REDACTED]` and refuses to be deserialized
/// from a redacted literal.
///
/// Used for API keys and similar secrets that should **not** be stored in
/// JSON config files. The runtime value is exposed only through
/// [`expose_secret`](Self::expose_secret).
#[derive(Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Expose the underlying string. The returned reference is valid for
    /// the lifetime of `self`; the caller must not log or persist it.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    /// Whether the secret is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("[REDACTED]")
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        if s == "[REDACTED]" || s == "[SECRET]" {
            return Err(D::Error::custom(
                "secret cannot be round-tripped through config; \
                 provide it via environment variable instead",
            ));
        }
        Ok(SecretString::new(s))
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the key management backend.
///
/// Serialized with `#[serde(tag = "type")]` so a JSON config looks like
/// `{"type": "local", "path": "...", "password_env": "..."}`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyBackendConfig {
    /// Local encrypted keystore.
    Local {
        /// Path to the keystore file.
        path: String,
        /// Environment variable holding the password.
        password_env: String,
        /// Whether to generate a new key when the keystore does not exist.
        ///
        /// **Default `false`.** Setting this to `true` allows a node to
        /// bring itself up on a fresh host; the generated key is
        /// persisted to `path` before `create_signer` returns, and a
        /// persistence failure aborts startup.
        #[serde(default)]
        allow_generate: bool,
    },
    /// Remote signer HTTPS service.
    Remote {
        /// Base URL (e.g. `https://signer.example.com`).
        url: String,
        /// Request timeout in seconds.
        #[serde(default = "default_timeout_s")]
        timeout_s: u64,
        /// Optional API key sent as `X-API-Key`.
        ///
        /// Serializes as `"[REDACTED]"` and cannot be round-tripped. For
        /// production use, leave this `None` in the JSON config and
        /// provide the key via the environment variable named in
        /// [`api_key_env`](Self::Remote::api_key_env).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key: Option<SecretString>,
        /// Environment variable holding the API key. Takes precedence
        /// over `api_key` when both are set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        api_key_env: Option<String>,
        /// Client TLS certificate path (PEM). Requires `client_key_path`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_cert_path: Option<String>,
        /// Client TLS private-key path (PEM). Requires `client_cert_path`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        client_key_path: Option<String>,
        /// CA certificate path (PEM). Adds an extra trust anchor.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ca_cert_path: Option<String>,
    },
    /// PKCS#11 HSM.
    Pkcs11 {
        /// Path to the PKCS#11 shared library.
        library_path: String,
        /// Slot ID.
        slot: u64,
        /// Key label.
        key_label: String,
        /// Environment variable holding the user PIN.
        pin_env: String,
    },
    /// AWS KMS. **Not implemented.** `create_signer` returns
    /// [`CryptoError::BackendUnsupported`].
    AwsKms {
        key_id: String,
        region: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        endpoint: Option<String>,
    },
    /// Azure Key Vault. **Not implemented.**
    AzureKeyVault {
        vault_url: String,
        key_name: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key_version: Option<String>,
    },
    /// GCP Cloud KMS. **Not implemented.**
    GcpKms {
        resource_name: String,
    },
}

fn default_timeout_s() -> u64 {
    10
}

impl Default for KeyBackendConfig {
    fn default() -> Self {
        Self::Local {
            path: "keys.enc".into(),
            password_env: "IONA_KEYSTORE_PASSWORD".into(),
            allow_generate: false,
        }
    }
}

impl KeyBackendConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), CryptoError> {
        match self {
            Self::Local { path, password_env, .. } => {
                if path.is_empty() {
                    return Err(CryptoError::Config("local.path must not be empty".into()));
                }
                if password_env.is_empty() {
                    return Err(CryptoError::Config(
                        "local.password_env must not be empty".into(),
                    ));
                }
            }
            Self::Remote {
                url,
                timeout_s,
                api_key,
                api_key_env,
                client_cert_path,
                client_key_path,
                ..
            } => {
                if url.is_empty() {
                    return Err(CryptoError::Config("remote.url must not be empty".into()));
                }
                if *timeout_s == 0 {
                    return Err(CryptoError::Config(
                        "remote.timeout_s must be > 0".into(),
                    ));
                }
                if *timeout_s > 600 {
                    return Err(CryptoError::Config(
                        "remote.timeout_s must be <= 600 (10 minutes)".into(),
                    ));
                }
                if api_key.is_some() && api_key_env.is_some() {
                    return Err(CryptoError::Config(
                        "remote: set either api_key or api_key_env, not both".into(),
                    ));
                }
                match (client_cert_path, client_key_path) {
                    (Some(_), None) | (None, Some(_)) => {
                        return Err(CryptoError::Config(
                            "remote: client_cert_path and client_key_path must both be set or both unset"
                                .into(),
                        ));
                    }
                    _ => {}
                }
            }
            Self::Pkcs11 { library_path, key_label, pin_env, .. } => {
                if library_path.is_empty() {
                    return Err(CryptoError::Config(
                        "pkcs11.library_path must not be empty".into(),
                    ));
                }
                if key_label.is_empty() {
                    return Err(CryptoError::Config(
                        "pkcs11.key_label must not be empty".into(),
                    ));
                }
                if pin_env.is_empty() {
                    return Err(CryptoError::Config(
                        "pkcs11.pin_env must not be empty".into(),
                    ));
                }
            }
            Self::AwsKms { key_id, region, .. } => {
                if key_id.is_empty() {
                    return Err(CryptoError::Config(
                        "aws_kms.key_id must not be empty".into(),
                    ));
                }
                if region.is_empty() {
                    return Err(CryptoError::Config(
                        "aws_kms.region must not be empty".into(),
                    ));
                }
            }
            Self::AzureKeyVault { vault_url, key_name, .. } => {
                if vault_url.is_empty() {
                    return Err(CryptoError::Config(
                        "azure_keyvault.vault_url must not be empty".into(),
                    ));
                }
                if key_name.is_empty() {
                    return Err(CryptoError::Config(
                        "azure_keyvault.key_name must not be empty".into(),
                    ));
                }
            }
            Self::GcpKms { resource_name } => {
                if resource_name.is_empty() {
                    return Err(CryptoError::Config(
                        "gcp_kms.resource_name must not be empty".into(),
                    ));
                }
            }
        }
        Ok(())
    }
}

// ── HsmSigner trait ──────────────────────────────────────────────────────

/// Backend-agnostic signing interface.
///
/// Implementations must be thread-safe: [`HsmManager`] stores them in an
/// `Arc` and callers may invoke `sign` from any thread.
pub trait HsmSigner: Send + Sync {
    /// Public key bytes. Implementations are expected to cache the key
    /// after the first successful fetch.
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError>;

    /// Sign a message.
    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError>;

    /// Backend name for logging and metrics labels.
    fn backend_name(&self) -> &'static str;

    /// Liveness probe. Called by [`HsmManager::health_check`].
    fn health_check(&self) -> Result<(), CryptoError>;

    /// Optional stable key identifier.
    fn key_id(&self) -> Option<String> {
        None
    }

    /// Optional key rotation.
    ///
    /// Default returns [`CryptoError::BackendUnsupported`]; implementations
    /// that support it (e.g. cloud KMS) override this.
    fn rotate_key(&self) -> Result<(), CryptoError> {
        Err(CryptoError::BackendUnsupported(format!(
            "{} does not support key rotation",
            self.backend_name()
        )))
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for HSM signing operations.
#[derive(Clone)]
pub struct HsmMetrics {
    pub sign_operations: CounterVec,
    pub sign_errors: CounterVec,
    pub sign_latency: HistogramVec,
    pub health_checks: CounterVec,
}

impl HsmMetrics {
    /// Register with the default Prometheus registry. Succeeds at most
    /// once per process.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            sign_operations: prometheus::register_counter_vec!(
                "iona_hsm_sign_operations_total",
                "HSM sign attempts, labelled by backend and result",
                &["backend", "result"]
            )?,
            sign_errors: prometheus::register_counter_vec!(
                "iona_hsm_sign_errors_total",
                "HSM sign errors",
                &["backend", "error_type"]
            )?,
            sign_latency: prometheus::register_histogram_vec!(
                "iona_hsm_sign_latency_seconds",
                "HSM sign latency",
                &["backend"]
            )?,
            health_checks: prometheus::register_counter_vec!(
                "iona_hsm_health_checks_total",
                "HSM health checks",
                &["backend", "status"]
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        Self {
            sign_operations: CounterVec::new(
                prometheus::Opts::new(
                    "iona_hsm_sign_operations_total",
                    "HSM sign attempts",
                ),
                &["backend", "result"],
            )
            .expect("counter vec construction is infallible"),
            sign_errors: CounterVec::new(
                prometheus::Opts::new("iona_hsm_sign_errors_total", "HSM sign errors"),
                &["backend", "error_type"],
            )
            .expect("counter vec construction is infallible"),
            sign_latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_hsm_sign_latency_seconds",
                    "HSM sign latency",
                ),
                &["backend"],
            )
            .expect("histogram vec construction is infallible"),
            health_checks: CounterVec::new(
                prometheus::Opts::new("iona_hsm_health_checks_total", "HSM health checks"),
                &["backend", "status"],
            )
            .expect("counter vec construction is infallible"),
        }
    }

    pub fn record_sign(&self, backend: &str, ok: bool, duration: Duration) {
        let result = if ok { "ok" } else { "error" };
        self.sign_operations
            .with_label_values(&[backend, result])
            .inc();
        self.sign_latency
            .with_label_values(&[backend])
            .observe(duration.as_secs_f64());
    }

    pub fn record_error(&self, backend: &str, error_type: &str) {
        self.sign_errors
            .with_label_values(&[backend, error_type])
            .inc();
    }

    pub fn record_health_check(&self, backend: &str, ok: bool) {
        self.health_checks
            .with_label_values(&[backend, if ok { "ok" } else { "error" }])
            .inc();
    }
}

impl Default for HsmMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

// ── HsmManager ────────────────────────────────────────────────────────────

/// Thread-safe manager for signing operations.
///
/// Cloning shares the underlying signer and metrics via `Arc`.
#[derive(Clone)]
pub struct HsmManager {
    signer: Arc<dyn HsmSigner>,
    metrics: Arc<HsmMetrics>,
}

impl HsmManager {
    /// Wrap a signer with unregistered metrics.
    ///
    /// If you want metrics, call [`with_metrics`](Self::with_metrics) or
    /// use [`with_health_check`](Self::with_health_check) to also verify
    /// the backend at construction.
    pub fn new(signer: Box<dyn HsmSigner>) -> Self {
        Self {
            signer: Arc::from(signer),
            metrics: Arc::new(HsmMetrics::unregistered()),
        }
    }

    /// Wrap a signer with a caller-supplied metrics bundle.
    pub fn with_metrics(signer: Box<dyn HsmSigner>, metrics: HsmMetrics) -> Self {
        Self {
            signer: Arc::from(signer),
            metrics: Arc::new(metrics),
        }
    }

    /// Wrap a signer, verify the backend, and return a `Result`.
    ///
    /// Intended for startup: if the HSM/KMS is unreachable, the node can
    /// choose to retry or abort rather than discovering the failure on
    /// the first consensus round.
    pub fn with_health_check(signer: Box<dyn HsmSigner>) -> Result<Self, CryptoError> {
        let mgr = Self::new(signer);
        mgr.health_check()?;
        Ok(mgr)
    }

    /// Public key bytes.
    pub fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        self.signer.public_key()
    }

    /// Sign a message, recording duration and outcome.
    pub fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let backend = self.signer.backend_name();
        let start = Instant::now();
        let result = self.signer.sign(msg);
        let duration = start.elapsed();
        self.metrics.record_sign(backend, result.is_ok(), duration);
        if let Err(e) = &result {
            self.metrics.record_error(backend, error_label(e));
        }
        result
    }

    /// Liveness probe.
    pub fn health_check(&self) -> Result<(), CryptoError> {
        let backend = self.signer.backend_name();
        let result = self.signer.health_check();
        self.metrics.record_health_check(backend, result.is_ok());
        result
    }

    /// Backend name.
    #[must_use]
    pub fn backend_name(&self) -> &'static str {
        self.signer.backend_name()
    }

    /// Key ID if the backend provides one.
    #[must_use]
    pub fn key_id(&self) -> Option<String> {
        self.signer.key_id()
    }

    /// Rotate the key if the backend supports it.
    pub fn rotate_key(&self) -> Result<(), CryptoError> {
        self.signer.rotate_key()
    }

    /// Access the metrics handle.
    #[must_use]
    pub fn metrics(&self) -> &HsmMetrics {
        &self.metrics
    }
}

fn error_label(e: &CryptoError) -> &'static str {
    match e {
        CryptoError::Network(_) => "network",
        CryptoError::Key(_) => "key",
        CryptoError::KeyLength { .. } => "key_length",
        CryptoError::KeyNotFound => "key_not_found",
        CryptoError::InvalidKey(_) => "invalid_key",
        CryptoError::InvalidSignature => "invalid_signature",
        CryptoError::Config(_) => "config",
        CryptoError::BackendUnsupported(_) => "unsupported",
        _ => "unknown",
    }
}

// ── Local signer ──────────────────────────────────────────────────────────

/// Ed25519 signer backed by an in-memory signing key.
///
/// The signing key zeroizes on drop.
pub struct LocalSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_key_bytes: PublicKeyBytes,
}

impl LocalSigner {
    /// Build from a 32-byte seed. The seed is borrowed; the caller keeps
    /// ownership.
    #[must_use]
    pub fn from_seed(seed: &[u8; SEED_LEN]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
        }
    }

    /// Build from a slice; the intermediate seed buffer is zeroized.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != SEED_LEN {
            return Err(CryptoError::KeyLength {
                expected: SEED_LEN,
                actual: slice.len(),
            });
        }
        let mut seed = [0u8; SEED_LEN];
        seed.copy_from_slice(slice);
        let signer = Self::from_seed(&seed);
        seed.zeroize();
        Ok(signer)
    }

    /// Generate a new signer using the OS RNG.
    ///
    /// # Errors
    ///
    /// Returns `Err` if `getrandom` is not seeded (early boot).
    pub fn try_random() -> Result<Self, CryptoError> {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut seed = [0u8; SEED_LEN];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|e| CryptoError::Key(format!("OS RNG unavailable: {e}")))?;
        let signer = Self::from_seed(&seed);
        seed.zeroize();
        Ok(signer)
    }

    /// Generate a new signer, panicking on RNG failure. Prefer
    /// [`try_random`](Self::try_random) in production.
    ///
    /// # Panics
    ///
    /// Panics if the OS RNG is unavailable.
    #[must_use]
    pub fn random() -> Self {
        Self::try_random().expect("OS RNG unavailable")
    }

    /// Export a copy of the seed. **Secret material.** The caller is
    /// responsible for zeroizing the returned buffer.
    #[must_use]
    pub fn export_seed(&self) -> [u8; SEED_LEN] {
        self.signing_key.to_bytes()
    }

    /// Load from a keystore file. The intermediate seed is zeroized.
    #[cfg(feature = "keystore")]
    pub fn try_from_keystore(path: &str, password: &str) -> Result<Self, CryptoError> {
        let mut seed = crate::crypto::keystore::decrypt_seed32_from_file(path, password)
            .map_err(|e| CryptoError::Key(format!("keystore decrypt failed: {e}")))?;
        let result = Self::from_seed(&seed);
        seed.zeroize();
        Ok(result)
    }

    #[cfg(not(feature = "keystore"))]
    pub fn try_from_keystore(_path: &str, _password: &str) -> Result<Self, CryptoError> {
        Err(CryptoError::BackendUnsupported(
            "keystore feature not compiled in".into(),
        ))
    }

    /// Parse from a hex-encoded seed.
    pub fn try_from_hex(hex_str: &str) -> Result<Self, CryptoError> {
        let mut bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::Key("invalid hex seed".into()))?;
        let result = Self::try_from_slice(&bytes);
        bytes.zeroize();
        result
    }

    /// Parse from a base64-encoded seed. See the module doc for the
    /// base64 version note.
    pub fn try_from_base64(b64: &str) -> Result<Self, CryptoError> {
        let mut bytes =
            base64::decode(b64).map_err(|_| CryptoError::Key("invalid base64 seed".into()))?;
        let result = Self::try_from_slice(&bytes);
        bytes.zeroize();
        result
    }
}

impl HsmSigner for LocalSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key_bytes.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let sig = self.signing_key.sign(msg);
        Ok(SignatureBytes(sig.to_bytes().to_vec()))
    }

    fn backend_name(&self) -> &'static str {
        LOCAL_BACKEND
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Ok(())
    }

    fn key_id(&self) -> Option<String> {
        Some(hex::encode(&self.public_key_bytes.0))
    }
}

// ── Remote signer ────────────────────────────────────────────────────────

/// HTTPS signer.
///
/// The public key is fetched at construction and cached. The HTTP client
/// enforces `timeout_s` on every request; there is no automatic retry.
pub struct RemoteSigner {
    client: reqwest::blocking::Client,
    url: String,
    public_key: PublicKeyBytes,
    api_key: Option<SecretString>,
}

impl RemoteSigner {
    /// Construct from config.
    ///
    /// # Errors
    ///
    /// - `Config` if `config` is not a `Remote` variant or validation
    ///   fails.
    /// - `Network` if the public-key endpoint is unreachable or returns a
    ///   non-2xx status.
    /// - `KeyLength` if the returned key is not exactly 32 bytes.
    pub fn from_config(config: &KeyBackendConfig) -> Result<Self, CryptoError> {
        let (url, timeout_s, mut api_key, api_key_env, cert, key, ca) = match config {
            KeyBackendConfig::Remote {
                url,
                timeout_s,
                api_key,
                api_key_env,
                client_cert_path,
                client_key_path,
                ca_cert_path,
            } => (
                url.clone(),
                *timeout_s,
                api_key.clone(),
                api_key_env.clone(),
                client_cert_path.clone(),
                client_key_path.clone(),
                ca_cert_path.clone(),
            ),
            _ => {
                return Err(CryptoError::Config(
                    "RemoteSigner::from_config requires a Remote variant".into(),
                ));
            }
        };

        // API key from env takes precedence.
        if let Some(env_name) = api_key_env {
            match std::env::var(&env_name) {
                Ok(v) if !v.is_empty() => api_key = Some(SecretString::new(v)),
                _ => {
                    return Err(CryptoError::Config(format!(
                        "environment variable `{env_name}` is not set"
                    )));
                }
            }
        }

        let mut builder = reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(timeout_s))
            .user_agent(concat!("iona-hsm/", env!("CARGO_PKG_VERSION")));

        if let (Some(cert_path), Some(key_path)) = (cert, key) {
            let cert_bytes = std::fs::read(&cert_path)
                .map_err(|e| CryptoError::Config(format!("cert read `{cert_path}`: {e}")))?;
            let key_bytes = std::fs::read(&key_path)
                .map_err(|e| CryptoError::Config(format!("key read `{key_path}`: {e}")))?;
            let identity = reqwest::Identity::from_pkcs8_pem(&cert_bytes, &key_bytes)
                .map_err(|e| CryptoError::Config(format!("invalid identity: {e}")))?;
            builder = builder.identity(identity);
        }
        if let Some(ca_path) = ca {
            let ca_bytes = std::fs::read(&ca_path)
                .map_err(|e| CryptoError::Config(format!("CA read `{ca_path}`: {e}")))?;
            let ca_cert = reqwest::Certificate::from_pem(&ca_bytes)
                .map_err(|e| CryptoError::Config(format!("invalid CA: {e}")))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let client = builder
            .build()
            .map_err(|e| CryptoError::Network(format!("client build: {e}")))?;

        let pubkey_url = format!("{}/pubkey", url.trim_end_matches('/'));
        let mut req = client.get(&pubkey_url);
        if let Some(k) = &api_key {
            req = req.header("X-API-Key", k.expose_secret());
        }
        let resp = req
            .send()
            .map_err(|e| CryptoError::Network(format!("GET {pubkey_url}: {e}")))?;
        if !resp.status().is_success() {
            return Err(CryptoError::Network(format!(
                "GET {pubkey_url}: HTTP {}",
                resp.status()
            )));
        }
        let json: serde_json::Value = resp
            .json()
            .map_err(|e| CryptoError::Network(format!("pubkey JSON: {e}")))?;
        let pubkey_b64 = json["pubkey_base64"]
            .as_str()
            .ok_or_else(|| CryptoError::Key("missing `pubkey_base64` in response".into()))?;
        let pubkey_bytes =
            base64::decode(pubkey_b64).map_err(|e| CryptoError::Key(format!("pubkey base64: {e}")))?;
        if pubkey_bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: pubkey_bytes.len(),
            });
        }

        Ok(Self {
            client,
            url,
            public_key: PublicKeyBytes(pubkey_bytes),
            api_key,
        })
    }
}

impl HsmSigner for RemoteSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let body = serde_json::json!({ "msg_base64": base64::encode(msg) });
        let url = format!("{}/sign", self.url.trim_end_matches('/'));
        let mut req = self.client.post(&url).json(&body);
        if let Some(k) = &self.api_key {
            req = req.header("X-API-Key", k.expose_secret());
        }
        let resp = req
            .send()
            .map_err(|e| CryptoError::Network(format!("POST {url}: {e}")))?;
        if !resp.status().is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(CryptoError::Network(format!("HTTP {}: {text}", resp.status())));
        }
        let json: serde_json::Value = resp
            .json()
            .map_err(|e| CryptoError::Network(format!("sign JSON: {e}")))?;
        let sig_b64 = json["sig_base64"]
            .as_str()
            .ok_or_else(|| CryptoError::Key("missing `sig_base64` in response".into()))?;
        let sig_bytes =
            base64::decode(sig_b64).map_err(|e| CryptoError::Key(format!("sig base64: {e}")))?;
        if sig_bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: sig_bytes.len(),
            });
        }
        Ok(SignatureBytes(sig_bytes))
    }

    fn backend_name(&self) -> &'static str {
        REMOTE_BACKEND
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let url = format!("{}/health", self.url.trim_end_matches('/'));
        let mut req = self.client.get(&url);
        if let Some(k) = &self.api_key {
            req = req.header("X-API-Key", k.expose_secret());
        }
        let resp = req
            .send()
            .map_err(|e| CryptoError::Network(format!("GET {url}: {e}")))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CryptoError::Network(format!(
                "health check failed: HTTP {}",
                resp.status()
            )))
        }
    }

    fn key_id(&self) -> Option<String> {
        Some(format!("remote:{}", hex::encode(&self.public_key.0)))
    }
}

// ── PKCS#11 signer ────────────────────────────────────────────────────────

#[cfg(feature = "pkcs11")]
pub struct Pkcs11Signer {
    inner: parking_lot::Mutex<Pkcs11Inner>,
    public_key_bytes: PublicKeyBytes,
}

#[cfg(feature = "pkcs11")]
struct Pkcs11Inner {
    session: cryptoki::session::Session,
    key_handle: cryptoki::object::ObjectHandle,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Signer {
    /// Open a session, log in, and locate the key by label.
    ///
    /// # Errors
    ///
    /// - `Config` for empty inputs.
    /// - `KeyNotFound` if the key is not found by label.
    /// - `Key` for any `cryptoki` error.
    pub fn from_config(
        library_path: &str,
        slot: u64,
        key_label: &str,
        pin: &str,
    ) -> Result<Self, CryptoError> {
        use cryptoki::context::Pkcs11;
        use cryptoki::object::{Attribute, ObjectClass};
        use cryptoki::session::{SessionFlags, UserType};
        use cryptoki::slot::SlotId;

        let ctx = Pkcs11::new(library_path)
            .map_err(|e| CryptoError::Key(format!("Pkcs11::new: {e}")))?;
        let session = ctx
            .open_session(SlotId(slot), SessionFlags::RW_SESSION)
            .map_err(|e| CryptoError::Key(format!("open_session: {e}")))?;
        session
            .login(UserType::User, Some(pin))
            .map_err(|e| CryptoError::Key(format!("login: {e}")))?;

        let template = vec![
            Attribute::Class(ObjectClass::PRIVATE_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ];
        let keys = session
            .find_objects(&template)
            .map_err(|e| CryptoError::Key(format!("find_objects(private): {e}")))?;
        let key_handle = keys
            .into_iter()
            .next()
            .ok_or(CryptoError::KeyNotFound)?;

        let pub_template = vec![
            Attribute::Class(ObjectClass::PUBLIC_KEY),
            Attribute::Label(key_label.as_bytes().to_vec()),
        ];
        let pub_objs = session
            .find_objects(&pub_template)
            .map_err(|e| CryptoError::Key(format!("find_objects(public): {e}")))?;
        let pub_handle = pub_objs.into_iter().next().ok_or(CryptoError::KeyNotFound)?;

        let attrs = session
            .get_attributes(pub_handle, &[Attribute::Value])
            .map_err(|e| CryptoError::Key(format!("get_attributes: {e}")))?;
        let pub_bytes = attrs
            .into_iter()
            .find_map(|a| match a {
                Attribute::Value(v) => Some(v),
                _ => None,
            })
            .ok_or_else(|| CryptoError::Key("public key value missing".into()))?;

        if pub_bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: pub_bytes.len(),
            });
        }

        Ok(Self {
            inner: parking_lot::Mutex::new(Pkcs11Inner { session, key_handle }),
            public_key_bytes: PublicKeyBytes(pub_bytes),
        })
    }
}

#[cfg(feature = "pkcs11")]
impl HsmSigner for Pkcs11Signer {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key_bytes.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use cryptoki::mechanism::Mechanism;
        // `Session::sign` requires `&mut self` in cryptoki 0.7+.
        let mut inner = self.inner.lock();
        let sig = inner
            .session
            .sign(&Mechanism::EdDSA, inner.key_handle, msg)
            .map_err(|e| CryptoError::Key(format!("PKCS#11 sign: {e}")))?;
        if sig.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: sig.len(),
            });
        }
        Ok(SignatureBytes(sig))
    }

    fn backend_name(&self) -> &'static str {
        PKCS11_BACKEND
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let inner = self.inner.lock();
        inner
            .session
            .get_session_info()
            .map(|_| ())
            .map_err(|e| CryptoError::Key(format!("PKCS#11 session info: {e}")))
    }

    fn key_id(&self) -> Option<String> {
        Some(hex::encode(&self.public_key_bytes.0))
    }
}

// ── Factory ───────────────────────────────────────────────────────────────

/// Build a signer from `config`.
///
/// # Errors
///
/// - `Config` if `config.validate()` fails or an environment variable
///   required by the backend is missing.
/// - `KeyNotFound` for a `Local` backend whose keystore is missing and
///   whose `allow_generate` flag is `false`.
/// - `BackendUnsupported` for a `Pkcs11` backend when the `pkcs11`
///   feature is not compiled in, or for any Cloud KMS backend (all are
///   declared but not implemented).
/// - Any error propagated by the backend's constructor.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    config.validate()?;

    match config {
        KeyBackendConfig::Local { path, password_env, allow_generate } => {
            create_local_signer(path, password_env, *allow_generate)
        }
        KeyBackendConfig::Remote { .. } => {
            Ok(Box::new(RemoteSigner::from_config(config)?))
        }
        KeyBackendConfig::Pkcs11 { library_path, slot, key_label, pin_env } => {
            #[cfg(feature = "pkcs11")]
            {
                let pin = std::env::var(pin_env).map_err(|_| {
                    CryptoError::Config(format!("environment variable `{pin_env}` is not set"))
                })?;
                Ok(Box::new(Pkcs11Signer::from_config(
                    library_path,
                    *slot,
                    key_label,
                    &pin,
                )?))
            }
            #[cfg(not(feature = "pkcs11"))]
            {
                let _ = (library_path, slot, key_label, pin_env);
                Err(CryptoError::BackendUnsupported(
                    "PKCS#11 not compiled in; enable the `pkcs11` feature".into(),
                ))
            }
        }
        KeyBackendConfig::AwsKms { .. } => Err(CryptoError::BackendUnsupported(
            "AWS KMS backend is not implemented".into(),
        )),
        KeyBackendConfig::AzureKeyVault { .. } => Err(CryptoError::BackendUnsupported(
            "Azure Key Vault backend is not implemented".into(),
        )),
        KeyBackendConfig::GcpKms { .. } => Err(CryptoError::BackendUnsupported(
            "GCP Cloud KMS backend is not implemented".into(),
        )),
    }
}

fn create_local_signer(
    path: &str,
    password_env: &str,
    allow_generate: bool,
) -> Result<Box<dyn HsmSigner>, CryptoError> {
    let file_exists = std::path::Path::new(path).exists();

    // ── Existing keystore ────────────────────────────────────────────────
    if file_exists {
        let password = std::env::var(password_env).map_err(|_| {
            CryptoError::Config(format!(
                "keystore `{path}` exists but `{password_env}` is not set"
            ))
        })?;
        if password.is_empty() {
            return Err(CryptoError::Config(format!(
                "`{password_env}` is empty; refusing to open keystore `{path}`"
            )));
        }
        let signer = LocalSigner::try_from_keystore(path, &password)?;
        debug!(path, backend = LOCAL_BACKEND, "loaded existing keystore");
        return Ok(Box::new(signer));
    }

    // ── Missing keystore ────────────────────────────────────────────────
    if !allow_generate {
        return Err(CryptoError::KeyNotFound);
    }

    let password = std::env::var(password_env).map_err(|_| {
        CryptoError::Config(format!(
            "generating a keystore at `{path}` requires `{password_env}`"
        ))
    })?;
    if password.is_empty() {
        return Err(CryptoError::Config(format!(
            "`{password_env}` is empty; refusing to generate a keystore without a password"
        )));
    }

    let signer = LocalSigner::try_random()?;
    let mut seed = signer.export_seed();

    #[cfg(feature = "keystore")]
    {
        let persist = crate::crypto::keystore::encrypt_seed32_to_file(path, &seed, &password);
        seed.zeroize();
        persist.map_err(|e| {
            CryptoError::Config(format!(
                "generated a new key but failed to persist it to `{path}`: {e}"
            ))
        })?;
        info!(path, "generated and persisted new keystore");
        Ok(Box::new(signer))
    }
    #[cfg(not(feature = "keystore"))]
    {
        seed.zeroize();
        Err(CryptoError::BackendUnsupported(
            "keystore feature not compiled in; cannot persist generated key".into(),
        ))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── SecretString ────────────────────────────────────────────────────

    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s:?}"), "[REDACTED]");
        assert_eq!(s.expose_secret(), "hunter2");
    }

    #[test]
    fn secret_serializes_as_redacted() {
        let s = SecretString::new("hunter2");
        assert_eq!(serde_json::to_string(&s).unwrap(), r#""[REDACTED]""#);
    }

    #[test]
    fn secret_refuses_to_roundtrip_redacted_literal() {
        // Regression: the previous implementation accepted `[SECRET]`
        // on deserialize and stored it as the literal API key.
        let r: Result<SecretString, _> = serde_json::from_str(r#""[REDACTED]""#);
        assert!(r.is_err());
        let r: Result<SecretString, _> = serde_json::from_str(r#""[SECRET]""#);
        assert!(r.is_err());
    }

    #[test]
    fn secret_deserializes_real_value() {
        let s: SecretString = serde_json::from_str(r#""hunter2""#).unwrap();
        assert_eq!(s.expose_secret(), "hunter2");
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_default_is_local_and_fails_closed() {
        match KeyBackendConfig::default() {
            KeyBackendConfig::Local { path, password_env, allow_generate } => {
                assert_eq!(path, "keys.enc");
                assert_eq!(password_env, "IONA_KEYSTORE_PASSWORD");
                assert!(!allow_generate);
            }
            _ => panic!("default must be Local"),
        }
    }

    #[test]
    fn config_validation_accepts_default() {
        KeyBackendConfig::default().validate().unwrap();
    }

    #[test]
    fn config_validation_rejects_each_invalid_variant() {
        // Local
        let mut c = KeyBackendConfig::default();
        if let KeyBackendConfig::Local { ref mut path, .. } = c {
            *path = String::new();
        }
        assert!(c.validate().is_err());

        // Remote — empty url
        let c = KeyBackendConfig::Remote {
            url: String::new(),
            timeout_s: 5,
            api_key: None,
            api_key_env: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
        };
        assert!(c.validate().is_err());

        // Remote — zero timeout
        let c = KeyBackendConfig::Remote {
            url: "https://s".into(),
            timeout_s: 0,
            api_key: None,
            api_key_env: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
        };
        assert!(c.validate().is_err());

        // Remote — cert without key
        let c = KeyBackendConfig::Remote {
            url: "https://s".into(),
            timeout_s: 5,
            api_key: None,
            api_key_env: None,
            client_cert_path: Some("c".into()),
            client_key_path: None,
            ca_cert_path: None,
        };
        assert!(c.validate().is_err());

        // PKCS#11 — empty label
        let c = KeyBackendConfig::Pkcs11 {
            library_path: "/lib.so".into(),
            slot: 0,
            key_label: String::new(),
            pin_env: "PIN".into(),
        };
        assert!(c.validate().is_err());

        // AWS — empty region
        let c = KeyBackendConfig::AwsKms {
            key_id: "k".into(),
            region: String::new(),
            endpoint: None,
        };
        assert!(c.validate().is_err());
    }

    #[test]
    fn config_json_roundtrip_without_secrets() {
        let configs = [
            KeyBackendConfig::Local {
                path: "keys.enc".into(),
                password_env: "PW".into(),
                allow_generate: false,
            },
            KeyBackendConfig::AwsKms {
                key_id: "arn:aws:kms:us-east-1:123:key/abc".into(),
                region: "us-east-1".into(),
                endpoint: None,
            },
            KeyBackendConfig::GcpKms {
                resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
            },
        ];
        for c in &configs {
            let json = serde_json::to_string(c).unwrap();
            let back: KeyBackendConfig = serde_json::from_str(&json).unwrap();
            assert_eq!(c, &back);
        }
    }

    // ── Local signer ────────────────────────────────────────────────────

    #[test]
    fn local_signer_is_deterministic() {
        let seed = [42u8; SEED_LEN];
        let a = LocalSigner::from_seed(&seed);
        let b = LocalSigner::from_seed(&seed);
        assert_eq!(a.public_key().unwrap().0, b.public_key().unwrap().0);
        assert_eq!(a.sign(b"hi").unwrap().0, b.sign(b"hi").unwrap().0);
    }

    #[test]
    fn local_signer_roundtrip_via_slice() {
        let seed = [7u8; SEED_LEN];
        let a = LocalSigner::from_seed(&seed);
        let b = LocalSigner::try_from_slice(&seed).unwrap();
        assert_eq!(a.public_key().unwrap().0, b.public_key().unwrap().0);
    }

    #[test]
    fn local_signer_rejects_wrong_seed_length() {
        let r = LocalSigner::try_from_slice(&[0u8; 31]);
        assert!(matches!(
            r,
            Err(CryptoError::KeyLength { expected: 32, actual: 31 })
        ));
    }

    #[test]
    fn local_signer_backend_name() {
        let s = LocalSigner::from_seed(&[0u8; SEED_LEN]);
        assert_eq!(s.backend_name(), LOCAL_BACKEND);
    }

    // ── Manager ─────────────────────────────────────────────────────────

    #[test]
    fn manager_wraps_local_signer() {
        let s = LocalSigner::try_random().unwrap();
        let m = HsmManager::new(Box::new(s));
        assert_eq!(m.backend_name(), LOCAL_BACKEND);
        assert!(m.public_key().is_ok());
        assert!(m.sign(b"x").is_ok());
        assert!(m.health_check().is_ok());
        assert!(m.key_id().is_some());
    }

    #[test]
    fn manager_rotate_key_errors_for_local() {
        let s = LocalSigner::from_seed(&[0u8; SEED_LEN]);
        let m = HsmManager::new(Box::new(s));
        assert!(matches!(
            m.rotate_key(),
            Err(CryptoError::BackendUnsupported(_))
        ));
    }

    // ── Factory fail-closed ─────────────────────────────────────────────

    #[test]
    fn create_local_signer_fails_when_keystore_missing_and_not_allow_generate() {
        // Regression: the previous factory generated a new key
        // *silently* when the keystore was missing, which is exactly the
        // failure mode that slashes a validator.
        let cfg = KeyBackendConfig::Local {
            path: "/nonexistent/keystore-test-does-not-exist.enc".into(),
            password_env: "IONA_TEST_PASSWORD_UNSET_XYZ".into(),
            allow_generate: false,
        };
        let r = create_signer(&cfg);
        assert!(matches!(r, Err(CryptoError::KeyNotFound)), "{r:?}");
    }

    #[test]
    fn create_local_signer_fails_when_allow_generate_without_password() {
        let cfg = KeyBackendConfig::Local {
            path: "/nonexistent/keystore-test-does-not-exist.enc".into(),
            password_env: "IONA_TEST_PASSWORD_UNSET_XYZ".into(),
            allow_generate: true,
        };
        // The env var is not set, so even with allow_generate we must
        // refuse.
        let r = create_signer(&cfg);
        assert!(matches!(r, Err(CryptoError::Config(_))), "{r:?}");
    }

    #[test]
    fn create_unsupported_cloud_backends_return_unsupported() {
        for cfg in [
            KeyBackendConfig::AwsKms {
                key_id: "k".into(),
                region: "r".into(),
                endpoint: None,
            },
            KeyBackendConfig::AzureKeyVault {
                vault_url: "https://v.vault.azure.net/".into(),
                key_name: "k".into(),
                key_version: None,
            },
            KeyBackendConfig::GcpKms {
                resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k".into(),
            },
        ] {
            assert!(
                matches!(create_signer(&cfg), Err(CryptoError::BackendUnsupported(_))),
                "expected BackendUnsupported for {cfg:?}"
            );
        }
    }

    #[test]
    fn create_pkcs11_without_feature_returns_unsupported() {
        #[cfg(not(feature = "pkcs11"))]
        {
            let cfg = KeyBackendConfig::Pkcs11 {
                library_path: "/lib.so".into(),
                slot: 0,
                key_label: "k".into(),
                pin_env: "PIN".into(),
            };
            assert!(matches!(
                create_signer(&cfg),
                Err(CryptoError::BackendUnsupported(_))
            ));
        }
    }

    #[test]
    fn create_rejects_invalid_config_before_any_io() {
        let cfg = KeyBackendConfig::Remote {
            url: String::new(),
            timeout_s: 5,
            api_key: None,
            api_key_env: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
        };
        assert!(matches!(
            create_signer(&cfg),
            Err(CryptoError::Config(_))
        ));
    }
}
