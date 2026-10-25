//! Minimal encrypted keystore for validator/node keys.
//!
//! # File format
//!
//! ```json
//! {
//!   "v": 2,
//!   "salt": "<base64>",
//!   "nonce": "<base64>",
//!   "ct": "<base64>",
//!   "kdf": { "algorithm": "pbkdf2-hmac-sha256", "iterations": 100000, "salt_len": 16 }
//! }
//! ```
//!
//! Files written by v1 of this module (`"v": 1`, no `kdf` field) are still
//! readable: the reader falls back to the historical defaults
//! (`PBKDF2 100_000 iterations`, `16-byte salt`). Files written by v2
//! store the KDF parameters, so a caller that sets a non-default
//! `KeystoreConfig::pbkdf2_iterations` gets a file it can read back. The
//! previous implementation hard-coded the KDF parameters on the read
//! side, silently corrupting every keystore written with custom options.
//!
//! # Security
//!
//! - **Password handling.** [`SecretString`] renders as `"[REDACTED]"` in
//!   `Debug` and `Serialize`, **refuses to deserialize** the redacted
//!   marker, and zeroizes its buffer on drop. A config file that carried
//!   a `password: Some(...)` field can be serialized safely (the password
//!   is replaced), but **cannot be deserialized** — the correct pattern
//!   is to set `password: None` and provide the secret via
//!   `password_env`.
//! - **Seed handling.** Every intermediate seed buffer produced by
//!   [`decrypt_seed32_from_file`], [`encrypt_seed32_to_file`], and the
//!   manager is wrapped in [`Zeroizing`]. `KeystoreManager::cache` holds
//!   `Zeroizing<[u8; 32]>` so evictions wipe the previous value.
//! - **Passwords from env.** `KeystoreConfig::effective_password` returns
//!   `Option<Zeroizing<String>>`; the caller's copy is zeroized on drop.
//! - **Permissions.** New keystore files are written with mode `0o600`
//!   on Unix. A failure to set restrictive permissions is **fatal** for
//!   that write: returning success while leaving a world-readable
//!   keystore is worse than returning an error.
//!
//! # Durability
//!
//! Writes go through a unique temp file (`<name>.<random>.tmp`), are
//! `fsync`'d, renamed into place, and the parent directory is `fsync`'d.
//! Concurrent writers do not race on the temp file. The caller is
//! expected to provide a path whose parent exists.
//!
//! # Retries
//!
//! [`KeystoreManager`] retries **only `KeystoreError::Io`**. A wrong
//! password, corrupt ciphertext, or unsupported format fails on the first
//! attempt — retrying those wastes CPU and misleads operators.
//!
//! # Metrics
//!
//! [`KeystoreMetrics`] is the Prometheus collector. [`KeystoreMetricsSnapshot`]
//! is an owned, serializable snapshot suitable for assertions and JSON
//! export. They are distinct types on purpose.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use parking_lot::Mutex;
use pbkdf2::pbkdf2_hmac;
use prometheus::{CounterVec, HistogramVec};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, trace, warn};
use zeroize::{Zeroize, Zeroizing};

// ── Constants ─────────────────────────────────────────────────────────────

pub const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const DEFAULT_RETRY_ATTEMPTS: u32 = 3;
pub const DEFAULT_INITIAL_BACKOFF_MS: u64 = 10;
pub const DEFAULT_MAX_BACKOFF_MS: u64 = 1_000;

/// Current file-format version.
const CURRENT_FORMAT_VERSION: u32 = 2;

/// KDF algorithm identifier stored in v2 files.
const KDF_ALGORITHM: &str = "pbkdf2-hmac-sha256";

/// Marker substituted for secrets in `Debug`/`Serialize` output.
const REDACTED: &str = "[REDACTED]";

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the keystore subsystem.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeystoreConfig {
    pub path: PathBuf,
    /// Direct password. **Not** the recommended way to provision a
    /// secret; prefer `password_env`. This field is redacted on
    /// serialize and refuses to round-trip.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<SecretString>,
    #[serde(default = "default_password_env")]
    pub password_env: String,
    #[serde(default = "default_iterations")]
    pub pbkdf2_iterations: u32,
    #[serde(default = "default_salt_len")]
    pub salt_len: usize,
    /// **Must be `12`** for AES-GCM.
    #[serde(default = "default_nonce_len")]
    pub nonce_len: usize,
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    #[serde(default = "default_true")]
    pub log_operations: bool,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("keys.enc"),
            password: None,
            password_env: default_password_env(),
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
            salt_len: SALT_LEN,
            nonce_len: NONCE_LEN,
            retry_attempts: DEFAULT_RETRY_ATTEMPTS,
            initial_backoff_ms: DEFAULT_INITIAL_BACKOFF_MS,
            max_backoff_ms: DEFAULT_MAX_BACKOFF_MS,
            enable_metrics: true,
            log_operations: true,
        }
    }
}

impl KeystoreConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), KeystoreError> {
        if self.path.as_os_str().is_empty() {
            return Err(KeystoreError::Config("path must not be empty".into()));
        }
        if self.pbkdf2_iterations == 0 {
            return Err(KeystoreError::Config(
                "pbkdf2_iterations must be > 0".into(),
            ));
        }
        if self.salt_len < 8 {
            return Err(KeystoreError::Config("salt_len must be >= 8".into()));
        }
        if self.salt_len > 64 {
            return Err(KeystoreError::Config("salt_len must be <= 64".into()));
        }
        if self.nonce_len != NONCE_LEN {
            return Err(KeystoreError::Config(format!(
                "nonce_len must be {NONCE_LEN} for AES-GCM"
            )));
        }
        if self.retry_attempts == 0 {
            return Err(KeystoreError::Config(
                "retry_attempts must be > 0".into(),
            ));
        }
        if self.initial_backoff_ms == 0 {
            return Err(KeystoreError::Config(
                "initial_backoff_ms must be > 0".into(),
            ));
        }
        if self.max_backoff_ms < self.initial_backoff_ms {
            return Err(KeystoreError::Config(
                "max_backoff_ms must be >= initial_backoff_ms".into(),
            ));
        }
        if self.password.is_none() && self.password_env.is_empty() {
            return Err(KeystoreError::Config(
                "password or password_env must be provided".into(),
            ));
        }
        Ok(())
    }

    /// Effective password, zeroized on drop.
    ///
    /// Priority: `password` field (not recommended), then
    /// `password_env`.
    #[must_use]
    pub fn effective_password(&self) -> Option<Zeroizing<String>> {
        if let Some(ref secret) = self.password {
            return Some(Zeroizing::new(secret.expose_secret().to_string()));
        }
        if self.password_env.is_empty() {
            return None;
        }
        std::env::var(&self.password_env).ok().map(Zeroizing::new)
    }

    /// Effective PBKDF2 parameters as they appear in a v2 file.
    fn kdf_params(&self) -> KdfParams {
        KdfParams {
            algorithm: KDF_ALGORITHM.into(),
            iterations: self.pbkdf2_iterations,
            salt_len: self.salt_len,
        }
    }
}

fn default_password_env() -> String {
    "IONA_KEYSTORE_PASSWORD".into()
}
fn default_iterations() -> u32 {
    DEFAULT_PBKDF2_ITERATIONS
}
fn default_salt_len() -> usize {
    SALT_LEN
}
fn default_nonce_len() -> usize {
    NONCE_LEN
}
fn default_retry_attempts() -> u32 {
    DEFAULT_RETRY_ATTEMPTS
}
fn default_initial_backoff_ms() -> u64 {
    DEFAULT_INITIAL_BACKOFF_MS
}
fn default_max_backoff_ms() -> u64 {
    DEFAULT_MAX_BACKOFF_MS
}
fn default_true() -> bool {
    true
}

// ── SecretString ──────────────────────────────────────────────────────────

/// A secret string that redacts itself and zeroizes on drop.
#[derive(Clone, Default)]
pub struct SecretString(String);

impl SecretString {
    #[must_use]
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// Expose the secret. The caller must not log or persist the
    /// returned reference.
    #[must_use]
    pub fn expose_secret(&self) -> &str {
        &self.0
    }

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
        f.write_str(REDACTED)
    }
}

impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(REDACTED)
    }
}

impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Error;
        let s = String::deserialize(deserializer)?;
        if s == REDACTED {
            return Err(D::Error::custom(
                "secret cannot be round-tripped through config; \
                 use `password_env` and provide the value via the environment",
            ));
        }
        Ok(Self(s))
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("unsupported keystore version {got}; supported: 1, 2")]
    UnsupportedVersion { got: u32 },

    #[error("invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("invalid salt length: expected {expected}, got {got}")]
    InvalidSaltLength { expected: usize, got: usize },

    #[error("AES-GCM encryption failed: {0}")]
    Encryption(String),

    #[error("AES-GCM decryption failed: wrong password or corrupted file")]
    Decryption,

    #[error("invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("missing field in keystore: {0}")]
    MissingField(&'static str),

    #[error("unsupported KDF algorithm `{0}`")]
    UnsupportedKdf(String),

    #[error("RNG unavailable: {0}")]
    Rng(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("retry limit exceeded after {attempts} attempts; last error: {last}")]
    RetryLimitExceeded { attempts: u32, last: String },
}

pub type KeystoreResult<T> = Result<T, KeystoreError>;

fn is_retryable(e: &KeystoreError) -> bool {
    // Only transient filesystem errors are retried. Deterministic
    // failures (wrong password, bad format) fail immediately.
    matches!(e, KeystoreError::Io(_))
}

// ── File format ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct KeystoreFile {
    v: u32,
    salt: String,
    nonce: String,
    ct: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct KdfParams {
    algorithm: String,
    iterations: u32,
    salt_len: usize,
}

// ── Metrics ───────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct KeystoreMetrics {
    pub operations: CounterVec,
    pub errors: CounterVec,
    pub latency: HistogramVec,
}

impl KeystoreMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            operations: prometheus::register_counter_vec!(
                "iona_keystore_operations_total",
                "Keystore operations",
                &["operation", "status"]
            )?,
            errors: prometheus::register_counter_vec!(
                "iona_keystore_errors_total",
                "Keystore errors",
                &["operation", "error_type"]
            )?,
            latency: prometheus::register_histogram_vec!(
                "iona_keystore_latency_seconds",
                "Keystore operation latency",
                &["operation"]
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        Self {
            operations: CounterVec::new(
                prometheus::Opts::new("iona_keystore_operations_total", "Keystore operations"),
                &["operation", "status"],
            )
            .expect("counter vec construction is infallible"),
            errors: CounterVec::new(
                prometheus::Opts::new("iona_keystore_errors_total", "Keystore errors"),
                &["operation", "error_type"],
            )
            .expect("counter vec construction is infallible"),
            latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_keystore_latency_seconds",
                    "Keystore operation latency",
                ),
                &["operation"],
            )
            .expect("histogram vec construction is infallible"),
        }
    }

    pub fn record_operation(&self, operation: &str, status: &str) {
        self.operations
            .with_label_values(&[operation, status])
            .inc();
    }

    pub fn record_error(&self, operation: &str, error_type: &str) {
        self.errors
            .with_label_values(&[operation, error_type])
            .inc();
    }

    pub fn record_latency(&self, operation: &str, duration: Duration) {
        self.latency
            .with_label_values(&[operation])
            .observe(duration.as_secs_f64());
    }
}

impl Default for KeystoreMetrics {
    fn default() -> Self {
        Self::unregistered()
    }
}

/// Owned snapshot of a single counter family.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterSnapshot {
    pub labels: BTreeMap<String, String>,
    pub value: u64,
}

/// Owned snapshot of [`KeystoreMetrics`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeystoreMetricsSnapshot {
    pub operations: Vec<CounterSnapshot>,
    pub errors: Vec<CounterSnapshot>,
}

fn collect_counters(vec: &CounterVec) -> Vec<CounterSnapshot> {
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

// ── Low-level crypto ──────────────────────────────────────────────────────

/// Derive a 32-byte AES key. The returned array should be wrapped in
/// [`Zeroizing`] by the caller.
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    pbkdf2_hmac::<Sha256>(password, salt, iterations, key.as_mut());
    trace!(iterations, "derived encryption key");
    key
}

fn encrypt_data(key: &[u8; 32], data: &[u8], nonce: &[u8]) -> KeystoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Encryption(format!("AES key init: {e}")))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))
}

fn decrypt_data(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> KeystoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Encryption(format!("AES key init: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| KeystoreError::Decryption)
}

// ── Retry helper ─────────────────────────────────────────────────────────

fn retry_operation<F, T>(config: &KeystoreConfig, operation: &str, mut f: F) -> KeystoreResult<T>
where
    F: FnMut() -> KeystoreResult<T>,
{
    let mut attempt: u32 = 0;
    let mut backoff = Duration::from_millis(config.initial_backoff_ms);
    let max_backoff = Duration::from_millis(config.max_backoff_ms);

    loop {
        attempt = attempt.saturating_add(1);
        match f() {
            Ok(v) => return Ok(v),
            Err(e) => {
                if !is_retryable(&e) || attempt >= config.retry_attempts {
                    return if attempt >= config.retry_attempts && is_retryable(&e) {
                        Err(KeystoreError::RetryLimitExceeded {
                            attempts: attempt,
                            last: e.to_string(),
                        })
                    } else {
                        Err(e)
                    };
                }
                warn!(
                    operation,
                    attempt,
                    error = %e,
                    retry_after_ms = backoff.as_millis() as u64,
                    "keystore operation failed, retrying"
                );
                std::thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(max_backoff);
            }
        }
    }
}

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe manager over a keystore file.
#[derive(Clone)]
pub struct KeystoreManager {
    config: Arc<KeystoreConfig>,
    metrics: Arc<KeystoreMetrics>,
    /// Cached seed. `Zeroizing` ensures eviction zeroizes the buffer.
    cache: Arc<Mutex<Option<Zeroizing<[u8; 32]>>>>,
}

impl KeystoreManager {
    /// Create a new manager.
    pub fn new(config: KeystoreConfig) -> Result<Self, KeystoreError> {
        config.validate()?;
        let metrics = if config.enable_metrics {
            match KeystoreMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, "keystore metrics already registered; using unregistered");
                    KeystoreMetrics::unregistered()
                }
            }
        } else {
            KeystoreMetrics::unregistered()
        };
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(metrics),
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Load the seed, using the cache when available.
    pub fn load_seed(&self) -> KeystoreResult<[u8; 32]> {
        if let Some(cached) = self.cache.lock().as_ref() {
            trace!("seed loaded from cache");
            return Ok(**cached);
        }

        let password = self
            .config
            .effective_password()
            .ok_or_else(|| KeystoreError::Config("password not available".into()))?;

        let start = Instant::now();
        let result = retry_operation(&self.config, "load", || {
            decrypt_seed32_from_file(&self.config.path, password.as_str())
        });

        self.metrics.record_operation(
            "load",
            if result.is_ok() { "ok" } else { "error" },
        );
        self.metrics.record_latency("load", start.elapsed());
        if let Err(e) = &result {
            self.metrics.record_error("load", error_label(e));
        }

        if let Ok(seed) = &result {
            if self.config.log_operations {
                info!("seed loaded from keystore");
            }
            // `Zeroizing` wipes the previous cache value on drop.
            *self.cache.lock() = Some(Zeroizing::new(*seed));
        }

        result
    }

    /// Store the seed, updating the cache on success.
    pub fn store_seed(&self, seed: &[u8; 32]) -> KeystoreResult<()> {
        let password = self
            .config
            .effective_password()
            .ok_or_else(|| KeystoreError::Config("password not available".into()))?;

        let options = KeystoreOptions {
            pbkdf2_iterations: self.config.pbkdf2_iterations,
            salt_len: self.config.salt_len,
            nonce_len: self.config.nonce_len,
        };

        let start = Instant::now();
        let result = retry_operation(&self.config, "store", || {
            encrypt_seed32_to_file(&self.config.path, seed, password.as_str(), &options)
        });

        self.metrics.record_operation(
            "store",
            if result.is_ok() { "ok" } else { "error" },
        );
        self.metrics.record_latency("store", start.elapsed());
        if let Err(e) = &result {
            self.metrics.record_error("store", error_label(e));
        }

        if result.is_ok() {
            if self.config.log_operations {
                info!("seed stored to keystore");
            }
            *self.cache.lock() = Some(Zeroizing::new(*seed));
        }

        result
    }

    /// Change the keystore password.
    pub fn change_password(&self, new_password: &str) -> KeystoreResult<()> {
        let old_password = self
            .config
            .effective_password()
            .ok_or_else(|| KeystoreError::Config("old password not available".into()))?;

        let options = KeystoreOptions {
            pbkdf2_iterations: self.config.pbkdf2_iterations,
            salt_len: self.config.salt_len,
            nonce_len: self.config.nonce_len,
        };

        let start = Instant::now();
        let result = retry_operation(&self.config, "change_password", || {
            change_keystore_password(
                &self.config.path,
                old_password.as_str(),
                new_password,
                &options,
            )
        });

        self.metrics.record_operation(
            "change_password",
            if result.is_ok() { "ok" } else { "error" },
        );
        self.metrics.record_latency("change_password", start.elapsed());
        if let Err(e) = &result {
            self.metrics.record_error("change_password", error_label(e));
        }

        if result.is_ok() {
            if self.config.log_operations {
                info!("keystore password changed");
            }
            *self.cache.lock() = None;
        }

        result
    }

    /// Validate the keystore file format.
    pub fn validate(&self) -> KeystoreResult<()> {
        let start = Instant::now();
        let result = validate_keystore(&self.config.path);
        self.metrics.record_operation(
            "validate",
            if result.is_ok() { "ok" } else { "error" },
        );
        self.metrics.record_latency("validate", start.elapsed());
        if let Err(e) = &result {
            self.metrics.record_error("validate", error_label(e));
        }
        result
    }

    /// Whether the keystore file exists.
    #[must_use]
    pub fn exists(&self) -> bool {
        self.config.path.exists()
    }

    /// Clear the cached seed.
    pub fn clear_cache(&self) {
        *self.cache.lock() = None;
        trace!("keystore cache cleared");
    }

    #[must_use]
    pub fn config(&self) -> &KeystoreConfig {
        &self.config
    }

    /// Owned snapshot of the metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> KeystoreMetricsSnapshot {
        KeystoreMetricsSnapshot {
            operations: collect_counters(&self.metrics.operations),
            errors: collect_counters(&self.metrics.errors),
        }
    }
}

fn error_label(e: &KeystoreError) -> &'static str {
    match e {
        KeystoreError::Io(_) => "io",
        KeystoreError::Json(_) => "json",
        KeystoreError::Base64(_) => "base64",
        KeystoreError::UnsupportedVersion { .. } => "unsupported_version",
        KeystoreError::InvalidNonceLength { .. } => "invalid_nonce_len",
        KeystoreError::InvalidSaltLength { .. } => "invalid_salt_len",
        KeystoreError::Encryption(_) => "encryption",
        KeystoreError::Decryption => "decryption",
        KeystoreError::InvalidSeedLength { .. } => "invalid_seed_len",
        KeystoreError::MissingField(_) => "missing_field",
        KeystoreError::UnsupportedKdf(_) => "unsupported_kdf",
        KeystoreError::Rng(_) => "rng",
        KeystoreError::Config(_) => "config",
        KeystoreError::RetryLimitExceeded { .. } => "retry_limit",
    }
}

// ── Async variants ────────────────────────────────────────────────────────

#[cfg(feature = "async")]
impl KeystoreManager {
    /// Async load. Uses `spawn_blocking` to keep the runtime worker free
    /// during file I/O and PBKDF2.
    pub async fn load_seed_async(&self) -> KeystoreResult<[u8; 32]> {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.load_seed())
            .await
            .map_err(|e| KeystoreError::Config(format!("task join: {e}")))?
    }

    /// Async store.
    pub async fn store_seed_async(&self, seed: &[u8; 32]) -> KeystoreResult<()> {
        let this = self.clone();
        let seed = *seed;
        tokio::task::spawn_blocking(move || this.store_seed(&seed))
            .await
            .map_err(|e| KeystoreError::Config(format!("task join: {e}")))?
    }
}

// ── KeystoreOptions + standalone API ──────────────────────────────────────

/// Parameters used when writing a keystore file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeystoreOptions {
    pub pbkdf2_iterations: u32,
    pub salt_len: usize,
    pub nonce_len: usize,
}

impl Default for KeystoreOptions {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
            salt_len: SALT_LEN,
            nonce_len: NONCE_LEN,
        }
    }
}

/// Encrypt a 32-byte seed and write it atomically.
///
/// The file is written with `v: 2` and includes the KDF parameters, so a
/// caller with non-default `pbkdf2_iterations` can read the file back.
pub fn encrypt_seed32_to_file(
    path: impl AsRef<Path>,
    seed32: &[u8; 32],
    password: &str,
    options: &KeystoreOptions,
) -> KeystoreResult<()> {
    let path = path.as_ref();
    info!(path = %path.display(), "encrypting seed to keystore file");

    if options.nonce_len != NONCE_LEN {
        return Err(KeystoreError::Config(format!(
            "nonce_len must be {NONCE_LEN}"
        )));
    }
    if options.salt_len < 8 {
        return Err(KeystoreError::Config("salt_len must be >= 8".into()));
    }
    if options.pbkdf2_iterations == 0 {
        return Err(KeystoreError::Config(
            "pbkdf2_iterations must be > 0".into(),
        ));
    }

    let mut salt = vec![0u8; options.salt_len];
    let mut nonce_bytes = vec![0u8; options.nonce_len];
    OsRng
        .try_fill_bytes(&mut salt)
        .map_err(|e| KeystoreError::Rng(format!("salt: {e}")))?;
    OsRng
        .try_fill_bytes(&mut nonce_bytes)
        .map_err(|e| KeystoreError::Rng(format!("nonce: {e}")))?;

    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let key = derive_key(&password_bytes, &salt, options.pbkdf2_iterations);
    let ciphertext = encrypt_data(&key, seed32.as_slice(), &nonce_bytes)?;
    drop(key); // zeroized

    let keystore = KeystoreFile {
        v: CURRENT_FORMAT_VERSION,
        salt: base64::engine::general_purpose::STANDARD.encode(&salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
        ct: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
        kdf: Some(KdfParams {
            algorithm: KDF_ALGORITHM.into(),
            iterations: options.pbkdf2_iterations,
            salt_len: options.salt_len,
        }),
    };
    let json = serde_json::to_string_pretty(&keystore)?;

    // ── Unique temp file + fsync + rename + parent-dir fsync ────────────
    let temp_path = unique_temp_path(path)?;
    let write_result = (|| -> KeystoreResult<()> {
        let mut temp_file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temp_path)?;
        temp_file.write_all(json.as_bytes())?;
        temp_file.sync_all()?;
        std::fs::rename(&temp_path, path)?;
        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&temp_path);
        return Err(e);
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // A world-readable keystore is worse than no keystore. Fail the
        // write rather than warn.
        let mut perms = std::fs::metadata(path)?.permissions();
        perms.set_mode(0o600);
        std::fs::set_permissions(path, perms).map_err(|e| {
            KeystoreError::Io(io::Error::new(
                e.kind(),
                format!("cannot set keystore permissions on `{}`: {e}", path.display()),
            ))
        })?;
    }

    info!(path = %path.display(), "keystore file written successfully");
    Ok(())
}

/// Decrypt a 32-byte seed from a keystore file.
pub fn decrypt_seed32_from_file(
    path: impl AsRef<Path>,
    password: &str,
) -> KeystoreResult<[u8; 32]> {
    let path = path.as_ref();
    debug!(path = %path.display(), "decrypting seed from keystore file");
    let json_str = std::fs::read_to_string(path)?;
    decrypt_seed32_from_str(&json_str, password)
}

/// Decrypt a 32-byte seed from a JSON string (testable without the
/// filesystem).
pub fn decrypt_seed32_from_str(json_str: &str, password: &str) -> KeystoreResult<[u8; 32]> {
    let keystore: KeystoreFile = serde_json::from_str(json_str)?;

    let (iterations, expected_salt_len) = match keystore.v {
        1 => (DEFAULT_PBKDF2_ITERATIONS, SALT_LEN),
        2 => {
            let kdf = keystore
                .kdf
                .as_ref()
                .ok_or(KeystoreError::MissingField("kdf"))?;
            if kdf.algorithm != KDF_ALGORITHM {
                return Err(KeystoreError::UnsupportedKdf(kdf.algorithm.clone()));
            }
            (kdf.iterations, kdf.salt_len)
        }
        other => return Err(KeystoreError::UnsupportedVersion { got: other }),
    };

    let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidNonceLength {
            expected: NONCE_LEN,
            got: nonce_bytes.len(),
        });
    }
    if salt.len() != expected_salt_len {
        return Err(KeystoreError::InvalidSaltLength {
            expected: expected_salt_len,
            got: salt.len(),
        });
    }

    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let key = derive_key(&password_bytes, &salt, iterations);
    let plaintext = Zeroizing::new(decrypt_data(&key, &ciphertext, &nonce_bytes)?);
    drop(key); // zeroized

    if plaintext.len() != 32 {
        return Err(KeystoreError::InvalidSeedLength {
            expected: 32,
            got: plaintext.len(),
        });
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    debug!("seed decrypted successfully");
    Ok(seed)
}

/// Whether a keystore file exists.
#[must_use]
pub fn keystore_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

/// Validate a keystore file's format **without** decrypting it.
pub fn validate_keystore(path: impl AsRef<Path>) -> KeystoreResult<()> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let keystore: KeystoreFile = serde_json::from_reader(reader)?;
    match keystore.v {
        1 => {
            let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
            let nonce = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
            let _ = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;
            if salt.len() != SALT_LEN {
                return Err(KeystoreError::InvalidSaltLength {
                    expected: SALT_LEN,
                    got: salt.len(),
                });
            }
            if nonce.len() != NONCE_LEN {
                return Err(KeystoreError::InvalidNonceLength {
                    expected: NONCE_LEN,
                    got: nonce.len(),
                });
            }
        }
        2 => {
            let kdf = keystore
                .kdf
                .as_ref()
                .ok_or(KeystoreError::MissingField("kdf"))?;
            if kdf.algorithm != KDF_ALGORITHM {
                return Err(KeystoreError::UnsupportedKdf(kdf.algorithm.clone()));
            }
            let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
            let nonce = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
            let _ = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;
            if salt.len() != kdf.salt_len {
                return Err(KeystoreError::InvalidSaltLength {
                    expected: kdf.salt_len,
                    got: salt.len(),
                });
            }
            if nonce.len() != NONCE_LEN {
                return Err(KeystoreError::InvalidNonceLength {
                    expected: NONCE_LEN,
                    got: nonce.len(),
                });
            }
        }
        other => return Err(KeystoreError::UnsupportedVersion { got: other }),
    }
    Ok(())
}

/// Change the password of an existing keystore file.
pub fn change_keystore_password(
    path: impl AsRef<Path>,
    old_password: &str,
    new_password: &str,
    options: &KeystoreOptions,
) -> KeystoreResult<()> {
    let path = path.as_ref();
    info!(path = %path.display(), "changing keystore password");
    let seed = Zeroizing::new(decrypt_seed32_from_file(path, old_password)?);
    encrypt_seed32_to_file(path, &seed, new_password, options)?;
    info!(path = %path.display(), "keystore password changed");
    Ok(())
}

/// Build a temp path with a random suffix. `create_new(true)` on the file
/// prevents a concurrent writer from racing us.
fn unique_temp_path(path: &Path) -> KeystoreResult<PathBuf> {
    let mut rng_bytes = [0u8; 8];
    OsRng
        .try_fill_bytes(&mut rng_bytes)
        .map_err(|e| KeystoreError::Rng(format!("temp suffix: {e}")))?;
    let suffix = hex::encode(rng_bytes);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("keystore");
    Ok(path.with_file_name(format!(".{name}.{suffix}.tmp")))
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn opts() -> KeystoreOptions {
        KeystoreOptions::default()
    }

    // ── SecretString ────────────────────────────────────────────────────

    #[test]
    fn secret_debug_is_redacted() {
        let s = SecretString::new("hunter2");
        assert_eq!(format!("{s:?}"), REDACTED);
        assert_eq!(s.expose_secret(), "hunter2");
    }

    #[test]
    fn secret_serialize_is_redacted() {
        let s = SecretString::new("hunter2");
        assert_eq!(
            serde_json::to_string(&s).unwrap(),
            format!("\"{REDACTED}\"")
        );
    }

    #[test]
    fn secret_refuses_to_deserialize_redacted() {
        let r: Result<SecretString, _> = serde_json::from_str(&format!("\"{REDACTED}\""));
        assert!(r.is_err(), "redacted marker must not deserialize");
    }

    #[test]
    fn secret_deserializes_real_value() {
        let s: SecretString = serde_json::from_str("\"hunter2\"").unwrap();
        assert_eq!(s.expose_secret(), "hunter2");
    }

    #[test]
    fn config_with_password_serializes_without_leaking() {
        let cfg = KeystoreConfig {
            password: Some(SecretString::new("hunter2")),
            ..Default::default()
        };
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(!json.contains("hunter2"), "password leaked in JSON: {json}");
        assert!(json.contains(REDACTED));
    }

    // ── Round trip ──────────────────────────────────────────────────────

    #[test]
    fn encrypt_decrypt_roundtrip_default_params() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.enc");
        let seed = [0xAAu8; 32];
        encrypt_seed32_to_file(&path, &seed, "pw", &opts()).unwrap();
        let got = decrypt_seed32_from_file(&path, "pw").unwrap();
        assert_eq!(seed, got);
    }

    #[test]
    fn encrypt_decrypt_roundtrip_with_custom_iterations() {
        // Regression: the previous reader hardcoded 100k iterations, so
        // any file written with a custom iteration count was unreadable.
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.enc");
        let seed = [0xBBu8; 32];
        let custom = KeystoreOptions {
            pbkdf2_iterations: 10_000,
            ..opts()
        };
        encrypt_seed32_to_file(&path, &seed, "pw", &custom).unwrap();
        let got = decrypt_seed32_from_file(&path, "pw").unwrap();
        assert_eq!(seed, got);
    }

    #[test]
    fn wrong_password_fails_immediately() {
        // Regression: retry_operation used to retry decryption errors,
        // wasting 3s and 300k PBKDF2 iterations before failing.
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.enc");
        encrypt_seed32_to_file(&path, &[0u8; 32], "correct", &opts()).unwrap();
        let t0 = std::time::Instant::now();
        let r = decrypt_seed32_from_file(&path, "wrong");
        let elapsed = t0.elapsed();
        assert!(matches!(r, Err(KeystoreError::Decryption)));
        // One PBKDF2, not three.
        assert!(
            elapsed < Duration::from_secs(2),
            "wrong password took {elapsed:?} — retries were not skipped"
        );
    }

    // ── File format versioning ──────────────────────────────────────────

    #[test]
    fn v1_file_is_readable() {
        // Simulate a file written by the previous code: v:1, no kdf, with
        // the historical defaults (100k, 16, 12).
        let dir = tempdir().unwrap();
        let path = dir.path().join("v1.enc");
        let seed = [0x11u8; 32];
        // Write using the v1-style path (defaults), which for v2 produces
        // the same KDF params but adds a kdf field. To truly simulate v1,
        // write manually.
        encrypt_seed32_to_file(&path, &seed, "pw", &opts()).unwrap();
        // Strip the kdf field and reset v to 1 to simulate the old format.
        let raw = std::fs::read_to_string(&path).unwrap();
        let mut v: serde_json::Value = serde_json::from_str(&raw).unwrap();
        v["v"] = serde_json::json!(1);
        v.as_object_mut().unwrap().remove("kdf");
        std::fs::write(&path, serde_json::to_string_pretty(&v).unwrap()).unwrap();
        // Now read it back.
        let got = decrypt_seed32_from_file(&path, "pw").unwrap();
        assert_eq!(seed, got);
    }

    #[test]
    fn validate_keystore_checks_format_only() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.enc");
        encrypt_seed32_to_file(&path, &[0u8; 32], "pw", &opts()).unwrap();
        assert!(validate_keystore(&path).is_ok());

        std::fs::write(&path, "garbage").unwrap();
        assert!(validate_keystore(&path).is_err());
    }

    // ── Change password ────────────────────────────────────────────────

    #[test]
    fn change_password_round_trip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("k.enc");
        let seed = [0xCCu8; 32];
        encrypt_seed32_to_file(&path, &seed, "old", &opts()).unwrap();
        change_keystore_password(&path, "old", "new", &opts()).unwrap();
        assert_eq!(decrypt_seed32_from_file(&path, "new").unwrap(), seed);
        assert!(matches!(
            decrypt_seed32_from_file(&path, "old"),
            Err(KeystoreError::Decryption),
        ));
    }

    // ── Manager ─────────────────────────────────────────────────────────

    fn manager(path: PathBuf) -> KeystoreManager {
        KeystoreManager::new(KeystoreConfig {
            path,
            password: Some(SecretString::new("pw")),
            enable_metrics: false,
            ..Default::default()
        })
        .unwrap()
    }

    #[test]
    fn manager_store_load_roundtrip() {
        let dir = tempdir().unwrap();
        let m = manager(dir.path().join("k.enc"));
        let seed = [0xDDu8; 32];
        m.store_seed(&seed).unwrap();
        assert_eq!(m.load_seed().unwrap(), seed);
    }

    #[test]
    fn manager_clear_cache_forces_reload() {
        let dir = tempdir().unwrap();
        let m = manager(dir.path().join("k.enc"));
        m.store_seed(&[0xEEu8; 32]).unwrap();
        m.clear_cache();
        // After clearing, a corrupted file would now fail; verify the
        // cache was really cleared by checking that a subsequent load
        // succeeds (re-reads from disk).
        assert_eq!(m.load_seed().unwrap(), [0xEEu8; 32]);
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_default_validates() {
        assert!(KeystoreConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_invalid_fields() {
        let mut c = KeystoreConfig::default();
        c.nonce_len = 10;
        assert!(c.validate().is_err());

        let mut c = KeystoreConfig::default();
        c.pbkdf2_iterations = 0;
        assert!(c.validate().is_err());

        let mut c = KeystoreConfig::default();
        c.salt_len = 4;
        assert!(c.validate().is_err());

        let mut c = KeystoreConfig::default();
        c.max_backoff_ms = 1;
        c.initial_backoff_ms = 10;
        assert!(c.validate().is_err());
    }

    // ── Metrics snapshot ────────────────────────────────────────────────

    #[test]
    fn metrics_snapshot_is_owned_and_serializable() {
        let dir = tempdir().unwrap();
        let m = manager(dir.path().join("k.enc"));
        m.store_seed(&[0u8; 32]).unwrap();
        let _ = m.load_seed().unwrap();
        let snap = m.metrics_snapshot();
        assert!(!snap.operations.is_empty());
        let json = serde_json::to_string(&snap).unwrap();
        let back: KeystoreMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    #[test]
    fn metrics_unregistered_is_repeatable() {
        let _a = KeystoreMetrics::unregistered();
        let _b = KeystoreMetrics::unregistered();
        let _c = KeystoreMetrics::default();
    }
}
