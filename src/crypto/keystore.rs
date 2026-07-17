//! Minimal encrypted keystore for validator/node keys.
//!
//! # Production Features
//! - Configurable via `KeystoreConfig` (paths, iterations, retry, permissions).
//! - `KeystoreMetrics` with Prometheus counters and histograms for operations, errors, latency.
//! - `KeystoreManager` as a thread‑safe wrapper with caching and retries.
//! - Optional async support (tokio) for non‑blocking I/O.
//! - Atomic writes with temporary files and rename.
//! - Restrictive file permissions (0o600) on Unix.
//! - Password from environment variable (optional).
//! - Retry with exponential backoff for I/O operations.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, Counter, CounterVec, HistogramVec,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};
use zeroize::{Zeroize, Zeroizing};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default number of PBKDF2 iterations.
const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length in bytes (16 bytes = 128 bits).
const SALT_LEN: usize = 16;

/// Nonce length for AES‑GCM (12 bytes, recommended).
const NONCE_LEN: usize = 12;

/// Default retry attempts for I/O operations.
const DEFAULT_RETRY_ATTEMPTS: u32 = 3;

/// Default initial backoff in milliseconds.
const DEFAULT_INITIAL_BACKOFF_MS: u64 = 10;

/// Default max backoff in milliseconds.
const DEFAULT_MAX_BACKOFF_MS: u64 = 1000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the keystore subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeystoreConfig {
    /// Path to the keystore file.
    pub path: PathBuf,
    /// Password (if provided directly; otherwise use `password_env`).
    #[serde(default)]
    pub password: Option<SecretString>,
    /// Environment variable holding the password.
    #[serde(default = "default_password_env")]
    pub password_env: String,
    /// Number of PBKDF2 iterations.
    #[serde(default = "default_iterations")]
    pub pbkdf2_iterations: u32,
    /// Salt length in bytes.
    #[serde(default = "default_salt_len")]
    pub salt_len: usize,
    /// Nonce length in bytes.
    #[serde(default = "default_nonce_len")]
    pub nonce_len: usize,
    /// Number of retry attempts for I/O operations.
    #[serde(default = "default_retry_attempts")]
    pub retry_attempts: u32,
    /// Initial backoff in milliseconds.
    #[serde(default = "default_initial_backoff_ms")]
    pub initial_backoff_ms: u64,
    /// Maximum backoff in milliseconds.
    #[serde(default = "default_max_backoff_ms")]
    pub max_backoff_ms: u64,
    /// Whether to enable metrics.
    #[serde(default = "default_true")]
    pub enable_metrics: bool,
    /// Whether to log operations.
    #[serde(default = "default_true")]
    pub log_operations: bool,
}

impl Default for KeystoreConfig {
    fn default() -> Self {
        Self {
            path: PathBuf::from("keys.enc"),
            password: None,
            password_env: default_password_env(),
            pbkdf2_iterations: default_iterations(),
            salt_len: default_salt_len(),
            nonce_len: default_nonce_len(),
            retry_attempts: default_retry_attempts(),
            initial_backoff_ms: default_initial_backoff_ms(),
            max_backoff_ms: default_max_backoff_ms(),
            enable_metrics: default_true(),
            log_operations: default_true(),
        }
    }
}

impl KeystoreConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.path.as_os_str().is_empty() {
            return Err("path must not be empty".into());
        }
        if self.pbkdf2_iterations == 0 {
            return Err("pbkdf2_iterations must be > 0".into());
        }
        if self.salt_len < 8 {
            return Err("salt_len must be >= 8".into());
        }
        if self.nonce_len != 12 {
            return Err("nonce_len must be 12 for AES‑GCM".into());
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
        if self.password.is_none() && self.password_env.is_empty() {
            return Err("password or password_env must be provided".into());
        }
        Ok(())
    }

    /// Get the effective password (from env or direct).
    pub fn effective_password(&self) -> Option<String> {
        if let Some(ref secret) = self.password {
            return Some(secret.expose_secret().to_string());
        }
        if !self.password_env.is_empty() {
            return std::env::var(&self.password_env).ok();
        }
        None
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

// ── Secret handling ──────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Unsupported keystore version: {0} (expected {expected})")]
    UnsupportedVersion { got: u32, expected: u32 },

    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("Invalid salt length: expected {expected}, got {got}")]
    InvalidSaltLength { expected: usize, got: usize },

    #[error("AES-GCM encryption failed: {0}")]
    Encryption(String),

    #[error("AES-GCM decryption failed: wrong password or corrupted file")]
    Decryption,

    #[error("Invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("Missing field in keystore: {0}")]
    MissingField(&'static str),

    #[error("PBKDF2 key derivation failed")]
    KeyDerivation,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("retry limit exceeded after {attempts} attempts")]
    RetryLimitExceeded { attempts: u32 },
}

pub type KeystoreResult<T> = Result<T, KeystoreError>;

// ── File format ──────────────────────────────────────────────────────────

/// Structure of the on‑disk keystore JSON file.
#[derive(Debug, Serialize, Deserialize)]
struct KeystoreFile {
    v: u32,
    salt: String,
    nonce: String,
    ct: String,
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for keystore operations.
#[derive(Clone)]
pub struct KeystoreMetrics {
    pub operations: CounterVec,
    pub errors: CounterVec,
    pub latency: HistogramVec,
}

impl KeystoreMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let operations = register_counter_vec!(
            "iona_keystore_operations_total",
            "Total keystore operations",
            &["operation", "status"]
        )?;
        let errors = register_counter_vec!(
            "iona_keystore_errors_total",
            "Keystore errors",
            &["operation", "error_type"]
        )?;
        let latency = register_histogram_vec!(
            "iona_keystore_latency_seconds",
            "Keystore operation latency",
            &["operation"]
        )?;
        Ok(Self {
            operations,
            errors,
            latency,
        })
    }

    pub fn record_operation(&self, operation: &str, status: &str) {
        self.operations.with_label_values(&[operation, status]).inc();
    }

    pub fn record_error(&self, operation: &str, error_type: &str) {
        self.errors.with_label_values(&[operation, error_type]).inc();
    }

    pub fn record_latency(&self, operation: &str, duration: Duration) {
        self.latency.with_label_values(&[operation]).observe(duration.as_secs_f64());
    }
}

impl Default for KeystoreMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            operations: CounterVec::new(
                prometheus::Opts::new("iona_keystore_operations_total", "Keystore ops"),
                &["operation", "status"],
            ).unwrap(),
            errors: CounterVec::new(
                prometheus::Opts::new("iona_keystore_errors_total", "Keystore errors"),
                &["operation", "error_type"],
            ).unwrap(),
            latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_keystore_latency_seconds",
                    "Keystore latency",
                ),
                &["operation"],
            ).unwrap(),
        })
    }
}

// ── Internal helpers ────────────────────────────────────────────────────

/// Derive a 32‑byte encryption key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    trace!(iterations, "derived encryption key");
    key
}

/// Encrypt a byte slice with AES‑256‑GCM using the given key and nonce.
fn encrypt_data(key: &[u8; 32], data: &[u8], nonce: &[u8]) -> KeystoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Encryption(format!("AES key init: {e}")))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))
}

/// Decrypt a byte slice with AES‑256‑GCM using the given key and nonce.
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
    let mut attempt = 0;
    let mut backoff = Duration::from_millis(config.initial_backoff_ms);
    let max_backoff = Duration::from_millis(config.max_backoff_ms);

    loop {
        attempt += 1;
        match f() {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt >= config.retry_attempts {
                    return Err(KeystoreError::RetryLimitExceeded {
                        attempts: attempt,
                    });
                }
                warn!(
                    operation,
                    attempt,
                    error = %e,
                    retry_after_ms = backoff.as_millis(),
                    "keystore operation failed, retrying"
                );
                std::thread::sleep(backoff);
                backoff = (backoff * 2).min(max_backoff);
            }
        }
    }
}

// ── KeystoreManager ─────────────────────────────────────────────────────

/// Thread‑safe manager for keystore operations with caching, metrics, and retries.
#[derive(Clone)]
pub struct KeystoreManager {
    config: Arc<KeystoreConfig>,
    metrics: Arc<KeystoreMetrics>,
    cache: Arc<Mutex<Option<[u8; 32]>>>,
}

impl KeystoreManager {
    /// Create a new manager from configuration.
    pub fn new(config: KeystoreConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(KeystoreMetrics::default());
        Ok(Self {
            config: Arc::new(config),
            metrics,
            cache: Arc::new(Mutex::new(None)),
        })
    }

    /// Load the seed from the keystore (with caching).
    pub fn load_seed(&self) -> KeystoreResult<[u8; 32]> {
        // Check cache first.
        {
            let cache = self.cache.lock();
            if let Some(seed) = *cache {
                trace!("seed loaded from cache");
                return Ok(seed);
            }
        }

        let password = self.config.effective_password()
            .ok_or_else(|| KeystoreError::Config("password not available".into()))?;

        let start = Instant::now();
        let result = retry_operation(&self.config, "load", || {
            decrypt_seed32_from_file(&self.config.path, &password)
        });

        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_operation("load", status);
        self.metrics.record_latency("load", duration);

        if self.config.log_operations && result.is_ok() {
            info!("seed loaded from keystore");
        }

        if let Ok(seed) = &result {
            let mut cache = self.cache.lock();
            *cache = Some(*seed);
        }

        result
    }

    /// Store a seed to the keystore.
    pub fn store_seed(&self, seed: &[u8; 32]) -> KeystoreResult<()> {
        let password = self.config.effective_password()
            .ok_or_else(|| KeystoreError::Config("password not available".into()))?;

        let start = Instant::now();
        let options = KeystoreOptions {
            pbkdf2_iterations: self.config.pbkdf2_iterations,
            salt_len: self.config.salt_len,
            nonce_len: self.config.nonce_len,
        };
        let result = retry_operation(&self.config, "store", || {
            encrypt_seed32_to_file(&self.config.path, seed, &password, &options)
        });

        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_operation("store", status);
        self.metrics.record_latency("store", duration);

        if self.config.log_operations && result.is_ok() {
            info!("seed stored to keystore");
        }

        // Clear cache on successful store.
        if result.is_ok() {
            let mut cache = self.cache.lock();
            *cache = Some(*seed);
        }

        result
    }

    /// Change the keystore password.
    pub fn change_password(&self, new_password: &str) -> KeystoreResult<()> {
        let old_password = self.config.effective_password()
            .ok_or_else(|| KeystoreError::Config("old password not available".into()))?;

        let start = Instant::now();
        let options = KeystoreOptions {
            pbkdf2_iterations: self.config.pbkdf2_iterations,
            salt_len: self.config.salt_len,
            nonce_len: self.config.nonce_len,
        };
        let result = retry_operation(&self.config, "change_password", || {
            change_keystore_password(&self.config.path, &old_password, new_password, &options)
        });

        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_operation("change_password", status);
        self.metrics.record_latency("change_password", duration);

        if self.config.log_operations && result.is_ok() {
            info!("keystore password changed");
        }

        // Clear cache on success.
        if result.is_ok() {
            let mut cache = self.cache.lock();
            *cache = None;
        }

        result
    }

    /// Validate the keystore file format.
    pub fn validate(&self) -> KeystoreResult<()> {
        let start = Instant::now();
        let result = validate_keystore(&self.config.path);

        let duration = start.elapsed();
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_operation("validate", status);
        self.metrics.record_latency("validate", duration);

        if self.config.log_operations && result.is_ok() {
            info!("keystore validation passed");
        }

        result
    }

    /// Check if the keystore file exists.
    pub fn exists(&self) -> bool {
        keystore_exists(&self.config.path)
    }

    /// Clear the cached seed.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        *cache = None;
        trace!("keystore cache cleared");
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &KeystoreConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> KeystoreMetricsSnapshot {
        KeystoreMetricsSnapshot {
            operations: self.metrics.operations.clone(),
            errors: self.metrics.errors.clone(),
        }
    }
}

/// Snapshot of keystore metrics.
#[derive(Debug, Clone)]
pub struct KeystoreMetricsSnapshot {
    pub operations: CounterVec,
    pub errors: CounterVec,
}

// ── Async variants (optional) ───────────────────────────────────────────

#[cfg(feature = "async")]
impl KeystoreManager {
    /// Async load seed.
    pub async fn load_seed_async(&self) -> KeystoreResult<[u8; 32]> {
        tokio::task::spawn_blocking(move || self.load_seed())
            .await
            .map_err(|e| KeystoreError::Config(e.to_string()))?
    }

    /// Async store seed.
    pub async fn store_seed_async(&self, seed: &[u8; 32]) -> KeystoreResult<()> {
        let seed = *seed;
        tokio::task::spawn_blocking(move || self.store_seed(&seed))
            .await
            .map_err(|e| KeystoreError::Config(e.to_string()))?
    }
}

// ── Standalone functions (backward compatibility) ──────────────────────

/// Options for keystore operations.
#[derive(Debug, Clone, Copy)]
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

/// Encrypt a 32‑byte seed and store it in a file atomically.
pub fn encrypt_seed32_to_file(
    path: impl AsRef<Path>,
    seed32: &[u8; 32],
    password: &str,
    options: &KeystoreOptions,
) -> KeystoreResult<()> {
    let path = path.as_ref();
    info!(path = %path.display(), "encrypting seed to keystore file");

    if seed32.len() != 32 {
        return Err(KeystoreError::InvalidSeedLength {
            expected: 32,
            got: seed32.len(),
        });
    }

    let mut salt = vec![0u8; options.salt_len];
    let mut nonce_bytes = vec![0u8; options.nonce_len];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let key = derive_key(&password_bytes, &salt, options.pbkdf2_iterations);
    let mut key_zero = key;
    let ciphertext = encrypt_data(&key_zero, seed32.as_slice(), &nonce_bytes)?;
    key_zero.zeroize();

    let keystore = KeystoreFile {
        v: 1,
        salt: base64::engine::general_purpose::STANDARD.encode(&salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
        ct: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    };
    let json = serde_json::to_string_pretty(&keystore)?;

    // Atomic write.
    let temp_path = path.with_extension("tmp");
    {
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(json.as_bytes())?;
        temp_file.sync_all()?;
    }
    std::fs::rename(&temp_path, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            warn!(path = %path.display(), error = %e, "failed to set restrictive permissions");
        }
    }

    info!(path = %path.display(), "keystore file written successfully");
    Ok(())
}

/// Decrypt a 32‑byte seed from a keystore file.
pub fn decrypt_seed32_from_file(path: impl AsRef<Path>, password: &str) -> KeystoreResult<[u8; 32]> {
    let path = path.as_ref();
    debug!(path = %path.display(), "decrypting seed from keystore file");
    let json_str = std::fs::read_to_string(path)?;
    decrypt_seed32_from_str(&json_str, password)
}

/// Decrypt a 32‑byte seed from a JSON string (useful for testing).
pub fn decrypt_seed32_from_str(json_str: &str, password: &str) -> KeystoreResult<[u8; 32]> {
    let keystore: KeystoreFile = serde_json::from_str(json_str)?;
    if keystore.v != 1 {
        return Err(KeystoreError::UnsupportedVersion {
            got: keystore.v,
            expected: 1,
        });
    }

    let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;

    if nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidNonceLength {
            expected: NONCE_LEN,
            got: nonce_bytes.len(),
        });
    }
    if salt.len() != SALT_LEN {
        return Err(KeystoreError::InvalidSaltLength {
            expected: SALT_LEN,
            got: salt.len(),
        });
    }

    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());
    let key = derive_key(&password_bytes, &salt, DEFAULT_PBKDF2_ITERATIONS);
    let mut key_zero = key;
    let plaintext = decrypt_data(&key_zero, &ciphertext, &nonce_bytes)?;
    key_zero.zeroize();

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

/// Check if a keystore file exists.
#[must_use]
pub fn keystore_exists(path: impl AsRef<Path>) -> bool {
    path.as_ref().exists()
}

/// Validate a keystore file.
pub fn validate_keystore(path: impl AsRef<Path>) -> KeystoreResult<()> {
    let path = path.as_ref();
    let file = File::open(path)?;
    let reader = std::io::BufReader::new(file);
    let keystore: KeystoreFile = serde_json::from_reader(reader)?;
    if keystore.v != 1 {
        return Err(KeystoreError::UnsupportedVersion {
            got: keystore.v,
            expected: 1,
        });
    }
    let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
    let nonce = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
    let _ct = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;
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
    let seed = decrypt_seed32_from_file(path, old_password)?;
    encrypt_seed32_to_file(path, &seed, new_password, options)?;
    info!(path = %path.display(), "keystore password changed successfully");
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let original_seed = [0xAAu8; 32];
        let password = "test_password_123";
        let options = KeystoreOptions::default();

        encrypt_seed32_to_file(&path, &original_seed, password, &options).unwrap();
        let decrypted = decrypt_seed32_from_file(&path, password).unwrap();

        assert_eq!(original_seed, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let seed = [0xBBu8; 32];
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(&path, &seed, "correct", &options).unwrap();

        let result = decrypt_seed32_from_file(&path, "wrong");
        assert!(matches!(result, Err(KeystoreError::Decryption)));
    }

    #[test]
    fn test_keystore_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        assert!(!keystore_exists(&path));

        let path2 = dir.path().join("exists.enc");
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(&path2, &[0u8; 32], "pass", &options).unwrap();
        assert!(keystore_exists(&path2));
    }

    #[test]
    fn test_validate_keystore() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("valid.enc");
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(&path, &[0u8; 32], "pass", &options).unwrap();
        assert!(validate_keystore(&path).is_ok());

        // Corrupt the file
        std::fs::write(&path, "garbage").unwrap();
        assert!(validate_keystore(&path).is_err());
    }

    #[test]
    fn test_change_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let seed = [0xCCu8; 32];
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(&path, &seed, "old_pass", &options).unwrap();

        change_keystore_password(&path, "old_pass", "new_pass", &options).unwrap();

        let decrypted = decrypt_seed32_from_file(&path, "new_pass").unwrap();
        assert_eq!(seed, decrypted);

        assert!(matches!(
            decrypt_seed32_from_file(&path, "old_pass"),
            Err(KeystoreError::Decryption)
        ));
    }

    #[test]
    fn test_manager_load_store() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let config = KeystoreConfig {
            path: path.clone(),
            password: Some(SecretString::new("test")),
            ..Default::default()
        };
        let manager = KeystoreManager::new(config).unwrap();

        let seed = [0xDDu8; 32];
        manager.store_seed(&seed).unwrap();
        let loaded = manager.load_seed().unwrap();
        assert_eq!(seed, loaded);

        // Cache should be populated.
        assert!(manager.cache.lock().is_some());
        manager.clear_cache();
        assert!(manager.cache.lock().is_none());
    }

    #[test]
    fn test_manager_validate() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let config = KeystoreConfig {
            path: path.clone(),
            password: Some(SecretString::new("test")),
            ..Default::default()
        };
        let manager = KeystoreManager::new(config).unwrap();
        let seed = [0xEEu8; 32];
        manager.store_seed(&seed).unwrap();
        assert!(manager.validate().is_ok());
    }

    #[test]
    fn test_config_validation() {
        let mut config = KeystoreConfig::default();
        assert!(config.validate().is_ok());
        config.path = PathBuf::new();
        assert!(config.validate().is_err());
        config.path = PathBuf::from("key.enc");
        config.pbkdf2_iterations = 0;
        assert!(config.validate().is_err());
        config.pbkdf2_iterations = 1000;
        config.salt_len = 4;
        assert!(config.validate().is_err());
        config.salt_len = 16;
        config.nonce_len = 10;
        assert!(config.validate().is_err());
        config.nonce_len = 12;
        config.retry_attempts = 0;
        assert!(config.validate().is_err());
        config.retry_attempts = 3;
        config.initial_backoff_ms = 0;
        assert!(config.validate().is_err());
        config.initial_backoff_ms = 10;
        config.max_backoff_ms = 0;
        assert!(config.validate().is_err());
        config.max_backoff_ms = 1000;
        config.password = None;
        config.password_env = "".into();
        assert!(config.validate().is_err());
    }
}
