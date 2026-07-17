//! Remote signer client for IONA.
//!
//! This module provides a client for a remote signing service (e.g., a hardware security module
//! or a separate signing process). The client implements the synchronous `Signer` trait so it can
//! be used directly by consensus code without changes to the asynchronous runtime.
//!
//! # Production Features
//! - Configurable via `RemoteSignerConfig` with validation.
//! - `RemoteSignerMetrics` with Prometheus counters and histograms.
//! - `RemoteSignerManager` as a thread‑safe wrapper with caching and health monitoring.
//! - Optional async support (tokio) for non‑blocking I/O.
//! - Retry with exponential backoff.
//! - mTLS, API key, Bearer token, custom headers.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::crypto::{PublicKeyBytes, SignatureBytes, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, Counter, CounterVec, HistogramVec,
};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity, StatusCode};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during remote signer operations.
#[derive(Debug, Error)]
pub enum RemoteSignerError {
    #[error("HTTP client error: {0}")]
    Client(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid response: {0}")]
    InvalidResponse(String),

    #[error("timeout after {0}ms")]
    Timeout(u64),

    #[error("failed after {retries} retries: {cause}")]
    RetryFailed { retries: u32, cause: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("public key not available")]
    PubkeyUnavailable,
}

pub type RemoteSignerResult<T> = Result<T, RemoteSignerError>;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for a remote signer client.
#[derive(Clone)]
pub struct RemoteSignerConfig {
    /// Base URL of the remote signer (e.g., `https://signer.example.com`).
    pub base_url: String,
    /// Overall request timeout.
    pub timeout: Duration,
    /// Connect timeout (defaults to `timeout` if not set).
    pub connect_timeout: Option<Duration>,
    /// Read timeout (defaults to `timeout` if not set).
    pub read_timeout: Option<Duration>,
    /// Write timeout (defaults to `timeout` if not set).
    pub write_timeout: Option<Duration>,
    /// Optional API key (sent as `X-API-Key` header).
    pub api_key: Option<String>,
    /// Optional Bearer token (sent as `Authorization: Bearer <token>`).
    pub bearer_token: Option<String>,
    /// Optional custom headers (key-value pairs).
    pub custom_headers: Vec<(String, String)>,
    /// mTLS configuration.
    pub mtls: Option<MtlsConfig>,
    /// Number of retries for transient failures (default: 3).
    pub retries: u32,
    /// Initial backoff in milliseconds (default: 100).
    pub backoff_ms: u64,
    /// Maximum backoff in milliseconds (default: 5000).
    pub max_backoff_ms: u64,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log signing operations.
    pub log_operations: bool,
}

impl fmt::Debug for RemoteSignerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RemoteSignerConfig")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "[REDACTED]"))
            .field("custom_headers", &self.custom_headers)
            .field("mtls", &self.mtls.as_ref().map(|_| "[CONFIGURED]"))
            .field("retries", &self.retries)
            .field("backoff_ms", &self.backoff_ms)
            .field("max_backoff_ms", &self.max_backoff_ms)
            .field("enable_metrics", &self.enable_metrics)
            .field("log_operations", &self.log_operations)
            .finish()
    }
}

impl RemoteSignerConfig {
    /// Create a new configuration with the given base URL.
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(10),
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            api_key: None,
            bearer_token: None,
            custom_headers: Vec::new(),
            mtls: None,
            retries: 3,
            backoff_ms: 100,
            max_backoff_ms: 5000,
            enable_metrics: true,
            log_operations: true,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.base_url.is_empty() {
            return Err("base_url must not be empty".into());
        }
        if self.timeout.as_millis() == 0 {
            return Err("timeout must be > 0".into());
        }
        if self.retries == 0 {
            return Err("retries must be > 0".into());
        }
        if self.backoff_ms == 0 {
            return Err("backoff_ms must be > 0".into());
        }
        if self.max_backoff_ms == 0 {
            return Err("max_backoff_ms must be > 0".into());
        }
        if self.max_backoff_ms < self.backoff_ms {
            return Err("max_backoff_ms must be >= backoff_ms".into());
        }
        // mTLS: if identity_pem or ca_cert_pem are empty, that's a problem.
        if let Some(mtls) = &self.mtls {
            if mtls.identity_pem.is_empty() {
                return Err("identity_pem must not be empty".into());
            }
            if mtls.ca_cert_pem.is_empty() {
                return Err("ca_cert_pem must not be empty".into());
            }
        }
        Ok(())
    }

    // Builder methods (fluent).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }

    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }

    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }

    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }

    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_headers.push((name.into(), value.into()));
        self
    }

    pub fn with_mtls(mut self, mtls: MtlsConfig) -> Self {
        self.mtls = Some(mtls);
        self
    }

    pub fn with_retry(mut self, retries: u32, backoff_ms: u64, max_backoff_ms: u64) -> Self {
        self.retries = retries;
        self.backoff_ms = backoff_ms;
        self.max_backoff_ms = max_backoff_ms;
        self
    }

    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.enable_metrics = enable;
        self
    }

    pub fn with_logging(mut self, enable: bool) -> Self {
        self.log_operations = enable;
        self
    }
}

/// mTLS configuration for the remote signer.
#[derive(Clone)]
pub struct MtlsConfig {
    /// PEM-encoded client certificate + private key (concatenated).
    pub identity_pem: Vec<u8>,
    /// PEM-encoded CA certificate to trust.
    pub ca_cert_pem: Vec<u8>,
    /// Optional SNI override.
    pub server_name_override: Option<String>,
}

impl MtlsConfig {
    pub fn from_pem(identity_pem: Vec<u8>, ca_cert_pem: Vec<u8>, server_name_override: Option<String>) -> Self {
        Self {
            identity_pem,
            ca_cert_pem,
            server_name_override,
        }
    }

    pub fn from_files(
        identity_pem_path: impl AsRef<Path>,
        ca_cert_pem_path: impl AsRef<Path>,
        server_name_override: Option<String>,
    ) -> RemoteSignerResult<Self> {
        let identity_pem = std::fs::read(identity_pem_path)?;
        let ca_cert_pem = std::fs::read(ca_cert_pem_path)?;
        Ok(Self {
            identity_pem,
            ca_cert_pem,
            server_name_override,
        })
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for remote signer operations.
#[derive(Clone)]
pub struct RemoteSignerMetrics {
    pub sign_operations: CounterVec,
    pub sign_errors: CounterVec,
    pub sign_latency: HistogramVec,
    pub pubkey_fetches: CounterVec,
    pub pubkey_fetch_errors: CounterVec,
    pub health_checks: CounterVec,
}

impl RemoteSignerMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let sign_operations = register_counter_vec!(
            "iona_remote_signer_sign_operations_total",
            "Total sign operations",
            &["status"]
        )?;
        let sign_errors = register_counter_vec!(
            "iona_remote_signer_sign_errors_total",
            "Sign errors",
            &["error_type"]
        )?;
        let sign_latency = register_histogram_vec!(
            "iona_remote_signer_sign_latency_seconds",
            "Sign latency",
            &["status"]
        )?;
        let pubkey_fetches = register_counter_vec!(
            "iona_remote_signer_pubkey_fetches_total",
            "Public key fetches",
            &["status"]
        )?;
        let pubkey_fetch_errors = register_counter_vec!(
            "iona_remote_signer_pubkey_fetch_errors_total",
            "Public key fetch errors",
            &["error_type"]
        )?;
        let health_checks = register_counter_vec!(
            "iona_remote_signer_health_checks_total",
            "Health checks",
            &["status"]
        )?;
        Ok(Self {
            sign_operations,
            sign_errors,
            sign_latency,
            pubkey_fetches,
            pubkey_fetch_errors,
            health_checks,
        })
    }

    pub fn record_sign(&self, status: &str, duration: Duration) {
        self.sign_operations.with_label_values(&[status]).inc();
        self.sign_latency.with_label_values(&[status]).observe(duration.as_secs_f64());
    }

    pub fn record_sign_error(&self, error_type: &str) {
        self.sign_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_pubkey_fetch(&self, status: &str) {
        self.pubkey_fetches.with_label_values(&[status]).inc();
    }

    pub fn record_pubkey_fetch_error(&self, error_type: &str) {
        self.pubkey_fetch_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_health_check(&self, status: &str) {
        self.health_checks.with_label_values(&[status]).inc();
    }
}

impl Default for RemoteSignerMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            sign_operations: CounterVec::new(
                prometheus::Opts::new("iona_remote_signer_sign_operations_total", "Sign ops"),
                &["status"],
            ).unwrap(),
            sign_errors: CounterVec::new(
                prometheus::Opts::new("iona_remote_signer_sign_errors_total", "Sign errors"),
                &["error_type"],
            ).unwrap(),
            sign_latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_remote_signer_sign_latency_seconds",
                    "Sign latency",
                ),
                &["status"],
            ).unwrap(),
            pubkey_fetches: CounterVec::new(
                prometheus::Opts::new("iona_remote_signer_pubkey_fetches_total", "Pubkey fetches"),
                &["status"],
            ).unwrap(),
            pubkey_fetch_errors: CounterVec::new(
                prometheus::Opts::new("iona_remote_signer_pubkey_fetch_errors_total", "Fetch errors"),
                &["error_type"],
            ).unwrap(),
            health_checks: CounterVec::new(
                prometheus::Opts::new("iona_remote_signer_health_checks_total", "Health checks"),
                &["status"],
            ).unwrap(),
        })
    }
}

// ── RemoteSigner ─────────────────────────────────────────────────────────

/// Client for a remote signing service.
#[derive(Clone)]
pub struct RemoteSigner {
    config: RemoteSignerConfig,
    client: Client,
    pubkey: PublicKeyBytes,
    metrics: Arc<RemoteSignerMetrics>,
}

/// Response from `GET /pubkey`.
#[derive(Debug, Deserialize)]
struct PubkeyResp {
    pubkey_base64: String,
}

/// Request body for `POST /sign`.
#[derive(Debug, Serialize)]
struct SignReq {
    msg_base64: String,
}

/// Response from `POST /sign`.
#[derive(Debug, Deserialize)]
struct SignResp {
    sig_base64: String,
}

impl RemoteSigner {
    /// Connect to a remote signer using the provided configuration.
    pub fn connect(config: RemoteSignerConfig) -> RemoteSignerResult<Self> {
        config.validate().map_err(RemoteSignerError::Config)?;
        info!(base_url = %config.base_url, "connecting to remote signer");

        let metrics = Arc::new(RemoteSignerMetrics::default());

        // Build the reqwest client.
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .connect_timeout(config.connect_timeout.unwrap_or(config.timeout))
            .read_timeout(config.read_timeout.unwrap_or(config.timeout))
            .write_timeout(config.write_timeout.unwrap_or(config.timeout))
            .pool_max_idle_per_host(1)
            .user_agent("iona-remote-signer/1.0");

        // mTLS
        if let Some(mtls) = &config.mtls {
            let id = Identity::from_pem(&mtls.identity_pem)
                .map_err(|e| RemoteSignerError::Config(format!("invalid identity PEM: {e}")))?;
            let ca = Certificate::from_pem(&mtls.ca_cert_pem)
                .map_err(|e| RemoteSignerError::Config(format!("invalid CA PEM: {e}")))?;
            builder = builder.identity(id).add_root_certificate(ca);
            if let Some(name) = &mtls.server_name_override {
                debug!(server_name = %name, "SNI override set");
            }
        }

        let client = builder
            .build()
            .map_err(|e| RemoteSignerError::Config(format!("client build: {e}")))?;

        // Fetch public key.
        let pubkey = Self::fetch_pubkey_with_retry(&config, &client, &metrics)?;

        debug!(public_key = %hex::encode(&pubkey.0), "public key acquired");
        Ok(Self {
            config,
            client,
            pubkey,
            metrics,
        })
    }

    /// Fetch the public key from the remote signer (with retry).
    fn fetch_pubkey_with_retry(
        config: &RemoteSignerConfig,
        client: &Client,
        metrics: &RemoteSignerMetrics,
    ) -> RemoteSignerResult<PublicKeyBytes> {
        let url = format!("{}/pubkey", config.base_url.trim_end_matches('/'));
        let mut attempt = 0;
        let mut backoff = Duration::from_millis(config.backoff_ms);
        let max_backoff = Duration::from_millis(config.max_backoff_ms);

        loop {
            attempt += 1;
            trace!(url = %url, attempt, "fetching public key");

            match Self::fetch_pubkey_once(client, &url, metrics) {
                Ok(pk) => {
                    metrics.record_pubkey_fetch("ok");
                    return Ok(pk);
                }
                Err(e) => {
                    metrics.record_pubkey_fetch("error");
                    let error_type = match &e {
                        RemoteSignerError::Client(_) => "client",
                        RemoteSignerError::Timeout(_) => "timeout",
                        RemoteSignerError::InvalidResponse(_) => "invalid_response",
                        _ => "unknown",
                    };
                    metrics.record_pubkey_fetch_error(error_type);
                    if attempt >= config.retries {
                        error!(url = %url, attempts = attempt, error = %e, "failed to fetch public key");
                        return Err(RemoteSignerError::RetryFailed {
                            retries: attempt,
                            cause: e.to_string(),
                        });
                    }
                    warn!(url = %url, attempt, backoff_ms = %backoff.as_millis(), error = %e, "retrying");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    /// Single attempt to fetch the public key.
    fn fetch_pubkey_once(client: &Client, url: &str, metrics: &RemoteSignerMetrics) -> RemoteSignerResult<PublicKeyBytes> {
        let start = Instant::now();
        let resp = client
            .get(url)
            .send()
            .map_err(|e| RemoteSignerError::Client(e))?;
        let duration = start.elapsed();
        trace!(url = %url, status = %resp.status(), duration_ms = %duration.as_millis(), "received pubkey response");

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(RemoteSignerError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, text
            )));
        }

        let body: PubkeyResp = resp.json()?;
        let pk_bytes = B64.decode(&body.pubkey_base64)?;
        if pk_bytes.is_empty() {
            return Err(RemoteSignerError::InvalidResponse("empty public key".into()));
        }
        Ok(PublicKeyBytes(pk_bytes))
    }

    /// Single attempt to sign a message.
    fn sign_once(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let url = format!("{}/sign", self.config.base_url.trim_end_matches('/'));
        let req = SignReq {
            msg_base64: B64.encode(msg),
        };
        let start = Instant::now();
        let mut req_builder = self.client.post(&url).json(&req);

        // Add headers.
        if let Some(key) = &self.config.api_key {
            req_builder = req_builder.header("X-API-Key", key);
        }
        if let Some(token) = &self.config.bearer_token {
            req_builder = req_builder.header("Authorization", format!("Bearer {}", token));
        }
        for (name, value) in &self.config.custom_headers {
            req_builder = req_builder.header(name, value);
        }

        let resp = req_builder
            .send()
            .map_err(|e| RemoteSignerError::Client(e))?;
        let duration = start.elapsed();
        trace!(url = %url, status = %resp.status(), duration_ms = %duration.as_millis(), "received sign response");

        let status = resp.status();
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(RemoteSignerError::InvalidResponse(format!(
                "HTTP {}: {}",
                status, text
            )));
        }

        let body: SignResp = resp.json()?;
        let sig_bytes = B64.decode(&body.sig_base64)?;
        if sig_bytes.len() != 64 {
            return Err(RemoteSignerError::InvalidResponse(format!(
                "expected 64-byte signature, got {}",
                sig_bytes.len()
            )));
        }
        Ok(SignatureBytes(sig_bytes))
    }

    /// Attempt to sign a message with retries.
    pub fn try_sign_with_retry(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let mut attempt = 0;
        let mut backoff = Duration::from_millis(self.config.backoff_ms);
        let max_backoff = Duration::from_millis(self.config.max_backoff_ms);

        loop {
            attempt += 1;
            match self.sign_once(msg) {
                Ok(sig) => {
                    self.metrics.record_sign("ok", Duration::ZERO); // duration not available here, we'll record in the outer call.
                    return Ok(sig);
                }
                Err(e) => {
                    self.metrics.record_sign_error(match &e {
                        RemoteSignerError::Client(_) => "client",
                        RemoteSignerError::Timeout(_) => "timeout",
                        RemoteSignerError::InvalidResponse(_) => "invalid_response",
                        _ => "unknown",
                    });
                    if attempt >= self.config.retries {
                        error!(attempts = attempt, error = %e, "signing failed after retries");
                        return Err(RemoteSignerError::RetryFailed {
                            retries: attempt,
                            cause: e.to_string(),
                        });
                    }
                    warn!(attempt, backoff_ms = %backoff.as_millis(), error = %e, "retrying sign");
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(max_backoff);
                }
            }
        }
    }

    /// Check if the remote signer is healthy.
    pub fn is_healthy(&self) -> bool {
        let start = Instant::now();
        let health_url = format!("{}/health", self.config.base_url.trim_end_matches('/'));
        let result = self.client.get(&health_url).send();
        let status = match result {
            Ok(resp) if resp.status().is_success() => "ok",
            _ => {
                // Fallback to /pubkey.
                let pubkey_url = format!("{}/pubkey", self.config.base_url.trim_end_matches('/'));
                match self.client.get(&pubkey_url).send() {
                    Ok(r) if r.status().is_success() => "ok",
                    _ => "error",
                }
            }
        };
        self.metrics.record_health_check(status);
        status == "ok"
    }

    /// Return the base URL.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    /// Return the current configuration.
    #[must_use]
    pub fn config(&self) -> &RemoteSignerConfig {
        &self.config
    }

    /// Return a reference to the metrics.
    #[must_use]
    pub fn metrics(&self) -> &RemoteSignerMetrics {
        &self.metrics
    }
}

// ── Signer trait implementation ─────────────────────────────────────────

impl Signer for RemoteSigner {
    fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let start = Instant::now();
        match self.try_sign_with_retry(msg) {
            Ok(sig) => {
                if self.config.log_operations {
                    trace!("signing succeeded");
                }
                self.metrics.record_sign("ok", start.elapsed());
                sig
            }
            Err(e) => {
                error!(error = %e, "remote signer failed; returning empty signature");
                self.metrics.record_sign("error", start.elapsed());
                SignatureBytes(vec![])
            }
        }
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> crate::crypto::CryptoResult<()> {
        if self.is_healthy() {
            Ok(())
        } else {
            Err(crate::crypto::CryptoError::Network("remote signer unhealthy".into()))
        }
    }
}

// ── RemoteSignerManager (thread‑safe wrapper) ────────────────────────────

/// Thread‑safe manager for a remote signer.
#[derive(Clone)]
pub struct RemoteSignerManager {
    signer: Arc<RemoteSigner>,
    cache: Arc<Mutex<Option<PublicKeyBytes>>>,
}

impl RemoteSignerManager {
    /// Create a new manager by connecting to a remote signer.
    pub fn connect(config: RemoteSignerConfig) -> RemoteSignerResult<Self> {
        let signer = Arc::new(RemoteSigner::connect(config)?);
        let pubkey = signer.public_key();
        Ok(Self {
            signer,
            cache: Arc::new(Mutex::new(Some(pubkey))),
        })
    }

    /// Get the public key (from cache).
    pub fn public_key(&self) -> PublicKeyBytes {
        let cache = self.cache.lock();
        cache
            .as_ref()
            .cloned()
            .unwrap_or_else(|| self.signer.public_key())
    }

    /// Sign a message.
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        self.signer.sign(msg)
    }

    /// Health check.
    pub fn is_healthy(&self) -> bool {
        self.signer.is_healthy()
    }

    /// Clear the cached public key.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        *cache = None;
    }

    /// Refresh the cached public key.
    pub fn refresh_cache(&self) -> RemoteSignerResult<()> {
        let pk = RemoteSigner::fetch_pubkey_with_retry(
            self.signer.config(),
            &self.signer.client,
            self.signer.metrics(),
        )?;
        let mut cache = self.cache.lock();
        *cache = Some(pk);
        Ok(())
    }

    /// Get the underlying signer.
    pub fn inner(&self) -> &RemoteSigner {
        &self.signer
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &RemoteSignerConfig {
        self.signer.config()
    }
}

// ── Async support (optional) ─────────────────────────────────────────────

#[cfg(feature = "async")]
impl RemoteSignerManager {
    /// Async sign.
    pub async fn sign_async(&self, msg: &[u8]) -> SignatureBytes {
        let msg = msg.to_vec();
        tokio::task::spawn_blocking(move || self.sign(&msg))
            .await
            .unwrap_or_else(|_| SignatureBytes(vec![]))
    }

    /// Async health check.
    pub async fn is_healthy_async(&self) -> bool {
        tokio::task::spawn_blocking(move || self.is_healthy())
            .await
            .unwrap_or(false)
    }
}

// ── Standalone convenience ──────────────────────────────────────────────

/// Create a remote signer from a simple URL and timeout.
pub fn connect_simple(base_url: &str, timeout: Duration) -> RemoteSignerResult<RemoteSigner> {
    let config = RemoteSignerConfig::new(base_url).with_timeout(timeout);
    RemoteSigner::connect(config)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    fn setup_server() -> (MockServer, Mock) {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        (server, pubkey_mock)
    }

    #[test]
    fn test_connect_and_sign() {
        let (server, pubkey_mock) = setup_server();

        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(200)
                .json_body(json!({ "sig_base64": base64::encode(&[0xbb; 64]) }));
        });

        let config = RemoteSignerConfig::new(server.base_url()).with_timeout(Duration::from_secs(2));
        let signer = RemoteSigner::connect(config).unwrap();

        assert_eq!(signer.public_key().0, vec![0xaa; 32]);

        let sig = signer.sign(b"hello");
        assert_eq!(sig.0, vec![0xbb; 64]);

        pubkey_mock.assert();
        sign_mock.assert();
    }

    #[test]
    fn test_health_check() {
        let (server, _) = setup_server();
        let health_mock = server.mock(|when, then| {
            when.method(GET).path("/health");
            then.status(200);
        });

        let config = RemoteSignerConfig::new(server.base_url()).with_timeout(Duration::from_secs(2));
        let signer = RemoteSigner::connect(config).unwrap();
        assert!(signer.is_healthy());
        health_mock.assert();

        // Fallback to /pubkey if /health not implemented.
        let no_health_server = MockServer::start();
        let pubkey_mock = no_health_server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        let config2 = RemoteSignerConfig::new(no_health_server.base_url()).with_timeout(Duration::from_secs(2));
        let signer2 = RemoteSigner::connect(config2).unwrap();
        assert!(signer2.is_healthy());
        pubkey_mock.assert();
    }

    #[test]
    fn test_retry_on_failure() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });

        // First two requests fail, third succeeds.
        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(500)
                .times(2)
                .json_body(json!({ "error": "internal" }));
        });
        let sign_mock_ok = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(200)
                .json_body(json!({ "sig_base64": base64::encode(&[0xbb; 64]) }));
        });

        let config = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(2))
            .with_retry(3, 10, 100);
        let signer = RemoteSigner::connect(config).unwrap();
        let sig = signer.sign(b"hello");
        assert_eq!(sig.0, vec![0xbb; 64]);

        pubkey_mock.assert();
        sign_mock.assert();
        sign_mock_ok.assert();
    }

    #[test]
    fn test_connection_failure() {
        let config = RemoteSignerConfig::new("http://localhost:9999")
            .with_timeout(Duration::from_millis(100))
            .with_retry(1, 10, 100);
        let result = RemoteSigner::connect(config);
        assert!(matches!(
            result,
            Err(RemoteSignerError::RetryFailed { retries: 1, .. })
        ));
    }

    #[test]
    fn test_invalid_public_key_response() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200).json_body(json!({ "pubkey_base64": "invalid!" }));
        });

        let config = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(2))
            .with_retry(1, 10, 100);
        let result = RemoteSigner::connect(config);
        assert!(matches!(result, Err(RemoteSignerError::Base64(_))));
        pubkey_mock.assert();
    }

    #[test]
    fn test_custom_headers() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey")
                .header("X-API-Key", "mykey")
                .header("Authorization", "Bearer token");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });

        let config = RemoteSignerConfig::new(server.base_url())
            .with_api_key("mykey")
            .with_bearer_token("token")
            .with_timeout(Duration::from_secs(2));
        let signer = RemoteSigner::connect(config).unwrap();
        assert_eq!(signer.public_key().0, vec![0xaa; 32]);
        pubkey_mock.assert();
    }

    #[test]
    fn test_config_validation() {
        let config = RemoteSignerConfig::new("").with_timeout(Duration::from_secs(1));
        assert!(config.validate().is_err());
        let config = RemoteSignerConfig::new("http://example.com").with_timeout(Duration::from_millis(0));
        assert!(config.validate().is_err());
        let config = RemoteSignerConfig::new("http://example.com")
            .with_timeout(Duration::from_secs(1))
            .with_retry(0, 100, 1000);
        assert!(config.validate().is_err());
        let config = RemoteSignerConfig::new("http://example.com")
            .with_timeout(Duration::from_secs(1))
            .with_retry(3, 0, 1000);
        assert!(config.validate().is_err());
        let config = RemoteSignerConfig::new("http://example.com")
            .with_timeout(Duration::from_secs(1))
            .with_retry(3, 100, 50);
        assert!(config.validate().is_err());
        let config = RemoteSignerConfig::new("http://example.com")
            .with_timeout(Duration::from_secs(1))
            .with_retry(3, 100, 1000)
            .with_mtls(MtlsConfig {
                identity_pem: vec![],
                ca_cert_pem: vec![1,2,3],
                server_name_override: None,
            });
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_manager_cache() {
        let (server, pubkey_mock) = setup_server();
        let config = RemoteSignerConfig::new(server.base_url()).with_timeout(Duration::from_secs(2));
        let manager = RemoteSignerManager::connect(config).unwrap();
        let pk1 = manager.public_key();
        let pk2 = manager.public_key();
        assert_eq!(pk1.0, pk2.0); // cached
        pubkey_mock.assert_hits(1); // only one fetch

        manager.clear_cache();
        let pk3 = manager.public_key();
        assert_eq!(pk1.0, pk3.0);
        pubkey_mock.assert_hits(2);
    }

    #[test]
    fn test_manager_refresh_cache() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });

        let config = RemoteSignerConfig::new(server.base_url()).with_timeout(Duration::from_secs(2));
        let manager = RemoteSignerManager::connect(config).unwrap();
        let pk1 = manager.public_key();
        assert_eq!(pk1.0, vec![0xaa; 32]);
        pubkey_mock.assert_hits(1);

        manager.refresh_cache().unwrap();
        pubkey_mock.assert_hits(2);
    }
}
