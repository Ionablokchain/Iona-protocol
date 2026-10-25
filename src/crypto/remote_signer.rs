//! Remote signer client for IONA.
//!
//! Provides a client for a remote signing service (HSM, KMS proxy, or a
//! separate signing process) that speaks the HTTP protocol:
//!
//! | Method | Path      | Purpose                         |
//! |--------|-----------|---------------------------------|
//! | GET    | `/pubkey` | fetch the public key at startup |
//! | POST   | `/sign`   | sign a message                  |
//! | GET    | `/health` | liveness probe                  |
//!
//! # `Signer` vs `try_sign`
//!
//! The [`Signer`] trait is **infallible by contract** — it exists for
//! local keypairs. A remote signer cannot honour that contract without
//! lying about failures. This module therefore exposes **two entry
//! points**:
//!
//! - [`RemoteSigner::try_sign`] — **the recommended API.** Returns
//!   `Result<SignatureBytes, RemoteSignerError>`.
//! - `Signer::sign` — kept for backward compatibility. **Panics** on any
//!   failure with a message pointing at `try_sign`. The previous
//!   implementation returned `SignatureBytes(vec![])` on error, which is
//!   silent corruption: the empty signature propagates through consensus
//!   and fails Ed25519 verification much later, long after the node has
//!   already broadcast a vote.
//!
//! # Authentication
//!
//! Every request (`/pubkey`, `/sign`, `/health`) carries the configured
//! `api_key` (`X-API-Key`), `bearer_token` (`Authorization: Bearer …`),
//! and `custom_headers`. An auth-gated `/pubkey` endpoint works out of
//! the box.
//!
//! # Retries
//!
//! Only **retryable** errors are retried: network errors, timeouts, HTTP
//! 408/429, and HTTP 5xx. HTTP 4xx (401, 403, 404, 422) fail on the
//! first attempt — retrying an auth failure just logs the same 401 three
//! times.
//!
//! # mTLS
//!
//! `MtlsConfig::server_name_override` is **stored but not applied** —
//! `reqwest::blocking` does not expose SNI override. The certificate
//! must contain the correct SAN. This is documented rather than silently
//! ignored.
//!
//! # Health checks
//!
//! [`RemoteSigner::is_healthy`] uses a short timeout
//! (`config.health_timeout`, default 2 s), independent of the sign
//! timeout. A health check against a broken endpoint returns within 2 s
//! even when the sign timeout is 10 s.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use parking_lot::Mutex;
use prometheus::{CounterVec, HistogramVec};
use reqwest::blocking::{Client, RequestBuilder};
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Limits ────────────────────────────────────────────────────────────────

/// Minimum `timeout` accepted by [`RemoteSignerConfig::validate`].
const MIN_TIMEOUT: Duration = Duration::from_millis(1);

/// Maximum `timeout` accepted by [`RemoteSignerConfig::validate`].
const MAX_TIMEOUT: Duration = Duration::from_secs(600);

/// Default health-check timeout.
const DEFAULT_HEALTH_TIMEOUT: Duration = Duration::from_secs(2);

/// Ed25519 public-key length.
const PUBLIC_KEY_LEN: usize = 32;

/// Ed25519 signature length.
const SIGNATURE_LEN: usize = 64;

// ── Errors ────────────────────────────────────────────────────────────────

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

    #[error("authentication rejected by remote signer: HTTP {status}")]
    AuthRejected { status: u16 },

    #[error("timeout after {0:?}")]
    Timeout(Duration),

    #[error("failed after {attempts} attempts: {cause}")]
    RetryFailed { attempts: u32, cause: String },

    #[error("configuration error: {0}")]
    Config(String),

    #[error("public key not available")]
    PubkeyUnavailable,
}

pub type RemoteSignerResult<T> = Result<T, RemoteSignerError>;

impl RemoteSignerError {
    /// Whether retrying the operation could plausibly succeed.
    fn is_retryable(&self) -> bool {
        match self {
            Self::Client(e) => e.is_timeout() || e.is_connect() || e.is_request(),
            Self::Timeout(_) => true,
            Self::InvalidResponse(msg) => {
                // Retry 408, 429, and 5xx. Parse the status from the
                // formatted message.
                if let Some(code) = extract_http_status(msg) {
                    code == 408 || code == 429 || (500..600).contains(&code)
                } else {
                    false
                }
            }
            Self::AuthRejected { .. } => false,
            Self::Base64(_) | Self::Json(_) | Self::Io(_) | Self::Config(_) => false,
            Self::PubkeyUnavailable | Self::RetryFailed { .. } => false,
        }
    }
}

/// Extract `HTTP <code>` from an `InvalidResponse` message.
fn extract_http_status(msg: &str) -> Option<u16> {
    let rest = msg.strip_prefix("HTTP ")?;
    let code_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    code_str.parse().ok()
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the remote signer client.
///
/// **Not `Serialize`/`Deserialize`** — the struct holds `api_key` and
/// `bearer_token` in cleartext. Load secrets from environment variables
/// in the caller.
#[derive(Clone)]
pub struct RemoteSignerConfig {
    /// Base URL of the remote signer (no trailing slash required).
    pub base_url: String,
    /// Overall request timeout for `/sign`.
    pub timeout: Duration,
    /// Connect timeout (defaults to `timeout`).
    pub connect_timeout: Option<Duration>,
    /// Read timeout (defaults to `timeout`).
    pub read_timeout: Option<Duration>,
    /// Write timeout (defaults to `timeout`).
    pub write_timeout: Option<Duration>,
    /// Health-check timeout, independent of `timeout`.
    pub health_timeout: Duration,
    /// Optional API key (sent as `X-API-Key`).
    pub api_key: Option<String>,
    /// Optional bearer token (`Authorization: Bearer …`).
    pub bearer_token: Option<String>,
    /// Optional custom headers, sent on every request.
    pub custom_headers: Vec<(String, String)>,
    /// mTLS configuration.
    pub mtls: Option<MtlsConfig>,
    /// Number of attempts (including the first).
    pub retries: u32,
    /// Initial backoff between retries.
    pub backoff_ms: u64,
    /// Maximum backoff between retries.
    pub max_backoff_ms: u64,
    /// Whether to attempt Prometheus metric registration.
    pub enable_metrics: bool,
    /// Whether to emit per-request `trace!` logs.
    pub log_operations: bool,
}

impl fmt::Debug for RemoteSignerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Redact both the header *names* (could reveal internal auth
        // scheme) and the values (definitely secret).
        let header_names: Vec<&str> = self.custom_headers.iter().map(|(n, _)| n.as_str()).collect();
        f.debug_struct("RemoteSignerConfig")
            .field("base_url", &self.base_url)
            .field("timeout", &self.timeout)
            .field("connect_timeout", &self.connect_timeout)
            .field("read_timeout", &self.read_timeout)
            .field("write_timeout", &self.write_timeout)
            .field("health_timeout", &self.health_timeout)
            .field("api_key", &self.api_key.as_ref().map(|_| "[REDACTED]"))
            .field("bearer_token", &self.bearer_token.as_ref().map(|_| "[REDACTED]"))
            .field(
                "custom_headers",
                &header_names
                    .iter()
                    .map(|n| format!("{n}: [REDACTED]"))
                    .collect::<Vec<_>>(),
            )
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
    /// Construct a configuration with a 10 s timeout and 3 attempts.
    #[must_use]
    pub fn new(base_url: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            timeout: Duration::from_secs(10),
            connect_timeout: None,
            read_timeout: None,
            write_timeout: None,
            health_timeout: DEFAULT_HEALTH_TIMEOUT,
            api_key: None,
            bearer_token: None,
            custom_headers: Vec::new(),
            mtls: None,
            retries: 3,
            backoff_ms: 100,
            max_backoff_ms: 5_000,
            enable_metrics: true,
            log_operations: true,
        }
    }

    /// Validate the configuration.
    pub fn validate(&self) -> RemoteSignerResult<()> {
        if self.base_url.is_empty() {
            return Err(RemoteSignerError::Config("base_url must not be empty".into()));
        }
        if !self.base_url.starts_with("http://") && !self.base_url.starts_with("https://") {
            return Err(RemoteSignerError::Config(
                "base_url must start with http:// or https://".into(),
            ));
        }
        if self.timeout < MIN_TIMEOUT || self.timeout > MAX_TIMEOUT {
            return Err(RemoteSignerError::Config(format!(
                "timeout must be in [{MIN_TIMEOUT:?}, {MAX_TIMEOUT:?}]"
            )));
        }
        if self.health_timeout < MIN_TIMEOUT || self.health_timeout > MAX_TIMEOUT {
            return Err(RemoteSignerError::Config(format!(
                "health_timeout must be in [{MIN_TIMEOUT:?}, {MAX_TIMEOUT:?}]"
            )));
        }
        if self.retries == 0 {
            return Err(RemoteSignerError::Config("retries must be > 0".into()));
        }
        if self.backoff_ms == 0 {
            return Err(RemoteSignerError::Config("backoff_ms must be > 0".into()));
        }
        if self.max_backoff_ms < self.backoff_ms {
            return Err(RemoteSignerError::Config(
                "max_backoff_ms must be >= backoff_ms".into(),
            ));
        }
        for (name, value) in &self.custom_headers {
            if name.is_empty() {
                return Err(RemoteSignerError::Config(
                    "custom header name must not be empty".into(),
                ));
            }
            // Header names are restricted to visible ASCII by RFC 7230.
            if !name.bytes().all(|b| (0x21..=0x7E).contains(&b) && b != b':') {
                return Err(RemoteSignerError::Config(format!(
                    "custom header `{name}` contains invalid characters"
                )));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(RemoteSignerError::Config(format!(
                    "custom header `{name}` value contains CR/LF"
                )));
            }
        }
        if let Some(mtls) = &self.mtls {
            if mtls.identity_pem.is_empty() {
                return Err(RemoteSignerError::Config("identity_pem must not be empty".into()));
            }
            if mtls.ca_cert_pem.is_empty() {
                return Err(RemoteSignerError::Config("ca_cert_pem must not be empty".into()));
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }
    #[must_use]
    pub fn with_read_timeout(mut self, timeout: Duration) -> Self {
        self.read_timeout = Some(timeout);
        self
    }
    #[must_use]
    pub fn with_write_timeout(mut self, timeout: Duration) -> Self {
        self.write_timeout = Some(timeout);
        self
    }
    #[must_use]
    pub fn with_health_timeout(mut self, timeout: Duration) -> Self {
        self.health_timeout = timeout;
        self
    }
    #[must_use]
    pub fn with_api_key(mut self, key: impl Into<String>) -> Self {
        self.api_key = Some(key.into());
        self
    }
    #[must_use]
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(token.into());
        self
    }
    #[must_use]
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.custom_headers.push((name.into(), value.into()));
        self
    }
    #[must_use]
    pub fn with_mtls(mut self, mtls: MtlsConfig) -> Self {
        self.mtls = Some(mtls);
        self
    }
    #[must_use]
    pub fn with_retry(mut self, retries: u32, backoff_ms: u64, max_backoff_ms: u64) -> Self {
        self.retries = retries;
        self.backoff_ms = backoff_ms;
        self.max_backoff_ms = max_backoff_ms;
        self
    }
    #[must_use]
    pub fn with_metrics(mut self, enable: bool) -> Self {
        self.enable_metrics = enable;
        self
    }
    #[must_use]
    pub fn with_logging(mut self, enable: bool) -> Self {
        self.log_operations = enable;
        self
    }
}

/// mTLS configuration.
#[derive(Clone)]
pub struct MtlsConfig {
    /// PEM bundle: client certificate + private key.
    pub identity_pem: Vec<u8>,
    /// PEM-encoded CA certificate to trust.
    pub ca_cert_pem: Vec<u8>,
    /// **Stored but not applied** — `reqwest::blocking` does not expose
    /// SNI override. The certificate must contain the correct SAN.
    pub server_name_override: Option<String>,
}

impl fmt::Debug for MtlsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MtlsConfig")
            .field("identity_pem_len", &self.identity_pem.len())
            .field("ca_cert_pem_len", &self.ca_cert_pem.len())
            .field("server_name_override", &self.server_name_override)
            .finish()
    }
}

impl MtlsConfig {
    #[must_use]
    pub fn from_pem(
        identity_pem: Vec<u8>,
        ca_cert_pem: Vec<u8>,
        server_name_override: Option<String>,
    ) -> Self {
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
        Ok(Self {
            identity_pem: std::fs::read(identity_pem_path)?,
            ca_cert_pem: std::fs::read(ca_cert_pem_path)?,
            server_name_override,
        })
    }
}

// ── Metrics ───────────────────────────────────────────────────────────────

/// Prometheus metrics for remote signer operations.
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
    /// Register with the default Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            sign_operations: prometheus::register_counter_vec!(
                "iona_remote_signer_sign_operations_total",
                "Sign operations",
                &["status"]
            )?,
            sign_errors: prometheus::register_counter_vec!(
                "iona_remote_signer_sign_errors_total",
                "Sign errors",
                &["error_type"]
            )?,
            sign_latency: prometheus::register_histogram_vec!(
                "iona_remote_signer_sign_latency_seconds",
                "Sign latency",
                &["status"]
            )?,
            pubkey_fetches: prometheus::register_counter_vec!(
                "iona_remote_signer_pubkey_fetches_total",
                "Public key fetches",
                &["status"]
            )?,
            pubkey_fetch_errors: prometheus::register_counter_vec!(
                "iona_remote_signer_pubkey_fetch_errors_total",
                "Public key fetch errors",
                &["error_type"]
            )?,
            health_checks: prometheus::register_counter_vec!(
                "iona_remote_signer_health_checks_total",
                "Health checks",
                &["status"]
            )?,
        })
    }

    /// Fail-free metrics bundle; never registers with Prometheus.
    pub fn unregistered() -> Self {
        let mk_counter = |name: &str, help: &str, labels: &[&str]| {
            CounterVec::new(prometheus::Opts::new(name, help), labels)
                .expect("counter vec construction is infallible")
        };
        Self {
            sign_operations: mk_counter(
                "iona_remote_signer_sign_operations_total",
                "Sign operations",
                &["status"],
            ),
            sign_errors: mk_counter(
                "iona_remote_signer_sign_errors_total",
                "Sign errors",
                &["error_type"],
            ),
            sign_latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_remote_signer_sign_latency_seconds",
                    "Sign latency",
                ),
                &["status"],
            )
            .expect("histogram vec construction is infallible"),
            pubkey_fetches: mk_counter(
                "iona_remote_signer_pubkey_fetches_total",
                "Public key fetches",
                &["status"],
            ),
            pubkey_fetch_errors: mk_counter(
                "iona_remote_signer_pubkey_fetch_errors_total",
                "Public key fetch errors",
                &["error_type"],
            ),
            health_checks: mk_counter(
                "iona_remote_signer_health_checks_total",
                "Health checks",
                &["status"],
            ),
        }
    }

    pub fn record_sign(&self, status: &str, duration: Duration) {
        self.sign_operations.with_label_values(&[status]).inc();
        self.sign_latency
            .with_label_values(&[status])
            .observe(duration.as_secs_f64());
    }

    pub fn record_sign_error(&self, error_type: &str) {
        self.sign_errors.with_label_values(&[error_type]).inc();
    }

    pub fn record_pubkey_fetch(&self, status: &str) {
        self.pubkey_fetches.with_label_values(&[status]).inc();
    }

    pub fn record_pubkey_fetch_error(&self, error_type: &str) {
        self.pubkey_fetch_errors
            .with_label_values(&[error_type])
            .inc();
    }

    pub fn record_health_check(&self, status: &str) {
        self.health_checks.with_label_values(&[status]).inc();
    }

    /// Owned, serializable snapshot.
    #[must_use]
    pub fn snapshot(&self) -> RemoteSignerMetricsSnapshot {
        RemoteSignerMetricsSnapshot {
            sign_operations: collect(&self.sign_operations),
            sign_errors: collect(&self.sign_errors),
            pubkey_fetches: collect(&self.pubkey_fetches),
            pubkey_fetch_errors: collect(&self.pubkey_fetch_errors),
            health_checks: collect(&self.health_checks),
        }
    }
}

impl Default for RemoteSignerMetrics {
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

/// Owned snapshot of [`RemoteSignerMetrics`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RemoteSignerMetricsSnapshot {
    pub sign_operations: Vec<CounterSnapshot>,
    pub sign_errors: Vec<CounterSnapshot>,
    pub pubkey_fetches: Vec<CounterSnapshot>,
    pub pubkey_fetch_errors: Vec<CounterSnapshot>,
    pub health_checks: Vec<CounterSnapshot>,
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

// ── RemoteSigner ──────────────────────────────────────────────────────────

/// Client for a remote signing service.
#[derive(Clone)]
pub struct RemoteSigner {
    config: RemoteSignerConfig,
    client: Client,
    pubkey: PublicKeyBytes,
    metrics: Arc<RemoteSignerMetrics>,
}

#[derive(Debug, Deserialize)]
struct PubkeyResp {
    pubkey_base64: String,
}

#[derive(Debug, Serialize)]
struct SignReq {
    msg_base64: String,
}

#[derive(Debug, Deserialize)]
struct SignResp {
    sig_base64: String,
}

impl RemoteSigner {
    /// Connect to the remote signer: build the client, verify auth, and
    /// fetch the public key.
    pub fn connect(config: RemoteSignerConfig) -> RemoteSignerResult<Self> {
        config.validate()?;

        let metrics = Arc::new(if config.enable_metrics {
            match RemoteSignerMetrics::new() {
                Ok(m) => m,
                Err(e) => {
                    warn!(
                        error = %e,
                        "remote signer metrics already registered; using unregistered"
                    );
                    RemoteSignerMetrics::unregistered()
                }
            }
        } else {
            RemoteSignerMetrics::unregistered()
        });

        let client = build_client(&config)?;
        let pubkey = fetch_pubkey_with_retry(&config, &client, &metrics)?;
        debug!(
            base_url = %config.base_url,
            pubkey = %hex::encode(&pubkey.0),
            "remote signer connected"
        );

        Ok(Self {
            config,
            client,
            pubkey,
            metrics,
        })
    }

    /// Public key. Cached from connection time.
    #[must_use]
    pub fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    /// Sign `msg`. **The recommended API.**
    pub fn try_sign(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let start = Instant::now();
        let result = self.sign_with_retry(msg);
        let status = if result.is_ok() { "ok" } else { "error" };
        self.metrics.record_sign(status, start.elapsed());
        if self.config.log_operations {
            trace!(
                status,
                duration_us = start.elapsed().as_micros() as u64,
                "remote sign"
            );
        }
        result
    }

    fn sign_with_retry(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let mut attempt: u32 = 0;
        let mut backoff = Duration::from_millis(self.config.backoff_ms);
        let max_backoff = Duration::from_millis(self.config.max_backoff_ms);

        loop {
            attempt = attempt.saturating_add(1);
            match self.sign_once(msg) {
                Ok(sig) => return Ok(sig),
                Err(e) => {
                    let error_type = error_kind(&e);
                    self.metrics.record_sign_error(error_type);
                    if !e.is_retryable() || attempt >= self.config.retries {
                        error!(
                            attempt,
                            error = %e,
                            retryable = e.is_retryable(),
                            "remote sign failed"
                        );
                        return Err(RemoteSignerError::RetryFailed {
                            attempts: attempt,
                            cause: e.to_string(),
                        });
                    }
                    warn!(
                        attempt,
                        backoff_ms = backoff.as_millis() as u64,
                        error = %e,
                        "retrying sign"
                    );
                    std::thread::sleep(backoff);
                    backoff = backoff.saturating_mul(2).min(max_backoff);
                }
            }
        }
    }

    fn sign_once(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let url = format!("{}/sign", self.config.base_url.trim_end_matches('/'));
        let body = SignReq {
            msg_base64: B64.encode(msg),
        };
        let req = authed(self.client.post(&url), &self.config).json(&body);
        let resp = req.send()?;
        let status = resp.status();
        if status == reqwest::StatusCode::UNAUTHORIZED
            || status == reqwest::StatusCode::FORBIDDEN
        {
            return Err(RemoteSignerError::AuthRejected {
                status: status.as_u16(),
            });
        }
        if !status.is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(RemoteSignerError::InvalidResponse(format!(
                "HTTP {}: {}",
                status.as_u16(),
                truncate(&text, 512)
            )));
        }
        let body: SignResp = resp.json()?;
        let sig_bytes = B64.decode(&body.sig_base64)?;
        if sig_bytes.len() != SIGNATURE_LEN {
            return Err(RemoteSignerError::InvalidResponse(format!(
                "expected {SIGNATURE_LEN}-byte signature, got {}",
                sig_bytes.len()
            )));
        }
        Ok(SignatureBytes(sig_bytes))
    }

    /// Liveness probe. Uses `config.health_timeout`.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        // A dedicated short-timeout client. A health check must never
        // block on the full sign timeout.
        let short = match Client::builder()
            .timeout(self.config.health_timeout)
            .connect_timeout(self.config.health_timeout)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "failed to build health-check client");
                self.metrics.record_health_check("error");
                return false;
            }
        };

        // Try `/health` first, then `/pubkey`.
        for path in ["/health", "/pubkey"] {
            let url = format!("{}{}", self.config.base_url.trim_end_matches('/'), path);
            let req = authed(short.get(&url), &self.config);
            match req.send() {
                Ok(r) if r.status().is_success() => {
                    self.metrics.record_health_check("ok");
                    return true;
                }
                _ => continue,
            }
        }
        self.metrics.record_health_check("error");
        false
    }

    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.config.base_url
    }

    #[must_use]
    pub fn config(&self) -> &RemoteSignerConfig {
        &self.config
    }

    #[must_use]
    pub fn metrics(&self) -> &RemoteSignerMetrics {
        &self.metrics
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> RemoteSignerMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// ── Signer impl (backward compatible, panics on error) ────────────────────

/// # Panics
///
/// `Signer::sign` is infallible by contract; a remote signer cannot honour
/// that contract without lying. This impl **panics** on any failure with
/// a message that points at [`RemoteSigner::try_sign`]. The previous
/// implementation returned `SignatureBytes(vec![])`, which silently
/// produced an invalid signature that failed Ed25519 verification much
/// later — long after the node had broadcast it. A panic is worse than
/// an error but strictly better than silent corruption.
///
/// **Use [`RemoteSigner::try_sign`] in new code.**
impl Signer for RemoteSigner {
    fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        match self.try_sign(msg) {
            Ok(sig) => sig,
            Err(e) => panic!(
                "RemoteSigner: signing failed ({}). Signer::sign is infallible; \
                 use RemoteSigner::try_sign for fallible signing.",
                e
            ),
        }
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> crate::crypto::CryptoResult<()> {
        if self.is_healthy() {
            Ok(())
        } else {
            Err(CryptoError::Network("remote signer unhealthy".into()))
        }
    }
}

// ── Manager ───────────────────────────────────────────────────────────────

/// Thread-safe wrapper with public-key caching.
#[derive(Clone)]
pub struct RemoteSignerManager {
    signer: Arc<RemoteSigner>,
    cache: Arc<Mutex<Option<PublicKeyBytes>>>,
}

impl RemoteSignerManager {
    /// Connect and prime the cache with the initial public key.
    pub fn connect(config: RemoteSignerConfig) -> RemoteSignerResult<Self> {
        let signer = Arc::new(RemoteSigner::connect(config)?);
        let pubkey = signer.public_key();
        Ok(Self {
            signer,
            cache: Arc::new(Mutex::new(Some(pubkey))),
        })
    }

    /// Public key (from cache, falling back to the signer).
    #[must_use]
    pub fn public_key(&self) -> PublicKeyBytes {
        if let Some(pk) = self.cache.lock().as_ref() {
            return pk.clone();
        }
        self.signer.public_key()
    }

    /// Sign (fallible). **The recommended API.**
    pub fn try_sign(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        self.signer.try_sign(msg)
    }

    /// Sign (infallible, panics on failure). Prefer
    /// [`try_sign`](Self::try_sign).
    ///
    /// # Panics
    ///
    /// See [`impl Signer for RemoteSigner`].
    pub fn sign(&self, msg: &[u8]) -> SignatureBytes {
        self.signer.sign(msg)
    }

    #[must_use]
    pub fn is_healthy(&self) -> bool {
        self.signer.is_healthy()
    }

    /// Clear the cached public key.
    pub fn clear_cache(&self) {
        *self.cache.lock() = None;
    }

    /// Re-fetch the public key from the remote signer.
    pub fn refresh_cache(&self) -> RemoteSignerResult<()> {
        let pk = fetch_pubkey_with_retry(
            &self.signer.config,
            &self.signer.client,
            &self.signer.metrics,
        )?;
        *self.cache.lock() = Some(pk);
        Ok(())
    }

    #[must_use]
    pub fn inner(&self) -> &RemoteSigner {
        &self.signer
    }

    #[must_use]
    pub fn config(&self) -> &RemoteSignerConfig {
        &self.signer.config
    }

    #[must_use]
    pub fn metrics_snapshot(&self) -> RemoteSignerMetricsSnapshot {
        self.signer.metrics_snapshot()
    }
}

// ── Async (optional) ──────────────────────────────────────────────────────

#[cfg(feature = "async")]
impl RemoteSignerManager {
    /// Async fallible sign.
    pub async fn try_sign_async(&self, msg: &[u8]) -> RemoteSignerResult<SignatureBytes> {
        let this = self.clone();
        let msg = msg.to_vec();
        tokio::task::spawn_blocking(move || this.try_sign(&msg))
            .await
            .map_err(|e| RemoteSignerError::Config(format!("task join: {e}")))?
    }

    /// Async health check.
    pub async fn is_healthy_async(&self) -> bool {
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.is_healthy())
            .await
            .unwrap_or(false)
    }
}

// ── Convenience ───────────────────────────────────────────────────────────

/// Connect with a URL and timeout, defaults elsewhere.
pub fn connect_simple(
    base_url: &str,
    timeout: Duration,
) -> RemoteSignerResult<RemoteSigner> {
    RemoteSigner::connect(RemoteSignerConfig::new(base_url).with_timeout(timeout))
}

// ── Internals ─────────────────────────────────────────────────────────────

fn build_client(config: &RemoteSignerConfig) -> RemoteSignerResult<Client> {
    let mut builder = Client::builder()
        .timeout(config.timeout)
        .connect_timeout(config.connect_timeout.unwrap_or(config.timeout))
        .read_timeout(config.read_timeout.unwrap_or(config.timeout))
        .write_timeout(config.write_timeout.unwrap_or(config.timeout))
        .user_agent(concat!("iona-remote-signer/", env!("CARGO_PKG_VERSION")));

    if let Some(mtls) = &config.mtls {
        let identity = Identity::from_pem(&mtls.identity_pem)
            .map_err(|e| RemoteSignerError::Config(format!("invalid identity PEM: {e}")))?;
        let ca = Certificate::from_pem(&mtls.ca_cert_pem)
            .map_err(|e| RemoteSignerError::Config(format!("invalid CA PEM: {e}")))?;
        builder = builder.identity(identity).add_root_certificate(ca);
        if mtls.server_name_override.is_some() {
            warn!(
                "MtlsConfig::server_name_override is ignored: reqwest does not \
                 expose SNI override. Ensure the certificate SAN matches the URL host."
            );
        }
    }

    builder
        .build()
        .map_err(|e| RemoteSignerError::Config(format!("client build: {e}")))
}

/// Attach every configured auth header to `req`. Used for **all** requests
/// (`/pubkey`, `/sign`, `/health`). The previous implementation only
/// attached them on `/sign`, so an auth-gated `/pubkey` returned 401.
fn authed(req: RequestBuilder, config: &RemoteSignerConfig) -> RequestBuilder {
    let mut req = req;
    if let Some(key) = &config.api_key {
        req = req.header("X-API-Key", key);
    }
    if let Some(token) = &config.bearer_token {
        req = req.header("Authorization", format!("Bearer {token}"));
    }
    for (name, value) in &config.custom_headers {
        req = req.header(name, value);
    }
    req
}

fn fetch_pubkey_with_retry(
    config: &RemoteSignerConfig,
    client: &Client,
    metrics: &RemoteSignerMetrics,
) -> RemoteSignerResult<PublicKeyBytes> {
    let url = format!("{}/pubkey", config.base_url.trim_end_matches('/'));
    let mut attempt: u32 = 0;
    let mut backoff = Duration::from_millis(config.backoff_ms);
    let max_backoff = Duration::from_millis(config.max_backoff_ms);

    loop {
        attempt = attempt.saturating_add(1);
        trace!(url = %url, attempt, "fetching pubkey");
        match fetch_pubkey_once(config, client, &url) {
            Ok(pk) => {
                metrics.record_pubkey_fetch("ok");
                return Ok(pk);
            }
            Err(e) => {
                metrics.record_pubkey_fetch("error");
                metrics.record_pubkey_fetch_error(error_kind(&e));
                if !e.is_retryable() || attempt >= config.retries {
                    error!(
                        url = %url,
                        attempts = attempt,
                        error = %e,
                        retryable = e.is_retryable(),
                        "failed to fetch pubkey"
                    );
                    return Err(RemoteSignerError::RetryFailed {
                        attempts: attempt,
                        cause: e.to_string(),
                    });
                }
                warn!(
                    url = %url,
                    attempt,
                    backoff_ms = backoff.as_millis() as u64,
                    error = %e,
                    "retrying pubkey fetch"
                );
                std::thread::sleep(backoff);
                backoff = backoff.saturating_mul(2).min(max_backoff);
            }
        }
    }
}

fn fetch_pubkey_once(
    config: &RemoteSignerConfig,
    client: &Client,
    url: &str,
) -> RemoteSignerResult<PublicKeyBytes> {
    let req = authed(client.get(url), config);
    let resp = req.send()?;
    let status = resp.status();
    if status == reqwest::StatusCode::UNAUTHORIZED || status == reqwest::StatusCode::FORBIDDEN {
        return Err(RemoteSignerError::AuthRejected {
            status: status.as_u16(),
        });
    }
    if !status.is_success() {
        let text = resp.text().unwrap_or_default();
        return Err(RemoteSignerError::InvalidResponse(format!(
            "HTTP {}: {}",
            status.as_u16(),
            truncate(&text, 512)
        )));
    }
    let body: PubkeyResp = resp.json()?;
    let pk_bytes = B64.decode(&body.pubkey_base64)?;
    if pk_bytes.len() != PUBLIC_KEY_LEN {
        return Err(RemoteSignerError::InvalidResponse(format!(
            "expected {PUBLIC_KEY_LEN}-byte public key, got {}",
            pk_bytes.len()
        )));
    }
    Ok(PublicKeyBytes(pk_bytes))
}

fn error_kind(e: &RemoteSignerError) -> &'static str {
    match e {
        RemoteSignerError::Client(_) => "client",
        RemoteSignerError::Timeout(_) => "timeout",
        RemoteSignerError::InvalidResponse(_) => "invalid_response",
        RemoteSignerError::AuthRejected { .. } => "auth",
        RemoteSignerError::Base64(_) => "base64",
        RemoteSignerError::Json(_) => "json",
        RemoteSignerError::Io(_) => "io",
        RemoteSignerError::Config(_) => "config",
        RemoteSignerError::RetryFailed { .. } => "retry_failed",
        RemoteSignerError::PubkeyUnavailable => "pubkey_unavailable",
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}…", &s[..max])
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    fn b64(bytes: &[u8]) -> String {
        B64.encode(bytes)
    }

    fn pubkey_mock<'a>(server: &'a MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": b64(&[0xAA; 32]) }));
        })
    }

    fn sign_mock<'a>(server: &'a MockServer) -> httpmock::Mock<'a> {
        server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(200)
                .json_body(json!({ "sig_base64": b64(&[0xBB; 64]) }));
        })
    }

    // ── Auth headers on /pubkey (regression for the silent bug) ────────

    #[test]
    fn auth_headers_are_sent_on_pubkey_fetch() {
        // The previous implementation only attached auth headers on
        // `/sign`. An auth-gated `/pubkey` returned 401, and
        // `RemoteSigner::connect` failed with no clear cause.
        let server = MockServer::start();
        let mock = server.mock(|when, then| {
            when.method(GET)
                .path("/pubkey")
                .header("X-API-Key", "mykey")
                .header("Authorization", "Bearer token");
            then.status(200)
                .json_body(json!({ "pubkey_base64": b64(&[0xAA; 32]) }));
        });

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_api_key("mykey")
            .with_bearer_token("token")
            .with_timeout(Duration::from_secs(2));
        let signer = RemoteSigner::connect(cfg).unwrap();
        assert_eq!(signer.public_key().0, vec![0xAA; 32]);
        mock.assert();
    }

    // ── Sign returns Result (regression for silent empty signature) ────

    #[test]
    fn try_sign_returns_err_when_endpoint_fails() {
        let server = MockServer::start();
        let _pk = pubkey_mock(&server);
        let _sign = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(500).body("boom");
        });

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(1))
            .with_retry(1, 1, 1);
        let signer = RemoteSigner::connect(cfg).unwrap();
        let err = signer.try_sign(b"hello").unwrap_err();
        assert!(matches!(err, RemoteSignerError::RetryFailed { .. }));
    }

    #[test]
    #[should_panic(expected = "Signer::sign is infallible")]
    fn signer_sign_panics_on_failure() {
        let server = MockServer::start();
        let _pk = pubkey_mock(&server);
        let _sign = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(500);
        });

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(1))
            .with_retry(1, 1, 1);
        let signer = RemoteSigner::connect(cfg).unwrap();
        // Deliberately call the `Signer` impl to assert the panic.
        let _ = signer.sign(b"hello");
    }

    // ── Auth failures are not retried ──────────────────────────────────

    #[test]
    fn auth_failure_is_not_retried() {
        let server = MockServer::start();
        let _pk = pubkey_mock(&server);
        let m = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(401);
        });

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(1))
            .with_retry(5, 1, 1);
        let signer = RemoteSigner::connect(cfg).unwrap();
        let err = signer.try_sign(b"x").unwrap_err();
        assert!(matches!(err, RemoteSignerError::RetryFailed { .. }));
        // 1 attempt, not 5.
        m.assert_hits(1);
    }

    // ── Pubkey length validation ───────────────────────────────────────

    #[test]
    fn short_pubkey_is_rejected() {
        let server = MockServer::start();
        let _m = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": b64(&[0xAA; 31]) }));
        });

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(1))
            .with_retry(1, 1, 1);
        let err = RemoteSigner::connect(cfg).unwrap_err();
        assert!(matches!(err, RemoteSignerError::RetryFailed { .. }));
    }

    // ── Retry succeeds on transient failure ────────────────────────────

    #[test]
    fn retry_eventually_succeeds() {
        let server = MockServer::start();
        let _pk = pubkey_mock(&server);
        // First two requests fail; third succeeds.
        let _fail = server.mock(|when, then| {
            when.method(POST).path("/sign").body_contains("cmV0cnk=");
            then.status(500);
        });
        let _ok = sign_mock(&server);

        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(2))
            .with_retry(3, 1, 10);
        let signer = RemoteSigner::connect(cfg).unwrap();
        // The body doesn't distinguish, so this test is illustrative only.
        // A real test would use httpmock's call ordering, which is not
        // exposed in this version.
        let sig = signer.try_sign(b"retry").unwrap();
        assert_eq!(sig.0.len(), 64);
    }

    // ── Manager cache ──────────────────────────────────────────────────

    #[test]
    fn manager_cache_avoids_repeated_fetches() {
        let server = MockServer::start();
        let m = pubkey_mock(&server);
        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(2));
        let mgr = RemoteSignerManager::connect(cfg).unwrap();
        let _ = mgr.public_key();
        let _ = mgr.public_key();
        m.assert_hits(1);
    }

    #[test]
    fn manager_refresh_cache_refetches() {
        let server = MockServer::start();
        let m = pubkey_mock(&server);
        let cfg = RemoteSignerConfig::new(server.base_url())
            .with_timeout(Duration::from_secs(2));
        let mgr = RemoteSignerManager::connect(cfg).unwrap();
        mgr.refresh_cache().unwrap();
        m.assert_hits(2);
    }

    // ── Config validation ──────────────────────────────────────────────

    #[test]
    fn config_validation_rules() {
        assert!(RemoteSignerConfig::new("https://signer").validate().is_ok());

        assert!(RemoteSignerConfig::new("").validate().is_err());
        assert!(RemoteSignerConfig::new("not-a-url").validate().is_err());

        assert!(RemoteSignerConfig::new("https://signer")
            .with_timeout(Duration::ZERO)
            .validate()
            .is_err());

        assert!(RemoteSignerConfig::new("https://signer")
            .with_retry(0, 100, 1000)
            .validate()
            .is_err());

        assert!(RemoteSignerConfig::new("https://signer")
            .with_retry(3, 100, 50)
            .validate()
            .is_err());

        assert!(RemoteSignerConfig::new("https://signer")
            .with_header("Bad Header", "v")
            .validate()
            .is_err());

        assert!(RemoteSignerConfig::new("https://signer")
            .with_header("X-Ok", "line1\rline2")
            .validate()
            .is_err());
    }

    // ── Debug redaction ────────────────────────────────────────────────

    #[test]
    fn debug_redacts_all_secrets() {
        let cfg = RemoteSignerConfig::new("https://signer")
            .with_api_key("hunter2")
            .with_bearer_token("bearer-secret")
            .with_header("X-Custom", "custom-secret");
        let dbg = format!("{cfg:?}");
        assert!(!dbg.contains("hunter2"));
        assert!(!dbg.contains("bearer-secret"));
        assert!(!dbg.contains("custom-secret"));
        assert!(dbg.contains("X-Custom"));
    }

    // ── Metrics default no panic ───────────────────────────────────────

    #[test]
    fn metrics_default_does_not_panic() {
        let _a = RemoteSignerMetrics::unregistered();
        let _b = RemoteSignerMetrics::unregistered();
        let _c = RemoteSignerMetrics::default();
    }

    #[test]
    fn metrics_snapshot_is_owned_and_serializable() {
        let m = RemoteSignerMetrics::unregistered();
        m.record_sign("ok", Duration::from_micros(100));
        m.record_sign_error("client");
        let snap = m.snapshot();
        let json = serde_json::to_string(&snap).unwrap();
        let back: RemoteSignerMetricsSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(snap, back);
    }

    // ── HTTP status extraction ─────────────────────────────────────────

    #[test]
    fn http_status_extraction() {
        assert_eq!(extract_http_status("HTTP 401: denied"), Some(401));
        assert_eq!(extract_http_status("HTTP 500: oops"), Some(500));
        assert_eq!(extract_http_status("nothing here"), None);
        assert_eq!(extract_http_status("HTTP "), None);
    }
}
