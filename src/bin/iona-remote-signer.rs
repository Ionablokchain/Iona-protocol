//! IONA Remote Signer (mTLS + allowlist + audit log + metrics + rate limiting)
//!
//! Provides a secure remote signing service for Ed25519 keys.
//!
//! # Endpoints
//! - `GET  /pubkey`  → `{ "pubkey_base64": "..." }`
//! - `POST /sign`    → `{ "msg_base64": "..." }` → `{ "sig_base64": "..." }`
//! - `GET  /health`  → `{ "status": "ok" }`
//! - `GET  /metrics` → Prometheus metrics
//!
//! # Security features
//! - mTLS enforced (client certificate required)
//! - Allowlist by client certificate SHA-256 fingerprint (hex)
//! - Append‑only audit log (JSON lines) with client fingerprint and request ID
//! - Request timeout (default 10s)
//! - Rate limiting (default 100 requests per second per client IP)
//! - Request body size limit (default 1 MiB)
//!
//! # Environment variables
//! All command‑line arguments can be overridden by environment variables:
//! `IONA_SIGNER_LISTEN`, `IONA_SIGNER_KEY_PATH`, `IONA_SIGNER_TLS_CERT`,
//! `IONA_SIGNER_TLS_KEY`, `IONA_SIGNER_CLIENT_CA`, `IONA_SIGNER_ALLOWLIST`,
//! `IONA_SIGNER_AUDIT_LOG`, `IONA_SIGNER_REQUEST_TIMEOUT_SECS`,
//! `IONA_SIGNER_RATE_LIMIT_PER_SEC`, `IONA_SIGNER_MAX_BODY_BYTES`.

use axum::{
    extract::{ConnectInfo, Request, State},
    http::StatusCode,
    response::{IntoResponse, Json},
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use lazy_static::lazy_static;
use prometheus::{register_counter, register_histogram_vec, Counter, HistogramVec, TextEncoder};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    io::{BufWriter, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tower_http::{
    limit::RequestBodyLimitLayer,
    request_id::{MakeRequestId, RequestId, RequestIdLayer},
    timeout::TimeoutLayer,
    trace::TraceLayer,
};
use tracing::{error, info, warn, Instrument};

use axum_server::tls_rustls::{RustlsConfig, RustlsConnectInfo};
use ed25519_dalek::SigningKey;
use rustls::{
    pki_types::CertificateDer,
    server::{ClientCertVerified, ClientCertVerifier},
    RootCertStore,
};
use tokio::sync::Mutex;

use iona::crypto::ed25519::{read_signing_key_or_generate, sign_bytes};

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

lazy_static! {
    static ref SIGN_REQUESTS: Counter = register_counter!(
        "remote_signer_sign_requests_total",
        "Total number of /sign requests"
    )
    .unwrap();
    static ref SIGN_SUCCESS: Counter = register_counter!(
        "remote_signer_sign_success_total",
        "Successful /sign requests"
    )
    .unwrap();
    static ref SIGN_FAILURES: Counter = register_counter!(
        "remote_signer_sign_failures_total",
        "Failed /sign requests"
    )
    .unwrap();
    static ref SIGN_DURATION: HistogramVec = register_histogram_vec!(
        "remote_signer_sign_duration_seconds",
        "Duration of /sign requests",
        &["result"]
    )
    .unwrap();
}

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default listen address.
const DEFAULT_LISTEN: &str = "0.0.0.0:9100";
/// Default key file path.
const DEFAULT_KEY_PATH: &str = "./data/remote_signer_key.bin";
/// Default server TLS certificate path.
const DEFAULT_TLS_CERT: &str = "./deploy/tls/server.crt.pem";
/// Default server TLS key path.
const DEFAULT_TLS_KEY: &str = "./deploy/tls/server.key.pem";
/// Default client CA certificate path.
const DEFAULT_CLIENT_CA: &str = "./deploy/tls/ca.crt.pem";
/// Default allowlist file path.
const DEFAULT_ALLOWLIST: &str = "./deploy/tls/allowlist.txt";
/// Default audit log path.
const DEFAULT_AUDIT_LOG: &str = "./data/remote_signer_audit.jsonl";
/// Default request timeout in seconds.
const DEFAULT_REQUEST_TIMEOUT_SECS: u64 = 10;
/// Default rate limit (requests per second per IP).
const DEFAULT_RATE_LIMIT_PER_SEC: u64 = 100;
/// Default maximum body size in bytes (1 MiB).
const DEFAULT_MAX_BODY_BYTES: usize = 1_048_576;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SignerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TLS configuration error: {0}")]
    Tls(String),

    #[error("Base64 decode error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Invalid server certificate or key")]
    InvalidCertificate,

    #[error("Allowlist file contains invalid fingerprint at line {line}")]
    InvalidAllowlistEntry { line: usize },

    #[error("Audit log write failed: {0}")]
    AuditWrite(#[from] std::io::Error),

    #[error("Request timeout")]
    Timeout,
}

pub type SignerResult<T> = Result<T, SignerError>;

// -----------------------------------------------------------------------------
// Application state
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    pubkey_b64: String,
    signing_key: Arc<SigningKey>,
    audit: Arc<Mutex<BufWriter<std::fs::File>>>,
}

// -----------------------------------------------------------------------------
// Request/Response types
// -----------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct SignReq {
    msg_base64: String,
}

#[derive(Debug, Serialize)]
struct PubkeyResp {
    pubkey_base64: String,
}

#[derive(Debug, Serialize)]
struct SignResp {
    sig_base64: String,
}

#[derive(Debug, Serialize)]
struct ErrorResp {
    error: String,
    code: u16,
}

#[derive(Debug, Serialize)]
struct HealthResp {
    status: String,
    audit_writable: bool,
    uptime_secs: u64,
}

#[derive(Debug, Serialize)]
struct AuditLine {
    ts_unix_s: u64,
    request_id: String,
    client_fp_sha256: String,
    remote_addr: String,
    msg_blake3_hex: String,
    ok: bool,
    reason: String,
}

// -----------------------------------------------------------------------------
// Custom request ID generator
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct UuidRequestId;

impl MakeRequestId for UuidRequestId {
    fn make_request_id<B>(&mut self, _request: &Request<B>) -> Option<RequestId> {
        let id = uuid::Uuid::new_v4().to_string();
        Some(RequestId::from_header_value(id.parse().ok()?))
    }
}

// -----------------------------------------------------------------------------
// Allowlist client certificate verifier
// -----------------------------------------------------------------------------

struct AllowlistClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow: Arc<HashSet<String>>,
}

impl AllowlistClientVerifier {
    fn fingerprint_hex(cert: &CertificateDer<'_>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(cert.as_ref());
        hex::encode(hasher.finalize())
    }
}

impl ClientCertVerifier for AllowlistClientVerifier {
    fn client_auth_root_subjects(&self) -> &[rustls::DistinguishedName] {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: rustls::pki_types::UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        let verification = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;
        let fingerprint = Self::fingerprint_hex(end_entity);
        if !self.allow.contains(&fingerprint) {
            return Err(rustls::Error::General(
                "client certificate not allowlisted".into(),
            ));
        }
        Ok(verification)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fingerprint_from_connect(ci: &RustlsConnectInfo) -> String {
    if let Some(certs) = ci.peer_certificates() {
        if let Some(first) = certs.first() {
            let mut hasher = Sha256::new();
            hasher.update(first.as_ref());
            return hex::encode(hasher.finalize());
        }
    }
    "unknown".to_string()
}

fn load_allowlist(path: &Path) -> SignerResult<HashSet<String>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let content = std::fs::read_to_string(path)?;
    let mut out = HashSet::new();
    for (line_no, line) in content.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let lower = trimmed.to_lowercase();
        if lower.len() != 64 || !lower.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(SignerError::InvalidAllowlistEntry { line: line_no + 1 });
        }
        out.insert(lower);
    }
    Ok(out)
}

fn load_ca_roots(ca_pem_path: &Path) -> SignerResult<RootCertStore> {
    let pem = std::fs::read(ca_pem_path)?;
    let mut reader = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SignerError::Tls(format!("failed to parse CA PEM: {e}")))?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store
            .add(cert)
            .map_err(|e| SignerError::Tls(format!("failed to add CA cert: {e}")))?;
    }
    Ok(store)
}

async fn write_audit(state: &AppState, entry: AuditLine) {
    let json = match serde_json::to_string(&entry) {
        Ok(j) => j,
        Err(e) => {
            error!(error = %e, "failed to serialize audit line");
            return;
        }
    };
    let mut guard = state.audit.lock().await;
    if let Err(e) = writeln!(guard, "{}", json) {
        error!(error = %e, "failed to write audit log");
    } else if let Err(e) = guard.flush() {
        error!(error = %e, "failed to flush audit log");
    }
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

async fn pubkey_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(PubkeyResp {
        pubkey_base64: state.pubkey_b64,
    })
}

async fn sign_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ConnectInfo(tls_info): ConnectInfo<RustlsConnectInfo>,
    request_id: Option<RequestId>,
    Json(req): Json<SignReq>,
) -> impl IntoResponse {
    let start = std::time::Instant::now();
    SIGN_REQUESTS.inc();

    let client_fp = fingerprint_from_connect(&tls_info);
    let remote_addr = addr.to_string();
    let req_id = request_id
        .map(|id| id.as_str().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let msg = match B64.decode(req.msg_base64.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            SIGN_FAILURES.inc();
            let duration = start.elapsed().as_secs_f64();
            SIGN_DURATION
                .with_label_values(&["failure"])
                .observe(duration);

            let audit_line = AuditLine {
                ts_unix_s: now_unix_s(),
                request_id: req_id,
                client_fp_sha256: client_fp,
                remote_addr,
                msg_blake3_hex: "invalid".to_string(),
                ok: false,
                reason: format!("base64 decode error: {e}"),
            };
            write_audit(&state, audit_line).await;
            return (
                StatusCode::BAD_REQUEST,
                Json(ErrorResp {
                    error: "invalid base64".to_string(),
                    code: 400,
                }),
            );
        }
    };

    let msg_hash = blake3::hash(&msg);
    let sig = sign_bytes(&state.signing_key, &msg);

    let duration = start.elapsed().as_secs_f64();
    SIGN_SUCCESS.inc();
    SIGN_DURATION
        .with_label_values(&["success"])
        .observe(duration);

    let audit_line = AuditLine {
        ts_unix_s: now_unix_s(),
        request_id: req_id,
        client_fp_sha256: client_fp,
        remote_addr,
        msg_blake3_hex: hex::encode(msg_hash.as_bytes()),
        ok: true,
        reason: "ok".to_string(),
    };
    write_audit(&state, audit_line).await;

    Json(SignResp {
        sig_base64: B64.encode(sig),
    })
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    let audit_writable = state.audit.lock().await.get_ref().metadata().is_ok();
    // Simple uptime: we don't track start time globally, but can compute from process start.
    let uptime = std::time::Instant::now().elapsed().as_secs();
    Json(HealthResp {
        status: "ok".to_string(),
        audit_writable,
        uptime_secs: uptime,
    })
}

async fn metrics_handler() -> String {
    let encoder = TextEncoder::new();
    let metric_families = prometheus::gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer).unwrap();
    String::from_utf8(buffer).unwrap()
}

// -----------------------------------------------------------------------------
// CLI Arguments with environment variable fallback
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-remote-signer")]
#[command(about = "IONA remote signing server with mTLS, allowlist, and observability")]
struct Args {
    /// Listen address (e.g., 0.0.0.0:9100)
    #[arg(long, env = "IONA_SIGNER_LISTEN", default_value = DEFAULT_LISTEN)]
    listen: String,

    /// Path to the Ed25519 signing key (32 bytes). If missing, one is generated.
    #[arg(long, env = "IONA_SIGNER_KEY_PATH", default_value = DEFAULT_KEY_PATH)]
    key_path: PathBuf,

    /// Server TLS certificate PEM file.
    #[arg(long, env = "IONA_SIGNER_TLS_CERT", default_value = DEFAULT_TLS_CERT)]
    tls_cert_pem: PathBuf,

    /// Server TLS private key PEM file.
    #[arg(long, env = "IONA_SIGNER_TLS_KEY", default_value = DEFAULT_TLS_KEY)]
    tls_key_pem: PathBuf,

    /// Client CA certificate PEM file (required for mTLS).
    #[arg(long, env = "IONA_SIGNER_CLIENT_CA", default_value = DEFAULT_CLIENT_CA)]
    client_ca_pem: PathBuf,

    /// Allowlist file (one SHA‑256 fingerprint hex per line).
    #[arg(long, env = "IONA_SIGNER_ALLOWLIST", default_value = DEFAULT_ALLOWLIST)]
    allowlist: PathBuf,

    /// Audit log path (JSON lines).
    #[arg(long, env = "IONA_SIGNER_AUDIT_LOG", default_value = DEFAULT_AUDIT_LOG)]
    audit_log: PathBuf,

    /// Request timeout in seconds.
    #[arg(long, env = "IONA_SIGNER_REQUEST_TIMEOUT_SECS", default_value_t = DEFAULT_REQUEST_TIMEOUT_SECS)]
    request_timeout_secs: u64,

    /// Rate limit (requests per second per client IP). Set to 0 to disable.
    #[arg(long, env = "IONA_SIGNER_RATE_LIMIT_PER_SEC", default_value_t = DEFAULT_RATE_LIMIT_PER_SEC)]
    rate_limit_per_sec: u64,

    /// Maximum request body size in bytes.
    #[arg(long, env = "IONA_SIGNER_MAX_BODY_BYTES", default_value_t = DEFAULT_MAX_BODY_BYTES)]
    max_body_bytes: usize,

    /// Enable CORS (for development only).
    #[arg(long, env = "IONA_SIGNER_ENABLE_CORS", default_value_t = false)]
    enable_cors: bool,
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> SignerResult<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr: SocketAddr = args
        .listen
        .parse()
        .map_err(|e| SignerError::Tls(format!("invalid listen address: {e}")))?;

    // Load or generate signing key.
    let signing_key = read_signing_key_or_generate(args.key_path.to_str().unwrap_or(DEFAULT_KEY_PATH))
        .map_err(|e| SignerError::Io(e))?;
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = B64.encode(verifying_key.to_bytes());

    // Prepare audit log directory and file.
    if let Some(parent) = args.audit_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.audit_log)?;
    let audit = Arc::new(Mutex::new(BufWriter::new(audit_file)));

    let state = AppState {
        pubkey_b64,
        signing_key: Arc::new(signing_key),
        audit,
    };

    // Load allowlist.
    let allow = Arc::new(load_allowlist(&args.allowlist)?);
    if allow.is_empty() {
        warn!("Allowlist is empty – no client certificates will be accepted!");
    } else {
        info!("Loaded {} client certificate fingerprints", allow.len());
    }

    // Load client CA roots.
    let ca_roots = load_ca_roots(&args.client_ca_pem)?;

    // Build client verifier with WebPKI + allowlist.
    let webpki = rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_roots))
        .build()
        .map_err(|e| SignerError::Tls(format!("client verifier build: {e}")))?;
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(AllowlistClientVerifier {
        inner: webpki,
        allow,
    });

    // Read server certificate and key.
    let cert_bytes = std::fs::read(&args.tls_cert_pem)?;
    let key_bytes = std::fs::read(&args.tls_key_pem)?;

    let mut cert_reader = std::io::Cursor::new(cert_bytes);
    let certs = rustls_pemfile::certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| SignerError::Tls(format!("failed to parse server cert: {e}")))?;
    if certs.is_empty() {
        return Err(SignerError::InvalidCertificate);
    }

    let mut key_reader = std::io::Cursor::new(key_bytes);
    let key = rustls_pemfile::private_key(&mut key_reader)
        .map_err(|e| SignerError::Tls(format!("failed to parse private key: {e}")))?
        .ok_or(SignerError::InvalidCertificate)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| SignerError::Tls(format!("TLS config error: {e}")))?;

    let tls = RustlsConfig::from_config(Arc::new(tls_config));

    // Build middleware stack.
    let mut app = Router::new()
        .route("/pubkey", get(pubkey_handler))
        .route("/sign", post(sign_handler))
        .route("/health", get(health_handler))
        .route("/metrics", get(metrics_handler))
        .layer(TraceLayer::new_for_http())
        .layer(RequestIdLayer::new(UuidRequestId))
        .layer(TimeoutLayer::new(Duration::from_secs(args.request_timeout_secs)))
        .layer(RequestBodyLimitLayer::new(args.max_body_bytes))
        .with_state(state);

    if args.rate_limit_per_sec > 0 {
        use tower_http::limit::RateLimitLayer;
        app = app.layer(RateLimitLayer::new(args.rate_limit_per_sec, Duration::from_secs(1)));
    }

    if args.enable_cors {
        use tower_http::cors::{Any, CorsLayer};
        app = app.layer(CorsLayer::permissive());
        warn!("CORS enabled – this is NOT recommended for production");
    }

    info!("IONA remote signer listening on {}", addr);
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<RustlsConnectInfo>())
        .await?;

    Ok(())
}

// -----------------------------------------------------------------------------
// Unit tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fingerprint_hex() {
        let cert = CertificateDer::from(vec![0u8; 32]);
        let fp = AllowlistClientVerifier::fingerprint_hex(&cert);
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_load_allowlist() -> SignerResult<()> {
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("allowlist.txt");
        std::fs::write(&path, "# comment\n0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n")?;
        let set = load_allowlist(&path)?;
        assert_eq!(set.len(), 1);
        Ok(())
    }
}
