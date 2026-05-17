//! IONA Remote Signer (mTLS + allowlist + audit log)
//!
//! Endpoints (JSON):
//! - GET  /pubkey  -> { "pubkey_base64": "..." }
//! - POST /sign    -> { "msg_base64": "..." }  -> { "sig_base64": "..." }
//!
//! Security features:
//! - mTLS enforced (client certificate required)
//! - Allowlist by client certificate SHA-256 fingerprint (hex)
//! - Append‑only audit log (JSON lines) with real client fingerprint per request

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use clap::Parser;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{error, info, warn};

use axum_server::tls_rustls::{RustlsConfig, RustlsConnectInfo};
use ed25519_dalek::SigningKey;
use rustls::{
    pki_types::CertificateDer,
    server::{ClientCertVerified, ClientCertVerifier},
    RootCertStore,
};

use iona::crypto::ed25519::{read_signing_key_or_generate, sign_bytes};

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

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during remote signer operation.
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
}

pub type SignerResult<T> = Result<T, SignerError>;

// -----------------------------------------------------------------------------
// Application state
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    pubkey_b64: String,
    signing_key: Arc<SigningKey>,
    audit: Arc<Mutex<std::fs::File>>,
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
struct AuditLine {
    ts_unix_s: u64,
    client_fp_sha256: String,
    remote_addr: String,
    msg_blake3_hex: String,
    ok: bool,
    reason: String,
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
        // Basic validation: hex string of length 64 (SHA-256)
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
    Json(req): Json<SignReq>,
) -> impl IntoResponse {
    let client_fp = fingerprint_from_connect(&tls_info);
    let remote_addr = addr.to_string();

    let msg = match B64.decode(req.msg_base64.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            // Log audit failure before returning error.
            let audit_line = AuditLine {
                ts_unix_s: now_unix_s(),
                client_fp_sha256: client_fp,
                remote_addr,
                msg_blake3_hex: "invalid".to_string(),
                ok: false,
                reason: format!("base64 decode error: {e}"),
            };
            if let Ok(json) = serde_json::to_string(&audit_line) {
                if let Ok(mut f) = state.audit.lock() {
                    let _ = writeln!(f, "{json}");
                }
            }
            return (StatusCode::BAD_REQUEST, "invalid base64").into_response();
        }
    };

    let msg_hash = blake3::hash(&msg);
    let sig = sign_bytes(&state.signing_key, &msg);

    // Audit log (success)
    let audit_line = AuditLine {
        ts_unix_s: now_unix_s(),
        client_fp_sha256: client_fp,
        remote_addr,
        msg_blake3_hex: hex::encode(msg_hash.as_bytes()),
        ok: true,
        reason: "ok".to_string(),
    };
    if let Ok(json) = serde_json::to_string(&audit_line) {
        if let Ok(mut f) = state.audit.lock() {
            let _ = writeln!(&mut *f, "{json}");
        }
    }

    Json(SignResp {
        sig_base64: B64.encode(sig),
    })
}

// -----------------------------------------------------------------------------
// CLI Arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-remote-signer")]
#[command(about = "IONA remote signing server with mTLS and allowlist")]
struct Args {
    /// Listen address (e.g., 0.0.0.0:9100)
    #[arg(long, default_value = DEFAULT_LISTEN)]
    listen: String,

    /// Path to the Ed25519 signing key (32 bytes). If missing, one is generated.
    #[arg(long, default_value = DEFAULT_KEY_PATH)]
    key_path: PathBuf,

    /// Server TLS certificate PEM file.
    #[arg(long, default_value = DEFAULT_TLS_CERT)]
    tls_cert_pem: PathBuf,

    /// Server TLS private key PEM file.
    #[arg(long, default_value = DEFAULT_TLS_KEY)]
    tls_key_pem: PathBuf,

    /// Client CA certificate PEM file (required for mTLS).
    #[arg(long, default_value = DEFAULT_CLIENT_CA)]
    client_ca_pem: PathBuf,

    /// Allowlist file (one SHA‑256 fingerprint hex per line).
    #[arg(long, default_value = DEFAULT_ALLOWLIST)]
    allowlist: PathBuf,

    /// Audit log path (JSON lines).
    #[arg(long, default_value = DEFAULT_AUDIT_LOG)]
    audit_log: PathBuf,
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

    // Create audit log directory and file.
    if let Some(parent) = args.audit_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.audit_log)?;

    let state = AppState {
        pubkey_b64,
        signing_key: Arc::new(signing_key),
        audit: Arc::new(Mutex::new(audit_file)),
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

    let app = Router::new()
        .route("/pubkey", get(pubkey_handler))
        .route("/sign", post(sign_handler))
        .with_state(state);

    info!("IONA remote signer listening on {}", addr);
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<RustlsConnectInfo>())
        .await?;

    Ok(())
}
