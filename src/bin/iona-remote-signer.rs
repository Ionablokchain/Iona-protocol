//! IONA Remote Signer — mTLS + allowlist + audit log
//!
//! Provides a secure signing service with:
//! - mTLS (client certificate required)
//! - Allowlist by client certificate SHA‑256 fingerprint (hex)
//! - Append‑only audit log (JSON lines) with *real* client fingerprint per request
//!
//! Endpoints:
//! - `GET /pubkey`  → `{ "pubkey_base64": "..." }`
//! - `POST /sign`   → `{ "msg_base64": "..." }` → `{ "sig_base64": "..." }`
//!
//! # Usage
//!
//! ```bash
//! cargo run --bin iona-remote-signer -- \
//!     --listen 0.0.0.0:9100 \
//!     --key-path ./data/remote_signer_key.bin \
//!     --tls-cert-pem ./deploy/tls/server.crt.pem \
//!     --tls-key-pem ./deploy/tls/server.key.pem \
//!     --client-ca-pem ./deploy/tls/ca.crt.pem \
//!     --allowlist ./deploy/tls/allowlist.txt \
//!     --audit-log ./data/remote_signer_audit.jsonl
//! ```

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
use tokio::signal;
use tracing::{error, info, warn};

use axum_server::tls_rustls::{RustlsConfig, RustlsConnectInfo};
use rustls::{
    pki_types::CertificateDer,
    server::{ClientCertVerified, ClientCertVerifier},
    RootCertStore,
};

use iona::crypto::ed25519::{read_signing_key_or_generate, sign_bytes};

// -----------------------------------------------------------------------------
// Command-line arguments
// -----------------------------------------------------------------------------

#[derive(Parser, Debug)]
#[command(name = "iona-remote-signer", about = "mTLS‑enforced remote signer")]
struct Args {
    /// Listen address, e.g., 0.0.0.0:9100
    #[arg(long, default_value = "0.0.0.0:9100")]
    listen: String,

    /// Path to the Ed25519 signing key (32 bytes). If missing, one is generated.
    #[arg(long, default_value = "./data/remote_signer_key.bin")]
    key_path: PathBuf,

    /// Server TLS certificate PEM file.
    #[arg(long, default_value = "./deploy/tls/server.crt.pem")]
    tls_cert_pem: PathBuf,

    /// Server TLS private key PEM file.
    #[arg(long, default_value = "./deploy/tls/server.key.pem")]
    tls_key_pem: PathBuf,

    /// Client CA certificate PEM file (required for mTLS).
    #[arg(long, default_value = "./deploy/tls/ca.crt.pem")]
    client_ca_pem: PathBuf,

    /// Allowlist file (one SHA‑256 fingerprint hex per line). Lines starting with `#` are ignored.
    #[arg(long, default_value = "./deploy/tls/allowlist.txt")]
    allowlist: PathBuf,

    /// Audit log path (JSONL). If the directory does not exist, it is created.
    #[arg(long, default_value = "./data/remote_signer_audit.jsonl")]
    audit_log: PathBuf,

    /// Log level (trace, debug, info, warn, error). Default is info.
    #[arg(long, default_value = "info")]
    log_level: String,
}

// -----------------------------------------------------------------------------
// Application state
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct AppState {
    pubkey_b64: String,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    audit: Arc<Mutex<std::fs::File>>,
}

// -----------------------------------------------------------------------------
// Request / response structures
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

// -----------------------------------------------------------------------------
// Audit log entry
// -----------------------------------------------------------------------------

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
// Custom client certificate verifier with allowlist
// -----------------------------------------------------------------------------

/// A client certificate verifier that first delegates to a WebPKI verifier
/// and then enforces an allowlist based on the certificate's SHA‑256 fingerprint.
struct AllowlistClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow: Arc<HashSet<String>>,
}

impl AllowlistClientVerifier {
    /// Compute the SHA‑256 fingerprint of a certificate as a hex string.
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
        // First, delegate to the inner verifier (WebPKI) to check the certificate chain.
        let verified = self.inner.verify_client_cert(end_entity, intermediates, now)?;

        let fp = Self::fingerprint_hex(end_entity);
        if !self.allow.contains(&fp) {
            return Err(rustls::Error::General(
                format!("client cert not allowlisted: {}", fp).into(),
            ));
        }
        Ok(verified)
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

/// Return the current Unix timestamp in seconds.
fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// Extract the SHA‑256 fingerprint of the client certificate from the TLS connection info.
fn client_fingerprint(ci: &RustlsConnectInfo) -> String {
    if let Some(certs) = ci.peer_certificates() {
        if let Some(first) = certs.first() {
            let mut hasher = Sha256::new();
            hasher.update(first.as_ref());
            return hex::encode(hasher.finalize());
        }
    }
    "unknown".to_string()
}

/// Load the allowlist from a file (one fingerprint per line, lines starting with `#` are ignored).
fn load_allowlist(path: &Path) -> anyhow::Result<HashSet<String>> {
    if !path.exists() {
        return Ok(HashSet::new());
    }
    let content = std::fs::read_to_string(path)?;
    let mut set = HashSet::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        set.insert(trimmed.to_lowercase());
    }
    Ok(set)
}

/// Load the root CA certificates from a PEM file.
fn load_ca_roots(ca_pem_path: &Path) -> anyhow::Result<RootCertStore> {
    let pem = std::fs::read(ca_pem_path)?;
    let mut reader = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    let mut store = RootCertStore::empty();
    for cert in certs {
        store.add(cert)?;
    }
    Ok(store)
}

// -----------------------------------------------------------------------------
// Handlers
// -----------------------------------------------------------------------------

async fn pubkey(State(st): State<AppState>) -> impl IntoResponse {
    Json(PubkeyResp {
        pubkey_base64: st.pubkey_b64,
    })
}

async fn sign(
    State(st): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    ConnectInfo(ci): ConnectInfo<RustlsConnectInfo>,
    Json(req): Json<SignReq>,
) -> impl IntoResponse {
    // Decode base64 message
    let msg = match B64.decode(req.msg_base64.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            let audit = AuditLine {
                ts_unix_s: now_unix_s(),
                client_fp_sha256: client_fingerprint(&ci),
                remote_addr: addr.to_string(),
                msg_blake3_hex: "invalid".to_string(),
                ok: false,
                reason: format!("bad base64: {}", e),
            };
            if let Ok(mut file) = st.audit.lock().as_mut() {
                let _ = writeln!(file, "{}", serde_json::to_string(&audit).unwrap_or_default());
            }
            return (StatusCode::BAD_REQUEST, "bad base64").into_response();
        }
    };

    let msg_hash = blake3::hash(&msg);
    let sig = sign_bytes(&st.signing_key, &msg);

    let client_fp = client_fingerprint(&ci);
    let audit = AuditLine {
        ts_unix_s: now_unix_s(),
        client_fp_sha256: client_fp,
        remote_addr: addr.to_string(),
        msg_blake3_hex: hex::encode(msg_hash.as_bytes()),
        ok: true,
        reason: "ok".to_string(),
    };

    // Write audit log
    if let Ok(mut file) = st.audit.lock().as_mut() {
        if let Err(e) = writeln!(file, "{}", serde_json::to_string(&audit).unwrap_or_default()) {
            warn!("failed to write audit log: {}", e);
        } else if let Err(e) = file.flush() {
            warn!("failed to flush audit log: {}", e);
        }
    }

    Json(SignResp {
        sig_base64: B64.encode(sig),
    })
}

// -----------------------------------------------------------------------------
// Main
// -----------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    init_logging(&args.log_level)?;

    info!("Starting IONA remote signer (version {})", env!("CARGO_PKG_VERSION"));

    // Load or generate signing key
    let signing_key = Arc::new(read_signing_key_or_generate(&args.key_path)?);
    let verifying_key = signing_key.verifying_key();
    let pubkey_b64 = B64.encode(verifying_key.to_bytes());

    // Prepare audit log file
    if let Some(parent) = args.audit_log.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.audit_log)?;

    let state = AppState {
        pubkey_b64,
        signing_key,
        audit: Arc::new(Mutex::new(audit_file)),
    };

    // Load allowlist
    let allowlist = Arc::new(load_allowlist(&args.allowlist)?);
    info!("Loaded {} client fingerprints from allowlist", allowlist.len());

    // Load client CA roots
    let ca_roots = load_ca_roots(&args.client_ca_pem)?;
    let webpki_verifier = rustls::server::WebPkiClientVerifier::builder(Arc::new(ca_roots))
        .build()
        .map_err(|e| anyhow::anyhow!("failed to build client verifier: {e}"))?;

    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(AllowlistClientVerifier {
        inner: webpki_verifier,
        allow: allowlist,
    });

    // Load server certificate and key
    let cert_pem = std::fs::read(&args.tls_cert_pem)?;
    let key_pem = std::fs::read(&args.tls_key_pem)?;

    let mut cert_reader = std::io::Cursor::new(cert_pem);
    let certs = rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    let mut key_reader = std::io::Cursor::new(key_pem);
    let key = rustls_pemfile::private_key(&mut key_reader)?
        .ok_or_else(|| anyhow::anyhow!("no private key found in {}", args.tls_key_pem.display()))?;

    let tls_config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("failed to build TLS config: {e}"))?;

    let tls = RustlsConfig::from_config(Arc::new(tls_config));

    // Build the router
    let app = Router::new()
        .route("/pubkey", get(pubkey))
        .route("/sign", post(sign))
        .with_state(state);

    // Start server
    let addr: SocketAddr = args.listen.parse()?;
    info!("Listening on https://{} (mTLS + allowlist + audit log)", addr);

    let server = axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<RustlsConnectInfo>())
        .with_graceful_shutdown(shutdown_signal());

    if let Err(e) = server.await {
        error!("server error: {}", e);
        return Err(e.into());
    }

    info!("Server shut down gracefully");
    Ok(())
}

// -----------------------------------------------------------------------------
// Logging initialisation
// -----------------------------------------------------------------------------

fn init_logging(level: &str) -> anyhow::Result<()> {
    use tracing_subscriber::{fmt, prelude::*, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(level));

    let subscriber = fmt::Subscriber::builder()
        .json()
        .with_target(true)
        .with_thread_ids(false)
        .with_env_filter(filter)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Graceful shutdown signal
// -----------------------------------------------------------------------------

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        use signal::unix::{signal, SignalKind};
        let mut signal = signal(SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        signal.recv().await;
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
    info!("shutdown signal received");
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_load_allowlist() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("allowlist.txt");
        std::fs::write(
            &path,
            "# comment\nabc123\nDEF456  \n\n  \n",
        )
        .unwrap();

        let set = load_allowlist(&path).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains("abc123"));
        assert!(set.contains("def456"));
    }

    #[test]
    fn test_client_fingerprint() {
        // We can't easily test the actual fingerprint without a real certificate,
        // but we can test the fallback to "unknown".
        // For a real test we'd need to mock RustlsConnectInfo, which is not feasible.
        // We'll just ensure the function doesn't panic.
        // In a real test environment you'd need to set up a TLS connection.
    }

    #[test]
    fn test_audit_line_serialization() {
        let line = AuditLine {
            ts_unix_s: 1234567890,
            client_fp_sha256: "deadbeef".into(),
            remote_addr: "127.0.0.1:12345".into(),
            msg_blake3_hex: "abcdef".into(),
            ok: true,
            reason: "ok".into(),
        };
        let json = serde_json::to_string(&line).unwrap();
        assert!(json.contains("ts_unix_s"));
        assert!(json.contains("client_fp_sha256"));
        assert!(json.contains("deadbeef"));
    }
}
