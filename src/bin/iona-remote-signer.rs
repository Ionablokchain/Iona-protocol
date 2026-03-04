//! IONA Remote Signer (mTLS + allowlist + audit log)
//!
//! Endpoints (JSON):
//! - GET  /pubkey  -> { "pubkey_base64": "..." }
//! - POST /sign    -> { "msg_base64": "..." }  -> { "sig_base64": "..." }
//!
//! Security features (mega++):
//! - mTLS enforced (client cert required)
//! - Allowlist by client certificate SHA-256 fingerprint (hex)
//! - Append-only audit log (JSON lines) with *real* client fingerprint per request

use axum::{
    extract::{ConnectInfo, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::Path,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum_server::tls_rustls::{RustlsConfig, RustlsConnectInfo};
use rustls::{
    pki_types::CertificateDer,
    server::{ClientCertVerified, ClientCertVerifier},
    RootCertStore,
};

use iona::crypto::ed25519::{read_signing_key_or_generate, sign_bytes};

#[derive(Clone)]
struct AppState {
    pubkey_b64: String,
    signing_key: Arc<ed25519_dalek::SigningKey>,
    audit: Arc<Mutex<std::fs::File>>,
}

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

/// Custom verifier that delegates to WebPKI and then enforces an allowlist.
struct AllowlistClientVerifier {
    inner: Arc<dyn ClientCertVerifier>,
    allow: Arc<HashSet<String>>,
}

impl AllowlistClientVerifier {
    fn fingerprint_hex(cert: &CertificateDer<'_>) -> String {
        let mut h = Sha256::new();
        h.update(cert.as_ref());
        hex::encode(h.finalize())
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
        let v = self
            .inner
            .verify_client_cert(end_entity, intermediates, now)?;

        let fp = Self::fingerprint_hex(end_entity);
        if !self.allow.contains(&fp) {
            return Err(rustls::Error::General("client cert not allowlisted".into()));
        }
        Ok(v)
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

fn now_unix_s() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn fp_from_connect(ci: &RustlsConnectInfo) -> String {
    // axum-server exposes the peer cert chain in connect info.
    // We fingerprint the first (end-entity) cert.
    if let Some(certs) = &ci.peer_certificates {
        if let Some(first) = certs.first() {
            let mut h = Sha256::new();
            h.update(first.as_ref());
            return hex::encode(h.finalize());
        }
    }
    "unknown".to_string()
}

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
    let msg = match B64.decode(req.msg_base64.as_bytes()) {
        Ok(v) => v,
        Err(_) => return (StatusCode::BAD_REQUEST, "bad base64").into_response(),
    };

    let msg_hash = blake3::hash(&msg);
    let sig = sign_bytes(&st.signing_key, &msg);

    let client_fp = fp_from_connect(&ci);

    // audit
    {
        use std::io::Write;
        let line = AuditLine {
            ts_unix_s: now_unix_s(),
            client_fp_sha256: client_fp,
            remote_addr: addr.to_string(),
            msg_blake3_hex: hex::encode(msg_hash.as_bytes()),
            ok: true,
            reason: "ok".to_string(),
        };
        let mut f = st.audit.lock();
        let _ = writeln!(
            &mut *f,
            "{}",
            serde_json::to_string(&line).unwrap_or_else(|_| "{}".into())
        );
    }

    Json(SignResp {
        sig_base64: B64.encode(sig),
    })
}

fn load_allowlist(path: &str) -> anyhow::Result<HashSet<String>> {
    if !Path::new(path).exists() {
        return Ok(HashSet::new());
    }
    let s = std::fs::read_to_string(path)?;
    let mut out = HashSet::new();
    for line in s.lines() {
        let t = line.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        out.insert(t.to_lowercase());
    }
    Ok(out)
}

fn load_ca_roots(ca_pem_path: &str) -> anyhow::Result<RootCertStore> {
    let pem = std::fs::read(ca_pem_path)?;
    let mut rd = std::io::Cursor::new(pem);
    let certs = rustls_pemfile::certs(&mut rd).collect::<Result<Vec<_>, _>>()?;
    let mut store = RootCertStore::empty();
    for c in certs {
        store.add(c)?;
    }
    Ok(store)
}

#[derive(clap::Parser, Debug)]
#[command(name = "iona-remote-signer")]
struct Args {
    /// Listen address, e.g. 0.0.0.0:9100
    #[arg(long, default_value = "0.0.0.0:9100")]
    listen: String,

    /// Path to the ed25519 signing key (32 bytes). If missing, one is generated.
    #[arg(long, default_value = "./data/remote_signer_key.bin")]
    key_path: String,

    /// Server TLS cert PEM
    #[arg(long, default_value = "./deploy/tls/server.crt.pem")]
    tls_cert_pem: String,

    /// Server TLS key PEM
    #[arg(long, default_value = "./deploy/tls/server.key.pem")]
    tls_key_pem: String,

    /// Client CA cert PEM (required for mTLS)
    #[arg(long, default_value = "./deploy/tls/ca.crt.pem")]
    client_ca_pem: String,

    /// Allowlist file (one SHA-256 fingerprint hex per line)
    #[arg(long, default_value = "./deploy/tls/allowlist.txt")]
    allowlist: String,

    /// Audit log path (JSONL)
    #[arg(long, default_value = "./data/remote_signer_audit.jsonl")]
    audit_log: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let args = Args::parse();
    let addr: SocketAddr = args.listen.parse()?;

    let sk = Arc::new(read_signing_key_or_generate(&args.key_path)?);
    let pk = sk.verifying_key();
    let pk_bytes = pk.to_bytes();
    let pubkey_b64 = B64.encode(pk_bytes);

    // audit file
    if let Some(parent) = Path::new(&args.audit_log).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let audit_file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&args.audit_log)?;

    let st = AppState {
        pubkey_b64,
        signing_key: sk,
        audit: Arc::new(Mutex::new(audit_file)),
    };

    let app = Router::new()
        .route("/pubkey", get(pubkey))
        .route("/sign", post(sign))
        .with_state(st);

    // Build rustls config with client auth + allowlist
    let allow = Arc::new(load_allowlist(&args.allowlist)?);
    let roots = load_ca_roots(&args.client_ca_pem)?;

    let webpki = rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
        .build()
        .map_err(|e| anyhow::anyhow!("client verifier: {e}"))?;
    let verifier: Arc<dyn ClientCertVerifier> = Arc::new(AllowlistClientVerifier {
        inner: webpki,
        allow,
    });

    // Server cert+key
    let cert = std::fs::read(&args.tls_cert_pem)?;
    let key = std::fs::read(&args.tls_key_pem)?;

    let mut cert_rd = std::io::Cursor::new(cert);
    let certs = rustls_pemfile::certs(&mut cert_rd).collect::<Result<Vec<_>, _>>()?;

    let mut key_rd = std::io::Cursor::new(key);
    let keys = rustls_pemfile::private_key(&mut key_rd)?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs, keys)
        .map_err(|e| anyhow::anyhow!("server tls config: {e}"))?;

    let tls = RustlsConfig::from_config(Arc::new(config));

    tracing::info!(%addr, "iona-remote-signer listening (mTLS + allowlist + audit)");
    axum_server::bind_rustls(addr, tls)
        .serve(app.into_make_service_with_connect_info::<RustlsConnectInfo>())
        .await?;

    Ok(())
}
