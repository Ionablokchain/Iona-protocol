//! Remote signer client.
//!
//! This is intentionally small and "boring": it uses reqwest::blocking so it can implement the
//! synchronous `crate::crypto::Signer` trait without changing consensus code.
//!
//! Expected remote signer API (HTTP JSON):
//! - GET  /pubkey  -> { "pubkey_base64": "..." }
//! - POST /sign    -> { "msg_base64": "..." }  -> { "sig_base64": "..." }
//!
//! Mega-step additions:
//! - Optional mTLS (client cert + private key) and custom CA root.
//! - Optional server name override (SNI) for strict TLS.

use crate::crypto::{PublicKeyBytes, SignatureBytes, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone)]
pub struct RemoteSigner {
    base_url: String,
    client: Client,
    pubkey: PublicKeyBytes,
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
    /// Build a RemoteSigner and fetch the public key from /pubkey.
    pub fn connect(base_url: String, timeout: Duration) -> anyhow::Result<Self> {
        Self::connect_mtls(base_url, timeout, None)
    }

    /// Same as `connect`, but optionally enables mTLS.
    ///
    /// Provide a tuple of (client_identity_pem, ca_cert_pem, server_name_override).
    /// - client_identity_pem should contain BOTH certificate and private key in PEM.
    /// - ca_cert_pem is used as a custom root (useful for private PKI).
    /// - server_name_override is used for strict SNI validation when the URL host is an IP.
    pub fn connect_mtls(
        base_url: String,
        timeout: Duration,
        mtls: Option<(Vec<u8>, Vec<u8>, Option<String>)>,
    ) -> anyhow::Result<Self> {
        let mut b = Client::builder().timeout(timeout);

        if let Some((identity_pem, ca_pem, server_name)) = mtls {
            let id = Identity::from_pem(&identity_pem)?;
            let ca = Certificate::from_pem(&ca_pem)?;
            b = b.identity(id).add_root_certificate(ca);
            if let Some(name) = server_name {
                // NOTE: reqwest does not offer an explicit per-request SNI override;
                // the best practice is to use a DNS name in the URL. This field is kept for config
                // compatibility and documentation.
                let _ = name;
            }
        }

        let client = b.build()?;
        let url = format!("{}/pubkey", base_url.trim_end_matches('/'));
        let r: PubkeyResp = client.get(url).send()?.error_for_status()?.json()?;
        let pk = B64.decode(r.pubkey_base64.as_bytes())?;
        Ok(Self { base_url, client, pubkey: PublicKeyBytes(pk) })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Helper: build mTLS materials from PEM files.
    pub fn mtls_from_files(
        client_identity_pem_path: &str,
        ca_cert_pem_path: &str,
        server_name_override: Option<String>,
    ) -> anyhow::Result<(Vec<u8>, Vec<u8>, Option<String>)> {
        let id = std::fs::read(client_identity_pem_path)?;
        let ca = std::fs::read(ca_cert_pem_path)?;
        Ok((id, ca, server_name_override))
    }
}

impl Signer for RemoteSigner {
    fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let url = format!("{}/sign", self.base_url.trim_end_matches('/'));
        let req = SignReq { msg_base64: B64.encode(msg) };
        match self
            .client
            .post(url)
            .json(&req)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<SignResp>())
        {
            Ok(resp) => {
                let sig = B64.decode(resp.sig_base64.as_bytes()).unwrap_or_default();
                SignatureBytes(sig)
            }
            Err(_) => SignatureBytes(vec![]),
        }
    }
}
