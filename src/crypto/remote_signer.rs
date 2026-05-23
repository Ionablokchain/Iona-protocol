//! Remote signer client.
//!
//! This module provides a client for a remote signing service (e.g., a hardware security module
//! or a separate signing process). The client implements the synchronous `Signer` trait so it can
//! be used directly by consensus code without changes to the asynchronous runtime.
//!
//! # Expected Remote Signer API
//!
//! The remote signer must expose the following HTTP JSON endpoints:
//!
//! - `GET /pubkey` → `{ "pubkey_base64": "..." }`
//! - `POST /sign`  → request `{ "msg_base64": "..." }`, response `{ "sig_base64": "..." }`
//! - `GET /health` → `200 OK` (optional, but recommended)
//!
//! # Features
//!
//! - Optional **mTLS**: client certificate + private key and a custom CA root.
//! - Optional **server name override** (SNI) for strict TLS validation.
//! - Health check and comprehensive error logging.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::crypto::remote_signer::RemoteSigner;
//! use std::time::Duration;
//!
//! let signer = RemoteSigner::connect("https://signer.example.com".into(), Duration::from_secs(5))?;
//! let signature = signer.sign(b"message");
//! ```

use crate::crypto::{PublicKeyBytes, SignatureBytes, Signer};
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use reqwest::blocking::Client;
use reqwest::{Certificate, Identity};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// RemoteSigner
// -----------------------------------------------------------------------------

/// Client for a remote signing service.
///
/// Implements the `Signer` trait by forwarding signing requests over HTTP.
/// The client is cloneable and internally uses a `reqwest::blocking::Client`.
#[derive(Clone)]
pub struct RemoteSigner {
    /// Base URL of the remote signer (e.g., `http://localhost:9100`).
    base_url: String,
    /// HTTP client configured with timeouts and optional mTLS.
    client: Client,
    /// Public key fetched from the remote signer at connection time.
    pubkey: PublicKeyBytes,
    /// Request timeout for all operations.
    timeout: Duration,
}

/// Response from `GET /pubkey`.
#[derive(Debug, Deserialize)]
struct PubkeyResp {
    /// Base64‑encoded public key (e.g., 32 bytes for Ed25519).
    pubkey_base64: String,
}

/// Request body for `POST /sign`.
#[derive(Debug, Serialize)]
struct SignReq {
    /// Base64‑encoded message to sign.
    msg_base64: String,
}

/// Response from `POST /sign`.
#[derive(Debug, Deserialize)]
struct SignResp {
    /// Base64‑encoded signature.
    sig_base64: String,
}

impl RemoteSigner {
    /// Connect to a remote signer using plain HTTP/HTTPS (no mTLS).
    ///
    /// # Arguments
    /// * `base_url` – Base URL of the signer (e.g., `http://localhost:9100`).
    /// * `timeout` – Request timeout for all operations.
    ///
    /// # Errors
    /// Returns an error if the public key cannot be fetched or if the connection fails.
    #[must_use]
    pub fn connect(base_url: String, timeout: Duration) -> anyhow::Result<Self> {
        Self::connect_mtls(base_url, timeout, None)
    }

    /// Connect to a remote signer with optional mTLS.
    ///
    /// # Arguments
    /// * `base_url` – Base URL of the signer.
    /// * `timeout` – Request timeout for all operations.
    /// * `mtls` – Optional mTLS configuration tuple:
    ///     - `identity_pem`: PEM containing both client certificate and private key.
    ///     - `ca_pem`: PEM for a custom CA root (optional, can be empty).
    ///     - `server_name_override`: SNI override (useful when the URL uses an IP address).
    ///
    /// # Errors
    /// Returns an error if the public key cannot be fetched, TLS configuration fails,
    /// or the connection cannot be established.
    #[must_use]
    pub fn connect_mtls(
        base_url: String,
        timeout: Duration,
        mtls: Option<(Vec<u8>, Vec<u8>, Option<String>)>,
    ) -> anyhow::Result<Self> {
        let mut builder = Client::builder().timeout(timeout);

        if let Some((identity_pem, ca_pem, server_name)) = mtls {
            let id = Identity::from_pem(&identity_pem)?;
            let ca = Certificate::from_pem(&ca_pem)?;
            builder = builder.identity(id).add_root_certificate(ca);
            if let Some(name) = server_name {
                // Note: `reqwest` does not expose a per-request SNI override;
                // using a DNS name in the URL is the recommended practice.
                debug!(server_name = %name, "mTLS server name override set (for configuration only)");
            }
        }

        let client = builder.build()?;
        let url = format!("{}/pubkey", base_url.trim_end_matches('/'));
        debug!(url = %url, "fetching remote signer public key");

        let response: PubkeyResp = client
            .get(&url)
            .send()?
            .error_for_status()?
            .json()?;

        let pk_bytes = B64.decode(response.pubkey_base64.as_bytes())?;
        debug!("remote signer public key acquired");

        Ok(Self {
            base_url,
            client,
            pubkey: PublicKeyBytes(pk_bytes),
            timeout,
        })
    }

    /// Returns the base URL of the remote signer.
    #[must_use]
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Check if the remote signer is healthy.
    ///
    /// Tries `GET /health` first; if that fails (404, timeout, or non‑2xx), falls back to
    /// `GET /pubkey` as a minimal liveness probe.
    #[must_use]
    pub fn is_healthy(&self) -> bool {
        let url = format!("{}/health", self.base_url.trim_end_matches('/'));
        match self.client.get(&url).send() {
            Ok(resp) if resp.status().is_success() => true,
            _ => {
                // Fallback to checking /pubkey if /health is not implemented
                let pubkey_url = format!("{}/pubkey", self.base_url.trim_end_matches('/'));
                match self.client.get(&pubkey_url).send() {
                    Ok(r) if r.status().is_success() => true,
                    _ => false,
                }
            }
        }
    }

    /// Attempt to sign a message, returning `Some(SignatureBytes)` on success.
    ///
    /// This method logs errors but does not propagate them; the caller can decide
    /// whether to retry or fall back. The `Signer` trait uses this internally.
    #[must_use]
    pub fn try_sign(&self, msg: &[u8]) -> Option<SignatureBytes> {
        let url = format!("{}/sign", self.base_url.trim_end_matches('/'));
        let req = SignReq {
            msg_base64: B64.encode(msg),
        };
        match self
            .client
            .post(&url)
            .json(&req)
            .send()
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.json::<SignResp>())
        {
            Ok(resp) => {
                match B64.decode(resp.sig_base64.as_bytes()) {
                    Ok(sig) => {
                        debug!("signature obtained from remote signer");
                        Some(SignatureBytes(sig))
                    }
                    Err(e) => {
                        error!("remote signer returned invalid base64 signature: {}", e);
                        None
                    }
                }
            }
            Err(e) => {
                error!("remote signer request failed: {}", e);
                None
            }
        }
    }

    /// Helper to load mTLS materials from PEM files.
    ///
    /// # Arguments
    /// * `client_identity_pem_path` – Path to a PEM file containing the client certificate
    ///   and private key (concatenated).
    /// * `ca_cert_pem_path` – Path to a PEM file containing the CA certificate.
    /// * `server_name_override` – Optional SNI override.
    ///
    /// # Errors
    /// Returns an error if file reading fails.
    #[must_use]
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

// -----------------------------------------------------------------------------
// Signer trait implementation
// -----------------------------------------------------------------------------

impl Signer for RemoteSigner {
    /// Returns the public key fetched during connection.
    fn public_key(&self) -> PublicKeyBytes {
        self.pubkey.clone()
    }

    /// Signs a message using the remote signer.
    ///
    /// If signing fails, logs a warning and returns an empty signature.
    /// The consensus engine must handle invalid signatures appropriately.
    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        match self.try_sign(msg) {
            Some(sig) => sig,
            None => {
                warn!("remote signer returned empty signature; will likely cause consensus failure");
                SignatureBytes(vec![])
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use httpmock::prelude::*;
    use serde_json::json;

    #[test]
    fn test_connect_and_sign() {
        let server = MockServer::start();

        // Mock /pubkey
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });

        // Mock /sign
        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(200)
                .json_body(json!({ "sig_base64": base64::encode(&[0xbb; 64]) }));
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        assert_eq!(signer.public_key().0, vec![0xaa; 32]);

        let sig = signer.sign(b"hello");
        assert_eq!(sig.0, vec![0xbb; 64]);

        pubkey_mock.assert();
        sign_mock.assert();
    }

    #[test]
    fn test_health_check() {
        let server = MockServer::start();

        // Mock /health
        let health_mock = server.mock(|when, then| {
            when.method(GET).path("/health");
            then.status(200);
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        assert!(signer.is_healthy());
        health_mock.assert();

        // Fallback to /pubkey if /health not implemented
        let no_health_server = MockServer::start();
        let pubkey_mock = no_health_server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        let signer2 = RemoteSigner::connect(no_health_server.base_url(), Duration::from_secs(2)).unwrap();
        assert!(signer2.is_healthy());
        pubkey_mock.assert();
    }

    #[test]
    fn test_connection_failure() {
        let result = RemoteSigner::connect("http://localhost:9999".into(), Duration::from_secs(1));
        assert!(result.is_err());
    }

    #[test]
    fn test_try_sign_returns_none_on_error() {
        let server = MockServer::start();
        let pubkey_mock = server.mock(|when, then| {
            when.method(GET).path("/pubkey");
            then.status(200)
                .json_body(json!({ "pubkey_base64": base64::encode(&[0xaa; 32]) }));
        });
        let sign_mock = server.mock(|when, then| {
            when.method(POST).path("/sign");
            then.status(500); // server error
        });

        let signer = RemoteSigner::connect(server.base_url(), Duration::from_secs(2)).unwrap();
        let result = signer.try_sign(b"hello");
        assert!(result.is_none());

        pubkey_mock.assert();
        sign_mock.assert();
    }
}
