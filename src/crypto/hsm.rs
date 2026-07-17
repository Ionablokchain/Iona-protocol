//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Provides a trait-based abstraction for signing operations that can be
//! backed by different key storage mechanisms:
//! - Local keystore (default, existing)
//! - Remote signer (HTTP service)
//! - HSM via PKCS#11 (feature‑gated)
//! - Cloud KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS (feature‑gated)
//!
//! # Production Features
//! - Configurable via `KeyBackendConfig` with validation.
//! - `HsmMetrics` for monitoring sign operations, errors, and latency.
//! - `HsmManager` as a thread‑safe wrapper (`Arc` + `Mutex` or `RwLock`).
//! - Support for key rotation (optional).
//! - Structured logging with `tracing`.
//! - Full test coverage for configuration and local signer.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use ed25519_dalek::{Signer as EdSigner, SigningKey, VerifyingKey};
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_histogram_vec, Counter, CounterVec, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// ── Secret handling ──────────────────────────────────────────────────────

#[cfg(feature = "secrecy")]
use secrecy::{ExposeSecret, SecretString};

#[cfg(not(feature = "secrecy"))]
#[derive(Clone, Default)]
pub struct SecretString(String);

#[cfg(not(feature = "secrecy"))]
impl SecretString {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

#[cfg(not(feature = "secrecy"))]
impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[SECRET]")
    }
}

#[cfg(not(feature = "secrecy"))]
impl Serialize for SecretString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str("[SECRET]")
    }
}

#[cfg(not(feature = "secrecy"))]
impl<'de> Deserialize<'de> for SecretString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(SecretString::new(s))
    }
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for key management backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum KeyBackendConfig {
    /// Local encrypted keystore (default).
    Local {
        /// Path to keystore file.
        path: String,
        /// Environment variable holding the password.
        password_env: String,
    },
    /// Remote signer HTTP service.
    Remote {
        /// Base URL of the remote signer (e.g., https://signer.example.com).
        url: String,
        /// Request timeout in seconds.
        #[serde(default = "default_timeout")]
        timeout_s: u64,
        /// Optional API key (sent as `X-API-Key` header).
        #[serde(default)]
        api_key: Option<SecretString>,
        /// Optional client TLS certificate path (for mTLS).
        #[serde(default)]
        client_cert_path: Option<String>,
        /// Optional client TLS key path.
        #[serde(default)]
        client_key_path: Option<String>,
        /// Optional CA certificate path.
        #[serde(default)]
        ca_cert_path: Option<String>,
    },
    /// PKCS#11 HSM (e.g., YubiHSM, Thales Luna).
    Pkcs11 {
        /// Path to PKCS#11 shared library.
        library_path: String,
        /// Slot ID.
        slot: u64,
        /// Key label in the HSM.
        key_label: String,
        /// PIN environment variable name.
        pin_env: String,
    },
    /// AWS KMS.
    AwsKms {
        /// KMS key ARN or alias.
        key_id: String,
        /// AWS region.
        region: String,
        /// Optional endpoint override (for LocalStack testing).
        #[serde(default)]
        endpoint: Option<String>,
    },
    /// Azure Key Vault.
    AzureKeyVault {
        /// Key Vault URL (e.g., https://myvault.vault.azure.net/).
        vault_url: String,
        /// Key name in the vault.
        key_name: String,
        /// Key version (optional, uses latest if empty).
        #[serde(default)]
        key_version: Option<String>,
    },
    /// GCP Cloud KMS.
    GcpKms {
        /// Full resource name:
        /// projects/{project}/locations/{location}/keyRings/{ring}/cryptoKeys/{key}/cryptoKeyVersions/{version}
        resource_name: String,
    },
}

impl Default for KeyBackendConfig {
    fn default() -> Self {
        Self::Local {
            path: "keys.enc".into(),
            password_env: "IONA_KEYSTORE_PASSWORD".into(),
        }
    }
}

impl KeyBackendConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::Local { path, password_env } => {
                if path.is_empty() {
                    return Err("path must not be empty".into());
                }
                if password_env.is_empty() {
                    return Err("password_env must not be empty".into());
                }
            }
            Self::Remote { url, timeout_s, .. } => {
                if url.is_empty() {
                    return Err("url must not be empty".into());
                }
                if *timeout_s == 0 {
                    return Err("timeout_s must be > 0".into());
                }
            }
            Self::Pkcs11 { library_path, slot, key_label, pin_env } => {
                if library_path.is_empty() {
                    return Err("library_path must not be empty".into());
                }
                if key_label.is_empty() {
                    return Err("key_label must not be empty".into());
                }
                if pin_env.is_empty() {
                    return Err("pin_env must not be empty".into());
                }
            }
            Self::AwsKms { key_id, region, .. } => {
                if key_id.is_empty() {
                    return Err("key_id must not be empty".into());
                }
                if region.is_empty() {
                    return Err("region must not be empty".into());
                }
            }
            Self::AzureKeyVault { vault_url, key_name, .. } => {
                if vault_url.is_empty() {
                    return Err("vault_url must not be empty".into());
                }
                if key_name.is_empty() {
                    return Err("key_name must not be empty".into());
                }
            }
            Self::GcpKms { resource_name } => {
                if resource_name.is_empty() {
                    return Err("resource_name must not be empty".into());
                }
            }
        }
        Ok(())
    }
}

fn default_timeout() -> u64 {
    10
}

// ── HsmSigner Trait ──────────────────────────────────────────────────────

/// Trait for HSM/KMS-backed signing operations.
pub trait HsmSigner: Send + Sync {
    /// Get the public key bytes.
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError>;

    /// Sign a message.
    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError>;

    /// Get the signer type name (for logging/audit).
    fn backend_name(&self) -> &str;

    /// Check if the signer is healthy / reachable.
    fn health_check(&self) -> Result<(), CryptoError>;

    /// Optional: get a unique identifier for the key.
    fn key_id(&self) -> Option<String> {
        None
    }

    /// Optional: rotate the key (if supported).
    fn rotate_key(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("key rotation not supported".into()))
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for HSM signing operations.
#[derive(Clone)]
pub struct HsmMetrics {
    pub sign_operations: CounterVec,
    pub sign_errors: CounterVec,
    pub sign_latency: HistogramVec,
    pub health_checks: CounterVec,
}

impl HsmMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let sign_operations = register_counter_vec!(
            "iona_hsm_sign_operations_total",
            "Total HSM sign operations",
            &["backend"]
        )?;
        let sign_errors = register_counter_vec!(
            "iona_hsm_sign_errors_total",
            "HSM sign errors",
            &["backend", "error_type"]
        )?;
        let sign_latency = register_histogram_vec!(
            "iona_hsm_sign_latency_seconds",
            "HSM sign latency",
            &["backend"]
        )?;
        let health_checks = register_counter_vec!(
            "iona_hsm_health_checks_total",
            "HSM health checks",
            &["backend", "status"]
        )?;
        Ok(Self {
            sign_operations,
            sign_errors,
            sign_latency,
            health_checks,
        })
    }

    pub fn record_sign(&self, backend: &str, duration: Duration) {
        self.sign_operations.with_label_values(&[backend]).inc();
        self.sign_latency.with_label_values(&[backend]).observe(duration.as_secs_f64());
    }

    pub fn record_error(&self, backend: &str, error_type: &str) {
        self.sign_errors.with_label_values(&[backend, error_type]).inc();
    }

    pub fn record_health_check(&self, backend: &str, status: &str) {
        self.health_checks.with_label_values(&[backend, status]).inc();
    }
}

impl Default for HsmMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            sign_operations: CounterVec::new(
                prometheus::Opts::new("iona_hsm_sign_operations_total", "HSM sign ops"),
                &["backend"],
            ).unwrap(),
            sign_errors: CounterVec::new(
                prometheus::Opts::new("iona_hsm_sign_errors_total", "HSM sign errors"),
                &["backend", "error_type"],
            ).unwrap(),
            sign_latency: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_hsm_sign_latency_seconds",
                    "HSM sign latency",
                ),
                &["backend"],
            ).unwrap(),
            health_checks: CounterVec::new(
                prometheus::Opts::new("iona_hsm_health_checks_total", "HSM health checks"),
                &["backend", "status"],
            ).unwrap(),
        })
    }
}

// ── HsmManager ───────────────────────────────────────────────────────────

/// Thread‑safe manager for HSM signing operations.
#[derive(Clone)]
pub struct HsmManager {
    signer: Arc<Box<dyn HsmSigner>>,
    metrics: Arc<HsmMetrics>,
}

impl HsmManager {
    /// Create a new manager from a signer.
    pub fn new(signer: Box<dyn HsmSigner>) -> Self {
        Self {
            signer: Arc::new(signer),
            metrics: Arc::new(HsmMetrics::default()),
        }
    }

    /// Get the public key.
    pub fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        self.signer.public_key()
    }

    /// Sign a message, recording metrics.
    pub fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let backend = self.signer.backend_name();
        let start = Instant::now();
        let result = self.signer.sign(msg);
        let duration = start.elapsed();
        self.metrics.record_sign(backend, duration);
        if let Err(e) = &result {
            let error_type = match e {
                CryptoError::Network(_) => "network",
                CryptoError::Key(_) => "key",
                CryptoError::KeyLength { .. } => "key_length",
                CryptoError::InvalidKey(_) => "invalid_key",
                CryptoError::InvalidSignature => "invalid_signature",
                CryptoError::Config(_) => "config",
                _ => "unknown",
            };
            self.metrics.record_error(backend, error_type);
        }
        result
    }

    /// Perform a health check, recording metrics.
    pub fn health_check(&self) -> Result<(), CryptoError> {
        let backend = self.signer.backend_name();
        let result = self.signer.health_check();
        self.metrics.record_health_check(backend, if result.is_ok() { "ok" } else { "error" });
        result
    }

    /// Get the backend name.
    pub fn backend_name(&self) -> &str {
        self.signer.backend_name()
    }

    /// Get the key ID (if available).
    pub fn key_id(&self) -> Option<String> {
        self.signer.key_id()
    }

    /// Rotate the key (if supported).
    pub fn rotate_key(&self) -> Result<(), CryptoError> {
        self.signer.rotate_key()
    }
}

// ── Local Signer ─────────────────────────────────────────────────────────

/// Local signer using Ed25519 keypair (in-memory, zeroized on drop).
pub struct LocalSigner {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    public_key_bytes: PublicKeyBytes,
}

impl LocalSigner {
    /// Create from a 32‑byte seed.
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
        }
    }

    /// Generate a random key.
    pub fn random() -> Self {
        use rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key,
            verifying_key,
            public_key_bytes,
        }
    }

    /// Load from a keystore file (using the existing keystore module).
    #[cfg(feature = "keystore")]
    pub fn from_keystore(path: &str, password: &str) -> Result<Self, CryptoError> {
        let seed = crate::crypto::keystore::decrypt_seed32_from_file(path, password)
            .map_err(|e| CryptoError::Key(format!("keystore decrypt failed: {e}")))?;
        Ok(Self::from_seed(&seed))
    }

    #[cfg(not(feature = "keystore"))]
    pub fn from_keystore(_path: &str, _password: &str) -> Result<Self, CryptoError> {
        Err(CryptoError::Key("keystore feature not enabled".into()))
    }
}

impl HsmSigner for LocalSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key_bytes.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let sig = self.signing_key.sign(msg);
        Ok(SignatureBytes(sig.to_bytes().to_vec()))
    }

    fn backend_name(&self) -> &str {
        "local"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Ok(())
    }

    fn key_id(&self) -> Option<String> {
        Some(hex::encode(&self.public_key_bytes.0))
    }
}

// ── Remote Signer ─────────────────────────────────────────────────────────

/// Remote signer using a HTTP service.
pub struct RemoteSigner {
    client: reqwest::blocking::Client,
    url: String,
    public_key: PublicKeyBytes,
    api_key: Option<SecretString>,
}

impl RemoteSigner {
    /// Create a new remote signer from configuration.
    pub fn new(config: &KeyBackendConfig) -> Result<Self, CryptoError> {
        let (url, timeout_s, api_key, client_cert_path, client_key_path, ca_cert_path) = match config {
            KeyBackendConfig::Remote {
                url,
                timeout_s,
                api_key,
                client_cert_path,
                client_key_path,
                ca_cert_path,
            } => (
                url.clone(),
                *timeout_s,
                api_key.clone(),
                client_cert_path.clone(),
                client_key_path.clone(),
                ca_cert_path.clone(),
            ),
            _ => return Err(CryptoError::Config("not a remote config".into())),
        };

        // Build reqwest client
        let mut builder = reqwest::blocking::ClientBuilder::new()
            .timeout(Duration::from_secs(timeout_s))
            .user_agent("iona-hsm/0.1");

        // mTLS
        if let (Some(cert_path), Some(key_path)) = (client_cert_path, client_key_path) {
            let cert = std::fs::read(&cert_path)
                .map_err(|e| CryptoError::Config(format!("cert read: {}", e)))?;
            let key = std::fs::read(&key_path)
                .map_err(|e| CryptoError::Config(format!("key read: {}", e)))?;
            let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
                .map_err(|e| CryptoError::Config(format!("invalid identity: {}", e)))?;
            builder = builder.identity(identity);
        }
        if let Some(ca_path) = ca_cert_path {
            let ca = std::fs::read(&ca_path)
                .map_err(|e| CryptoError::Config(format!("CA read: {}", e)))?;
            let ca_cert = reqwest::Certificate::from_pem(&ca)
                .map_err(|e| CryptoError::Config(format!("invalid CA: {}", e)))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let client = builder.build().map_err(|e| CryptoError::Network(e.to_string()))?;

        // Fetch public key
        let pubkey_url = format!("{}/pubkey", url);
        let mut request = client.get(&pubkey_url);
        if let Some(api_key) = &api_key {
            request = request.header("X-API-Key", api_key.expose_secret());
        }
        let resp = request.send().map_err(|e| CryptoError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(CryptoError::Network(format!("HTTP {}", resp.status())));
        }
        let json: serde_json::Value = resp.json().map_err(|e| CryptoError::Network(e.to_string()))?;
        let pubkey_b64 = json["pubkey_base64"]
            .as_str()
            .ok_or_else(|| CryptoError::Key("missing pubkey".into()))?;
        let pubkey_bytes = base64::decode(pubkey_b64).map_err(|e| CryptoError::Key(e.to_string()))?;
        let public_key = PublicKeyBytes(pubkey_bytes);

        Ok(Self {
            client,
            url,
            public_key,
            api_key,
        })
    }
}

impl HsmSigner for RemoteSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        let msg_b64 = base64::encode(msg);
        let body = serde_json::json!({ "msg_base64": msg_b64 });
        let mut request = self.client.post(format!("{}/sign", self.url)).json(&body);
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key.expose_secret());
        }
        let resp = request.send().map_err(|e| CryptoError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            let text = resp.text().unwrap_or_default();
            return Err(CryptoError::Network(format!("HTTP {}: {}", resp.status(), text)));
        }
        let json: serde_json::Value = resp.json().map_err(|e| CryptoError::Network(e.to_string()))?;
        let sig_b64 = json["sig_base64"]
            .as_str()
            .ok_or_else(|| CryptoError::Key("missing signature".into()))?;
        let sig_bytes = base64::decode(sig_b64).map_err(|e| CryptoError::Key(e.to_string()))?;
        if sig_bytes.len() != 64 {
            return Err(CryptoError::KeyLength {
                expected: 64,
                actual: sig_bytes.len(),
            });
        }
        Ok(SignatureBytes(sig_bytes))
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let mut request = self.client.get(format!("{}/health", self.url));
        if let Some(api_key) = &self.api_key {
            request = request.header("X-API-Key", api_key.expose_secret());
        }
        let resp = request.send().map_err(|e| CryptoError::Network(e.to_string()))?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(CryptoError::Network(format!("health check failed: {}", resp.status())))
        }
    }

    fn key_id(&self) -> Option<String> {
        Some(format!("remote:{}", hex::encode(&self.public_key.0)))
    }
}

// ── PKCS#11 Signer ──────────────────────────────────────────────────────

#[cfg(feature = "pkcs11")]
pub struct Pkcs11Signer {
    session: cryptoki::session::Session,
    key_handle: cryptoki::object::ObjectHandle,
    public_key_bytes: PublicKeyBytes,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Signer {
    pub fn new(
        library_path: &str,
        slot: u64,
        key_label: &str,
        pin: &str,
    ) -> Result<Self, CryptoError> {
        use cryptoki::context::Pkcs11;
        use cryptoki::session::UserType;
        use cryptoki::object::ObjectClass;
        use cryptoki::attributes::Attribute;

        let pkcs11 = Pkcs11::new(library_path).map_err(|e| CryptoError::Key(e.to_string()))?;
        let slot_id = cryptoki::slot::SlotId(slot);
        let session = pkcs11
            .open_session(slot_id, cryptoki::session::SessionFlags::RW_SESSION)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        session
            .login(UserType::User, pin)
            .map_err(|e| CryptoError::Key(e.to_string()))?;

        // Find key by label
        let mut template = Vec::new();
        template.push(Attribute::Class(ObjectClass::PRIVATE_KEY));
        template.push(Attribute::Label(key_label.to_string()));
        let mut objects = session
            .find_objects(&template)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let key_handle = objects
            .pop()
            .ok_or_else(|| CryptoError::Key("key not found by label".into()))?;

        // Extract public key
        let mut pub_template = Vec::new();
        pub_template.push(Attribute::Class(ObjectClass::PUBLIC_KEY));
        pub_template.push(Attribute::Label(key_label.to_string()));
        let pub_objects = session
            .find_objects(&pub_template)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let pub_handle = pub_objects
            .first()
            .ok_or_else(|| CryptoError::Key("public key not found".into()))?;
        let attrs = session
            .get_attributes(pub_handle, &[Attribute::Value])
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        let pub_bytes = attrs
            .get(0)
            .and_then(|a| match a {
                Attribute::Value(v) => Some(v.clone()),
                _ => None,
            })
            .ok_or_else(|| CryptoError::Key("public key bytes missing".into()))?;
        let public_key_bytes = PublicKeyBytes(pub_bytes);

        Ok(Self {
            session,
            key_handle,
            public_key_bytes,
        })
    }
}

#[cfg(feature = "pkcs11")]
impl HsmSigner for Pkcs11Signer {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key_bytes.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use cryptoki::mechanism::Mechanism;
        let mechanism = Mechanism::EdDSA;
        let sig = self
            .session
            .sign(&mechanism, self.key_handle, msg)
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        if sig.len() != 64 {
            return Err(CryptoError::KeyLength {
                expected: 64,
                actual: sig.len(),
            });
        }
        Ok(SignatureBytes(sig))
    }

    fn backend_name(&self) -> &str {
        "pkcs11"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let _ = self
            .session
            .get_session_info()
            .map_err(|e| CryptoError::Key(e.to_string()))?;
        Ok(())
    }

    fn key_id(&self) -> Option<String> {
        Some(hex::encode(&self.public_key_bytes.0))
    }
}

// ── Cloud KMS Stubs ─────────────────────────────────────────────────────

macro_rules! stub_signer {
    ($name:ident, $backend:expr) => {
        pub struct $name {
            pub_key: PublicKeyBytes,
        }
        impl $name {
            pub fn new(_config: &KeyBackendConfig) -> Result<Self, CryptoError> {
                Err(CryptoError::Key(format!("{} not yet implemented", $backend)))
            }
        }
        impl HsmSigner for $name {
            fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
                Err(CryptoError::Key(format!("{} not implemented", $backend)))
            }
            fn sign(&self, _msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
                Err(CryptoError::Key(format!("{} not implemented", $backend)))
            }
            fn backend_name(&self) -> &str {
                $backend
            }
            fn health_check(&self) -> Result<(), CryptoError> {
                Err(CryptoError::Key(format!("{} not implemented", $backend)))
            }
        }
    };
}

stub_signer!(AwsKmsSigner, "aws_kms");
stub_signer!(AzureKeyVaultSigner, "azure_keyvault");
stub_signer!(GcpKmsSigner, "gcp_kms");

// ── Factory ──────────────────────────────────────────────────────────────

/// Create an HsmSigner from configuration.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    match config {
        KeyBackendConfig::Local { path, password_env } => {
            let password = std::env::var(password_env).unwrap_or_default();
            if !password.is_empty() {
                // Try to load from keystore
                #[cfg(feature = "keystore")]
                {
                    let signer = LocalSigner::from_keystore(path, &password)
                        .map_err(|e| CryptoError::Key(format!("keystore load failed: {e}")))?;
                    return Ok(Box::new(signer));
                }
                #[cfg(not(feature = "keystore"))]
                {
                    return Err(CryptoError::Key("keystore feature not enabled".into()));
                }
            } else if std::path::Path::new(path).exists() {
                // Try to load with empty password (plain text)
                let signer = LocalSigner::from_keystore(path, "")
                    .map_err(|e| CryptoError::Key(format!("keystore load failed: {e}")))?;
                return Ok(Box::new(signer));
            } else {
                // Generate new key and store
                use rand::rngs::OsRng;
                let seed: [u8; 32] = rand::Rng::gen(&mut OsRng);
                let signer = LocalSigner::from_seed(&seed);
                // Save keystore if password is set
                #[cfg(feature = "keystore")]
                if !password.is_empty() {
                    crate::crypto::keystore::encrypt_seed32_to_file(path, &seed, &password)
                        .map_err(|e| CryptoError::Key(format!("keystore write failed: {e}")))?;
                }
                return Ok(Box::new(signer));
            }
        }
        KeyBackendConfig::Remote { .. } => {
            let signer = RemoteSigner::new(config)?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::Pkcs11 { library_path, slot, key_label, pin_env } => {
            #[cfg(feature = "pkcs11")]
            {
                let pin = std::env::var(pin_env).unwrap_or_default();
                let signer = Pkcs11Signer::new(library_path, *slot, key_label, &pin)?;
                Ok(Box::new(signer))
            }
            #[cfg(not(feature = "pkcs11"))]
            {
                Err(CryptoError::Key("PKCS#11 support not compiled (enable 'pkcs11' feature)".into()))
            }
        }
        KeyBackendConfig::AwsKms { .. } => {
            let signer = AwsKmsSigner::new(config)?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::AzureKeyVault { .. } => {
            let signer = AzureKeyVaultSigner::new(config)?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::GcpKms { .. } => {
            let signer = GcpKmsSigner::new(config)?;
            Ok(Box::new(signer))
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_signer() {
        let seed = [42u8; 32];
        let signer = LocalSigner::from_seed(&seed);
        assert_eq!(signer.backend_name(), "local");
        assert!(signer.health_check().is_ok());

        let pk = signer.public_key().unwrap();
        assert!(!pk.0.is_empty());

        let sig = signer.sign(b"test message").unwrap();
        assert!(!sig.0.is_empty());
    }

    #[test]
    fn test_local_signer_deterministic() {
        let seed = [42u8; 32];
        let s1 = LocalSigner::from_seed(&seed);
        let s2 = LocalSigner::from_seed(&seed);
        let sig1 = s1.sign(b"hello").unwrap();
        let sig2 = s2.sign(b"hello").unwrap();
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_config_default() {
        let config = KeyBackendConfig::default();
        match config {
            KeyBackendConfig::Local { path, password_env } => {
                assert_eq!(path, "keys.enc");
                assert_eq!(password_env, "IONA_KEYSTORE_PASSWORD");
            }
            _ => panic!("default should be Local"),
        }
    }

    #[test]
    fn test_config_validation() {
        let mut config = KeyBackendConfig::default();
        assert!(config.validate().is_ok());

        if let KeyBackendConfig::Local { ref mut path, .. } = config {
            *path = "".into();
        }
        assert!(config.validate().is_err());

        let remote = KeyBackendConfig::Remote {
            url: "".into(),
            timeout_s: 5,
            api_key: None,
            client_cert_path: None,
            client_key_path: None,
            ca_cert_path: None,
        };
        assert!(remote.validate().is_err());

        let pkcs11 = KeyBackendConfig::Pkcs11 {
            library_path: "/lib.so".into(),
            slot: 1,
            key_label: "".into(),
            pin_env: "PIN".into(),
        };
        assert!(pkcs11.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let configs = vec![
            KeyBackendConfig::Local { path: "keys.enc".into(), password_env: "PW".into() },
            KeyBackendConfig::Remote {
                url: "https://signer.example".into(),
                timeout_s: 5,
                api_key: Some(SecretString::new("key123")),
                client_cert_path: None,
                client_key_path: None,
                ca_cert_path: None,
            },
            KeyBackendConfig::AwsKms {
                key_id: "arn:aws:kms:us-east-1:123:key/abc".into(),
                region: "us-east-1".into(),
                endpoint: None,
            },
            KeyBackendConfig::AzureKeyVault {
                vault_url: "https://v.vault.azure.net/".into(),
                key_name: "k".into(),
                key_version: None,
            },
            KeyBackendConfig::GcpKms {
                resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".into(),
            },
        ];
        for c in &configs {
            let json = serde_json::to_string(c).unwrap();
            let _: KeyBackendConfig = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_hsm_manager() {
        let signer = Box::new(LocalSigner::random());
        let manager = HsmManager::new(signer);
        let pk = manager.public_key().unwrap();
        assert!(!pk.0.is_empty());
        let sig = manager.sign(b"test").unwrap();
        assert!(!sig.0.is_empty());
        assert!(manager.health_check().is_ok());
        assert_eq!(manager.backend_name(), "local");
        assert!(manager.key_id().is_some());
    }
}
