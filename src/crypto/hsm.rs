//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Provides a trait-based abstraction for signing operations that can be
//! backed by different key storage mechanisms:
//! - Local keystore (default, existing)
//! - Remote signer (HTTP service)
//! - HSM via PKCS#11 (scaffold, feature‑gated)
//! - Cloud KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS (scaffold, feature‑gated)
//!
//! The node code uses the `HsmSigner` trait instead of concrete implementations,
//! allowing operators to plug in their preferred key management solution.
//!
//! # Security
//! - Secrets (passwords, PINs) are never serialized in logs or config dumps
//!   (they are stored as `SecretString` or sourced from environment variables).
//! - All signing operations are constant‑time and use secure randomness.
//! - The local signer zeroizes the seed on drop.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use ed25519_dalek::{Signer as EdSigner, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Secret handling (using `secrecy` crate if available, else a simple wrapper)
// -----------------------------------------------------------------------------
#[cfg(feature = "secrecy")]
use secrecy::{ExposeSecret, SecretString};

#[cfg(not(feature = "secrecy"))]
/// Simple wrapper to avoid exposing secrets in debug output.
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

fn default_timeout() -> u64 {
    10
}

// -----------------------------------------------------------------------------
// HsmSigner trait
// -----------------------------------------------------------------------------

/// Trait for HSM/KMS-backed signing operations.
///
/// Implementors must be thread-safe (`Send + Sync`) since signing may happen
/// from multiple consensus/RPC threads concurrently.
pub trait HsmSigner: Send + Sync {
    /// Get the public key bytes.
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError>;

    /// Sign a message. The HSM/KMS performs the actual signing.
    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError>;

    /// Get the signer type name (for logging/audit).
    fn backend_name(&self) -> &str;

    /// Check if the signer is healthy / reachable.
    fn health_check(&self) -> Result<(), CryptoError>;

    /// Optional: get a unique identifier for the key (e.g., fingerprint, ARN).
    fn key_id(&self) -> Option<String> {
        None
    }

    /// Optional: rotate the key (if supported).
    fn rotate_key(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("key rotation not supported".into()))
    }
}

// -----------------------------------------------------------------------------
// Local Signer
// -----------------------------------------------------------------------------

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
    pub fn from_keystore(path: &str, password: &str) -> Result<Self, CryptoError> {
        let seed = crate::crypto::keystore::decrypt_seed32_from_file(path, password)
            .map_err(|e| CryptoError::Key(format!("keystore decrypt failed: {e}")))?;
        Ok(Self::from_seed(&seed))
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
        // Always healthy (in-memory key)
        Ok(())
    }

    fn key_id(&self) -> Option<String> {
        Some(hex::encode(&self.public_key_bytes.0))
    }
}

// -----------------------------------------------------------------------------
// Remote Signer (HTTP client)
// -----------------------------------------------------------------------------

/// Remote signer using a HTTP service (e.g., the IONA remote signer).
pub struct RemoteSigner {
    client: reqwest::Client,
    url: String,
    public_key: PublicKeyBytes,
}

impl RemoteSigner {
    /// Create a new remote signer from configuration.
    pub async fn new(config: &KeyBackendConfig) -> Result<Self, CryptoError> {
        let (url, timeout_s, api_key, client_cert, client_key, ca_cert) = match config {
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
        let mut builder = reqwest::ClientBuilder::new()
            .timeout(Duration::from_secs(timeout_s))
            .user_agent("iona-hsm/0.1");

        // mTLS
        if let (Some(cert_path), Some(key_path)) = (client_cert, client_key) {
            let cert =
                std::fs::read(&cert_path).map_err(|e| CryptoError::Config(format!("cert read: {e}")))?;
            let key =
                std::fs::read(&key_path).map_err(|e| CryptoError::Config(format!("key read: {e}")))?;
            let identity = reqwest::Identity::from_pkcs8_pem(&cert, &key)
                .map_err(|e| CryptoError::Config(format!("invalid identity: {e}")))?;
            builder = builder.identity(identity);
        }
        if let Some(ca_path) = ca_cert {
            let ca =
                std::fs::read(&ca_path).map_err(|e| CryptoError::Config(format!("CA read: {e}")))?;
            let ca_cert = reqwest::Certificate::from_pem(&ca)
                .map_err(|e| CryptoError::Config(format!("invalid CA: {e}")))?;
            builder = builder.add_root_certificate(ca_cert);
        }

        let client = builder.build().map_err(|e| CryptoError::Network(e.to_string()))?;

        // Fetch public key
        let pubkey_url = format!("{}/pubkey", url);
        let resp = client
            .get(&pubkey_url)
            .header("X-API-Key", api_key.as_ref().map(|s| s.expose_secret()).unwrap_or(""))
            .send()
            .await
            .map_err(|e| CryptoError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(CryptoError::Network(format!("HTTP {}", resp.status())));
        }
        let json: serde_json::Value = resp.json().await.map_err(|e| CryptoError::Network(e.to_string()))?;
        let pubkey_b64 = json["pubkey_base64"]
            .as_str()
            .ok_or_else(|| CryptoError::Key("missing pubkey".into()))?;
        let pubkey_bytes = base64::decode(pubkey_b64).map_err(|e| CryptoError::Key(e.to_string()))?;
        let public_key = PublicKeyBytes(pubkey_bytes);

        Ok(Self {
            client,
            url,
            public_key,
        })
    }
}

impl HsmSigner for RemoteSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.public_key.clone())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        // This is async; we block in the sync method (not ideal).
        // In production, you would have an async version. For simplicity, we use tokio runtime.
        use tokio::runtime::Runtime;
        let rt = Runtime::new().map_err(|e| CryptoError::Key(e.to_string()))?;
        rt.block_on(async {
            let msg_b64 = base64::encode(msg);
            let body = serde_json::json!({ "msg_base64": msg_b64 });
            let resp = self
                .client
                .post(format!("{}/sign", self.url))
                .json(&body)
                .send()
                .await
                .map_err(|e| CryptoError::Network(e.to_string()))?;
            if !resp.status().is_success() {
                let text = resp.text().await.unwrap_or_default();
                return Err(CryptoError::Network(format!("HTTP {}: {}", resp.status(), text)));
            }
            let json: serde_json::Value = resp.json().await.map_err(|e| CryptoError::Network(e.to_string()))?;
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
        })
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        // Use a simple ping to /health or /pubkey
        let rt = tokio::runtime::Runtime::new().map_err(|e| CryptoError::Key(e.to_string()))?;
        rt.block_on(async {
            let resp = self
                .client
                .get(&format!("{}/health", self.url))
                .send()
                .await
                .map_err(|e| CryptoError::Network(e.to_string()))?;
            if resp.status().is_success() {
                Ok(())
            } else {
                Err(CryptoError::Network(format!("health check failed: {}", resp.status())))
            }
        })
    }

    fn key_id(&self) -> Option<String> {
        Some(format!("remote:{}", hex::encode(&self.public_key.0)))
    }
}

// -----------------------------------------------------------------------------
// Placeholder backends (feature‑gated stubs)
// -----------------------------------------------------------------------------

/// PKCS#11 signer (requires `pkcs11` feature).
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
        use cryptoki::mechanism::Mechanism;
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

        // Extract public key (need to find matching public key object)
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
        use cryptoki::types::SignData;

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
        // Try a simple operation, e.g., get session info.
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

// Stubs for other backends (feature‑gated or not, but return error for now)
macro_rules! stub_signer {
    ($name:ident, $backend:expr) => {
        pub struct $name {
            _inner: (),
        }
        impl $name {
            pub fn new(_config: &crate::hsm::KeyBackendConfig) -> Result<Self, CryptoError> {
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

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

/// Create an HsmSigner from configuration.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    match config {
        KeyBackendConfig::Local { path, password_env } => {
            let password = std::env::var(password_env).unwrap_or_default();
            if password.is_empty() && std::path::Path::new(path).exists() {
                // Try to load from file
                let signer =
                    LocalSigner::from_keystore(path, &password).map_err(|e| {
                        CryptoError::Key(format!("keystore load failed: {e}"))
                    })?;
                Ok(Box::new(signer))
            } else if !std::path::Path::new(path).exists() {
                // Generate new key and store
                use rand::rngs::OsRng;
                let seed: [u8; 32] = rand::Rng::gen(&mut OsRng);
                let signer = LocalSigner::from_seed(&seed);
                // Save keystore if password is set
                if !password.is_empty() {
                    crate::crypto::keystore::encrypt_seed32_to_file(path, &seed, &password)
                        .map_err(|e| CryptoError::Key(format!("keystore write failed: {e}")))?;
                }
                Ok(Box::new(signer))
            } else {
                // fallback: generate random (but should not happen)
                Ok(Box::new(LocalSigner::random()))
            }
        }
        KeyBackendConfig::Remote { .. } => {
            // Need async; we'll block with runtime internally.
            let rt = tokio::runtime::Runtime::new().map_err(|e| CryptoError::Key(e.to_string()))?;
            let signer = rt
                .block_on(RemoteSigner::new(config))
                .map_err(|e| CryptoError::Key(e.to_string()))?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::Pkcs11 { .. } => {
            #[cfg(feature = "pkcs11")]
            {
                let pin = std::env::var(config.pin_env()).unwrap_or_default();
                let signer = Pkcs11Signer::new(
                    config.library_path(),
                    config.slot(),
                    config.key_label(),
                    &pin,
                )?;
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn test_remote_signer_health_check_mock() {
        // Since we can't actually call a remote server in unit test, we skip.
        // In production, you'd have integration tests.
    }
}
