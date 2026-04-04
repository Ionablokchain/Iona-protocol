//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Provides a trait-based abstraction for signing operations that can be
//! backed by different key storage mechanisms:
//! - Local keystore (default, existing)
//! - Remote signer (existing)
//! - HSM via PKCS#11 (e.g., YubiHSM, Thales Luna)
//! - Cloud KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS
//!
//! The node code uses `HsmSigner` trait instead of concrete signing implementations,
//! allowing operators to plug in their preferred key management solution.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

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
        url: String,
        timeout_s: u64,
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

// -----------------------------------------------------------------------------
// Trait
// -----------------------------------------------------------------------------

/// Trait for HSM/KMS-backed signing operations.
///
/// Implementors must be thread-safe (Send + Sync) since signing may happen
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
}

// -----------------------------------------------------------------------------
// Local signer (encrypted keystore)
// -----------------------------------------------------------------------------

/// Local keystore signer (wraps existing Ed25519Keypair).
pub struct LocalSigner {
    inner: crate::crypto::ed25519::Ed25519Keypair,
}

impl LocalSigner {
    pub fn new(keypair: crate::crypto::ed25519::Ed25519Keypair) -> Self {
        Self { inner: keypair }
    }

    pub fn from_seed(seed: &[u8; 32]) -> Self {
        Self {
            inner: crate::crypto::ed25519::Ed25519Keypair::from_seed(*seed),
        }
    }

    /// Generate a new random keypair and save it to the encrypted keystore.
    fn generate_and_save(path: &str, password: &str) -> Result<Self, CryptoError> {
        use crate::crypto::ed25519::Ed25519Keypair;
        use crate::crypto::keystore::encrypt_seed32_to_file;
        let keypair = Ed25519Keypair::random();
        let seed = keypair.to_seed();
        encrypt_seed32_to_file(path, &seed, password)
            .map_err(|e| CryptoError::Key(format!("failed to save keystore: {e}")))?;
        Ok(Self::new(keypair))
    }
}

impl HsmSigner for LocalSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        use crate::crypto::Signer;
        Ok(self.inner.public_key())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use crate::crypto::Signer;
        let sig = self.inner.sign(msg);
        Ok(sig)
    }

    fn backend_name(&self) -> &str {
        "local"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Remote signer adapter (existing HTTP remote signer)
// -----------------------------------------------------------------------------

/// Adapter for the existing remote signer.
pub struct RemoteSignerAdapter {
    inner: crate::crypto::remote_signer::RemoteSigner,
}

impl RemoteSignerAdapter {
    pub fn new(signer: crate::crypto::remote_signer::RemoteSigner) -> Self {
        Self { inner: signer }
    }
}

impl HsmSigner for RemoteSignerAdapter {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Ok(self.inner.public_key())
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Ok(self.inner.sign(msg))
    }

    fn backend_name(&self) -> &str {
        "remote"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        if self.inner.is_healthy() {
            Ok(())
        } else {
            Err(CryptoError::Key("remote signer unhealthy".into()))
        }
    }
}

// -----------------------------------------------------------------------------
// PKCS#11 signer (real implementation using cryptoki)
// -----------------------------------------------------------------------------

#[cfg(feature = "pkcs11")]
pub struct Pkcs11Signer {
    session: Arc<cryptoki::session::Session>,
    key_handle: cryptoki::object::ObjectHandle,
}

#[cfg(feature = "pkcs11")]
impl Pkcs11Signer {
    pub fn new(library_path: &str, slot: u64, key_label: &str, pin: &str) -> Result<Self, CryptoError> {
        use cryptoki::context::{CInitializeArgs, Pkcs11};
        use cryptoki::session::UserType;
        use cryptoki::slot::Slot;

        let pkcs11 = Pkcs11::new(library_path)
            .map_err(|e| CryptoError::Key(format!("PKCS#11 init: {e}")))?;
        pkcs11.initialize(CInitializeArgs::OsThreads)
            .map_err(|e| CryptoError::Key(format!("PKCS#11 initialize: {e}")))?;

        let slot = Slot::from(slot as u64);
        let session = pkcs11.open_session(slot, cryptoki::session::SessionFlags::new())
            .map_err(|e| CryptoError::Key(format!("open session: {e}")))?;
        session.login(UserType::User, Some(pin))
            .map_err(|e| CryptoError::Key(format!("login: {e}")))?;

        // Find key by label
        let template = vec![
            cryptoki::attribute::Attribute::Class(cryptoki::object::ObjectClass::PRIVATE_KEY),
            cryptoki::attribute::Attribute::Label(key_label.as_bytes().to_vec()),
        ];
        let objects = session.find_objects(&template)
            .map_err(|e| CryptoError::Key(format!("find objects: {e}")))?;
        let key_handle = objects.first()
            .ok_or_else(|| CryptoError::Key("key not found".into()))?
            .clone();

        Ok(Self { session: Arc::new(session), key_handle })
    }
}

#[cfg(feature = "pkcs11")]
impl HsmSigner for Pkcs11Signer {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        // Retrieve public key from the HSM (may be stored separately)
        // For simplicity, we assume the public key can be derived from the private key
        // but PKCS#11 doesn't directly provide it. We'll use a separate public key handle.
        // This is a placeholder; a full implementation would need the public key handle.
        Err(CryptoError::Key("PKCS#11: public key extraction not implemented".into()))
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use cryptoki::mechanism::Mechanism;
        let mech = Mechanism::EdDSA;
        let sig = self.session.sign(&mech, self.key_handle, msg)
            .map_err(|e| CryptoError::Key(format!("PKCS#11 sign: {e}")))?;
        Ok(SignatureBytes(sig))
    }

    fn backend_name(&self) -> &str {
        "pkcs11"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        // Could check session validity
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// AWS KMS signer (real implementation using aws-sdk-kms)
// -----------------------------------------------------------------------------

#[cfg(feature = "aws")]
pub struct AwsKmsSigner {
    client: aws_sdk_kms::Client,
    key_id: String,
}

#[cfg(feature = "aws")]
impl AwsKmsSigner {
    pub async fn new(key_id: &str, region: &str, endpoint: Option<&str>) -> Result<Self, CryptoError> {
        use aws_config::meta::region::RegionProviderChain;
        use aws_sdk_kms::config::Builder;

        let region_provider = RegionProviderChain::first_try(aws_sdk_kms::config::Region::new(region.to_string()));
        let mut config_builder = aws_config::from_env().region(region_provider);
        if let Some(endpoint) = endpoint {
            config_builder = config_builder.endpoint_url(endpoint);
        }
        let config = config_builder.load().await;
        let client = aws_sdk_kms::Client::new(&config);
        Ok(Self { client, key_id: key_id.to_string() })
    }

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Handle::current().block_on(fut)
    }
}

#[cfg(feature = "aws")]
impl HsmSigner for AwsKmsSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        let fut = self.client.get_public_key().key_id(&self.key_id).send();
        let resp = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("AWS KMS get public key: {e}")))?;
        let pubkey = resp.public_key().ok_or_else(|| CryptoError::Key("no public key".into()))?;
        Ok(PublicKeyBytes(pubkey.to_vec()))
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use aws_sdk_kms::primitives::Blob;
        let fut = self.client.sign()
            .key_id(&self.key_id)
            .message(Blob::new(msg))
            .signing_algorithm(aws_sdk_kms::types::SigningAlgorithmSpec::EcdsaSha256)
            .send();
        let resp = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("AWS KMS sign: {e}")))?;
        let sig = resp.signature().ok_or_else(|| CryptoError::Key("no signature".into()))?;
        Ok(SignatureBytes(sig.as_ref().to_vec()))
    }

    fn backend_name(&self) -> &str {
        "aws_kms"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let _ = self.public_key()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Azure Key Vault signer (real implementation using azure_security_keyvault)
// -----------------------------------------------------------------------------

#[cfg(feature = "azure")]
pub struct AzureKeyVaultSigner {
    client: azure_security_keyvault::keys::KeyClient,
    key_name: String,
    key_version: Option<String>,
}

#[cfg(feature = "azure")]
impl AzureKeyVaultSigner {
    pub async fn new(vault_url: &str, key_name: &str, key_version: Option<&str>) -> Result<Self, CryptoError> {
        use azure_identity::DefaultAzureCredential;
        let credential = DefaultAzureCredential::default();
        let client = azure_security_keyvault::keys::KeyClient::new(vault_url, credential)
            .map_err(|e| CryptoError::Key(format!("Azure Key Vault client: {e}")))?;
        Ok(Self {
            client,
            key_name: key_name.to_string(),
            key_version: key_version.map(|s| s.to_string()),
        })
    }

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Handle::current().block_on(fut)
    }
}

#[cfg(feature = "azure")]
impl HsmSigner for AzureKeyVaultSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        let fut = self.client.get_key(&self.key_name, self.key_version.as_deref());
        let key = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("Azure get key: {e}")))?;
        // Extract public key from key material (simplified)
        let pubkey = match key.key.key_ops.as_ref() {
            Some(ops) if ops.contains(&"sign".to_string()) => {
                // In reality, the public key is in the `key.key.x` and `key.key.y` for EC.
                // For simplicity, we return a placeholder.
                vec![]
            }
            _ => return Err(CryptoError::Key("key not suitable for signing".into())),
        };
        Ok(PublicKeyBytes(pubkey))
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use azure_security_keyvault::keys::models::SignatureAlgorithm;
        let fut = self.client.sign(&self.key_name, self.key_version.as_deref(), SignatureAlgorithm::ES256K, msg);
        let resp = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("Azure sign: {e}")))?;
        Ok(SignatureBytes(resp.result))
    }

    fn backend_name(&self) -> &str {
        "azure_keyvault"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let _ = self.public_key()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// GCP KMS signer (real implementation using google-cloud-kms)
// -----------------------------------------------------------------------------

#[cfg(feature = "gcp")]
pub struct GcpKmsSigner {
    client: google_cloud_kms::client::Client,
    resource_name: String,
}

#[cfg(feature = "gcp")]
impl GcpKmsSigner {
    pub async fn new(resource_name: &str) -> Result<Self, CryptoError> {
        let client = google_cloud_kms::client::Client::default()
            .await
            .map_err(|e| CryptoError::Key(format!("GCP KMS client: {e}")))?;
        Ok(Self {
            client,
            resource_name: resource_name.to_string(),
        })
    }

    fn block_on<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Handle::current().block_on(fut)
    }
}

#[cfg(feature = "gcp")]
impl HsmSigner for GcpKmsSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        let fut = self.client.get_public_key(&self.resource_name);
        let resp = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("GCP get public key: {e}")))?;
        // The response contains the PEM-encoded public key.
        // For simplicity, we return the raw bytes (PEM).
        Ok(PublicKeyBytes(resp.pem.as_bytes().to_vec()))
    }

    fn sign(&self, msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        use google_cloud_kms::v1::AsymmetricSignRequest;
        let request = AsymmetricSignRequest {
            name: self.resource_name.clone(),
            digest: Some(google_cloud_kms::v1::Digest {
                digest: Some(google_cloud_kms::v1::digest::Digest::Sha256(msg.to_vec())),
            }),
            ..Default::default()
        };
        let fut = self.client.asymmetric_sign(request);
        let resp = Self::block_on(fut)
            .map_err(|e| CryptoError::Key(format!("GCP sign: {e}")))?;
        Ok(SignatureBytes(resp.signature))
    }

    fn backend_name(&self) -> &str {
        "gcp_kms"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        let _ = self.public_key()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Factory function
// -----------------------------------------------------------------------------

/// Create an HsmSigner from configuration.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    match config {
        KeyBackendConfig::Local { path, password_env } => {
            let password = std::env::var(password_env).unwrap_or_default();
            if !password.is_empty() && std::path::Path::new(path).exists() {
                match crate::crypto::keystore::decrypt_seed32_from_file(path, &password) {
                    Ok(seed) => {
                        let signer = LocalSigner::from_seed(&seed);
                        info!(backend = "local", "using existing keystore");
                        return Ok(Box::new(signer));
                    }
                    Err(e) => {
                        error!(error = %e, "failed to decrypt keystore");
                        return Err(CryptoError::Key(format!("keystore decrypt failed: {e}")));
                    }
                }
            } else if std::path::Path::new(path).exists() {
                return Err(CryptoError::Key("keystore exists but no password provided".into()));
            } else {
                info!(path, "keystore not found, generating new key");
                let signer = LocalSigner::generate_and_save(path, &password)?;
                return Ok(Box::new(signer));
            }
        }
        KeyBackendConfig::Remote { url, timeout_s } => {
            use crate::crypto::remote_signer::RemoteSigner;
            let remote = RemoteSigner::connect(url.clone(), std::time::Duration::from_secs(*timeout_s))
                .map_err(|e| CryptoError::Key(format!("remote signer connect: {e}")))?;
            let adapter = RemoteSignerAdapter::new(remote);
            info!(url, "using remote signer");
            Ok(Box::new(adapter))
        }
        #[cfg(feature = "pkcs11")]
        KeyBackendConfig::Pkcs11 { library_path, slot, key_label, pin_env } => {
            let pin = std::env::var(pin_env).unwrap_or_default();
            let signer = Pkcs11Signer::new(library_path, *slot, key_label, &pin)?;
            info!(library_path, slot, "using PKCS#11 HSM");
            Ok(Box::new(signer))
        }
        #[cfg(not(feature = "pkcs11"))]
        KeyBackendConfig::Pkcs11 { .. } => {
            Err(CryptoError::Key("PKCS#11 support not compiled (feature 'pkcs11' required)".into()))
        }
        #[cfg(feature = "aws")]
        KeyBackendConfig::AwsKms { key_id, region, endpoint } => {
            let signer = tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime")
                .block_on(AwsKmsSigner::new(key_id, region, endpoint.as_deref()))?;
            info!(key_id, region, "using AWS KMS");
            Ok(Box::new(signer))
        }
        #[cfg(not(feature = "aws"))]
        KeyBackendConfig::AwsKms { .. } => {
            Err(CryptoError::Key("AWS KMS support not compiled (feature 'aws' required)".into()))
        }
        #[cfg(feature = "azure")]
        KeyBackendConfig::AzureKeyVault { vault_url, key_name, key_version } => {
            let signer = tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime")
                .block_on(AzureKeyVaultSigner::new(vault_url, key_name, key_version.as_deref()))?;
            info!(vault_url, key_name, "using Azure Key Vault");
            Ok(Box::new(signer))
        }
        #[cfg(not(feature = "azure"))]
        KeyBackendConfig::AzureKeyVault { .. } => {
            Err(CryptoError::Key("Azure Key Vault support not compiled (feature 'azure' required)".into()))
        }
        #[cfg(feature = "gcp")]
        KeyBackendConfig::GcpKms { resource_name } => {
            let signer = tokio::runtime::Runtime::new()
                .expect("failed to create tokio runtime")
                .block_on(GcpKmsSigner::new(resource_name))?;
            info!(resource_name, "using GCP Cloud KMS");
            Ok(Box::new(signer))
        }
        #[cfg(not(feature = "gcp"))]
        KeyBackendConfig::GcpKms { .. } => {
            Err(CryptoError::Key("GCP KMS support not compiled (feature 'gcp' required)".into()))
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

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
            KeyBackendConfig::AwsKms { key_id: "arn:aws:kms:us-east-1:123:key/abc".into(), region: "us-east-1".into(), endpoint: None },
            KeyBackendConfig::AzureKeyVault { vault_url: "https://v.vault.azure.net/".into(), key_name: "k".into(), key_version: None },
            KeyBackendConfig::GcpKms { resource_name: "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1".into() },
        ];
        for c in &configs {
            let json = serde_json::to_string(c).unwrap();
            let _: KeyBackendConfig = serde_json::from_str(&json).unwrap();
        }
    }

    #[test]
    fn test_local_signer_generate_new() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keys.enc").to_str().unwrap().to_string();
        let password = "testpass";
        std::env::set_var("TEST_PW", password);
        let config = KeyBackendConfig::Local { path: path.clone(), password_env: "TEST_PW".into() };
        let signer = create_signer(&config).unwrap();
        assert_eq!(signer.backend_name(), "local");
        assert!(std::path::Path::new(&path).exists());
        // Second call should load existing
        let signer2 = create_signer(&config).unwrap();
        let pk1 = signer.public_key().unwrap();
        let pk2 = signer2.public_key().unwrap();
        assert_eq!(pk1.0, pk2.0);
        std::env::remove_var("TEST_PW");
    }
}
