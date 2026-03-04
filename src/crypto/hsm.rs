//! HSM (Hardware Security Module) and KMS (Key Management Service) integration.
//!
//! Provides a trait-based abstraction for signing operations that can be
//! backed by different key storage mechanisms:
//! - Local keystore (default, existing)
//! - Remote signer (existing)
//! - HSM via PKCS#11 (scaffold)
//! - Cloud KMS: AWS KMS, Azure Key Vault, GCP Cloud KMS (scaffold)
//!
//! The node code uses `HsmSigner` trait instead of concrete signing implementations,
//! allowing operators to plug in their preferred key management solution.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use serde::{Deserialize, Serialize};

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

/// Placeholder PKCS#11 signer.
/// In production, this would use the `cryptoki` crate to talk to the HSM.
pub struct Pkcs11Signer {
    _library_path: String,
    _slot: u64,
    _key_label: String,
}

impl Pkcs11Signer {
    pub fn new(library_path: &str, slot: u64, key_label: &str, _pin: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            _library_path: library_path.to_string(),
            _slot: slot,
            _key_label: key_label.to_string(),
        })
    }
}

impl HsmSigner for Pkcs11Signer {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Err(CryptoError::Key("PKCS#11: not yet implemented".into()))
    }

    fn sign(&self, _msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Err(CryptoError::Key("PKCS#11: not yet implemented".into()))
    }

    fn backend_name(&self) -> &str {
        "pkcs11"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("PKCS#11: not yet implemented".into()))
    }
}

/// Placeholder AWS KMS signer.
pub struct AwsKmsSigner {
    _key_id: String,
    _region: String,
}

impl AwsKmsSigner {
    pub fn new(key_id: &str, region: &str, _endpoint: Option<&str>) -> Result<Self, CryptoError> {
        Ok(Self {
            _key_id: key_id.to_string(),
            _region: region.to_string(),
        })
    }
}

impl HsmSigner for AwsKmsSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Err(CryptoError::Key("AWS KMS: not yet implemented".into()))
    }

    fn sign(&self, _msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Err(CryptoError::Key("AWS KMS: not yet implemented".into()))
    }

    fn backend_name(&self) -> &str {
        "aws_kms"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("AWS KMS: not yet implemented".into()))
    }
}

/// Placeholder Azure Key Vault signer.
pub struct AzureKeyVaultSigner {
    _vault_url: String,
    _key_name: String,
}

impl AzureKeyVaultSigner {
    pub fn new(vault_url: &str, key_name: &str, _key_version: Option<&str>) -> Result<Self, CryptoError> {
        Ok(Self {
            _vault_url: vault_url.to_string(),
            _key_name: key_name.to_string(),
        })
    }
}

impl HsmSigner for AzureKeyVaultSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Err(CryptoError::Key("Azure Key Vault: not yet implemented".into()))
    }

    fn sign(&self, _msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Err(CryptoError::Key("Azure Key Vault: not yet implemented".into()))
    }

    fn backend_name(&self) -> &str {
        "azure_keyvault"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("Azure Key Vault: not yet implemented".into()))
    }
}

/// Placeholder GCP Cloud KMS signer.
pub struct GcpKmsSigner {
    _resource_name: String,
}

impl GcpKmsSigner {
    pub fn new(resource_name: &str) -> Result<Self, CryptoError> {
        Ok(Self {
            _resource_name: resource_name.to_string(),
        })
    }
}

impl HsmSigner for GcpKmsSigner {
    fn public_key(&self) -> Result<PublicKeyBytes, CryptoError> {
        Err(CryptoError::Key("GCP KMS: not yet implemented".into()))
    }

    fn sign(&self, _msg: &[u8]) -> Result<SignatureBytes, CryptoError> {
        Err(CryptoError::Key("GCP KMS: not yet implemented".into()))
    }

    fn backend_name(&self) -> &str {
        "gcp_kms"
    }

    fn health_check(&self) -> Result<(), CryptoError> {
        Err(CryptoError::Key("GCP KMS: not yet implemented".into()))
    }
}

/// Create an HsmSigner from configuration.
pub fn create_signer(config: &KeyBackendConfig) -> Result<Box<dyn HsmSigner>, CryptoError> {
    match config {
        KeyBackendConfig::Local { path, password_env } => {
            let password = std::env::var(password_env).unwrap_or_default();
            if !password.is_empty() && std::path::Path::new(path).exists() {
                match crate::crypto::keystore::decrypt_seed32_from_file(path, &password) {
                    Ok(seed) => {
                        let signer = LocalSigner::from_seed(&seed);
                        return Ok(Box::new(signer));
                    }
                    Err(e) => {
                        return Err(CryptoError::Key(format!("keystore decrypt failed: {e}")));
                    }
                }
            }
            let seed = [1u8; 32];
            Ok(Box::new(LocalSigner::from_seed(&seed)))
        }
        KeyBackendConfig::Remote { .. } => {
            Err(CryptoError::Key("remote signer: use remote_signer module instead".into()))
        }
        KeyBackendConfig::Pkcs11 { library_path, slot, key_label, pin_env } => {
            let pin = std::env::var(pin_env).unwrap_or_default();
            let signer = Pkcs11Signer::new(library_path, *slot, key_label, &pin)?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::AwsKms { key_id, region, endpoint } => {
            let signer = AwsKmsSigner::new(key_id, region, endpoint.as_deref())?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::AzureKeyVault { vault_url, key_name, key_version } => {
            let signer = AzureKeyVaultSigner::new(vault_url, key_name, key_version.as_deref())?;
            Ok(Box::new(signer))
        }
        KeyBackendConfig::GcpKms { resource_name } => {
            let signer = GcpKmsSigner::new(resource_name)?;
            Ok(Box::new(signer))
        }
    }
}

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
    fn test_pkcs11_placeholder() {
        let s = Pkcs11Signer::new("/usr/lib/libpkcs11.so", 0, "key1", "1234").unwrap();
        assert_eq!(s.backend_name(), "pkcs11");
        assert!(s.public_key().is_err());
        assert!(s.sign(b"test").is_err());
        assert!(s.health_check().is_err());
    }

    #[test]
    fn test_aws_kms_placeholder() {
        let s = AwsKmsSigner::new("arn:key", "us-east-1", None).unwrap();
        assert_eq!(s.backend_name(), "aws_kms");
        assert!(s.public_key().is_err());
    }

    #[test]
    fn test_azure_placeholder() {
        let s = AzureKeyVaultSigner::new("https://v.vault.azure.net/", "key1", None).unwrap();
        assert_eq!(s.backend_name(), "azure_keyvault");
        assert!(s.sign(b"test").is_err());
    }

    #[test]
    fn test_gcp_placeholder() {
        let s = GcpKmsSigner::new("projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1").unwrap();
        assert_eq!(s.backend_name(), "gcp_kms");
        assert!(s.health_check().is_err());
    }
}
