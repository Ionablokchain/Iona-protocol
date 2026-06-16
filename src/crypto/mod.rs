//! Cryptographic primitives for IONA.
//!
//! This module provides:
//! - Public key and signature type wrappers with hex and base64 serialisation.
//! - Traits `Signer` and `Verifier` for pluggable signing backends.
//! - Ed25519 implementation (ed25519 module).
//! - Transaction signing utilities (tx module).
//! - Encrypted keystore (keystore module).
//! - Remote signer client (remote_signer module).
//! - HSM support (hsm module, optional).
//!
//! # Example
//!
//! ```
//! use iona::crypto::{Signer, Verifier, ed25519::Ed25519Signer, PublicKeyBytes};
//!
//! let signer = Ed25519Signer::random();
//! let msg = b"hello world";
//! let sig = signer.sign(msg);
//! let pk = signer.public_key();
//! assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Length of an Ed25519 public key in bytes.
pub const PUBLIC_KEY_LEN: usize = 32;

/// Length of an Ed25519 signature in bytes.
pub const SIGNATURE_LEN: usize = 64;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Cryptographic errors that can occur during signature verification or key handling.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CryptoError {
    /// Signature verification failed (invalid signature for the given message and public key).
    #[error("invalid signature")]
    InvalidSignature,

    /// Invalid key (e.g., wrong format, unsupported algorithm).
    #[error("invalid key: {0}")]
    InvalidKey(String),

    /// Key length mismatch (expected a certain number of bytes).
    #[error("invalid key length: expected {expected}, got {actual}")]
    KeyLength { expected: usize, actual: usize },

    /// Configuration error (e.g., missing field, invalid value).
    #[error("configuration error: {0}")]
    Config(String),

    /// Network error (e.g., remote signer unreachable).
    #[error("network error: {0}")]
    Network(String),

    /// Timeout error (e.g., remote signer timeout).
    #[error("timeout")]
    Timeout,

    /// Backend‑specific error (e.g., HSM failure).
    #[error("backend error: {0}")]
    Backend(String),

    /// Internal error (e.g., cryptographic primitive failure).
    #[error("internal error: {0}")]
    Internal(String),
}

pub type CryptoResult<T> = Result<T, CryptoError>;

// -----------------------------------------------------------------------------
// PublicKeyBytes
// -----------------------------------------------------------------------------

/// Public key bytes wrapper with hex and base64 serialisation.
///
/// This wrapper is used for public keys (e.g., Ed25519). It serialises
/// as a hex string when used with `serde_json` or other formats,
/// and implements `Display` and `FromStr` for human‑readable representation.
///
/// # Example
/// ```
/// use iona::crypto::PublicKeyBytes;
/// let pk = PublicKeyBytes(vec![0xAA; 32]);
/// assert_eq!(pk.to_string().len(), 64);
/// ```
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl PublicKeyBytes {
    /// Create a new public key from a hex string.
    ///
    /// # Errors
    /// Returns `CryptoError::KeyLength` if the hex string does not decode to exactly 32 bytes.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }

    /// Create a new public key from a base64 string.
    ///
    /// # Errors
    /// Returns `CryptoError::KeyLength` if the base64 string does not decode to exactly 32 bytes.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = base64::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(CryptoError::KeyLength {
                expected: PUBLIC_KEY_LEN,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }

    /// Encode the public key as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Encode the public key as a base64 string.
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }

    /// Check if the public key is empty (all zero bytes).
    pub fn is_empty(&self) -> bool {
        self.0.iter().all(|&b| b == 0)
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

// -----------------------------------------------------------------------------
// SignatureBytes
// -----------------------------------------------------------------------------

/// Signature bytes wrapper (usually 64 bytes for Ed25519).
///
/// Unlike `PublicKeyBytes`, this type is serialised as a byte array (via `serde` derive)
/// because signatures are never used as map keys. It also implements `Display`
/// and `FromStr` for hex representation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignatureBytes(pub Vec<u8>);

impl SignatureBytes {
    /// Create a new signature from a hex string.
    ///
    /// # Errors
    /// Returns `CryptoError::KeyLength` if the hex string does not decode to exactly 64 bytes.
    pub fn from_hex(s: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
    }

    /// Create a new signature from a base64 string.
    ///
    /// # Errors
    /// Returns `CryptoError::KeyLength` if the base64 string does not decode to exactly 64 bytes.
    pub fn from_base64(s: &str) -> CryptoResult<Self> {
        let bytes = base64::decode(s).map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        if bytes.len() != SIGNATURE_LEN {
            return Err(CryptoError::KeyLength {
                expected: SIGNATURE_LEN,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
    }

    /// Encode the signature as a hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }

    /// Encode the signature as a base64 string.
    pub fn to_base64(&self) -> String {
        base64::encode(&self.0)
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl FromStr for SignatureBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_hex(s)
    }
}

// -----------------------------------------------------------------------------
// Signer trait
// -----------------------------------------------------------------------------

/// A signer that can produce signatures for arbitrary messages.
///
/// Implementations must be thread‑safe (`Send + Sync`) and can be backed
/// by local keys, remote signing services, or hardware security modules.
pub trait Signer: Send + Sync {
    /// Return the public key corresponding to this signer.
    fn public_key(&self) -> PublicKeyBytes;

    /// Sign the given message and return the signature.
    ///
    /// # Panics
    /// Implementations should avoid panicking; instead they may return an empty
    /// signature if signing fails (the caller must handle that case).
    fn sign(&self, msg: &[u8]) -> SignatureBytes;

    /// Return a human‑readable name of the signing backend.
    fn backend_name(&self) -> &str {
        "unknown"
    }

    /// Check if the signer is healthy / reachable.
    ///
    /// Default implementation always returns `Ok(())`. Override for remote or HSM backends.
    fn health_check(&self) -> CryptoResult<()> {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Verifier trait
// -----------------------------------------------------------------------------

/// A stateless verifier that can validate signatures against public keys.
pub trait Verifier: Send + Sync {
    /// Verify that `sig` is a valid signature for `msg` under `pk`.
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(CryptoError::InvalidSignature)` otherwise.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()>;

    /// Verify a batch of signatures (same key, multiple messages).
    ///
    /// Default implementation calls `verify` sequentially. Implementations may
    /// override for batch verification optimisation.
    fn verify_batch(
        pk: &PublicKeyBytes,
        msgs: &[&[u8]],
        sigs: &[SignatureBytes],
    ) -> CryptoResult<()> {
        if msgs.len() != sigs.len() {
            return Err(CryptoError::KeyLength {
                expected: msgs.len(),
                actual: sigs.len(),
            });
        }
        for (msg, sig) in msgs.iter().zip(sigs.iter()) {
            Self::verify(pk, msg, sig)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Convenience functions
// -----------------------------------------------------------------------------

/// Verify an Ed25519 signature using the `ed25519` module.
///
/// This is a convenience wrapper around `ed25519::Ed25519Verifier::verify`.
pub fn verify_ed25519(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> CryptoResult<()> {
    crate::crypto::ed25519::Ed25519Verifier::verify(pk, msg, sig)
}

/// Create a public key from a hex string.
pub fn public_key_from_hex(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_hex(s)
}

/// Create a public key from a base64 string.
pub fn public_key_from_base64(s: &str) -> CryptoResult<PublicKeyBytes> {
    PublicKeyBytes::from_base64(s)
}

/// Create a signature from a hex string.
pub fn signature_from_hex(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_hex(s)
}

/// Create a signature from a base64 string.
pub fn signature_from_base64(s: &str) -> CryptoResult<SignatureBytes> {
    SignatureBytes::from_base64(s)
}

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod ed25519;
pub mod tx;
pub mod keystore;
pub mod remote_signer;
pub mod hsm;

// Re‑export commonly used items from submodules for convenience.
pub use ed25519::Ed25519Signer;
pub use ed25519::Ed25519Verifier;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_public_key_bytes_hex_roundtrip() {
        let orig = PublicKeyBytes(vec![0xAA; 32]);
        let hex = orig.to_hex();
        let restored = PublicKeyBytes::from_hex(&hex).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_base64_roundtrip() {
        let orig = PublicKeyBytes(vec![0xBB; 32]);
        let b64 = orig.to_base64();
        let restored = PublicKeyBytes::from_base64(&b64).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_display_fromstr() {
        let orig = PublicKeyBytes(vec![0xCC; 32]);
        let s = orig.to_string();
        let restored: PublicKeyBytes = s.parse().unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_serialize() {
        let pk = PublicKeyBytes(vec![0xDD; 32]);
        let json = serde_json::to_string(&pk).unwrap();
        assert!(json.contains(&pk.to_hex()));
        let restored: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn test_signature_bytes_hex_roundtrip() {
        let orig = SignatureBytes(vec![0xEE; 64]);
        let hex = orig.to_hex();
        let restored = SignatureBytes::from_hex(&hex).unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_signature_bytes_display_fromstr() {
        let orig = SignatureBytes(vec![0xFF; 64]);
        let s = orig.to_string();
        let restored: SignatureBytes = s.parse().unwrap();
        assert_eq!(orig, restored);
    }

    #[test]
    fn test_public_key_bytes_empty() {
        let empty = PublicKeyBytes::default();
        assert!(empty.is_empty());
        let non_empty = PublicKeyBytes(vec![1u8; 32]);
        assert!(!non_empty.is_empty());
    }

    #[test]
    fn test_public_key_from_hex_invalid() {
        assert!(PublicKeyBytes::from_hex("not hex").is_err());
        assert!(PublicKeyBytes::from_hex("aa").is_err()); // too short
    }

    #[test]
    fn test_signature_from_hex_invalid() {
        assert!(SignatureBytes::from_hex("not hex").is_err());
        assert!(SignatureBytes::from_hex("aa").is_err()); // too short
    }

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::InvalidSignature;
        assert_eq!(err.to_string(), "invalid signature");
        let err = CryptoError::KeyLength { expected: 32, actual: 16 };
        assert!(err.to_string().contains("32"));
        assert!(err.to_string().contains("16"));
    }
}
