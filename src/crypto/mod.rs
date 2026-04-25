//! Cryptographic primitives and utilities for IONA.
//!
//! This module provides:
//! - Ed25519 signing and verification (`ed25519` submodule)
//! - Transaction signing helpers (`tx`)
//! - Encrypted keystore for key persistence (`keystore`)
//! - Remote signer client (`remote_signer`)
//! - HSM/KMS abstraction (`hsm`)
//!
//! # Example
//!
//! ```rust
//! use iona::crypto::prelude::*;
//!
//! let signer = Ed25519Keypair::generate();
//! let msg = b"hello";
//! let sig = signer.sign(msg);
//! let pk = signer.public_key();
//! assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
//! ```

pub mod ed25519;
pub mod hsm;
pub mod keystore;
pub mod remote_signer;
pub mod tx;

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// CryptoError
// -----------------------------------------------------------------------------

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed.
    #[error("invalid signature")]
    InvalidSignature,
    /// Key‑related error (e.g., invalid format, length).
    #[error("key error: {0}")]
    Key(String),
}

// -----------------------------------------------------------------------------
// PublicKeyBytes
// -----------------------------------------------------------------------------

/// Public key bytes — serializes as hex string for JSON compatibility.
///
/// JSON map keys must be strings, so we serialize as hex instead of byte arrays.
/// This fixes "stakes.json encode: key must be a string" when `BTreeMap<PublicKeyBytes, _>`
/// is serialized to JSON.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PublicKeyBytes(pub Vec<u8>);

impl std::fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl std::str::FromStr for PublicKeyBytes {
    type Err = hex::FromHexError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(PublicKeyBytes(hex::decode(s)?))
    }
}

impl Serialize for PublicKeyBytes {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for PublicKeyBytes {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s)
            .map(PublicKeyBytes)
            .map_err(serde::de::Error::custom)
    }
}

// -----------------------------------------------------------------------------
// SignatureBytes
// -----------------------------------------------------------------------------

/// Signature bytes (usually 64 bytes for Ed25519).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

// -----------------------------------------------------------------------------
// Traits
// -----------------------------------------------------------------------------

/// Trait for signing messages.
pub trait Signer: Send + Sync {
    /// Returns the public key.
    fn public_key(&self) -> PublicKeyBytes;
    /// Signs a message and returns the signature.
    fn sign(&self, msg: &[u8]) -> SignatureBytes;
}

/// Trait for verifying signatures.
pub trait Verifier: Send + Sync {
    /// Verifies a signature against a message and public key.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError>;
}

// -----------------------------------------------------------------------------
// Re‑exports for a convenient top‑level API
// -----------------------------------------------------------------------------

pub use ed25519::{Ed25519Keypair, Ed25519Verifier};
pub use hsm::{create_signer, HsmSigner, KeyBackendConfig};
pub use keystore::{decrypt_seed32_from_file, encrypt_seed32_to_file, keystore_exists};

// Re‑export commonly used types from the tx module.
pub use tx::{
    derive_address, sign_tx, tx_sign_bytes, verify_tx_signature,
};

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// A prelude module that re‑exports the most common types and traits
/// from the crypto module.
///
/// # Example
///
/// ```
/// use iona::crypto::prelude::*;
/// ```
pub mod prelude {
    pub use super::{
        CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier,
        Ed25519Keypair, Ed25519Verifier,
        derive_address, sign_tx, tx_sign_bytes, verify_tx_signature,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn test_public_key_bytes_hex_roundtrip() {
        let original = PublicKeyBytes(vec![0xaa; 32]);
        let json = serde_json::to_string(&original).unwrap();
        let deserialized: PublicKeyBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(original, deserialized);
    }

    #[test]
    fn test_public_key_bytes_display() {
        let pk = PublicKeyBytes(vec![0x12, 0x34]);
        let s = format!("{}", pk);
        assert_eq!(s, "1234");
    }

    #[test]
    fn test_from_str() {
        let s = "abcdef";
        let pk = PublicKeyBytes::from_str(s).unwrap();
        assert_eq!(pk.0, hex::decode(s).unwrap());
    }
}
