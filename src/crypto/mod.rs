//! Cryptographic primitives for IONA.
//!
//! This module provides:
//! - Public key and signature type wrappers with hex serialisation.
//! - Traits `Signer` and `Verifier` for pluggable signing backends.
//! - Ed25519 implementation (ed25519 module).
//! - Transaction signing utilities (tx module).
//! - Encrypted keystore (keystore module).
//! - Remote signer client (remote_signer module).
//! - HSM support (hsm module, optional).

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Cryptographic errors that can occur during signature verification or key handling.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// Signature verification failed (invalid signature for the given message and public key).
    #[error("invalid signature")]
    InvalidSignature,

    /// Key‑related error (e.g., invalid key format, unsupported algorithm).
    #[error("key error: {0}")]
    Key(String),
}

// -----------------------------------------------------------------------------
// PublicKeyBytes
// -----------------------------------------------------------------------------

/// Public key bytes wrapper with hex serialisation.
///
/// JSON map keys must be strings, so this wrapper serialises as a hex string
/// instead of a byte array. This fixes encoding issues when used as keys in
/// `BTreeMap` or `HashMap` (e.g., `stakes.json`).
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

/// Signature bytes wrapper (usually 64 bytes for Ed25519).
/// Unlike `PublicKeyBytes`, this type is serialised as a byte array (via `serde` derive)
/// because signatures are never used as map keys.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureBytes(pub Vec<u8>);

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
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError>;
}

// -----------------------------------------------------------------------------
// Submodules
// -----------------------------------------------------------------------------

pub mod ed25519;
pub mod tx;
pub mod keystore;
pub mod remote_signer;
pub mod hsm;
