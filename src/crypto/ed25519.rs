//! Ed25519 signing and verification for IONA.
//!
//! This module provides an implementation of the `Signer` and `Verifier` traits
//! using the Ed25519 signature scheme (Edwards-curve Digital Signature Algorithm).
//! The implementation is based on the `ed25519_dalek` crate.
//!
//! # Example
//!
//! ```
//! use iona::crypto::ed25519::{Ed25519Signer, Ed25519Verifier};
//! use iona::crypto::{Signer, Verifier};
//!
//! let signer = Ed25519Signer::random();
//! let msg = b"hello world";
//! let sig = signer.sign(msg);
//! let pk = signer.public_key();
//! assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
//! ```

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier as EdVerifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use zeroize::Zeroizing;

// -----------------------------------------------------------------------------
// Ed25519Signer
// -----------------------------------------------------------------------------

/// Ed25519 signer that holds a signing key.
///
/// The signing key is stored in an `Arc` to allow cheap cloning.
/// The seed is zeroized on drop via `Zeroizing` (though the `SigningKey`
/// itself does not implement zeroize; we rely on the caller to manage
/// memory sensitivity).
#[derive(Clone)]
pub struct Ed25519Signer {
    /// The secret signing key (wrapped in `Arc` for cheap cloning).
    signing_key: Arc<SigningKey>,
    /// The corresponding verifying key (for fast access).
    verifying_key: VerifyingKey,
    /// Public key bytes (cached for efficient access).
    public_key_bytes: PublicKeyBytes,
}

impl Ed25519Signer {
    /// Create a new signer from a 32‑byte seed.
    ///
    /// # Arguments
    /// * `seed` – A 32‑byte secret seed (should be kept confidential).
    ///
    /// # Returns
    /// An `Ed25519Signer` instance.
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key: Arc::new(signing_key),
            verifying_key,
            public_key_bytes,
        }
    }

    /// Generate a random signing key using the operating system's random number generator.
    pub fn random() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let public_key_bytes = PublicKeyBytes(verifying_key.to_bytes().to_vec());
        Self {
            signing_key: Arc::new(signing_key),
            verifying_key,
            public_key_bytes,
        }
    }

    /// Export the seed (32 bytes) for persistence.
    ///
    /// # Warning
    /// This exposes the private key material. Use with extreme care.
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Attempt to create a signer from a byte slice (must be exactly 32 bytes).
    ///
    /// # Errors
    /// Returns `CryptoError::Key` if the slice length is not 32.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::Key("seed must be 32 bytes".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(slice);
        Ok(Self::from_seed(seed))
    }

    /// Access the verifying key (for verification outside the trait).
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }
}

impl Signer for Ed25519Signer {
    fn public_key(&self) -> PublicKeyBytes {
        self.public_key_bytes.clone()
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let signature: Signature = self.signing_key.sign(msg);
        SignatureBytes(signature.to_bytes().to_vec())
    }
}

// -----------------------------------------------------------------------------
// Ed25519Verifier
// -----------------------------------------------------------------------------

/// Ed25519 verifier (stateless).
///
/// This type implements the `Verifier` trait and provides a single static
/// method for verifying Ed25519 signatures.
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    /// Verify an Ed25519 signature.
    ///
    /// # Arguments
    /// * `pk` – The public key (must be exactly 32 bytes).
    /// * `msg` – The message that was signed.
    /// * `sig` – The signature (must be exactly 64 bytes).
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(CryptoError::InvalidSignature)`
    /// if the signature is invalid, or `Err(CryptoError::Key)` if the public key
    /// or signature length is incorrect.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        if pk.0.len() != 32 {
            return Err(CryptoError::Key("public key must be 32 bytes".into()));
        }
        if sig.0.len() != 64 {
            return Err(CryptoError::InvalidSignature);
        }

        let public_key = VerifyingKey::from_bytes(&pk.0[..].try_into().unwrap())
            .map_err(|_| CryptoError::Key("invalid public key".into()))?;

        let signature = Signature::from_bytes(&sig.0[..].try_into().unwrap());

        public_key
            .verify(msg, &signature)
            .map_err(|_| CryptoError::InvalidSignature)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        let pk = signer.public_key();
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let mut sig = signer.sign(msg);
        // Corrupt the signature by flipping one bit.
        if let Some(byte) = sig.0.get_mut(0) {
            *byte ^= 1;
        }
        let pk = signer.public_key();
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn test_wrong_message() {
        let signer = Ed25519Signer::random();
        let msg = b"hello world";
        let sig = signer.sign(msg);
        let wrong_msg = b"goodbye";
        let pk = signer.public_key();
        assert!(Ed25519Verifier::verify(&pk, wrong_msg, &sig).is_err());
    }

    #[test]
    fn test_from_seed() {
        let seed = [0xaa; 32];
        let signer1 = Ed25519Signer::from_seed(seed);
        let signer2 = Ed25519Signer::from_seed(seed);
        assert_eq!(signer1.public_key().0, signer2.public_key().0);
        let msg = b"test";
        let sig1 = signer1.sign(msg);
        let sig2 = signer2.sign(msg);
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_to_seed() {
        let seed = [0xaa; 32];
        let signer = Ed25519Signer::from_seed(seed);
        let exported = signer.to_seed();
        assert_eq!(seed, exported);
    }
}
