//! Ed25519 signing and verification for IONA.
//!
//! This module provides an implementation of the `Signer` and `Verifier` traits
//! using the Ed25519 signature scheme (Edwards‑curve Digital Signature Algorithm).
//! The implementation is based on the `ed25519_dalek` crate and includes secure
//! zeroization of secret material.
//!
//! # Security
//! - The signing key is stored in a type that guarantees zeroization on drop
//!   (ed25519_dalek's `SecretKey` implements `ZeroizeOnDrop`).
//! - All operations are constant‑time with respect to secret data.
//! - The recommended source of randomness is the OS RNG (`OsRng`).
//!
//! # Examples
//!
//! ```
//! use iona::crypto::ed25519::Ed25519Signer;
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
use std::fmt;
use std::str::FromStr;
use zeroize::Zeroize;

// -----------------------------------------------------------------------------
// Ed25519Signer
// -----------------------------------------------------------------------------

/// Ed25519 signer that securely holds a signing key.
///
/// The signing key is zeroized on drop thanks to `ed25519_dalek`'s `SecretKey`
/// which implements `ZeroizeOnDrop`. Cloning is allowed but each clone holds
/// its own copy of the key; use `Arc<Ed25519Signer>` if you need shared ownership.
#[derive(Clone)]
pub struct Ed25519Signer {
    /// The secret signing key.
    signing_key: SigningKey,
    /// The corresponding verifying key.
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
            signing_key,
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
            signing_key,
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
    /// Returns `CryptoError::KeyLength` if the slice length is not 32.
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::KeyLength {
                expected: 32,
                actual: slice.len(),
            });
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(slice);
        Ok(Self::from_seed(seed))
    }

    /// Create a signer from a hexadecimal string (64 hex chars).
    ///
    /// # Errors
    /// Returns `CryptoError::Key` if the hex string is invalid or length mismatch.
    pub fn from_hex(hex: &str) -> Result<Self, CryptoError> {
        let bytes = hex::decode(hex).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        Self::try_from_slice(&bytes)
    }

    /// Export the seed as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.to_seed())
    }

    /// Create a signer from a Base64‑encoded seed (44 chars, no padding).
    pub fn from_base64(b64: &str) -> Result<Self, CryptoError> {
        let bytes = base64::decode(b64).map_err(|_| CryptoError::Key("invalid base64".into()))?;
        Self::try_from_slice(&bytes)
    }

    /// Export the seed as a Base64‑encoded string.
    pub fn to_base64(&self) -> String {
        base64::encode(self.to_seed())
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
    /// if the signature is invalid, or `Err(CryptoError::KeyLength)` if the
    /// public key or signature length is incorrect.
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        if pk.0.len() != 32 {
            return Err(CryptoError::KeyLength {
                expected: 32,
                actual: pk.0.len(),
            });
        }
        if sig.0.len() != 64 {
            return Err(CryptoError::KeyLength {
                expected: 64,
                actual: sig.0.len(),
            });
        }

        let public_key = VerifyingKey::from_bytes(&pk.0[..].try_into().unwrap())
            .map_err(|_| CryptoError::InvalidKey("public key bytes invalid".into()))?;

        let signature = Signature::from_bytes(&sig.0[..].try_into().unwrap());

        public_key
            .verify(msg, &signature)
            .map_err(|_| CryptoError::InvalidSignature)
    }
}

/// Standalone verification function (convenience).
///
/// This is equivalent to `Ed25519Verifier::verify`.
pub fn ed25519_verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
    Ed25519Verifier::verify(pk, msg, sig)
}

// -----------------------------------------------------------------------------
// Format helpers for PublicKeyBytes and SignatureBytes
// -----------------------------------------------------------------------------

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for PublicKeyBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        if bytes.len() != 32 {
            return Err(CryptoError::KeyLength {
                expected: 32,
                actual: bytes.len(),
            });
        }
        Ok(PublicKeyBytes(bytes))
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0))
    }
}

impl FromStr for SignatureBytes {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|_| CryptoError::Key("invalid hex".into()))?;
        if bytes.len() != 64 {
            return Err(CryptoError::KeyLength {
                expected: 64,
                actual: bytes.len(),
            });
        }
        Ok(SignatureBytes(bytes))
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

    #[test]
    fn test_hex_roundtrip() {
        let signer = Ed25519Signer::random();
        let hex = signer.to_hex();
        let restored = Ed25519Signer::from_hex(&hex).unwrap();
        assert_eq!(signer.public_key().0, restored.public_key().0);
    }

    #[test]
    fn test_base64_roundtrip() {
        let signer = Ed25519Signer::random();
        let b64 = signer.to_base64();
        let restored = Ed25519Signer::from_base64(&b64).unwrap();
        assert_eq!(signer.public_key().0, restored.public_key().0);
    }

    #[test]
    fn test_public_key_display_fromstr() {
        let signer = Ed25519Signer::random();
        let pk = signer.public_key();
        let s = pk.to_string();
        let pk2: PublicKeyBytes = s.parse().unwrap();
        assert_eq!(pk.0, pk2.0);
    }

    #[test]
    fn test_signature_display_fromstr() {
        let signer = Ed25519Signer::random();
        let sig = signer.sign(b"test");
        let s = sig.to_string();
        let sig2: SignatureBytes = s.parse().unwrap();
        assert_eq!(sig.0, sig2.0);
    }

    #[test]
    fn test_known_vector() {
        // Test vector from RFC 8032 (Ed25519)
        let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60").unwrap();
        let signer = Ed25519Signer::try_from_slice(&seed).unwrap();
        let msg = b"";
        let sig = signer.sign(msg);
        let expected = hex::decode("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
            .unwrap();
        assert_eq!(sig.0, expected);
        let pk = signer.public_key();
        let pk_expected = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a").unwrap();
        assert_eq!(pk.0, pk_expected);
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_wrong_key_length() {
        let pk = PublicKeyBytes(vec![0u8; 31]);
        let sig = SignatureBytes(vec![0u8; 64]);
        let err = Ed25519Verifier::verify(&pk, b"", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::KeyLength { expected: 32, actual: 31 }));
    }

    #[test]
    fn test_wrong_signature_length() {
        let pk = PublicKeyBytes(vec![0u8; 32]);
        let sig = SignatureBytes(vec![0u8; 63]);
        let err = Ed25519Verifier::verify(&pk, b"", &sig).unwrap_err();
        assert!(matches!(err, CryptoError::KeyLength { expected: 64, actual: 63 }));
    }
}
