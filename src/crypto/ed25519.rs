//! Ed25519 signing and verification for IONA.

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{Signature, Signer as EdSigner, SigningKey, Verifier as EdVerifier, VerifyingKey};
use rand::rngs::OsRng;
use std::sync::Arc;
use zeroize::Zeroizing;

/// Ed25519 signer that holds a signing key.
#[derive(Clone)]
pub struct Ed25519Signer {
    signing_key: Arc<SigningKey>,
    verifying_key: VerifyingKey,
    public_key_bytes: PublicKeyBytes,
}

impl Ed25519Signer {
    /// Create a new signer from a seed (32 bytes).
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

    /// Generate a random signing key.
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

    /// Export the seed (32 bytes) for persistence (careful!).
    pub fn to_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Try to create a signer from a byte slice (must be 32 bytes).
    pub fn try_from_slice(slice: &[u8]) -> Result<Self, CryptoError> {
        if slice.len() != 32 {
            return Err(CryptoError::Key("seed must be 32 bytes".into()));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(slice);
        Ok(Self::from_seed(seed))
    }

    /// Access the verifying key (for verification).
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

/// Ed25519 verifier (stateless).
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
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
        // Corrupt signature
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
