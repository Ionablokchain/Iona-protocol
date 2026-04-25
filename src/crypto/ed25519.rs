//! Ed25519 signing and verification for IONA.
//!
//! This module provides:
//! - `Ed25519Keypair` for signing (generation, from seed, deterministic signing).
//! - `Ed25519Verifier` for signature verification.
//! - Utilities for remote signer (reading keys from disk, signing raw bytes).
//!
//! # Example
//!
//! ```
//! use iona::crypto::ed25519::{Ed25519Keypair, Ed25519Verifier};
//! use iona::crypto::{Signer, Verifier, PublicKeyBytes};
//!
//! let kp = Ed25519Keypair::generate();
//! let pk = kp.public_key();
//! let msg = b"hello";
//! let sig = kp.sign(msg);
//! assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
//! ```

use super::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{
    Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey,
};
use rand::rngs::OsRng;
use std::fs;
use std::io::Write;
use std::path::Path;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Ed25519Keypair
// -----------------------------------------------------------------------------

/// Ed25519 key pair for signing.
#[derive(Clone)]
pub struct Ed25519Keypair {
    sk: SigningKey,
}

impl Ed25519Keypair {
    /// Generate a new random key pair.
    #[must_use]
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        debug!("generated new Ed25519 keypair");
        Self { sk }
    }

    /// Create a key pair from a 32‑byte seed (deterministic).
    #[must_use]
    pub fn from_seed(seed32: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed32);
        debug!("created Ed25519 keypair from seed (first 4 bytes: {:02x?})", &seed32[..4]);
        Self { sk }
    }

    /// Export the seed (32 bytes) for persistence (careful!).
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.sk.to_bytes()
    }
}

impl Signer for Ed25519Keypair {
    fn public_key(&self) -> PublicKeyBytes {
        PublicKeyBytes(self.sk.verifying_key().to_bytes().to_vec())
    }

    fn sign(&self, msg: &[u8]) -> SignatureBytes {
        let sig: Signature = self.sk.sign(msg);
        debug!(msg_len = msg.len(), "signed message with Ed25519");
        SignatureBytes(sig.to_bytes().to_vec())
    }
}

// -----------------------------------------------------------------------------
// Ed25519Verifier
// -----------------------------------------------------------------------------

/// Ed25519 signature verifier (stateless).
pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        let pk_slice: &[u8] = pk.0.as_slice();
        let vk = VerifyingKey::from_bytes(
            pk_slice
                .try_into()
                .map_err(|_| {
                    let err = CryptoError::Key("bad pk bytes: expected 32 bytes".into());
                    warn!("Ed25519 verification failed: {}", err);
                    err
                })?,
        )
        .map_err(|e| {
            let err = CryptoError::Key(format!("invalid public key: {e}"));
            warn!("Ed25519 verification failed: {}", err);
            err
        })?;

        let sig_slice: &[u8] = sig.0.as_slice();
        let sig = Signature::from_bytes(
            sig_slice
                .try_into()
                .map_err(|_| {
                    let err = CryptoError::Key("bad sig bytes: expected 64 bytes".into());
                    warn!("Ed25519 verification failed: {}", err);
                    err
                })?,
        );

        vk.verify(msg, &sig).map_err(|_| {
            warn!("Ed25519 signature invalid for given message and public key");
            CryptoError::InvalidSignature
        })?;

        debug!(msg_len = msg.len(), "Ed25519 signature verified successfully");
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Utilities for remote signer server
// -----------------------------------------------------------------------------

/// Read a 32‑byte Ed25519 signing key from `path`, or generate and persist a new one.
///
/// If the file does not exist, it is created with a newly generated key.
/// Returns an error if the file exists but is not exactly 32 bytes or cannot be read.
///
/// # Security
/// The key is stored in plain text. For production, use encrypted keystore or HSM.
#[must_use]
pub fn read_signing_key_or_generate(path: &str) -> std::io::Result<SigningKey> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    if let Ok(bytes) = fs::read(path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            debug!(path = %path.display(), "loaded signing key from disk");
            return Ok(SigningKey::from_bytes(&seed));
        } else {
            let err_msg = format!("key file exists but length {} != 32", bytes.len());
            error!(path = %path.display(), "{}", err_msg);
            return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, err_msg));
        }
    }

    // Generate new key.
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let mut f = fs::File::create(path)?;
    f.write_all(&sk.to_bytes())?;
    info!(path = %path.display(), "generated and saved new signing key");
    Ok(sk)
}

/// Sign bytes and return the raw 64‑byte signature.
#[must_use]
pub fn sign_bytes(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = sk.sign(msg);
    debug!(msg_len = msg.len(), "raw signature generated");
    sig.to_bytes().to_vec()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_verify() {
        let kp = Ed25519Keypair::generate();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        let pk = kp.public_key();
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_ok());
    }

    #[test]
    fn test_invalid_signature() {
        let kp = Ed25519Keypair::generate();
        let msg = b"hello world";
        let mut sig = kp.sign(msg);
        // Corrupt signature
        if let Some(byte) = sig.0.get_mut(0) {
            *byte ^= 1;
        }
        let pk = kp.public_key();
        assert!(Ed25519Verifier::verify(&pk, msg, &sig).is_err());
    }

    #[test]
    fn test_wrong_message() {
        let kp = Ed25519Keypair::generate();
        let msg = b"hello world";
        let sig = kp.sign(msg);
        let wrong_msg = b"goodbye";
        let pk = kp.public_key();
        assert!(Ed25519Verifier::verify(&pk, wrong_msg, &sig).is_err());
    }

    #[test]
    fn test_from_seed() {
        let seed = [0xaa; 32];
        let kp1 = Ed25519Keypair::from_seed(seed);
        let kp2 = Ed25519Keypair::from_seed(seed);
        assert_eq!(kp1.public_key().0, kp2.public_key().0);
        let msg = b"test";
        let sig1 = kp1.sign(msg);
        let sig2 = kp2.sign(msg);
        assert_eq!(sig1.0, sig2.0);
    }

    #[test]
    fn test_to_bytes() {
        let seed = [0xbb; 32];
        let kp = Ed25519Keypair::from_seed(seed);
        let exported = kp.to_bytes();
        assert_eq!(seed, exported);
    }

    #[test]
    fn test_read_signing_key_or_generate() -> std::io::Result<()> {
        use tempfile::tempdir;
        let dir = tempdir()?;
        let path = dir.path().join("key.bin");
        let key1 = read_signing_key_or_generate(path.to_str().unwrap())?;
        let key2 = read_signing_key_or_generate(path.to_str().unwrap())?;
        assert_eq!(key1.to_bytes(), key2.to_bytes());
        Ok(())
    }
}
