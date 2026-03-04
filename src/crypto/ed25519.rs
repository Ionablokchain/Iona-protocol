use super::{CryptoError, PublicKeyBytes, SignatureBytes, Signer, Verifier};
use ed25519_dalek::{Signature, Signer as DalekSigner, SigningKey, Verifier as DalekVerifier, VerifyingKey};
use rand::rngs::OsRng;

#[derive(Clone)]
pub struct Ed25519Keypair {
    sk: SigningKey,
}

impl Ed25519Keypair {
    pub fn generate() -> Self {
        let mut rng = OsRng;
        let sk = SigningKey::generate(&mut rng);
        Self { sk }
    }

    pub fn from_seed(seed32: [u8; 32]) -> Self {
        let sk = SigningKey::from_bytes(&seed32);
        Self { sk }
    }

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
        SignatureBytes(sig.to_bytes().to_vec())
    }
}

pub struct Ed25519Verifier;

impl Verifier for Ed25519Verifier {
    fn verify(pk: &PublicKeyBytes, msg: &[u8], sig: &SignatureBytes) -> Result<(), CryptoError> {
        let vk = VerifyingKey::from_bytes(
            pk.0.as_slice()
                .try_into()
                .map_err(|_| CryptoError::Key("bad pk bytes".into()))?,
        )
        .map_err(|e| CryptoError::Key(format!("{e}")))?;

        let sig = Signature::from_bytes(
            sig.0.as_slice()
                .try_into()
                .map_err(|_| CryptoError::Key("bad sig bytes".into()))?,
        );
        vk.verify(msg, &sig).map_err(|_| CryptoError::InvalidSignature)
    }
}

// --- Utilities for the remote signer server ---

/// Read a 32-byte ed25519 signing key from `path`, or generate and persist a new one.
pub fn read_signing_key_or_generate(path: &str) -> std::io::Result<SigningKey> {
    use std::io::Write;
    if let Some(parent) = std::path::Path::new(path).parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    if let Ok(bytes) = std::fs::read(path) {
        if bytes.len() == 32 {
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(SigningKey::from_bytes(&seed));
        }
    }
    let mut rng = OsRng;
    let sk = SigningKey::generate(&mut rng);
    let mut f = std::fs::File::create(path)?;
    f.write_all(&sk.to_bytes())?;
    Ok(sk)
}

/// Sign bytes and return the raw 64-byte signature.
pub fn sign_bytes(sk: &SigningKey, msg: &[u8]) -> Vec<u8> {
    let sig: Signature = sk.sign(msg);
    sig.to_bytes().to_vec()
}
