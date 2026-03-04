//! Minimal encrypted keystore for validator/node keys.
//!
//! This is intentionally simple: it encrypts the 32-byte seed used to derive an ed25519 keypair.
//!
//! Format (JSON):
//! { "v": 1, "salt": "..b64..", "nonce": "..b64..", "ct": "..b64.." }
//!
//! Derivation: PBKDF2-HMAC-SHA256 (100_000 iterations) -> 32-byte key
//! Encryption: AES-256-GCM

use aes_gcm::{aead::{Aead, KeyInit}, Aes256Gcm, Nonce};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::{fs, io, path::Path};
use zeroize::Zeroize;

const V: u32 = 1;
const PBKDF2_ITERS: u32 = 100_000;

#[derive(Debug, Serialize, Deserialize)]
struct KeystoreFile {
    v: u32,
    salt: String,
    nonce: String,
    ct: String,
}

fn derive_key(pass: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    key
}

pub fn encrypt_seed32_to_file(path: &str, seed32: [u8; 32], pass: &str) -> io::Result<()> {
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let mut key = derive_key(pass, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("aes key: {e}")))?;

    let ct = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed32.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encrypt: {e}")))?;

    // Zero secrets as best-effort.
    key.zeroize();

    let out = KeystoreFile {
        v: V,
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ct: base64::engine::general_purpose::STANDARD.encode(ct),
    };

    let s = serde_json::to_string_pretty(&out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keystore encode: {e}")))?;
    fs::write(path, s)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }

    Ok(())
}

pub fn decrypt_seed32_from_file(path: &str, pass: &str) -> io::Result<[u8; 32]> {
    let s = fs::read_to_string(path)?;
    let k: KeystoreFile = serde_json::from_str(&s)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keystore parse: {e}")))?;
    if k.v != V {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("unsupported keystore version {}", k.v)));
    }

    let salt = base64::engine::general_purpose::STANDARD
        .decode(k.salt)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad salt"))?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(k.nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad nonce"))?;
    let ct = base64::engine::general_purpose::STANDARD
        .decode(k.ct)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "bad ct"))?;

    if nonce_bytes.len() != 12 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "nonce len"));
    }

    let mut key = derive_key(pass, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("aes key: {e}")))?;

    let pt = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ct.as_ref())
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "wrong password or corrupted keystore"))?;

    key.zeroize();

    if pt.len() != 32 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "seed len"));
    }
    let mut seed32 = [0u8; 32];
    seed32.copy_from_slice(&pt);
    Ok(seed32)
}

pub fn keystore_exists(path: &str) -> bool {
    Path::new(path).exists()
}
