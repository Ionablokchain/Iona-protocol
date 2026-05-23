//! Minimal encrypted keystore for validator/node keys.
//!
//! This module encrypts a 32‑byte seed (the root secret used to derive an Ed25519 keypair)
//! and stores it in a JSON file. The keystore file has the following format:
//!
//! ```json
//! {
//!   "v": 1,
//!   "salt": "base64...",
//!   "nonce": "base64...",
//!   "ct": "base64..."
//! }
//! ```
//!
//! # Algorithm
//!
//! - **Key derivation**: PBKDF2-HMAC-SHA256 with 100,000 iterations → 32‑byte key.
//! - **Encryption**: AES-256-GCM.
//! - **Nonce**: 12 bytes (random).
//! - **Salt**: 16 bytes (random).
//!
//! # Security notes
//!
//! - The password is not zeroised after use (it is passed as `&str` and cannot be
//!   safely overwritten). Callers should use zeroising types if possible.
//! - On Unix systems, the keystore file is created with permissions `0o600`
//!   (owner read/write only).
//!
//! # Example
//!
//! ```
//! use iona::crypto::keystore::{encrypt_seed32_to_file, decrypt_seed32_from_file};
//! use tempfile::tempdir;
//!
//! let dir = tempdir().unwrap();
//! let path = dir.path().join("key.enc").to_str().unwrap().to_string();
//! let seed = [0xaa; 32];
//! let password = "my_secure_password";
//!
//! encrypt_seed32_to_file(&path, seed, password).unwrap();
//! let decrypted = decrypt_seed32_from_file(&path, password).unwrap();
//! assert_eq!(seed, decrypted);
//! ```

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::Engine;
use pbkdf2::pbkdf2_hmac;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
use std::io;
use std::path::Path;
use tracing::{debug, error, info, warn};
use zeroize::Zeroize;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Keystore file format version (incremented on breaking changes).
const KEYSTORE_VERSION: u32 = 1;

/// Number of PBKDF2 iterations (high enough to slow down brute‑force).
const PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length in bytes (16 bytes = 128 bits).
const SALT_LEN: usize = 16;

/// Nonce length for AES‑GCM (12 bytes, recommended).
const NONCE_LEN: usize = 12;

// -----------------------------------------------------------------------------
// File format
// -----------------------------------------------------------------------------

/// Structure of the on‑disk keystore JSON file.
#[derive(Debug, Serialize, Deserialize)]
struct KeystoreFile {
    /// Format version.
    v: u32,
    /// Base64‑encoded salt (16 bytes).
    salt: String,
    /// Base64‑encoded nonce (12 bytes).
    nonce: String,
    /// Base64‑encoded ciphertext (seed encrypted).
    ct: String,
}

// -----------------------------------------------------------------------------
// Key derivation
// -----------------------------------------------------------------------------

/// Derive a 32‑byte encryption key from a password and salt using PBKDF2-HMAC-SHA256.
///
/// # Arguments
/// * `password` – The user password (should be strong).
/// * `salt` – A random 16‑byte salt.
///
/// # Returns
/// A 32‑byte key suitable for AES‑256.
#[must_use]
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), salt, PBKDF2_ITERATIONS, &mut key);
    debug!(
        iterations = PBKDF2_ITERATIONS,
        "derived encryption key from password"
    );
    key
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Encrypt a 32‑byte seed and store it in a file.
///
/// The file is created with Unix permissions `0o600` (owner read/write only)
/// if running on a Unix system. On other platforms, no special permissions
/// are set (caller should handle appropriately).
///
/// # Arguments
/// * `path` – Destination file path.
/// * `seed32` – The 32‑byte seed to encrypt.
/// * `password` – Password used for encryption (should be strong and not hardcoded).
///
/// # Errors
/// Returns an `io::Error` if the file cannot be written, or if encryption fails
/// (unlikely except for OOM or invalid key length).
pub fn encrypt_seed32_to_file(path: &str, seed32: [u8; 32], password: &str) -> io::Result<()> {
    info!(path, "encrypting seed to keystore file");

    // Generate random salt and nonce
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);
    debug!("generated random salt and nonce");

    // Derive key
    let mut key = derive_key(password, &salt);

    // Encrypt
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("AES key init: {e}")))?;
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), seed32.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("encryption failed: {e}")))?;
    debug!(ciphertext_len = ciphertext.len(), "seed encrypted");

    // Zero the key from memory as best effort
    key.zeroize();

    // Build keystore JSON
    let keystore = KeystoreFile {
        v: KEYSTORE_VERSION,
        salt: base64::engine::general_purpose::STANDARD.encode(salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(nonce_bytes),
        ct: base64::engine::general_purpose::STANDARD.encode(ciphertext),
    };
    let json = serde_json::to_string_pretty(&keystore)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("JSON encode: {e}")))?;

    // Write file
    fs::write(path, json)?;

    // Set restrictive permissions on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Err(e) = fs::set_permissions(path, fs::Permissions::from_mode(0o600)) {
            warn!(
                path,
                error = %e,
                "failed to set restrictive permissions on keystore file"
            );
        }
    }

    info!(path, "keystore file written successfully");
    Ok(())
}

/// Decrypt a 32‑byte seed from a keystore file.
///
/// # Arguments
/// * `path` – Path to the keystore file.
/// * `password` – Password used for encryption.
///
/// # Errors
/// Returns:
/// - `io::ErrorKind::InvalidData` if the file is malformed or the version is unsupported.
/// - `io::ErrorKind::PermissionDenied` if the password is incorrect or the ciphertext
///   cannot be decrypted (e.g., corrupted file).
/// - Other `io::Error` variants for file I/O problems.
pub fn decrypt_seed32_from_file(path: &str, password: &str) -> io::Result<[u8; 32]> {
    debug!(path, "decrypting seed from keystore file");

    // Read and parse JSON
    let json_str = fs::read_to_string(path)?;
    let keystore: KeystoreFile = serde_json::from_str(&json_str)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("JSON parse: {e}")))?;

    if keystore.v != KEYSTORE_VERSION {
        let err = format!("unsupported keystore version {}", keystore.v);
        error!("{}", err);
        return Err(io::Error::new(io::ErrorKind::InvalidData, err));
    }

    // Decode base64 fields
    let salt = base64::engine::general_purpose::STANDARD
        .decode(keystore.salt)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid salt encoding"))?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD
        .decode(keystore.nonce)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid nonce encoding"))?;
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(keystore.ct)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid ciphertext encoding"))?;

    // Validate nonce length
    if nonce_bytes.len() != NONCE_LEN {
        let err = format!("invalid nonce length: expected {}, got {}", NONCE_LEN, nonce_bytes.len());
        error!("{}", err);
        return Err(io::Error::new(io::ErrorKind::InvalidData, err));
    }

    // Derive key
    let mut key = derive_key(password, &salt);
    let cipher = Aes256Gcm::new_from_slice(&key)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, format!("AES key init: {e}")))?;

    // Decrypt
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_bytes), ciphertext.as_ref())
        .map_err(|_| {
            error!(path, "decryption failed: wrong password or corrupted keystore");
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "wrong password or corrupted keystore",
            )
        })?;

    // Zero the key
    key.zeroize();

    // Verify length
    if plaintext.len() != 32 {
        let err = format!("invalid seed length: expected 32, got {}", plaintext.len());
        error!("{}", err);
        return Err(io::Error::new(io::ErrorKind::InvalidData, err));
    }

    // Copy into fixed-size array
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    debug!(path, "seed decrypted successfully");
    Ok(seed)
}

/// Check if a keystore file exists at the given path.
#[must_use]
pub fn keystore_exists(path: &str) -> bool {
    Path::new(path).exists()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let path_str = path.to_str().unwrap();

        let original_seed = [0xAAu8; 32];
        let password = "test_password_123";

        encrypt_seed32_to_file(path_str, original_seed, password).unwrap();
        let decrypted = decrypt_seed32_from_file(path_str, password).unwrap();

        assert_eq!(original_seed, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let path_str = path.to_str().unwrap();

        let seed = [0xBBu8; 32];
        encrypt_seed32_to_file(path_str, seed, "correct").unwrap();

        let result = decrypt_seed32_from_file(path_str, "wrong");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn test_keystore_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        assert!(!keystore_exists(path.to_str().unwrap()));

        let path2 = dir.path().join("exists.enc");
        encrypt_seed32_to_file(path2.to_str().unwrap(), [0u8; 32], "pass").unwrap();
        assert!(keystore_exists(path2.to_str().unwrap()));
    }
}
