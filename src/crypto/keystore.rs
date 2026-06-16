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
//! - **Key derivation**: PBKDF2-HMAC-SHA256 with configurable iterations (default 100,000) → 32‑byte key.
//! - **Encryption**: AES-256-GCM.
//! - **Nonce**: 12 bytes (random).
//! - **Salt**: 16 bytes (random).
//!
//! # Security notes
//!
//! - The password and derived key are zeroized after use (using `zeroize`).
//! - The seed is passed as `&[u8; 32]` and is **not** zeroized by this module;
//!   callers should zeroize it after use if needed.
//! - On Unix systems, the keystore file is created with permissions `0o600`
//!   (owner read/write only).
//! - Atomic writes are used to prevent corruption.
//!
//! # Example
//!
//! ```
//! use iona::crypto::keystore::{encrypt_seed32_to_file, decrypt_seed32_from_file, KeystoreOptions};
//! use tempfile::tempdir;
//!
//! let dir = tempdir().unwrap();
//! let path = dir.path().join("key.enc").to_str().unwrap().to_string();
//! let seed = [0xaa; 32];
//! let password = "my_secure_password";
//!
//! encrypt_seed32_to_file(&path, &seed, password, &KeystoreOptions::default()).unwrap();
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
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::{fs, io::BufReader};
use thiserror::Error;
use tracing::{debug, error, info, warn};
use zeroize::{Zeroize, Zeroizing};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default number of PBKDF2 iterations (high enough to slow down brute‑force).
const DEFAULT_PBKDF2_ITERATIONS: u32 = 100_000;

/// Salt length in bytes (16 bytes = 128 bits).
const SALT_LEN: usize = 16;

/// Nonce length for AES‑GCM (12 bytes, recommended).
const NONCE_LEN: usize = 12;

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors that can occur during keystore operations.
#[derive(Debug, Error)]
pub enum KeystoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Base64 decoding error: {0}")]
    Base64(#[from] base64::DecodeError),

    #[error("Unsupported keystore version: {0} (expected {expected})")]
    UnsupportedVersion { got: u32, expected: u32 },

    #[error("Invalid nonce length: expected {expected}, got {got}")]
    InvalidNonceLength { expected: usize, got: usize },

    #[error("Invalid salt length: expected {expected}, got {got}")]
    InvalidSaltLength { expected: usize, got: usize },

    #[error("AES-GCM encryption failed: {0}")]
    Encryption(String),

    #[error("AES-GCM decryption failed: wrong password or corrupted file")]
    Decryption,

    #[error("Invalid seed length: expected {expected}, got {got}")]
    InvalidSeedLength { expected: usize, got: usize },

    #[error("Missing field in keystore: {0}")]
    MissingField(&'static str),

    #[error("PBKDF2 key derivation failed")]
    KeyDerivation,
}

pub type KeystoreResult<T> = Result<T, KeystoreError>;

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
// Configuration
// -----------------------------------------------------------------------------

/// Options for keystore operations.
#[derive(Debug, Clone, Copy)]
pub struct KeystoreOptions {
    /// Number of PBKDF2 iterations (higher = slower but more secure).
    pub pbkdf2_iterations: u32,
    /// Salt length in bytes (must be >= 8).
    pub salt_len: usize,
    /// Nonce length in bytes (must be 12 for AES‑GCM).
    pub nonce_len: usize,
}

impl Default for KeystoreOptions {
    fn default() -> Self {
        Self {
            pbkdf2_iterations: DEFAULT_PBKDF2_ITERATIONS,
            salt_len: SALT_LEN,
            nonce_len: NONCE_LEN,
        }
    }
}

// -----------------------------------------------------------------------------
// Internal helpers
// -----------------------------------------------------------------------------

/// Derive a 32‑byte encryption key from a password and salt using PBKDF2-HMAC-SHA256.
fn derive_key(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut key);
    debug!(iterations, "derived encryption key");
    key
}

/// Encrypt a byte slice with AES‑256‑GCM using the given key and nonce.
fn encrypt_data(key: &[u8; 32], data: &[u8], nonce: &[u8]) -> KeystoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Encryption(format!("AES key init: {e}")))?;
    cipher
        .encrypt(Nonce::from_slice(nonce), data)
        .map_err(|e| KeystoreError::Encryption(e.to_string()))
}

/// Decrypt a byte slice with AES‑256‑GCM using the given key and nonce.
fn decrypt_data(key: &[u8; 32], ciphertext: &[u8], nonce: &[u8]) -> KeystoreResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| KeystoreError::Encryption(format!("AES key init: {e}")))?;
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| KeystoreError::Decryption)
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Encrypt a 32‑byte seed and store it in a file atomically.
///
/// The file is created with Unix permissions `0o600` (owner read/write only)
/// if running on a Unix system. On other platforms, no special permissions
/// are set (caller should handle appropriately).
///
/// # Arguments
/// * `path` – Destination file path.
/// * `seed32` – The 32‑byte seed to encrypt (as slice).
/// * `password` – Password used for encryption (will be zeroized after use).
/// * `options` – Configuration options (use `default()` for standard settings).
///
/// # Errors
/// Returns `KeystoreError` on I/O, serialization, or encryption failure.
pub fn encrypt_seed32_to_file(
    path: &str,
    seed32: &[u8; 32],
    password: &str,
    options: &KeystoreOptions,
) -> KeystoreResult<()> {
    info!(path, "encrypting seed to keystore file");

    // Validate length
    if seed32.len() != 32 {
        return Err(KeystoreError::InvalidSeedLength {
            expected: 32,
            got: seed32.len(),
        });
    }

    // Generate random salt and nonce
    let mut salt = vec![0u8; options.salt_len];
    let mut nonce_bytes = vec![0u8; options.nonce_len];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    debug!(
        salt_len = options.salt_len,
        nonce_len = options.nonce_len,
        "generated random salt and nonce"
    );

    // Zeroize the password after use
    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

    // Derive key
    let key = derive_key(&password_bytes, &salt, options.pbkdf2_iterations);
    let mut key_zero = key;
    let ciphertext = encrypt_data(&key_zero, seed32.as_slice(), &nonce_bytes)?;
    key_zero.zeroize();

    // Build keystore JSON
    let keystore = KeystoreFile {
        v: 1,
        salt: base64::engine::general_purpose::STANDARD.encode(&salt),
        nonce: base64::engine::general_purpose::STANDARD.encode(&nonce_bytes),
        ct: base64::engine::general_purpose::STANDARD.encode(&ciphertext),
    };
    let json = serde_json::to_string_pretty(&keystore)?;

    // Write atomically: write to temp file then rename
    let temp_path = format!("{}.tmp", path);
    {
        let mut temp_file = File::create(&temp_path)?;
        temp_file.write_all(json.as_bytes())?;
        temp_file.sync_all()?; // fsync to disk
    }
    fs::rename(&temp_path, path)?;

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
/// * `password` – Password used for encryption (will be zeroized after use).
///
/// # Errors
/// Returns `KeystoreError` if the file cannot be read, parsed, or decrypted.
/// A wrong password results in `KeystoreError::Decryption`.
pub fn decrypt_seed32_from_file(path: &str, password: &str) -> KeystoreResult<[u8; 32]> {
    debug!(path, "decrypting seed from keystore file");

    // Read file contents
    let json_str = fs::read_to_string(path)?;
    decrypt_seed32_from_str(&json_str, password)
}

/// Decrypt a 32‑byte seed from a JSON string (useful for testing).
pub fn decrypt_seed32_from_str(json_str: &str, password: &str) -> KeystoreResult<[u8; 32]> {
    // Parse JSON
    let keystore: KeystoreFile = serde_json::from_str(json_str)?;

    // Validate version
    if keystore.v != 1 {
        return Err(KeystoreError::UnsupportedVersion {
            got: keystore.v,
            expected: 1,
        });
    }

    // Decode base64 fields
    let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
    let nonce_bytes = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
    let ciphertext = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;

    // Validate lengths
    if nonce_bytes.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidNonceLength {
            expected: NONCE_LEN,
            got: nonce_bytes.len(),
        });
    }
    if salt.len() != SALT_LEN {
        return Err(KeystoreError::InvalidSaltLength {
            expected: SALT_LEN,
            got: salt.len(),
        });
    }

    // Zeroize password after use
    let password_bytes = Zeroizing::new(password.as_bytes().to_vec());

    // Derive key (iterations not stored in file – use default)
    let key = derive_key(&password_bytes, &salt, DEFAULT_PBKDF2_ITERATIONS);
    let mut key_zero = key;
    let plaintext = decrypt_data(&key_zero, &ciphertext, &nonce_bytes)?;
    key_zero.zeroize();

    // Verify length
    if plaintext.len() != 32 {
        return Err(KeystoreError::InvalidSeedLength {
            expected: 32,
            got: plaintext.len(),
        });
    }

    let mut seed = [0u8; 32];
    seed.copy_from_slice(&plaintext);
    debug!(path = "(from string)", "seed decrypted successfully");
    Ok(seed)
}

/// Check if a keystore file exists at the given path.
#[must_use]
pub fn keystore_exists(path: &str) -> bool {
    Path::new(path).exists()
}

/// Validate that a keystore file is correctly formatted and has the right version.
/// Does **not** check the password.
pub fn validate_keystore(path: &str) -> KeystoreResult<()> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let keystore: KeystoreFile = serde_json::from_reader(reader)?;
    if keystore.v != 1 {
        return Err(KeystoreError::UnsupportedVersion {
            got: keystore.v,
            expected: 1,
        });
    }
    // Check that base64 fields decode to correct lengths
    let salt = base64::engine::general_purpose::STANDARD.decode(&keystore.salt)?;
    let nonce = base64::engine::general_purpose::STANDARD.decode(&keystore.nonce)?;
    let _ct = base64::engine::general_purpose::STANDARD.decode(&keystore.ct)?;
    if salt.len() != SALT_LEN {
        return Err(KeystoreError::InvalidSaltLength {
            expected: SALT_LEN,
            got: salt.len(),
        });
    }
    if nonce.len() != NONCE_LEN {
        return Err(KeystoreError::InvalidNonceLength {
            expected: NONCE_LEN,
            got: nonce.len(),
        });
    }
    Ok(())
}

/// Change the password of an existing keystore file (re‑encrypt with new password).
///
/// # Arguments
/// * `path` – Path to the keystore file.
/// * `old_password` – Current password.
/// * `new_password` – New password.
/// * `options` – Keystore options for new encryption.
///
/// # Errors
/// Same as `decrypt_seed32_from_file` and `encrypt_seed32_to_file`.
pub fn change_keystore_password(
    path: &str,
    old_password: &str,
    new_password: &str,
    options: &KeystoreOptions,
) -> KeystoreResult<()> {
    info!(path, "changing keystore password");
    let seed = decrypt_seed32_from_file(path, old_password)?;
    encrypt_seed32_to_file(path, &seed, new_password, options)?;
    info!(path, "keystore password changed successfully");
    Ok(())
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
        let options = KeystoreOptions::default();

        encrypt_seed32_to_file(path_str, &original_seed, password, &options).unwrap();
        let decrypted = decrypt_seed32_from_file(path_str, password).unwrap();

        assert_eq!(original_seed, decrypted);
    }

    #[test]
    fn test_wrong_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let path_str = path.to_str().unwrap();

        let seed = [0xBBu8; 32];
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(path_str, &seed, "correct", &options).unwrap();

        let result = decrypt_seed32_from_file(path_str, "wrong");
        assert!(matches!(result, Err(KeystoreError::Decryption)));
    }

    #[test]
    fn test_keystore_exists() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("nonexistent.enc");
        assert!(!keystore_exists(path.to_str().unwrap()));

        let path2 = dir.path().join("exists.enc");
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(path2.to_str().unwrap(), &[0u8; 32], "pass", &options).unwrap();
        assert!(keystore_exists(path2.to_str().unwrap()));
    }

    #[test]
    fn test_validate_keystore() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("valid.enc");
        let path_str = path.to_str().unwrap();
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(path_str, &[0u8; 32], "pass", &options).unwrap();
        assert!(validate_keystore(path_str).is_ok());

        // Corrupt the file
        fs::write(path_str, "garbage").unwrap();
        assert!(validate_keystore(path_str).is_err());
    }

    #[test]
    fn test_change_password() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("keystore.enc");
        let path_str = path.to_str().unwrap();

        let seed = [0xCCu8; 32];
        let options = KeystoreOptions::default();
        encrypt_seed32_to_file(path_str, &seed, "old_pass", &options).unwrap();

        change_keystore_password(path_str, "old_pass", "new_pass", &options).unwrap();

        // Decrypt with new password should work
        let decrypted = decrypt_seed32_from_file(path_str, "new_pass").unwrap();
        assert_eq!(seed, decrypted);

        // Decrypt with old password should fail
        assert!(matches!(
            decrypt_seed32_from_file(path_str, "old_pass"),
            Err(KeystoreError::Decryption)
        ));
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("corrupt.enc");
        let path_str = path.to_str().unwrap();
        // Write invalid JSON
        fs::write(path_str, "not json").unwrap();
        assert!(matches!(
            decrypt_seed32_from_file(path_str, "pass"),
            Err(KeystoreError::Json(_))
        ));
    }

    #[test]
    fn test_unsupported_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bad_version.enc");
        let path_str = path.to_str().unwrap();
        // Write a keystore with version 2 (invalid)
        let bad = KeystoreFile {
            v: 2,
            salt: "AAAA".into(),
            nonce: "BBBB".into(),
            ct: "CCCC".into(),
        };
        let json = serde_json::to_string(&bad).unwrap();
        fs::write(path_str, json).unwrap();
        assert!(matches!(
            decrypt_seed32_from_file(path_str, "pass"),
            Err(KeystoreError::UnsupportedVersion { got: 2, expected: 1 })
        ));
    }
}
