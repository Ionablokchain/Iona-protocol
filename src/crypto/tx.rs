//! Transaction signing and address derivation.
//!
//! This module provides utilities for deriving Iona addresses from public keys
//! and for producing the canonical byte representation that is signed over a
//! transaction.
//!
//! # Address derivation
//!
//! Iona addresses are derived as the first 20 bytes of the Blake3 hash of the
//! public key, encoded as a 40‑character hex string (without `0x` prefix).
//!
//! # Signing payload
//!
//! The canonical signing payload is a deterministic JSON array:
//! `["iona-tx-v1", chain_id, pubkey, nonce, max_fee_per_gas,
//!   max_priority_fee_per_gas, gas_limit, payload]`
//!
//! This format is stable across serialisation library versions and does not
//! include the signature itself.
//!
//! # Examples
//!
//! ```
//! use iona::types::Tx;
//! use iona::crypto::tx::{derive_address, tx_sign_bytes, sign_tx, verify_tx_signature};
//! use iona::crypto::ed25519::Ed25519Keypair;
//!
//! let signer = Ed25519Keypair::generate();
//! let mut tx = Tx {
//!     pubkey: signer.public_key().0,
//!     from: String::new(),
//!     nonce: 0,
//!     max_fee_per_gas: 100,
//!     max_priority_fee_per_gas: 10,
//!     gas_limit: 21_000,
//!     payload: "set key value".into(),
//!     signature: vec![],
//!     chain_id: 1,
//! };
//! sign_tx(&mut tx, &signer).unwrap();
//! assert!(verify_tx_signature(&tx).is_ok());
//! ```

use crate::crypto::{CryptoError, PublicKeyBytes, SignatureBytes};
use crate::types::Tx;
use serde::Serialize;
use thiserror::Error;
use tracing::{debug, error, trace};

// -----------------------------------------------------------------------------
// Error type
// -----------------------------------------------------------------------------

/// Errors that can occur during transaction signing or verification.
#[derive(Debug, Error)]
pub enum TxSignError {
    #[error("cryptographic error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("empty signing payload")]
    EmptyPayload,

    #[error("invalid chain ID: {0}")]
    InvalidChainId(u64),
}

pub type TxSignResult<T> = Result<T, TxSignError>;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Transaction signing version string.
const TX_SIGN_VERSION: &str = "iona-tx-v1";

/// Expected public key length (32 bytes for Ed25519).
const PUBLIC_KEY_LEN: usize = 32;

/// Expected signature length (64 bytes for Ed25519).
const SIGNATURE_LEN: usize = 64;

// -----------------------------------------------------------------------------
// Signing payload
// -----------------------------------------------------------------------------

/// Canonical signing payload for a transaction.
///
/// This struct represents the data that is actually signed.
/// It is serialised as a JSON array to ensure deterministic encoding.
#[derive(Debug, Serialize)]
struct TxSigningPayload<'a> {
    version: &'static str,
    chain_id: u64,
    pubkey: &'a [u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &'a str,
}

impl<'a> TxSigningPayload<'a> {
    fn from_tx(tx: &'a Tx) -> Self {
        Self {
            version: TX_SIGN_VERSION,
            chain_id: tx.chain_id,
            pubkey: &tx.pubkey,
            nonce: tx.nonce,
            max_fee_per_gas: tx.max_fee_per_gas,
            max_priority_fee_per_gas: tx.max_priority_fee_per_gas,
            gas_limit: tx.gas_limit,
            payload: &tx.payload,
        }
    }

    /// Serialize to a JSON array (canonical form).
    fn to_bytes(&self) -> TxSignResult<Vec<u8>> {
        // Serialize as a tuple/array to maintain field order.
        // This is the critical part: we use a tuple to preserve order.
        let value = serde_json::to_vec(&(
            self.version,
            self.chain_id,
            self.pubkey,
            self.nonce,
            self.max_fee_per_gas,
            self.max_priority_fee_per_gas,
            self.gas_limit,
            self.payload,
        ))?;
        Ok(value)
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Derive an Iona address (20‑byte hex string) from a public key.
///
/// The address is computed as the first 20 bytes of the Blake3 hash of the
/// public key. This produces a human‑readable hex string (40 characters)
/// suitable for use as an account identifier.
///
/// # Arguments
/// * `pubkey` – The public key bytes (must be exactly 32 bytes for Ed25519).
///
/// # Returns
/// A 40‑character hex string (without `0x` prefix).
///
/// # Errors
/// Returns `TxSignError::InvalidPublicKey` if the public key length is not 32 bytes.
///
/// # Example
/// ```
/// let pubkey = vec![0xAA; 32];
/// let addr = derive_address(&pubkey).unwrap();
/// assert_eq!(addr.len(), 40);
/// ```
pub fn derive_address(pubkey: &[u8]) -> TxSignResult<String> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LEN,
            pubkey.len()
        )));
    }
    let hash = blake3::hash(pubkey);
    let addr = hex::encode(&hash.as_bytes()[..20]);
    debug!(addr_len = addr.len(), "derived address from public key");
    Ok(addr)
}

/// Derive an Iona address from a `PublicKeyBytes` wrapper.
pub fn derive_address_from_pk(pk: &PublicKeyBytes) -> TxSignResult<String> {
    derive_address(&pk.0)
}

/// Compute the bytes that are signed for a transaction.
///
/// The signing payload is a deterministic JSON array containing:
/// `["iona-tx-v1", chain_id, pubkey, nonce, max_fee_per_gas,
///   max_priority_fee_per_gas, gas_limit, payload]`
///
/// The order of fields must match what the signer expects. This format is stable
/// across serialisation library versions and does not include the signature itself.
///
/// # Arguments
/// * `tx` – The transaction to sign (signature field is ignored).
///
/// # Returns
/// A byte vector representing the canonical signing payload.
///
/// # Errors
/// Returns `TxSignError::Serialization` if serialisation fails (unlikely under normal operation).
///
/// # Example
/// ```
/// let tx = Tx { /* ... */ };
/// let bytes = tx_sign_bytes(&tx).unwrap();
/// assert!(!bytes.is_empty());
/// ```
pub fn tx_sign_bytes(tx: &Tx) -> TxSignResult<Vec<u8>> {
    let payload = TxSigningPayload::from_tx(tx);
    let bytes = payload.to_bytes()?;
    trace!(len = bytes.len(), "computed transaction signing bytes");
    Ok(bytes)
}

/// Compute signing bytes from individual transaction fields.
pub fn tx_sign_bytes_from_parts(
    chain_id: u64,
    pubkey: &[u8],
    nonce: u64,
    max_fee_per_gas: u64,
    max_priority_fee_per_gas: u64,
    gas_limit: u64,
    payload: &str,
) -> TxSignResult<Vec<u8>> {
    let payload_struct = TxSigningPayload {
        version: TX_SIGN_VERSION,
        chain_id,
        pubkey,
        nonce,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        gas_limit,
        payload,
    };
    payload_struct.to_bytes()
}

/// Sign a transaction using an Ed25519 signer.
///
/// This function computes the signing payload, signs it with the provided
/// Ed25519 keypair, and updates the transaction's `signature` and `from` fields.
///
/// # Arguments
/// * `tx` – The transaction to sign (will be modified in place).
/// * `signer` – The Ed25519 signer (must implement `crate::crypto::Signer`).
///
/// # Returns
/// `Ok(())` on success, or a `TxSignError` if signing fails.
///
/// # Example
/// ```
/// use iona::crypto::ed25519::Ed25519Keypair;
/// use iona::crypto::tx::sign_tx;
///
/// let signer = Ed25519Keypair::generate();
/// let mut tx = Tx::default();
/// sign_tx(&mut tx, &signer).unwrap();
/// assert!(!tx.signature.is_empty());
/// ```
pub fn sign_tx(tx: &mut Tx, signer: &dyn crate::crypto::Signer) -> TxSignResult<()> {
    let msg = tx_sign_bytes(tx)?;
    let sig = signer.sign(&msg);

    if sig.0.is_empty() {
        return Err(TxSignError::InvalidSignature("empty signature".into()));
    }
    if sig.0.len() != SIGNATURE_LEN {
        return Err(TxSignError::InvalidSignature(format!(
            "expected {} bytes, got {}",
            SIGNATURE_LEN,
            sig.0.len()
        )));
    }

    tx.signature = sig.0;
    tx.from = derive_address(&tx.pubkey)?;
    debug!("transaction signed successfully");
    Ok(())
}

/// Verify a transaction's signature.
///
/// Re‑computes the signing payload and checks the signature against the
/// transaction's public key.
///
/// # Arguments
/// * `tx` – The transaction to verify.
///
/// # Returns
/// `Ok(())` if the signature is valid, otherwise a `TxSignError`.
pub fn verify_tx_signature(tx: &Tx) -> TxSignResult<()> {
    if tx.signature.is_empty() {
        return Err(TxSignError::InvalidSignature("empty signature".into()));
    }
    if tx.signature.len() != SIGNATURE_LEN {
        return Err(TxSignError::InvalidSignature(format!(
            "expected {} bytes, got {}",
            SIGNATURE_LEN,
            tx.signature.len()
        )));
    }
    if tx.pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LEN,
            tx.pubkey.len()
        )));
    }

    let msg = tx_sign_bytes(tx)?;
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());

    crate::crypto::ed25519::Ed25519Verifier::verify(&pk, &msg, &sig)?;
    trace!("transaction signature verified");
    Ok(())
}

/// Verify a signature using individual components.
pub fn verify_signature(
    pubkey: &[u8],
    msg: &[u8],
    signature: &[u8],
) -> TxSignResult<()> {
    if pubkey.len() != PUBLIC_KEY_LEN {
        return Err(TxSignError::InvalidPublicKey(format!(
            "expected {} bytes, got {}",
            PUBLIC_KEY_LEN,
            pubkey.len()
        )));
    }
    if signature.len() != SIGNATURE_LEN {
        return Err(TxSignError::InvalidSignature(format!(
            "expected {} bytes, got {}",
            SIGNATURE_LEN,
            signature.len()
        )));
    }

    let pk = PublicKeyBytes(pubkey.to_vec());
    let sig = SignatureBytes(signature.to_vec());

    crate::crypto::ed25519::Ed25519Verifier::verify(&pk, msg, &sig)?;
    Ok(())
}

/// Validate that a transaction is well‑formed and has a valid signature.
pub fn validate_tx(tx: &Tx) -> TxSignResult<()> {
    if tx.chain_id == 0 {
        return Err(TxSignError::InvalidChainId(tx.chain_id));
    }
    if tx.pubkey.is_empty() {
        return Err(TxSignError::InvalidPublicKey("empty public key".into()));
    }
    if tx.gas_limit == 0 {
        return Err(TxSignError::InvalidPublicKey("gas limit must be > 0".into()));
    }
    verify_tx_signature(tx)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;
    use crate::types::Tx;

    fn dummy_tx() -> Tx {
        Tx {
            pubkey: vec![0x01; 32],
            from: "".into(),
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21_000,
            payload: "set key value".into(),
            signature: vec![],
            chain_id: 1,
        }
    }

    #[test]
    fn test_derive_address() {
        let pubkey = vec![0xAA; 32];
        let addr = derive_address(&pubkey).unwrap();
        assert_eq!(addr.len(), 40);
        // Deterministic
        let addr2 = derive_address(&pubkey).unwrap();
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_derive_address_invalid_length() {
        let pubkey = vec![0xAA; 31];
        let result = derive_address(&pubkey);
        assert!(matches!(result, Err(TxSignError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_tx_sign_bytes_deterministic() {
        let tx = dummy_tx();
        let bytes1 = tx_sign_bytes(&tx).unwrap();
        let bytes2 = tx_sign_bytes(&tx).unwrap();
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer).unwrap();
        assert!(verify_tx_signature(&tx).is_ok());
        assert_eq!(tx.from, derive_address(&tx.pubkey).unwrap());
    }

    #[test]
    fn test_verify_corrupted_signature() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer).unwrap();
        // Corrupt the signature
        if let Some(byte) = tx.signature.get_mut(0) {
            *byte ^= 1;
        }
        let result = verify_tx_signature(&tx);
        assert!(matches!(result, Err(TxSignError::Crypto(CryptoError::InvalidSignature))));
    }

    #[test]
    fn test_verify_wrong_public_key() {
        let mut tx = dummy_tx();
        let signer1 = Ed25519Keypair::generate();
        let signer2 = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer1).unwrap();
        // Replace with wrong public key
        tx.pubkey = signer2.public_key().0;
        let result = verify_tx_signature(&tx);
        assert!(matches!(result, Err(TxSignError::Crypto(CryptoError::InvalidSignature))));
    }

    #[test]
    fn test_validate_tx() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer).unwrap();
        assert!(validate_tx(&tx).is_ok());

        // Invalid chain ID
        tx.chain_id = 0;
        let result = validate_tx(&tx);
        assert!(matches!(result, Err(TxSignError::InvalidChainId(0))));

        // Empty public key
        let mut tx2 = dummy_tx();
        tx2.pubkey = vec![];
        let result = validate_tx(&tx2);
        assert!(matches!(result, Err(TxSignError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_sign_bytes_from_parts() {
        let pk = vec![0x01; 32];
        let bytes1 = tx_sign_bytes_from_parts(1, &pk, 0, 100, 10, 21000, "payload").unwrap();
        let tx = Tx {
            chain_id: 1,
            pubkey: pk,
            nonce: 0,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21000,
            payload: "payload".into(),
            ..Default::default()
        };
        let bytes2 = tx_sign_bytes(&tx).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_verify_signature_parts() {
        let signer = Ed25519Keypair::generate();
        let msg = b"test message";
        let sig = signer.sign(msg);
        assert!(verify_signature(&signer.public_key().0, msg, &sig.0).is_ok());

        // Wrong message
        let result = verify_signature(&signer.public_key().0, b"wrong", &sig.0);
        assert!(matches!(result, Err(TxSignError::Crypto(CryptoError::InvalidSignature))));
    }
}
