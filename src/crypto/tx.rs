//! Transaction signing and address derivation.
//!
//! This module provides utilities for deriving Iona addresses from public keys
//! and for producing the canonical byte representation that is signed over a
//! transaction.
//!
//! # Example
//!
//! ```
//! use iona::types::Tx;
//! use iona::crypto::tx::{derive_address, tx_sign_bytes};
//!
//! let tx = Tx {
//!     pubkey: vec![1; 32],
//!     from: "alice".into(),
//!     nonce: 0,
//!     max_fee_per_gas: 100,
//!     max_priority_fee_per_gas: 10,
//!     gas_limit: 21_000,
//!     payload: "set key value".into(),
//!     signature: vec![],
//!     chain_id: 1,
//! };
//! let address = derive_address(&tx.pubkey);
//! let sign_bytes = tx_sign_bytes(&tx);
//! ```

use crate::types::Tx;
use tracing::debug;

/// Derive an Iona address (20‑byte hex string) from a public key.
///
/// The address is computed as the first 20 bytes of the Blake3 hash of the public key.
/// This produces a human‑readable hex string (40 characters) suitable for use as
/// an account identifier.
///
/// # Arguments
/// * `pubkey` – The public key bytes (e.g., 32 bytes for Ed25519).
///
/// # Returns
/// A 40‑character hex string (without `0x` prefix).
///
/// # Example
/// ```
/// let pubkey = vec![0xAA; 32];
/// let addr = derive_address(&pubkey);
/// assert_eq!(addr.len(), 40);
/// ```
#[must_use]
pub fn derive_address(pubkey: &[u8]) -> String {
    let hash = blake3::hash(pubkey);
    let addr = hex::encode(&hash.as_bytes()[..20]);
    debug!(addr_len = addr.len(), "derived address from public key");
    addr
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
/// If serialisation fails (unlikely under normal operation), returns an empty vector.
///
/// # Example
/// ```
/// let tx = Tx { /* ... */ };
/// let bytes = tx_sign_bytes(&tx);
/// assert!(!bytes.is_empty());
/// ```
#[must_use]
pub fn tx_sign_bytes(tx: &Tx) -> Vec<u8> {
    let payload = serde_json::to_vec(&(
        "iona-tx-v1",
        tx.chain_id,
        &tx.pubkey,
        tx.nonce,
        tx.max_fee_per_gas,
        tx.max_priority_fee_per_gas,
        tx.gas_limit,
        &tx.payload,
    ));
    match payload {
        Ok(bytes) => {
            debug!(len = bytes.len(), "computed transaction signing bytes");
            bytes
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to serialize tx signing bytes");
            Vec::new()
        }
    }
}

/// Sign a transaction using an Ed25519 signer.
///
/// # Arguments
/// * `tx` – The transaction to sign (will be modified in place).
/// * `signer` – The Ed25519 signer.
///
/// # Example
/// ```
/// use iona::crypto::ed25519::Ed25519Keypair;
/// use iona::crypto::tx::sign_tx;
///
/// let signer = Ed25519Keypair::generate();
/// let mut tx = Tx::default();
/// sign_tx(&mut tx, &signer);
/// assert!(!tx.signature.is_empty());
/// ```
pub fn sign_tx(tx: &mut Tx, signer: &crate::crypto::ed25519::Ed25519Keypair) {
    let msg = tx_sign_bytes(tx);
    let sig = signer.sign(&msg);
    tx.signature = sig.0;
    tx.from = derive_address(&tx.pubkey);
    debug!("transaction signed");
}

/// Verify a transaction's signature.
///
/// # Arguments
/// * `tx` – The transaction to verify.
///
/// # Returns
/// `Ok(())` if the signature is valid, otherwise a `CryptoError`.
pub fn verify_tx_signature(tx: &Tx) -> Result<(), crate::crypto::CryptoError> {
    use crate::crypto::ed25519::Ed25519Verifier;
    use crate::crypto::{PublicKeyBytes, SignatureBytes, Verifier};

    let msg = tx_sign_bytes(tx);
    let pk = PublicKeyBytes(tx.pubkey.clone());
    let sig = SignatureBytes(tx.signature.clone());
    Ed25519Verifier::verify(&pk, &msg, &sig)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
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
        let addr = derive_address(&pubkey);
        assert_eq!(addr.len(), 40);
        // Deterministic
        let addr2 = derive_address(&pubkey);
        assert_eq!(addr, addr2);
    }

    #[test]
    fn test_tx_sign_bytes_deterministic() {
        let tx = dummy_tx();
        let bytes1 = tx_sign_bytes(&tx);
        let bytes2 = tx_sign_bytes(&tx);
        assert_eq!(bytes1, bytes2);
        assert!(!bytes1.is_empty());
    }

    #[test]
    fn test_sign_and_verify() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer);
        assert!(verify_tx_signature(&tx).is_ok());
    }

    #[test]
    fn test_verify_corrupted_signature() {
        let mut tx = dummy_tx();
        let signer = Ed25519Keypair::generate();
        sign_tx(&mut tx, &signer);
        // Corrupt the signature
        if let Some(byte) = tx.signature.get_mut(0) {
            *byte ^= 1;
        }
        assert!(verify_tx_signature(&tx).is_err());
    }
}
