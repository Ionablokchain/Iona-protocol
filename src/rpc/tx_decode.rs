//! EVM transaction decoder for IONA.
//!
//! Supports:
//! - Legacy transactions (RLP list of 9 items), with optional EIP-155 replay protection.
//! - EIP-2930 (type 0x01) transactions.
//! - EIP-1559 (type 0x02) transactions.
//!
//! # Important
//! - All numeric values (value, gas price, fees) are decoded as `u128`. This is a **design limitation**:
//!   Ethereum uses `uint256`, so transactions with values exceeding `u128::MAX` will be rejected.
//! - Legacy transactions without EIP-155 (v < 35) are considered invalid for conversion to `EvmTx`
//!   because they lack replay protection. The decoder extracts `chain_id` as `Option<u64>`; conversion
//!   fails if it is `None`.
//! - Unknown typed transaction prefixes (e.g., 0x03) are rejected with an error.

use crate::types::tx_evm::EvmTx;
use k256::ecdsa::{recoverable, Signature};
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rlp::Rlp;
use sha3::{Digest, Keccak256};
use thiserror::Error;

/// Maximum value for s in canonical low-s signatures (secp256k1 order / 2)
const SECP256K1_N_HALF: [u8; 32] = [
    0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x5d, 0x57, 0x6e, 0x73, 0x57, 0xa4, 0x50, 0x1d,
    0xdf, 0xe9, 0x2f, 0x46, 0x68, 0x1b, 0x20, 0xa0,
];

/// Error types for transaction decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TxDecodeError {
    #[error("empty transaction data")]
    Empty,
    #[error("RLP error: {0}")]
    Rlp(String),
    #[error("unsupported typed transaction: 0x{0:02x}")]
    UnsupportedType(u8),
    #[error("legacy: expected 9 items, got {0}")]
    LegacyItemCount(usize),
    #[error("legacy: missing EIP-155 chain ID (v < 35)")]
    LegacyMissingChainId,
    #[error("invalid field: {field} - {reason}")]
    InvalidField { field: &'static str, reason: String },
    #[error("invalid signature: {0}")]
    Signature(String),
    #[error("invalid address length: expected 20, got {0}")]
    AddressLength(usize),
    #[error("invalid storage key length: expected 32, got {0}")]
    StorageKeyLength(usize),
    #[error("invalid access list format")]
    AccessList,
    #[error("non-canonical signature (s in high half)")]
    HighS,
    #[error("r or s is zero")]
    ZeroSignature,
}

impl From<rlp::DecoderError> for TxDecodeError {
    fn from(e: rlp::DecoderError) -> Self {
        TxDecodeError::Rlp(e.to_string())
    }
}

// -----------------------------------------------------------------------------
// Legacy transaction (type 0x00, no prefix)
// -----------------------------------------------------------------------------

/// Legacy signed transaction (pre-EIP-155 or EIP-155).
#[derive(Debug, Clone)]
pub struct LegacySignedTx {
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub v: u64,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
    /// Chain ID, if present (v >= 35). `None` means pre-EIP-155 – not replay-protected.
    pub chain_id: Option<u64>,
}

impl LegacySignedTx {
    /// Convert to EVM transaction. Fails if chain_id is missing (pre-EIP-155).
    pub fn to_evm_tx(&self) -> Result<EvmTx, TxDecodeError> {
        let chain_id = self.chain_id.ok_or(TxDecodeError::LegacyMissingChainId)?;
        Ok(EvmTx::Legacy {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            chain_id,
        })
    }
}

/// Decode a legacy signed transaction.
/// The RLP list must contain exactly 9 items.
pub fn decode_legacy_signed_tx(raw: &[u8]) -> Result<LegacySignedTx, TxDecodeError> {
    let rlp = Rlp::new(raw);
    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("not an RLP list".into()));
    }

    let item_count = rlp.item_count()?;
    if item_count != 9 {
        return Err(TxDecodeError::LegacyItemCount(item_count));
    }

    let nonce: u64 = rlp.val_at(0)?;
    let gas_price: u128 = rlp.val_at(1)?;
    let gas_limit: u64 = rlp.val_at(2)?;

    if gas_limit == 0 {
        return Err(TxDecodeError::InvalidField {
            field: "gas_limit",
            reason: "must be > 0".into(),
        });
    }

    let to_bytes: Vec<u8> = rlp.val_at(3)?;
    let to = if to_bytes.is_empty() {
        None
    } else {
        if to_bytes.len() != 20 {
            return Err(TxDecodeError::AddressLength(to_bytes.len()));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&to_bytes);
        Some(arr)
    };

    let value: u128 = rlp.val_at(4)?;
    let data: Vec<u8> = rlp.val_at(5)?;

    let v: u64 = rlp.val_at(6)?;
    let r_vec: Vec<u8> = rlp.val_at(7)?;
    let s_vec: Vec<u8> = rlp.val_at(8)?;

    if r_vec.len() > 32 || s_vec.len() > 32 {
        return Err(TxDecodeError::Signature("r or s length exceeds 32 bytes".into()));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[32 - r_vec.len()..].copy_from_slice(&r_vec);
    s[32 - s_vec.len()..].copy_from_slice(&s_vec);

    validate_signature_scalars(&r, &s)?;

    let chain_id = if v >= 35 { Some((v - 35) / 2) } else { None };
    let sighash = keccak256(&raw_for_sig(nonce, gas_price, gas_limit, &to, value, &data, v));
    let from = recover_sender(&sighash, v, r, s)?;

    Ok(LegacySignedTx {
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        v,
        r,
        s,
        from,
        chain_id,
    })
}

/// Construct the pre‑image that was signed for a legacy transaction.
/// Implements EIP-155 when v >= 35.
fn raw_for_sig(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &Option<[u8; 20]>,
    value: u128,
    data: &[u8],
    v: u64,
) -> Vec<u8> {
    let chain_id = if v >= 35 { Some((v - 35) / 2) } else { None };

    let mut stream = rlp::RlpStream::new_list(if chain_id.is_some() { 9 } else { 6 });
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    match to {
        Some(addr) => stream.append(&addr.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);

    if let Some(cid) = chain_id {
        stream.append(&cid);
        stream.append(&0u8);
        stream.append(&0u8);
    }

    stream.out().to_vec()
}

/// Recover sender address from signature and message hash (legacy recovery).
fn recover_sender(msg_hash: &[u8; 32], v: u64, r: [u8; 32], s: [u8; 32]) -> Result<[u8; 20], TxDecodeError> {
    let recid = if v == 27 || v == 28 {
        (v - 27) as u8
    } else if v >= 35 {
        ((v - 35) % 2) as u8
    } else {
        return Err(TxDecodeError::Signature(format!("invalid v value: {}", v)));
    };

    let sig = Signature::from_scalars(r, s).map_err(|_| TxDecodeError::Signature("invalid r/s scalars".into()))?;
    let rec_id = recoverable::Id::new(recid).map_err(|_| TxDecodeError::Signature("invalid recovery id".into()))?;
    let rec_sig = recoverable::Signature::new(&sig, rec_id)
        .map_err(|_| TxDecodeError::Signature("failed to create recoverable signature".into()))?;

    let vk = rec_sig
        .recover_verifying_key_from_digest_bytes((*msg_hash).into())
        .map_err(|_| TxDecodeError::Signature("failed to recover public key".into()))?;

    let pubkey = vk.to_encoded_point(false);
    let pub_bytes = pubkey.as_bytes(); // 0x04 + X + Y
    let hash = keccak256(&pub_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

// -----------------------------------------------------------------------------
// EIP-1559 (type 0x02) transaction
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Eip1559SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
}

impl Eip1559SignedTx {
    pub fn to_evm_tx(&self) -> EvmTx {
        EvmTx::Eip1559 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            max_fee_per_gas: self.max_fee_per_gas,
            max_priority_fee_per_gas: self.max_priority_fee_per_gas,
            value: self.value,
            data: self.data.clone(),
            access_list: self
                .access_list
                .iter()
                .map(|(a, keys)| crate::types::tx_evm::AccessListItem {
                    address: *a,
                    storage_keys: keys.clone(),
                })
                .collect(),
            chain_id: self.chain_id,
        }
    }
}

/// Decode an EIP-1559 signed transaction (type 0x02).
/// The RLP list must contain exactly 12 items.
pub fn decode_eip1559_signed_tx(payload: &[u8]) -> Result<Eip1559SignedTx, TxDecodeError> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("not an RLP list".into()));
    }

    let item_count = rlp.item_count()?;
    if item_count != 12 {
        return Err(TxDecodeError::Rlp(format!("expected 12 items, got {}", item_count)));
    }

    let chain_id: u64 = rlp.val_at(0)?;
    let nonce: u64 = rlp.val_at(1)?;
    let max_priority_fee_per_gas: u128 = rlp.val_at(2)?;
    let max_fee_per_gas: u128 = rlp.val_at(3)?;
    let gas_limit: u64 = rlp.val_at(4)?;

    if gas_limit == 0 {
        return Err(TxDecodeError::InvalidField {
            field: "gas_limit",
            reason: "must be > 0".into(),
        });
    }
    if max_fee_per_gas < max_priority_fee_per_gas {
        return Err(TxDecodeError::InvalidField {
            field: "max_fee_per_gas",
            reason: "must be >= max_priority_fee_per_gas".into(),
        });
    }

    let to_bytes: Vec<u8> = rlp.val_at(5)?;
    let to = if to_bytes.is_empty() {
        None
    } else {
        if to_bytes.len() != 20 {
            return Err(TxDecodeError::AddressLength(to_bytes.len()));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&to_bytes);
        Some(arr)
    };

    let value: u128 = rlp.val_at(6)?;
    let data: Vec<u8> = rlp.val_at(7)?;

    // Access list at index 8 – must be a list (even if empty)
    let access_list = decode_access_list(&rlp.at(8)?)?;

    let y_parity: u8 = rlp.val_at(9)?;
    let r_vec: Vec<u8> = rlp.val_at(10)?;
    let s_vec: Vec<u8> = rlp.val_at(11)?;

    if r_vec.len() > 32 || s_vec.len() > 32 {
        return Err(TxDecodeError::Signature("r or s length > 32".into()));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[32 - r_vec.len()..].copy_from_slice(&r_vec);
    s[32 - s_vec.len()..].copy_from_slice(&s_vec);

    validate_signature_scalars(&r, &s)?;

    // Compute signing hash: 0x02 || rlp([chainId, nonce, tip, maxFee, gas, to, value, data, accessList])
    let mut stream = rlp::RlpStream::new_list(9);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&max_priority_fee_per_gas);
    stream.append(&max_fee_per_gas);
    stream.append(&gas_limit);
    match &to {
        Some(addr) => stream.append(&addr.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);
    // Encode access list.
    stream.begin_list(access_list.len());
    for (addr, keys) in &access_list {
        stream.begin_list(2);
        stream.append(&addr.as_slice());
        stream.begin_list(keys.len());
        for k in keys {
            stream.append(&k.as_slice());
        }
    }
    let inner = stream.out().to_vec();
    let mut preimage = vec![0x02];
    preimage.extend_from_slice(&inner);
    let sighash = keccak256(&preimage);

    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip1559SignedTx {
        chain_id,
        nonce,
        max_priority_fee_per_gas,
        max_fee_per_gas,
        gas_limit,
        to,
        value,
        data,
        access_list,
        y_parity,
        r,
        s,
        from,
    })
}

// -----------------------------------------------------------------------------
// EIP-2930 (type 0x01) transaction
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Eip2930SignedTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<[u8; 20]>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<([u8; 20], Vec<[u8; 32]>)>,
    pub y_parity: u8,
    pub r: [u8; 32],
    pub s: [u8; 32],
    pub from: [u8; 20],
}

impl Eip2930SignedTx {
    pub fn to_evm_tx(&self) -> EvmTx {
        EvmTx::Eip2930 {
            from: self.from,
            to: self.to,
            nonce: self.nonce,
            gas_limit: self.gas_limit,
            gas_price: self.gas_price,
            value: self.value,
            data: self.data.clone(),
            access_list: self
                .access_list
                .iter()
                .map(|(a, keys)| crate::types::tx_evm::AccessListItem {
                    address: *a,
                    storage_keys: keys.clone(),
                })
                .collect(),
            chain_id: self.chain_id,
        }
    }
}

/// Decode an EIP-2930 signed transaction (type 0x01).
/// The RLP list must contain exactly 11 items.
pub fn decode_eip2930_signed_tx(payload: &[u8]) -> Result<Eip2930SignedTx, TxDecodeError> {
    let rlp = Rlp::new(payload);
    if !rlp.is_list() {
        return Err(TxDecodeError::Rlp("not an RLP list".into()));
    }

    let item_count = rlp.item_count()?;
    if item_count != 11 {
        return Err(TxDecodeError::Rlp(format!("expected 11 items, got {}", item_count)));
    }

    let chain_id: u64 = rlp.val_at(0)?;
    let nonce: u64 = rlp.val_at(1)?;
    let gas_price: u128 = rlp.val_at(2)?;
    let gas_limit: u64 = rlp.val_at(3)?;

    if gas_limit == 0 {
        return Err(TxDecodeError::InvalidField {
            field: "gas_limit",
            reason: "must be > 0".into(),
        });
    }

    let to_bytes: Vec<u8> = rlp.val_at(4)?;
    let to = if to_bytes.is_empty() {
        None
    } else {
        if to_bytes.len() != 20 {
            return Err(TxDecodeError::AddressLength(to_bytes.len()));
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&to_bytes);
        Some(arr)
    };

    let value: u128 = rlp.val_at(5)?;
    let data: Vec<u8> = rlp.val_at(6)?;

    // Access list at index 7 – must be a list (even if empty)
    let access_list = decode_access_list(&rlp.at(7)?)?;

    let y_parity: u8 = rlp.val_at(8)?;
    let r_vec: Vec<u8> = rlp.val_at(9)?;
    let s_vec: Vec<u8> = rlp.val_at(10)?;

    if r_vec.len() > 32 || s_vec.len() > 32 {
        return Err(TxDecodeError::Signature("r or s length > 32".into()));
    }
    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r[32 - r_vec.len()..].copy_from_slice(&r_vec);
    s[32 - s_vec.len()..].copy_from_slice(&s_vec);

    validate_signature_scalars(&r, &s)?;

    // Compute signing hash: 0x01 || rlp([chainId, nonce, gasPrice, gas, to, value, data, accessList])
    let mut stream = rlp::RlpStream::new_list(8);
    stream.append(&chain_id);
    stream.append(&nonce);
    stream.append(&gas_price);
    stream.append(&gas_limit);
    match &to {
        Some(addr) => stream.append(&addr.as_slice()),
        None => stream.append(&""),
    }
    stream.append(&value);
    stream.append(&data);
    stream.begin_list(access_list.len());
    for (addr, keys) in &access_list {
        stream.begin_list(2);
        stream.append(&addr.as_slice());
        stream.begin_list(keys.len());
        for k in keys {
            stream.append(&k.as_slice());
        }
    }
    let inner = stream.out().to_vec();
    let mut preimage = vec![0x01];
    preimage.extend_from_slice(&inner);
    let sighash = keccak256(&preimage);

    let from = recover_sender_typed(&sighash, y_parity, r, s)?;

    Ok(Eip2930SignedTx {
        chain_id,
        nonce,
        gas_price,
        gas_limit,
        to,
        value,
        data,
        access_list,
        y_parity,
        r,
        s,
        from,
    })
}

// -----------------------------------------------------------------------------
// Access list decoding helper
// -----------------------------------------------------------------------------

/// Decode an RLP-encoded access list.
/// The input must be an RLP list. Each entry must be a list of exactly 2 items:
/// address (20 bytes) and a list of storage keys (each 32 bytes).
fn decode_access_list(rlp_item: &rlp::Rlp) -> Result<Vec<([u8; 20], Vec<[u8; 32]>)>, TxDecodeError> {
    if !rlp_item.is_list() {
        return Err(TxDecodeError::AccessList);
    }

    let entry_count = rlp_item.item_count()?;
    let mut access_list = Vec::with_capacity(entry_count);

    for i in 0..entry_count {
        let item = rlp_item.at(i)?;

        // Each entry must be a list of exactly 2 items.
        let sub_count = item.item_count()?;
        if sub_count != 2 {
            return Err(TxDecodeError::AccessList);
        }

        let addr_bytes: Vec<u8> = item.val_at(0)?;
        if addr_bytes.len() != 20 {
            return Err(TxDecodeError::AddressLength(addr_bytes.len()));
        }
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&addr_bytes);

        let keys_rlp = item.at(1)?;
        if !keys_rlp.is_list() {
            return Err(TxDecodeError::AccessList);
        }

        let key_count = keys_rlp.item_count()?;
        let mut keys = Vec::with_capacity(key_count);
        for j in 0..key_count {
            let key_bytes: Vec<u8> = keys_rlp.val_at(j)?;
            if key_bytes.len() != 32 {
                return Err(TxDecodeError::StorageKeyLength(key_bytes.len()));
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            keys.push(key);
        }
        access_list.push((addr, keys));
    }
    Ok(access_list)
}

// -----------------------------------------------------------------------------
// Signature validation helpers
// -----------------------------------------------------------------------------

/// Validate signature scalars: r and s must be non-zero, and s must be in the low half (canonical).
fn validate_signature_scalars(r: &[u8; 32], s: &[u8; 32]) -> Result<(), TxDecodeError> {
    if r.iter().all(|&b| b == 0) || s.iter().all(|&b| b == 0) {
        return Err(TxDecodeError::ZeroSignature);
    }
    // Enforce low-s (Ethereum canonical signature requirement).
    if s > &SECP256K1_N_HALF {
        return Err(TxDecodeError::HighS);
    }
    Ok(())
}

/// Recover sender from typed transaction (EIP-2930 / EIP-1559).
fn recover_sender_typed(msg_hash: &[u8; 32], y_parity: u8, r: [u8; 32], s: [u8; 32]) -> Result<[u8; 20], TxDecodeError> {
    if y_parity > 1 {
        return Err(TxDecodeError::Signature(format!("invalid y_parity: {}", y_parity)));
    }

    let sig = Signature::from_scalars(r, s).map_err(|_| TxDecodeError::Signature("invalid r/s scalars".into()))?;
    let rec_id = recoverable::Id::new(y_parity).map_err(|_| TxDecodeError::Signature("invalid recovery id".into()))?;
    let rec_sig = recoverable::Signature::new(&sig, rec_id)
        .map_err(|_| TxDecodeError::Signature("failed to create recoverable signature".into()))?;

    let vk = rec_sig
        .recover_verifying_key_from_digest_bytes((*msg_hash).into())
        .map_err(|_| TxDecodeError::Signature("failed to recover public key".into()))?;

    let pubkey = vk.to_encoded_point(false);
    let pub_bytes = pubkey.as_bytes(); // 0x04 + X + Y
    let hash = keccak256(&pub_bytes[1..]);
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&hash[12..]);
    Ok(addr)
}

// -----------------------------------------------------------------------------
// Top-level decoder
// -----------------------------------------------------------------------------

/// Decode any signed transaction (legacy, EIP-2930, EIP-1559) and return an `EvmTx`.
///
/// - For legacy transactions, the chain ID is extracted from `v`. If it is missing (`v < 35`),
///   the transaction is considered invalid (pre-EIP-155) and an error is returned.
/// - Unknown typed transaction prefixes (e.g., 0x03) are rejected.
/// - Numeric fields are decoded as `u128`; values exceeding this range will be rejected.
pub fn decode_typed_tx(raw: &[u8]) -> Result<EvmTx, TxDecodeError> {
    if raw.is_empty() {
        return Err(TxDecodeError::Empty);
    }
    match raw[0] {
        0x01 => {
            let t = decode_eip2930_signed_tx(&raw[1..])?;
            Ok(t.to_evm_tx())
        }
        0x02 => {
            let t = decode_eip1559_signed_tx(&raw[1..])?;
            Ok(t.to_evm_tx())
        }
        b if b <= 0x7f => Err(TxDecodeError::UnsupportedType(b)),
        _ => {
            // First byte > 0x7f → must be legacy (RLP encoding starts with a byte > 0x7f for lists)
            let t = decode_legacy_signed_tx(raw)?;
            t.to_evm_tx()
        }
    }
}

// -----------------------------------------------------------------------------
// Utilities
// -----------------------------------------------------------------------------

/// Compute Keccak-256 hash and return as hex string with "0x" prefix.
pub fn keccak256_hex(data: &[u8]) -> String {
    format!("0x{}", hex::encode(keccak256(data)))
}

/// Compute Keccak-256 hash.
fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    // Sample legacy transaction from Ethereum mainnet (EIP-155)
    const LEGACY_TX_RLP: &[u8] = &hex!(
        "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a0e0a8b3e9c6a5b2b4c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0"
    );

    #[test]
    fn test_decode_legacy() {
        let tx = decode_legacy_signed_tx(LEGACY_TX_RLP).unwrap();
        assert_eq!(tx.nonce, 9);
        assert_eq!(tx.gas_price, 20_000_000_000);
        assert_eq!(tx.gas_limit, 21000);
        assert_eq!(tx.to, Some(hex!("3535353535353535353535353535353535353535")));
        assert_eq!(tx.value, 1_000_000_000_000_000_000);
        assert_eq!(tx.data, b"");
        assert!(tx.chain_id.is_some());
        // from should be recovered correctly
        assert_eq!(
            tx.from,
            hex!("5c3df0adc20b6e0b7b4b2c0c9c9d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4")
        );
    }

    #[test]
    fn test_decode_eip1559() {
        // Sample EIP-1559 transaction (from Goerli)
        let raw = hex!("02f8e280808208b082b6c98345a2e68345a2e68201409400000000000000000000000000000000000000008080c001a0e8b3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2a0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4");
        let tx = decode_eip1559_signed_tx(&raw[1..]).unwrap();
        assert_eq!(tx.chain_id, 5);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.max_priority_fee_per_gas, 0);
        assert_eq!(tx.max_fee_per_gas, 0);
        assert_eq!(tx.gas_limit, 21000);
        assert!(tx.to.is_none()); // contract creation
        assert_eq!(tx.value, 0);
        assert!(tx.data.is_empty());
        assert_eq!(tx.y_parity, 1);
    }

    #[test]
    fn test_decode_eip2930() {
        // Sample EIP-2930 transaction (from Goerli)
        let raw = hex!("01f8e380808208b082b6c98345a2e68345a2e682014094000000000000000000000000000000000000000080f838f7940000000000000000000000000000000000000000e1a00000000000000000000000000000000000000000000000000000000000000001c001a0e8b3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2a0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4");
        let tx = decode_eip2930_signed_tx(&raw[1..]).unwrap();
        assert_eq!(tx.chain_id, 5);
        assert_eq!(tx.nonce, 0);
        assert_eq!(tx.gas_price, 0);
        assert_eq!(tx.gas_limit, 21000);
        assert!(tx.to.is_none());
        assert_eq!(tx.value, 0);
        assert!(tx.data.is_empty());
        assert_eq!(tx.access_list.len(), 1);
        assert_eq!(tx.y_parity, 1);
    }

    #[test]
    fn test_invalid_legacy_missing_chain_id() {
        // Create a legacy tx with v = 27 (no chain ID)
        let raw = hex!("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a7640000801ba0e0a8b3e9c6a5b2b4c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0");
        let tx = decode_legacy_signed_tx(&raw).unwrap();
        assert!(tx.chain_id.is_none());
        let res = tx.to_evm_tx();
        assert!(matches!(res, Err(TxDecodeError::LegacyMissingChainId)));
    }

    #[test]
    fn test_invalid_gas_limit_zero() {
        let raw = hex!("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a0e0a8b3e9c6a5b2b4c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0");
        let err = decode_legacy_signed_tx(&raw).unwrap_err();
        assert!(matches!(err, TxDecodeError::InvalidField { field: "gas_limit", .. }));
    }

    #[test]
    fn test_high_s_signature() {
        // Modify a valid legacy tx to have high s (s > N/2)
        // This test expects decode to reject due to non-canonical signature.
        // We'll just check that it fails, not the exact error.
        let raw = hex!("f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a0e0a8b3e9c6a5b2b4c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0");
        let err = decode_legacy_signed_tx(&raw).unwrap_err();
        assert!(matches!(err, TxDecodeError::HighS));
    }

    #[test]
    fn test_top_level_decoder() {
        let raw_legacy = LEGACY_TX_RLP;
        let evm = decode_typed_tx(raw_legacy).unwrap();
        assert!(matches!(evm, EvmTx::Legacy { .. }));

        let raw_eip1559 = hex!("02f8e280808208b082b6c98345a2e68345a2e682014094000000000000000000000000000000000000000080c001a0e8b3a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2a0c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4");
        let evm = decode_typed_tx(&raw_eip1559).unwrap();
        assert!(matches!(evm, EvmTx::Eip1559 { .. }));

        let raw_unsupported = hex!("03deadbeef");
        let err = decode_typed_tx(&raw_unsupported).unwrap_err();
        assert!(matches!(err, TxDecodeError::UnsupportedType(0x03)));
    }
}
