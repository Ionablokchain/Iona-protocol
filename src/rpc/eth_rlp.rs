//! RLP (Recursive Length Prefix) encoding utilities for Ethereum-compatible receipts and logs.
//!
//! This module provides functions to encode logs and receipts into RLP format
//! as used by Ethereum clients (e.g., for JSON‑RPC responses and block headers).
//! Supports both legacy receipts and typed (EIP‑2718) receipts.

use crate::rpc::eth_rpc::{Log, Receipt};
use rlp::RlpStream;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Bloom filter size in bytes (Ethereum logsBloom).
pub const BLOOM_BYTES_LEN: usize = 256;

/// Maximum number of topics in a log.
pub const MAX_TOPICS: usize = 4;

/// Valid topic length in bytes (each topic is 32 bytes).
pub const TOPIC_BYTES_LEN: usize = 32;

/// Valid address length in bytes (20 bytes).
pub const ADDRESS_BYTES_LEN: usize = 20;

/// EIP‑2718 transaction type for EIP‑1559 transactions.
pub const TX_TYPE_EIP1559: u8 = 0x02;

/// EIP‑2718 transaction type for legacy transactions (no prefix).
pub const TX_TYPE_LEGACY: u8 = 0x00;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during RLP encoding.
#[derive(Debug, Error)]
pub enum RlpError {
    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid address length: expected {expected}, got {actual}")]
    InvalidAddressLength { expected: usize, actual: usize },

    #[error("invalid topic length: expected {expected}, got {actual}")]
    InvalidTopicLength { expected: usize, actual: usize },

    #[error("too many topics: max {max}, got {actual}")]
    TooManyTopics { max: usize, actual: usize },

    #[error("invalid logsBloom length: expected {expected}, got {actual}")]
    InvalidBloomLength { expected: usize, actual: usize },

    #[error("unsupported transaction type: 0x{type_byte:02X}")]
    UnsupportedTxType { type_byte: u8 },
}

pub type RlpResult<T> = Result<T, RlpError>;

// -----------------------------------------------------------------------------
// Hex decoding helper
// -----------------------------------------------------------------------------

/// Convert a hex string (with or without 0x prefix) to bytes.
/// Returns an error if the hex string is malformed.
fn decode_hex(hex_str: &str) -> RlpResult<Vec<u8>> {
    let stripped = hex_str.trim_start_matches("0x");
    Ok(hex::decode(stripped)?)
}

// -----------------------------------------------------------------------------
// Log RLP encoding
// -----------------------------------------------------------------------------

/// Encode a log entry into RLP bytes.
///
/// The format is: `[address, topics, data]` where:
/// - `address` is 20 bytes
/// - `topics` is a list of up to 4 32‑byte values
/// - `data` is arbitrary byte array
///
/// # Errors
/// - If the address hex string is invalid or length != 20
/// - If any topic hex string is invalid or length != 32
/// - If there are more than 4 topics
pub fn rlp_encode_log(log: &Log) -> RlpResult<Vec<u8>> {
    let address_bytes = decode_hex(&log.address)?;
    if address_bytes.len() != ADDRESS_BYTES_LEN {
        return Err(RlpError::InvalidAddressLength {
            expected: ADDRESS_BYTES_LEN,
            actual: address_bytes.len(),
        });
    }

    if log.topics.len() > MAX_TOPICS {
        return Err(RlpError::TooManyTopics {
            max: MAX_TOPICS,
            actual: log.topics.len(),
        });
    }

    let mut s = RlpStream::new_list(3);
    s.append(&address_bytes);

    // topics list
    s.begin_list(log.topics.len());
    for topic_hex in &log.topics {
        let topic_bytes = decode_hex(topic_hex)?;
        if topic_bytes.len() != TOPIC_BYTES_LEN {
            return Err(RlpError::InvalidTopicLength {
                expected: TOPIC_BYTES_LEN,
                actual: topic_bytes.len(),
            });
        }
        s.append(&topic_bytes);
    }

    let data_bytes = decode_hex(&log.data)?;
    s.append(&data_bytes);

    Ok(s.out().to_vec())
}

// -----------------------------------------------------------------------------
// Receipt RLP encoding (legacy)
// -----------------------------------------------------------------------------

/// Encode a receipt into RLP bytes using the post‑Byzantium format.
///
/// The format is: `[status, cumulativeGasUsed, logsBloom, logs]`
/// - `status`: 0 (failure) or 1 (success)
/// - `cumulativeGasUsed`: total gas used up to this transaction
/// - `logsBloom`: 256‑byte bloom filter
/// - `logs`: list of encoded logs (using `rlp_encode_log`)
///
/// # Errors
/// - If logsBloom has invalid hex or length != 256
/// - If any log fails to encode
pub fn rlp_encode_receipt(receipt: &Receipt) -> RlpResult<Vec<u8>> {
    let bloom_bytes = decode_hex(&receipt.logs_bloom)?;
    if bloom_bytes.len() != BLOOM_BYTES_LEN {
        return Err(RlpError::InvalidBloomLength {
            expected: BLOOM_BYTES_LEN,
            actual: bloom_bytes.len(),
        });
    }

    let mut s = RlpStream::new_list(4);
    s.append(&if receipt.status { 1u8 } else { 0u8 });
    s.append(&receipt.cumulative_gas_used);
    s.append(&bloom_bytes);

    // Encode logs list
    s.begin_list(receipt.logs.len());
    for log in &receipt.logs {
        let log_rlp = rlp_encode_log(log)?;
        s.append_raw(&log_rlp, 1);
    }

    Ok(s.out().to_vec())
}

// -----------------------------------------------------------------------------
// Typed receipt envelope (EIP‑2718)
// -----------------------------------------------------------------------------

/// Encode a receipt into a typed envelope per EIP‑2718.
///
/// For legacy transactions (`tx_type == 0x00`), returns the legacy receipt RLP.
/// For EIP‑1559 transactions (`tx_type == 0x02`), returns `0x02 || RLP(receipt)`.
/// Other types are rejected.
///
/// # Errors
/// - If `tx_type` is not `0x00` or `0x02`.
/// - If the underlying receipt encoding fails.
pub fn rlp_encode_typed_receipt(tx_type: u8, receipt: &Receipt) -> RlpResult<Vec<u8>> {
    let inner = rlp_encode_receipt(receipt)?;
    match tx_type {
        TX_TYPE_LEGACY => Ok(inner),
        TX_TYPE_EIP1559 => {
            let mut out = Vec::with_capacity(1 + inner.len());
            out.push(TX_TYPE_EIP1559);
            out.extend(inner);
            Ok(out)
        }
        other => Err(RlpError::UnsupportedTxType { type_byte: other }),
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_log() -> Log {
        Log {
            address: "0x0000000000000000000000000000000000000000".into(),
            topics: vec!["0x".to_string(); 0],
            data: "0x".into(),
            block_number: Some(0),
            ..Default::default()
        }
    }

    fn sample_receipt() -> Receipt {
        Receipt {
            status: true,
            cumulative_gas_used: 21000,
            logs_bloom: "0x".to_string() + &"00".repeat(256),
            logs: vec![],
            ..Default::default()
        }
    }

    #[test]
    fn test_decode_hex_ok() {
        let bytes = decode_hex("0x1234").unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
        let bytes = decode_hex("1234").unwrap();
        assert_eq!(bytes, vec![0x12, 0x34]);
    }

    #[test]
    fn test_decode_hex_invalid() {
        assert!(decode_hex("0xzz").is_err());
    }

    #[test]
    fn test_rlp_encode_log_ok() {
        let log = sample_log();
        let encoded = rlp_encode_log(&log).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_log_invalid_address() {
        let mut log = sample_log();
        log.address = "0x1234".into();
        let err = rlp_encode_log(&log).unwrap_err();
        assert!(matches!(err, RlpError::InvalidAddressLength { .. }));
    }

    #[test]
    fn test_rlp_encode_receipt_ok() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_receipt(&receipt).unwrap();
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_rlp_encode_receipt_invalid_bloom() {
        let mut receipt = sample_receipt();
        receipt.logs_bloom = "0x1234".into();
        let err = rlp_encode_receipt(&receipt).unwrap_err();
        assert!(matches!(err, RlpError::InvalidBloomLength { .. }));
    }

    #[test]
    fn test_typed_receipt_legacy() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_typed_receipt(TX_TYPE_LEGACY, &receipt).unwrap();
        assert_eq!(encoded, rlp_encode_receipt(&receipt).unwrap());
    }

    #[test]
    fn test_typed_receipt_eip1559() {
        let receipt = sample_receipt();
        let encoded = rlp_encode_typed_receipt(TX_TYPE_EIP1559, &receipt).unwrap();
        assert_eq!(encoded[0], TX_TYPE_EIP1559);
    }

    #[test]
    fn test_typed_receipt_unsupported() {
        let receipt = sample_receipt();
        let err = rlp_encode_typed_receipt(0x01, &receipt).unwrap_err();
        assert!(matches!(err, RlpError::UnsupportedTxType { type_byte: 0x01 }));
    }
}
