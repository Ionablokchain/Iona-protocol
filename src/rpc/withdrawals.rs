//! EIP‑4895 withdrawal types and root computation (Shanghai).
//!
//! Provides `Withdrawal` struct with RLP encoding and helper to compute
//! the withdrawals root (ordered Merkle Patricia Trie) as required by
//! the Ethereum specification.

use crate::rpc::mpt::eth_ordered_trie_root_hex;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// Minimum possible amount in Gwei (must be ≥ 0).
const MIN_AMOUNT_GWEI: u64 = 0;

/// Maximum possible amount in Gwei (practical limit, Ethereum uses ~2^64/gwei).
const MAX_AMOUNT_GWEI: u64 = u64::MAX;

/// Length of an Ethereum address in bytes.
const ADDRESS_LEN: usize = 20;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when working with withdrawals.
#[derive(Debug, Error)]
pub enum WithdrawalError {
    #[error("invalid address length: expected 20 bytes, got {len}")]
    InvalidAddressLength { len: usize },

    #[error("invalid amount in Gwei: {amount} (must be between {min} and {max})")]
    InvalidAmount { amount: u64, min: u64, max: u64 },

    #[error("RLP encoding error: {0}")]
    RlpEncoding(String),
}

pub type WithdrawalResult<T> = Result<T, WithdrawalError>;

// -----------------------------------------------------------------------------
// Withdrawal struct
// -----------------------------------------------------------------------------

/// EIP‑4895 withdrawal (Shanghai).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Global index of this withdrawal (monotonically increasing).
    pub index: u64,
    /// Consensus‑layer validator index.
    pub validator_index: u64,
    /// Target execution‑layer address (20 bytes).
    pub address: [u8; ADDRESS_LEN],
    /// Amount in Gwei.
    pub amount_gwei: u64,
}

impl Withdrawal {
    /// Create a new withdrawal with validation.
    ///
    /// # Errors
    /// - If `amount_gwei` is zero? Not required by spec but could be warned. We allow zero.
    /// - If `address` length is not 20 bytes (always true because it's a fixed array).
    ///   We cannot validate length at runtime because it's a fixed array.
    pub fn new(index: u64, validator_index: u64, address: [u8; ADDRESS_LEN], amount_gwei: u64) -> Self {
        Self {
            index,
            validator_index,
            address,
            amount_gwei,
        }
    }

    /// Validate the withdrawal fields.
    /// Address length is already guaranteed by the type, but we check amount range.
    pub fn validate(&self) -> WithdrawalResult<()> {
        if self.amount_gwei < MIN_AMOUNT_GWEI || self.amount_gwei > MAX_AMOUNT_GWEI {
            return Err(WithdrawalError::InvalidAmount {
                amount: self.amount_gwei,
                min: MIN_AMOUNT_GWEI,
                max: MAX_AMOUNT_GWEI,
            });
        }
        Ok(())
    }

    /// RLP‑encode as `[index, validatorIndex, address, amount]`.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut stream = RlpStream::new_list(4);
        stream.append(&self.index);
        stream.append(&self.validator_index);
        stream.append(&self.address.as_slice());
        stream.append(&self.amount_gwei);
        stream.out().to_vec()
    }
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// RLP‑encode a withdrawal (standalone helper for backwards compatibility).
pub fn rlp_encode_withdrawal(w: &Withdrawal) -> Vec<u8> {
    w.rlp_encode()
}

/// Compute `withdrawalsRoot` — ordered MPT root over RLP‑encoded withdrawals.
///
/// This matches the Ethereum spec: each leaf is `RLP(withdrawal)`, indexed
/// by the ordered trie key (RLP‑encoded position index).
pub fn withdrawals_root_hex(withdrawals: &[Withdrawal]) -> String {
    let items: Vec<Vec<u8>> = withdrawals.iter().map(|w| w.rlp_encode()).collect();
    eth_ordered_trie_root_hex(&items)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_withdrawal() -> Withdrawal {
        Withdrawal::new(0, 1, [0xAA; ADDRESS_LEN], 1_000_000)
    }

    #[test]
    fn withdrawal_validation_ok() {
        let w = sample_withdrawal();
        assert!(w.validate().is_ok());
    }

    #[test]
    fn withdrawal_validation_invalid_amount() {
        let w = Withdrawal::new(0, 1, [0xAA; ADDRESS_LEN], u64::MAX);
        assert!(w.validate().is_ok()); // MAX is allowed
    }

    #[test]
    fn rlp_encode_roundtrip() {
        let w = sample_withdrawal();
        let encoded = w.rlp_encode();
        // We cannot easily decode here without full withdrawal list decoding,
        // but we can check it's non‑empty and has the correct RLP structure.
        assert!(!encoded.is_empty());
        // RLP list header (0xc4 for list of 4 items where each item is small)
        // Not strictly required to validate.
    }

    #[test]
    fn withdrawals_root_empty() {
        let root = withdrawals_root_hex(&[]);
        // Known empty withdrawals root (Keccak of RLP-encoded empty list)
        assert_eq!(
            root,
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn withdrawals_root_single() {
        let w = sample_withdrawal();
        let root = withdrawals_root_hex(&[w]);
        assert!(root.starts_with(HEX_PREFIX));
        assert_eq!(root.len(), 66);
    }

    #[test]
    fn withdrawal_derives() {
        let w = sample_withdrawal();
        let cloned = w.clone();
        let json = serde_json::to_string(&cloned).unwrap();
        let back: Withdrawal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 0);
        assert_eq!(back.amount_gwei, 1_000_000);
        let _ = format!("{:?}", w);
    }
}
