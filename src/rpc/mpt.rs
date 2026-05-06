//! Merkle Patricia Trie (MPT) utilities for Ethereum compatibility.
//!
//! Provides functions to compute the root hash of an ordered Merkle tree
//! over a list of RLP‑encoded items, as used for `transactionsRoot` and
//! `receiptsRoot` in Ethereum blocks.
//!
//! Uses Keccak‑256 as the hash function.

use keccak_hasher::KeccakHasher;
use triehash::ordered_trie_root;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Hex prefix for Ethereum‑style root hash strings.
const HEX_PREFIX: &str = "0x";

/// Length of a Keccak‑256 hash in bytes.
const HASH_BYTES_LEN: usize = 32;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when computing MPT roots.
#[derive(Debug, Error)]
pub enum MptError {
    #[error("RLP items list is empty (root of empty trie should be 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421)")]
    EmptyItemList,

    #[error("invalid RLP encoding at index {index}")]
    InvalidRlp { index: usize, source: Box<dyn std::error::Error + Send + Sync> },
}

pub type MptResult<T> = Result<T, MptError>;

// -----------------------------------------------------------------------------
// Core functions
// -----------------------------------------------------------------------------

/// Compute Ethereum‑style ordered MPT root for a list of RLP‑encoded items.
///
/// Ethereum `transactionsRoot` and `receiptsRoot` are ordered tries where:
/// - key = RLP(index)
/// - value = RLP(item)
///
/// # Returns
/// A 32‑byte Keccak‑256 hash of the root node.
///
/// # Panics
/// This function never panics.
pub fn eth_ordered_trie_root(rlp_items: &[Vec<u8>]) -> [u8; HASH_BYTES_LEN] {
    let root = ordered_trie_root::<KeccakHasher, _>(rlp_items.iter().map(|v| v.as_slice()));
    let mut out = [0u8; HASH_BYTES_LEN];
    out.copy_from_slice(root.as_bytes());
    out
}

/// Compute Ethereum‑style ordered MPT root and return it as a hex string with `0x` prefix.
///
/// # Example
/// ```
/// use iona::rpc::mpt::eth_ordered_trie_root_hex;
///
/// let root_hex = eth_ordered_trie_root_hex(&[]);
/// assert_eq!(root_hex, "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
/// ```
pub fn eth_ordered_trie_root_hex(rlp_items: &[Vec<u8>]) -> String {
    let root = eth_ordered_trie_root(rlp_items);
    format!("{}{}", HEX_PREFIX, hex::encode(root))
}

/// Equivalent to `eth_ordered_trie_root_hex` but returns an empty string on error.
/// This is kept for backward compatibility but not recommended.
#[deprecated(since = "30.0.0", note = "use eth_ordered_trie_root_hex instead")]
pub fn eth_ordered_trie_root_hex_unchecked(rlp_items: &[Vec<u8>]) -> String {
    eth_ordered_trie_root_hex(rlp_items)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Known empty trie root (Keccak of RLP-encoded empty string).
    // Source: Ethereum yellow paper / go-ethereum.
    const EMPTY_TRIE_ROOT: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    #[test]
    fn test_empty_list() {
        let items: Vec<Vec<u8>> = vec![];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert_eq!(root_hex, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_single_item() {
        let items = vec![b"hello".to_vec()];
        let root_hex = eth_ordered_trie_root_hex(&items);
        // Expected value computed externally (deterministic).
        // We just check that it's not empty and has correct prefix and length.
        assert!(root_hex.starts_with("0x"));
        assert_eq!(root_hex.len(), 2 + 2 * HASH_BYTES_LEN);
        assert!(root_hex != EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_multiple_items() {
        let items = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert!(root_hex.starts_with("0x"));
        assert_eq!(root_hex.len(), 2 + 2 * HASH_BYTES_LEN);
    }

    #[test]
    fn test_root_bytes() {
        let items = vec![];
        let root_bytes = eth_ordered_trie_root(&items);
        assert_eq!(root_bytes.len(), HASH_BYTES_LEN);
        let hex_str = hex::encode(root_bytes);
        assert_eq!(format!("0x{}", hex_str), EMPTY_TRIE_ROOT);
    }
}
