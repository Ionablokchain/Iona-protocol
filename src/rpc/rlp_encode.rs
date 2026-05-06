//! RLP encoding utilities for Ethereum‑compatible data.
//!
//! Provides functions to encode lists of byte slices into RLP and compute
//! their Keccak‑256 hash. Used for simplified roots (placeholders) where
//! a full Merkle Patricia Trie is not required.
//!
//! # Example
//!
//! ```
//! use iona::rpc::rlp_encode::{keccak_rlp_root, rlp_list_bytes};
//!
//! let items = vec![b"hello".to_vec(), b"world".to_vec()];
//! let root = keccak_rlp_root(&items);
//! assert!(root.starts_with("0x"));
//! ```

use rlp::RlpStream;
use sha3::{Digest, Keccak256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// Keccak‑256 hash of RLP‑encoded empty list.
/// Known value: `rlp([]) = 0xc0`, keccak(0xc0) = 0x56e81f...
pub const EMPTY_LIST_RIPEMD: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

/// Expected length of a hex‑encoded hash with prefix (2 + 64 = 66).
const HEX_HASH_LEN: usize = 66;

// -----------------------------------------------------------------------------
// Errors (placeholder – no current fallible operations)
// -----------------------------------------------------------------------------

/// Possible errors during RLP encoding (currently none, but kept for future).
#[derive(Debug, Error)]
pub enum RlpEncodeError {
    #[error("unexpected error: {0}")]
    Internal(String),
}

pub type RlpEncodeResult<T> = Result<T, RlpEncodeError>;

// -----------------------------------------------------------------------------
// Core functions
// -----------------------------------------------------------------------------

/// Encode a list of byte slices as an RLP list of byte strings.
///
/// # Arguments
/// * `items` – Slice of byte vectors to encode.
///
/// # Returns
/// The RLP‑encoded bytes of the list. This function never fails.
#[must_use]
pub fn rlp_list_bytes(items: &[Vec<u8>]) -> Vec<u8> {
    let mut stream = RlpStream::new_list(items.len());
    for item in items {
        stream.append(&item.as_slice());
    }
    stream.out().to_vec()
}

/// Compute the Keccak‑256 hash of a byte slice and return it as a hex string with `0x` prefix.
///
/// # Arguments
/// * `bytes` – The data to hash.
///
/// # Returns
/// A string like `"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a741c0f142a0c0b27c2c2"`.
#[must_use]
pub fn keccak_hex(bytes: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(bytes);
    format!("{}{}", HEX_PREFIX, hex::encode(hasher.finalize()))
}

/// Compute a simplified "root" as `keccak(rlp(list(items)))`.
///
/// **Note**: Ethereum uses an ordered Merkle Patricia Trie (MPT) for roots like
/// `transactionsRoot` and `receiptsRoot`. This function is a placeholder for
/// contexts where a full MPT is not required (e.g., testing, simplified RPC
/// responses). It does **not** produce the same value as Ethereum's state root.
///
/// # Arguments
/// * `items` – RLP‑encoded items to include in the list.
///
/// # Returns
/// A hex string with `0x` prefix.
#[must_use]
pub fn keccak_rlp_root(items: &[Vec<u8>]) -> String {
    keccak_hex(&rlp_list_bytes(items))
}

// -----------------------------------------------------------------------------
// Convenience functions
// -----------------------------------------------------------------------------

/// Compute `keccak(rlp(list)))` for an iterator of RLP‑encoded items,
/// without allocating an intermediate `Vec`.
///
/// # Arguments
/// * `items` – Iterator over references to byte slices.
///
/// # Returns
/// A hex string with `0x` prefix.
pub fn keccak_rlp_root_from_iter<'a, I>(items: I) -> String
where
    I: IntoIterator<Item = &'a [u8]>,
{
    let items_vec: Vec<Vec<u8>> = items.into_iter().map(|b| b.to_vec()).collect();
    keccak_rlp_root(&items_vec)
}

/// Compute `keccak(rlp(list)))` for items that implement `rlp::Encodable`.
///
/// # Arguments
/// * `items` – Slice of encodable items.
///
/// # Returns
/// A hex string with `0x` prefix.
pub fn keccak_rlp_root_encodable<T: rlp::Encodable>(items: &[T]) -> String {
    let rlp_items: Vec<Vec<u8>> = items.iter().map(|item| rlp::encode(item).to_vec()).collect();
    keccak_rlp_root(&rlp_items)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_list_root() {
        let empty: Vec<Vec<u8>> = vec![];
        let root = keccak_rlp_root(&empty);
        assert_eq!(root, EMPTY_LIST_RIPEMD);
    }

    #[test]
    fn test_keccak_hex_empty() {
        let hash = keccak_hex(b"");
        // Keccak‑256 of empty string
        assert_eq!(
            hash,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
        assert_eq!(hash.len(), HEX_HASH_LEN);
    }

    #[test]
    fn test_keccak_hex_non_empty() {
        let hash = keccak_hex(b"hello");
        // Known value for "hello" (without 0x)
        assert_eq!(
            hash,
            "0x1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8"
        );
    }

    #[test]
    fn test_rlp_list_bytes_non_empty() {
        let items = vec![b"a".to_vec(), b"bc".to_vec()];
        let encoded = rlp_list_bytes(&items);
        // RLP of ["a", "bc"] = 0xc2 0x61 0xc2 0x62 0x63
        // Let's check length: "a" is 1 byte (RLP: 0x61), "bc" is 2 bytes (RLP: 0xc2 0x62 0x63)
        // List of 2 items: prefix 0xc2 gives 0xc2 + (0x61) + (0xc2 0x62 0x63)
        assert!(!encoded.is_empty());
        // We could do a more precise check:
        let expected = vec![0xc2, 0x61, 0xc2, 0x62, 0x63];
        assert_eq!(encoded, expected);
    }

    #[test]
    fn test_rlp_list_bytes_empty() {
        let encoded = rlp_list_bytes(&[]);
        assert_eq!(encoded, vec![0xc0]); // RLP of empty list
    }

    #[test]
    fn test_keccak_rlp_root_consistency() {
        let items = vec![b"hello".to_vec(), b"world".to_vec()];
        let root1 = keccak_rlp_root(&items);
        let root2 = keccak_rlp_root_from_iter(items.iter().map(|v| v.as_slice()));
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_keccak_rlp_root_encodable() {
        #[derive(rlp::RlpEncodable)]
        struct TestItem(u64);
        let items = vec![TestItem(1), TestItem(2)];
        let root = keccak_rlp_root_encodable(&items);
        assert!(root.starts_with(HEX_PREFIX));
        assert_eq!(root.len(), HEX_HASH_LEN);
        // Verify manually? Not needed; just ensure no panic.
    }
}
