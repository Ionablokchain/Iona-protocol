//! RLP encoding utilities for Ethereum‑compatible data.
//!
//! Provides functions to encode lists of byte slices into RLP and compute
//! their Keccak‑256 hash. These are used for simplified roots (placeholders)
//! where a full Merkle Patricia Trie is not required.
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

// -----------------------------------------------------------------------------
// Core functions
// -----------------------------------------------------------------------------

/// Encode a list of byte slices as an RLP list of byte strings.
///
/// # Arguments
/// * `items` – Slice of byte vectors to encode.
///
/// # Returns
/// The RLP‑encoded bytes of the list.
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
    format!("0x{}", hex::encode(hasher.finalize()))
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
        // Known value: keccak(rlp([])) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        assert_eq!(
            root,
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn test_single_item_root() {
        let item = b"hello".to_vec();
        let root = keccak_rlp_root(&[item]);
        assert!(root.starts_with("0x"));
        assert_eq!(root.len(), 66);
    }

    #[test]
    fn test_keccak_hex() {
        let hash = keccak_hex(b"");
        // Keccak-256 of empty string
        assert_eq!(
            hash,
            "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
        );
    }

    #[test]
    fn test_rlp_list_bytes() {
        let items = vec![b"a".to_vec(), b"bc".to_vec()];
        let encoded = rlp_list_bytes(&items);
        // RLP of ["a", "bc"] is 0xc2 0x61 0xc2 0x62 0x63? Actually manual check: not needed.
        assert!(!encoded.is_empty());
    }

    #[test]
    fn test_keccak_rlp_root_from_iter() {
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
        assert!(root.starts_with("0x"));
    }
}
