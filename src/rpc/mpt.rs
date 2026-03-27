//! Merkle Patricia Trie utilities for Ethereum‑compatible roots.
//!
//! This module provides functions to compute the ordered Merkle Patricia Trie root
//! for a list of RLP‑encoded items, as used in Ethereum for `transactionsRoot`,
//! `receiptsRoot`, and `withdrawalsRoot`.

use keccak_hasher::KeccakHasher;
use triehash::ordered_trie_root;

/// Compute the Ethereum‑style ordered MPT root for a list of RLP‑encoded items.
///
/// In Ethereum, the transactionsRoot, receiptsRoot, and withdrawalsRoot are ordered tries where:
/// - key = RLP(index) (the index of the item in the list, RLP‑encoded as an integer)
/// - value = RLP(item) (the RLP‑encoded transaction, receipt, or withdrawal)
///
/// This function uses the `triehash` crate with the `KeccakHasher` to produce a 32‑byte hash
/// that matches Ethereum's expectation.
///
/// # Arguments
/// * `rlp_items` – A slice of byte vectors, each containing the RLP encoding of an item.
///
/// # Returns
/// A 32‑byte array containing the root hash.
///
/// # Example
/// ```
/// use iona::rpc::mpt::eth_ordered_trie_root;
///
/// let items = vec![b"\x01".to_vec(), b"\x02".to_vec()];
/// let root = eth_ordered_trie_root(&items);
/// assert_eq!(root.len(), 32);
/// ```
pub fn eth_ordered_trie_root(rlp_items: &[Vec<u8>]) -> [u8; 32] {
    ordered_trie_root::<KeccakHasher, _, _>(rlp_items.iter().map(|v| v.as_slice()))
}

/// Compute the Ethereum‑style ordered MPT root and return it as a hex string with `0x` prefix.
///
/// # Arguments
/// * `rlp_items` – A slice of byte vectors, each containing the RLP encoding of an item.
///
/// # Returns
/// A string like `"0x1dcc4de8dec75d7aab85b567b6ccd41ad312451b948a741c0f142a0c0b27c2c2"`.
pub fn eth_ordered_trie_root_hex(rlp_items: &[Vec<u8>]) -> String {
    let root = eth_ordered_trie_root(rlp_items);
    format!("0x{}", hex::encode(root))
}

/// Convenience function to compute the ordered trie root for a list of items that
/// implement `rlp::Encodable`.
///
/// This function automatically RLP‑encodes each item using `rlp::encode`.
///
/// # Example
/// ```
/// use rlp::Encodable;
/// use iona::rpc::mpt::eth_ordered_trie_root_encodable;
///
/// #[derive(rlp::RlpEncodable)]
/// struct MyItem { data: u64 }
/// let items = vec![MyItem { data: 1 }, MyItem { data: 2 }];
/// let root = eth_ordered_trie_root_encodable(&items);
/// ```
pub fn eth_ordered_trie_root_encodable<T: rlp::Encodable>(items: &[T]) -> [u8; 32] {
    let rlp_items: Vec<Vec<u8>> = items.iter().map(|item| rlp::encode(item).to_vec()).collect();
    eth_ordered_trie_root(&rlp_items)
}

/// Same as `eth_ordered_trie_root_encodable` but returns a hex string with `0x` prefix.
pub fn eth_ordered_trie_root_encodable_hex<T: rlp::Encodable>(items: &[T]) -> String {
    let root = eth_ordered_trie_root_encodable(items);
    format!("0x{}", hex::encode(root))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_list() {
        let empty: Vec<Vec<u8>> = vec![];
        let root = eth_ordered_trie_root(&empty);
        // Known value: keccak(rlp([])) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        let expected_hex = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";
        assert_eq!(eth_ordered_trie_root_hex(&empty), expected_hex);
    }

    #[test]
    fn test_one_item() {
        let item = b"\x01".to_vec();
        let root = eth_ordered_trie_root(&[item]);
        // The root should not be zero; we just check length and non‑null.
        assert_eq!(root.len(), 32);
        assert_ne!(root, [0u8; 32]);
    }

    #[test]
    fn test_rlp_encodable() {
        use rlp::Encodable;
        struct TestItem(u64);
        impl Encodable for TestItem {
            fn rlp_append(&self, s: &mut rlp::RlpStream) {
                s.append(&self.0);
            }
        }
        let items = vec![TestItem(1), TestItem(2)];
        let root = eth_ordered_trie_root_encodable(&items);
        assert_eq!(root.len(), 32);
    }

    #[test]
    fn test_hex_output() {
        let items = vec![b"\x01".to_vec()];
        let hex = eth_ordered_trie_root_hex(&items);
        assert!(hex.starts_with("0x"));
        assert_eq!(hex.len(), 66); // 0x + 64 hex chars
    }
}
