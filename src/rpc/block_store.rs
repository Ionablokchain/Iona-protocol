//! Utility functions for RPC responses: hashing, bloom filtering, and root computations.
//!
//! These helpers are used to format Ethereum‑compatible data for JSON‑RPC endpoints.

use crate::rpc::bloom::Bloom;
use crate::rpc::rlp_encode::keccak_rlp_root;
use sha3::{Digest, Keccak256};

/// Compute the Keccak-256 hash of the given data and return it as a hex string with a `0x` prefix.
///
/// # Example
/// ```
/// let hash = keccak_hex(b"hello");
/// assert!(hash.starts_with("0x"));
/// ```
pub fn keccak_hex(data: &[u8]) -> String {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Compute a simple concatenation hash of a list of strings.
///
/// **Important**: This is NOT a Merkle Patricia Trie root; it is a placeholder used only
/// for testing and non‑critical RPC fields. For a real Merkle root, use `rlp_root_hex`.
///
/// The hash is computed by concatenating all string bytes (in order) and hashing them.
/// No length prefix is included, so `["ab","c"]` and `["a","bc"]` produce the same hash.
/// Do not use for consensus‑critical data.
pub fn concat_hash(items: &[String]) -> String {
    let mut hasher = Keccak256::new();
    for item in items {
        hasher.update(item.as_bytes());
    }
    format!("0x{}", hex::encode(hasher.finalize()))
}

/// Combine multiple bloom filters into a single filter by bitwise OR.
///
/// Returns the resulting filter as a hex string with a `0x` prefix.
pub fn bloom_or_hex(blooms: &[Bloom]) -> String {
    let mut combined = Bloom::default();
    for b in blooms {
        // Perform bytewise OR
        for i in 0..256 {
            combined.0[i] |= b.0[i];
        }
    }
    combined.to_hex()
}

/// Compute the Keccak‑256 hash of the RLP‑encoded list of items.
///
/// This is used for Ethereum‑style transaction and receipt roots.
/// The result is returned as a hex string with a `0x` prefix.
///
/// # Errors
/// If the underlying `keccak_rlp_root` fails (e.g., invalid RLP data), an error string is returned.
pub fn rlp_root_hex(items: &[Vec<u8>]) -> Result<String, String> {
    keccak_rlp_root(items).map(|hash| format!("0x{}", hex::encode(hash)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keccak_hex() {
        let hash = keccak_hex(b"");
        // Keccak-256 of empty string
        assert_eq!(hash, "0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    }

    #[test]
    fn test_concat_hash() {
        let items = vec!["a".to_string(), "b".to_string()];
        let h1 = concat_hash(&items);
        // same as hashing "ab"
        let h2 = keccak_hex(b"ab");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_bloom_or_hex() {
        let mut b1 = Bloom::default();
        let mut b2 = Bloom::default();
        b1.0[0] = 0x01;
        b2.0[1] = 0x02;
        let result = bloom_or_hex(&[b1, b2]);
        // Expect hex of a bloom where first byte = 0x01, second = 0x02, rest zero.
        let expected_hex = "0x".to_string() + &hex::encode(&[0x01, 0x02, 0u8; 254].concat());
        assert_eq!(result, expected_hex);
    }

    #[test]
    fn test_rlp_root_hex() {
        // Empty list should produce the RLP root of an empty list.
        let empty: Vec<Vec<u8>> = vec![];
        let root = rlp_root_hex(&empty).unwrap();
        // Known value: keccak(rlp([])) = 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421
        assert_eq!(
            root,
            "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }
}
