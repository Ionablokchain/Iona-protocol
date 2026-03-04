use crate::rpc::bloom::Bloom;
use sha3::{Digest, Keccak256};
use crate::rpc::rlp_encode::keccak_rlp_root;

pub fn keccak_hex(data: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(data);
    format!("0x{}", hex::encode(h.finalize()))
}

/// Very small "root" helpers (NOT Merkle Patricia Trie).
/// These are placeholders to keep structure similar to Ethereum.
pub fn pseudo_root(items: &[String]) -> String {
    let mut h = Keccak256::new();
    for it in items {
        h.update(it.as_bytes());
    }
    format!("0x{}", hex::encode(h.finalize()))
}

pub fn bloom_or_hex(blooms: &[Bloom]) -> String {
    let mut out = Bloom::default();
    for b in blooms {
        for i in 0..256 {
            out.0[i] |= b.0[i];
        }
    }
    out.to_hex()
}


/// Convenience wrapper to compute keccak(rlp(list(items))) root.
pub fn rlp_root_hex(items: &[Vec<u8>]) -> String {
    keccak_rlp_root(items)
}
