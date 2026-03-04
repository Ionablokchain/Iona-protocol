use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// Encode a list of byte blobs as an RLP list of byte strings.
pub fn rlp_list_bytes(items: &[Vec<u8>]) -> Vec<u8> {
    let mut s = RlpStream::new_list(items.len());
    for it in items {
        s.append(&it.as_slice());
    }
    s.out().to_vec()
}

/// Keccak256 hex of bytes.
pub fn keccak_hex(bytes: &[u8]) -> String {
    let mut h = Keccak256::new();
    h.update(bytes);
    format!("0x{}", hex::encode(h.finalize()))
}

/// Approximate "root" as keccak(rlp(list(items))).
/// NOTE: Ethereum uses Merkle Patricia Trie roots; this is a closer placeholder than concatenation.
pub fn keccak_rlp_root(items: &[Vec<u8>]) -> String {
    keccak_hex(&rlp_list_bytes(items))
}
