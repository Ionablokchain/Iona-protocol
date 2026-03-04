use triehash::ordered_trie_root;
use keccak_hasher::KeccakHasher;

/// Compute Ethereum-style ordered MPT root for a list of RLP-encoded items.
///
/// Ethereum transactionsRoot and receiptsRoot are ordered tries where:
/// - key = RLP(index)
/// - value = RLP(item)
pub fn eth_ordered_trie_root(rlp_items: &[Vec<u8>]) -> [u8; 32] {
    ordered_trie_root::<KeccakHasher, _, _>(rlp_items.iter().map(|v| v.as_slice()))
}

pub fn eth_ordered_trie_root_hex(rlp_items: &[Vec<u8>]) -> String {
    let r = eth_ordered_trie_root(rlp_items);
    format!("0x{}", hex::encode(r))
}
