/// Deterministic Merkle tree for IONA state root computation.
///
/// v18 used blake3(serde_json(state)) which is:
/// 1. Non-deterministic across serde versions / key ordering changes
/// 2. Requires hashing the entire state even for 1 changed key
///
/// This module implements a simple sorted-leaf Merkle tree using SHA-256:
/// - Leaves are sorted by key (deterministic regardless of insertion order)
/// - Internal nodes: H(left || right)
/// - Single leaf: H(key || value)
/// - Empty tree: H(b"empty")
///
/// This is not a sparse Merkle tree (no proofs), but it is:
/// - Fully deterministic across platforms and versions
/// - Incrementally composable (sort+hash is stable)
/// - Fast: O(n log n) where n = number of KV entries

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub fn state_merkle_root(kv: &BTreeMap<String, String>) -> [u8; 32] {
    if kv.is_empty() {
        return leaf_hash(b"empty", b"");
    }

    // Compute leaf hashes (already sorted by BTreeMap)
    let leaves: Vec<[u8; 32]> = kv.iter()
        .map(|(k, v)| leaf_hash(k.as_bytes(), v.as_bytes()))
        .collect();

    merkle_root_of(&leaves)
}

/// Hash for a state key-value pair.
fn leaf_hash(key: &[u8], value: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"\x00"); // domain separator: leaf
    h.update(&(key.len() as u32).to_le_bytes());
    h.update(key);
    h.update(&(value.len() as u32).to_le_bytes());
    h.update(value);
    h.finalize().into()
}

/// Hash for an internal Merkle node.
fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"\x01"); // domain separator: internal node
    h.update(left);
    h.update(right);
    h.finalize().into()
}

fn merkle_root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    assert!(!leaves.is_empty());
    if leaves.len() == 1 { return leaves[0]; }

    let mid = leaves.len().next_power_of_two() / 2;
    let (left_leaves, right_leaves) = if leaves.len() > mid {
        (&leaves[..mid], &leaves[mid..])
    } else {
        (&leaves[..], &leaves[..0])
    };

    let left = merkle_root_of(left_leaves);
    let right = if right_leaves.is_empty() {
        left  // duplicate left for odd trees (standard Bitcoin-style)
    } else {
        merkle_root_of(right_leaves)
    };
    node_hash(&left, &right)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a".to_string(), "1".to_string());
        kv1.insert("b".to_string(), "2".to_string());
        let mut kv2 = BTreeMap::new();
        kv2.insert("b".to_string(), "2".to_string());
        kv2.insert("a".to_string(), "1".to_string());
        assert_eq!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn different_values() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("k".to_string(), "v1".to_string());
        let mut kv2 = BTreeMap::new();
        kv2.insert("k".to_string(), "v2".to_string());
        assert_ne!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }
}
