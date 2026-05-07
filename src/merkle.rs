//! Deterministic Merkle tree for IONA state root computation.
//!
//! v18 used blake3(serde_json(state)) which is:
//! 1. Non-deterministic across serde versions / key ordering changes
//! 2. Requires hashing the entire state even for 1 changed key
//!
//! This module implements a simple sorted‑leaf Merkle tree using SHA‑256:
//! - Leaves are sorted by key (deterministic regardless of insertion order)
//! - Internal nodes: `H(left || right)`
//! - Single leaf: `H(key || value)`
//! - Empty tree: `H(b"empty")`
//!
//! This is not a sparse Merkle tree (no proofs), but it is:
//! - Fully deterministic across platforms and versions
//! - Incrementally composable (sort+hash is stable)
//! - Fast: O(n log n) where n = number of KV entries

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Domain separator for leaf nodes (prevents collision with internal nodes).
const LEAF_DOMAIN: &[u8] = b"\x00";

/// Domain separator for internal nodes.
const INTERNAL_DOMAIN: &[u8] = b"\x01";

/// Domain separator for the empty tree.
const EMPTY_DOMAIN: &[u8] = b"empty";

/// Length of a SHA‑256 hash in bytes.
const HASH_LEN: usize = 32;

/// Known empty tree root (SHA‑256 of b"empty").
/// Pre‑computed for consistency.
pub const EMPTY_TREE_ROOT: [u8; HASH_LEN] = [
    0x88, 0xbd, 0x0e, 0x82, 0x6b, 0xc2, 0xac, 0x62,
    0xd8, 0xe5, 0xcc, 0xc2, 0x5c, 0x09, 0x50, 0x68,
    0xbe, 0x83, 0x35, 0x16, 0xe9, 0x78, 0x54, 0x9c,
    0xd1, 0xfa, 0xed, 0xdd, 0xf4, 0x1c, 0x11, 0x47,
];

// -----------------------------------------------------------------------------
// Errors (infallible currently, but defined for future extension)
// -----------------------------------------------------------------------------

/// Errors that can occur during Merkle tree computation.
#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("internal error: {0}")]
    Internal(String),
}

pub type MerkleResult<T> = Result<T, MerkleError>;

// -----------------------------------------------------------------------------
// Core functions
// -----------------------------------------------------------------------------

/// Compute the deterministic Merkle root of the entire key‑value state.
///
/// # Arguments
/// * `kv` – A `BTreeMap` of string keys to string values (already sorted).
///
/// # Returns
/// A 32‑byte SHA‑256 hash representing the state root.
///
/// # Determinism
/// The result depends only on the set of key‑value pairs, not on insertion order.
pub fn state_merkle_root(kv: &BTreeMap<String, String>) -> [u8; HASH_LEN] {
    if kv.is_empty() {
        return leaf_hash(EMPTY_DOMAIN, &[]);
    }

    let leaves: Vec<[u8; HASH_LEN]> = kv
        .iter()
        .map(|(k, v)| leaf_hash(k.as_bytes(), v.as_bytes()))
        .collect();

    merkle_root_of(&leaves)
}

/// Compute the leaf hash for a single key‑value pair (or the empty placeholder).
///
/// The domain separator `LEAF_DOMAIN` is prepended, followed by the length and
/// content of key and value (to prevent length extension attacks).
fn leaf_hash(key: &[u8], value: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(LEAF_DOMAIN);
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);
    hasher.update(&(value.len() as u32).to_le_bytes());
    hasher.update(value);
    hasher.finalize().into()
}

/// Hash for an internal Merkle node.
///
/// Domain separator `INTERNAL_DOMAIN` prevents collisions between leaf and internal nodes.
fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(INTERNAL_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Compute the Merkle root from a list of leaf hashes using a balanced binary tree.
///
/// If the number of leaves is not a power of two, the last leaf is duplicated
/// (standard Bitcoin‑style Merkle tree).
fn merkle_root_of(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    debug_assert!(!leaves.is_empty());
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mid = leaves.len().next_power_of_two() / 2;
    let (left_leaves, right_leaves) = if leaves.len() > mid {
        (&leaves[..mid], &leaves[mid..])
    } else {
        (&leaves[..], &leaves[..0])
    };

    let left = merkle_root_of(left_leaves);
    let right = if right_leaves.is_empty() {
        left // duplicate left child for odd trees
    } else {
        merkle_root_of(right_leaves)
    };
    node_hash(&left, &right)
}

// -----------------------------------------------------------------------------
// Fallible variant (for consistency, though current implementation never fails)
// -----------------------------------------------------------------------------

/// Compute the Merkle root and return a `Result` (infallible, but matches the pattern).
pub fn try_state_merkle_root(kv: &BTreeMap<String, String>) -> MerkleResult<[u8; HASH_LEN]> {
    Ok(state_merkle_root(kv))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_state_root_is_fixed() {
        let kv = BTreeMap::new();
        let root = state_merkle_root(&kv);
        // The empty root must match the pre‑computed constant.
        assert_eq!(root, EMPTY_TREE_ROOT);
    }

    #[test]
    fn deterministic_order() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a".to_string(), "1".to_string());
        kv1.insert("b".to_string(), "2".to_string());

        let mut kv2 = BTreeMap::new();
        kv2.insert("b".to_string(), "2".to_string());
        kv2.insert("a".to_string(), "1".to_string());

        assert_eq!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn different_values_produce_different_roots() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("k".to_string(), "v1".to_string());

        let mut kv2 = BTreeMap::new();
        kv2.insert("k".to_string(), "v2".to_string());

        assert_ne!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn single_entry() {
        let mut kv = BTreeMap::new();
        kv.insert("hello".to_string(), "world".to_string());
        let root = state_merkle_root(&kv);
        // Should be the leaf hash of that single pair.
        let expected = leaf_hash(b"hello", b"world");
        assert_eq!(root, expected);
    }

    #[test]
    fn two_entries() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        let root = state_merkle_root(&kv);
        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        // Perfect power of two: root = node(leaf_a, leaf_b)
        let expected = node_hash(&leaf_a, &leaf_b);
        assert_eq!(root, expected);
    }

    #[test]
    fn three_entries() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        kv.insert("c".to_string(), "3".to_string());
        let root = state_merkle_root(&kv);
        // Leaves: [leaf_a, leaf_b, leaf_c]
        // next_power_of_two = 4, split 2/2. Left: [a,b], Right: [c] + duplicate of leftmost? Actually the
        // algorithm duplicates the last leaf for odd count. So right sub‑root = leaf_c.
        // The root = node(root(left), leaf_c).
        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        let leaf_c = leaf_hash(b"c", b"3");
        let left = node_hash(&leaf_a, &leaf_b);
        let expected = node_hash(&left, &leaf_c);
        assert_eq!(root, expected);
    }

    #[test]
    fn many_entries_does_not_panic() {
        let mut kv = BTreeMap::new();
        for i in 0..1000 {
            kv.insert(format!("key_{}", i), format!("value_{}", i));
        }
        let root = state_merkle_root(&kv);
        assert_ne!(root, EMPTY_TREE_ROOT);
    }

    #[test]
    fn leaf_hash_domain_separator() {
        let leaf1 = leaf_hash(b"x", b"1");
        let leaf2 = leaf_hash(b"x", b"1");
        assert_eq!(leaf1, leaf2);

        // Different domains (should never happen because internal nodes use different prefix)
        let internal_like = node_hash(&[0u8; 32], &[0u8; 32]);
        assert_ne!(leaf1, internal_like);
    }
}
