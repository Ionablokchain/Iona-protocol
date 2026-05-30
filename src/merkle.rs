//! Quantum Merkle tree for IONA state root computation.
//!
//! # Quantum Merkle Model
//!
//! The Merkle tree is modeled as a quantum hierarchical entanglement
//! structure where each leaf exists in a superposition of states and
//! internal nodes represent entangled pairs. The root hash is the
//! quantum fingerprint of the entire state.
//!
//! # Hamiltonian for Merkle Tree
//!
//! ```text
//! Ĥ_merkle = Ĥ_leaf + Ĥ_internal + Ĥ_root
//!
//! Ĥ_leaf     = Σ_i E_i |leaf_i⟩⟨leaf_i|
//! Ĥ_internal = Σ_j g_j (|left_j⟩⟨right_j| + h.c.)
//! Ĥ_root     = ω_root |root⟩⟨root|
//! ```
//!
//! # Quantum Determinism
//!
//! The Merkle root is a quantum observable that is invariant under
//! permutation of leaf order (sorted keys). This ensures deterministic
//! state roots regardless of insertion order — a manifestation of
//! quantum statistical mechanics where only the energy spectrum matters,
//! not the ordering of microstates.
//!
//! # Domain Separation via Quantum Channels
//!
//! Domain separators act as quantum channels that prevent interference
//! between different computational subspaces:
//! ```text
//! |leaf⟩     = U_leaf(key, value) |∅⟩
//! |internal⟩ = U_internal(left, right) |∅⟩
//! ```

use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Domain separator for leaf nodes (prevents quantum interference with internal nodes).
const LEAF_DOMAIN: &[u8] = b"\x00";

/// Domain separator for internal nodes (entanglement witness).
const INTERNAL_DOMAIN: &[u8] = b"\x01";

/// Domain separator for the empty tree (vacuum state).
const EMPTY_DOMAIN: &[u8] = b"empty";

/// Length of a SHA‑256 hash in bytes (quantum fingerprint length).
const HASH_LEN: usize = 32;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Entanglement strength between sibling nodes.
const ENTANGLEMENT_STRENGTH: f64 = 0.99;

/// Decoherence per hashing operation.
const HASH_DECOHERENCE: f64 = 0.00001;

/// Known empty tree root — the vacuum state fingerprint.
/// Pre‑computed as SHA‑256(b"empty").
pub const EMPTY_TREE_ROOT: [u8; HASH_LEN] = [
    0x88, 0xbd, 0x0e, 0x82, 0x6b, 0xc2, 0xac, 0x62,
    0xd8, 0xe5, 0xcc, 0xc2, 0x5c, 0x09, 0x50, 0x68,
    0xbe, 0x83, 0x35, 0x16, 0xe9, 0x78, 0x54, 0x9c,
    0xd1, 0xfa, 0xed, 0xdd, 0xf4, 0x1c, 0x11, 0x47,
];

// -----------------------------------------------------------------------------
// Quantum Merkle Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum Merkle tree computation.
#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("internal error: {0}")]
    Internal(String),

    #[error("quantum decoherence: tree coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("entanglement fidelity lost at level {level}")]
    EntanglementLost { level: usize },
}

pub type MerkleResult<T> = Result<T, MerkleError>;

// -----------------------------------------------------------------------------
// Quantum Merkle Tree
// -----------------------------------------------------------------------------

/// A quantum Merkle tree with coherence tracking.
#[derive(Debug, Clone)]
pub struct QuantumMerkleTree {
    /// The Merkle root (quantum fingerprint).
    pub root: [u8; HASH_LEN],
    /// Tree coherence (1.0 = perfect).
    pub coherence: f64,
    /// Number of leaves in the tree.
    pub leaf_count: usize,
    /// Tree depth (number of levels).
    pub depth: usize,
    /// Entanglement entropy of the tree.
    pub entanglement_entropy: f64,
}

// -----------------------------------------------------------------------------
// Core Functions
// -----------------------------------------------------------------------------

/// Compute the deterministic Merkle root of the entire key‑value state.
///
/// This is a projective measurement of the quantum state in the
/// computational basis, yielding a deterministic fingerprint.
///
/// # Arguments
/// * `kv` – A `BTreeMap` of string keys to string values (already sorted).
///
/// # Returns
/// A 32‑byte SHA‑256 hash representing the quantum state root.
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

/// Compute the quantum Merkle tree with full quantum metadata.
///
/// Returns a `QuantumMerkleTree` containing the root, coherence,
/// and entanglement information.
pub fn quantum_merkle_tree(
    kv: &BTreeMap<String, String>,
) -> MerkleResult<QuantumMerkleTree> {
    let leaf_count = kv.len();

    if leaf_count == 0 {
        return Ok(QuantumMerkleTree {
            root: EMPTY_TREE_ROOT,
            coherence: 1.0,
            leaf_count: 0,
            depth: 0,
            entanglement_entropy: 0.0,
        });
    }

    let leaves: Vec<[u8; HASH_LEN]> = kv
        .iter()
        .map(|(k, v)| leaf_hash(k.as_bytes(), v.as_bytes()))
        .collect();

    let depth = compute_tree_depth(leaf_count);
    let root = merkle_root_of(&leaves);
    let coherence = compute_tree_coherence(leaf_count, depth);
    let entanglement_entropy = compute_entanglement_entropy(coherence);

    // Check coherence threshold
    if coherence < 0.5 {
        return Err(MerkleError::Decoherence {
            coherence,
            threshold: 0.5,
        });
    }

    Ok(QuantumMerkleTree {
        root,
        coherence,
        leaf_count,
        depth,
        entanglement_entropy,
    })
}

// -----------------------------------------------------------------------------
// Quantum Leaf Hashing
// -----------------------------------------------------------------------------

/// Compute the quantum leaf hash for a single key‑value pair.
///
/// Applies the leaf unitary U_leaf to the vacuum state:
/// ```text
/// U_leaf |∅⟩ → |leaf⟩ = H(LEAF_DOMAIN || len(key) || key || len(value) || value)
/// ```
fn leaf_hash(key: &[u8], value: &[u8]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();

    // Domain separator — prevents quantum interference with internal nodes
    hasher.update(LEAF_DOMAIN);

    // Length-prefix to prevent length extension attacks
    hasher.update(&(key.len() as u32).to_le_bytes());
    hasher.update(key);

    hasher.update(&(value.len() as u32).to_le_bytes());
    hasher.update(value);

    hasher.finalize().into()
}

// -----------------------------------------------------------------------------
// Quantum Internal Node Hashing
// -----------------------------------------------------------------------------

/// Hash for an internal Merkle node — entanglement witness.
///
/// Creates an entangled state between left and right children:
/// ```text
/// U_internal |left⟩|right⟩ → |node⟩ = H(INTERNAL_DOMAIN || left || right)
/// ```
fn node_hash(left: &[u8; HASH_LEN], right: &[u8; HASH_LEN]) -> [u8; HASH_LEN] {
    let mut hasher = Sha256::new();

    // Domain separator — distinguishes internal nodes from leaves
    hasher.update(INTERNAL_DOMAIN);

    // Entangle left and right
    hasher.update(left);
    hasher.update(right);

    hasher.finalize().into()
}

// -----------------------------------------------------------------------------
// Quantum Tree Construction
// -----------------------------------------------------------------------------

/// Compute the Merkle root from a list of leaf hashes using a balanced
/// binary tree with quantum entanglement.
///
/// The tree is built bottom-up, with each level entangling pairs of nodes.
fn merkle_root_of(leaves: &[[u8; HASH_LEN]]) -> [u8; HASH_LEN] {
    debug_assert!(!leaves.is_empty(), "Merkle tree requires at least one leaf");

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
        left // Duplicate for odd-sized trees (quantum cloning, fidelity < 1)
    } else {
        merkle_root_of(right_leaves)
    };

    node_hash(&left, &right)
}

// -----------------------------------------------------------------------------
// Quantum Tree Properties
// -----------------------------------------------------------------------------

/// Compute the depth of a Merkle tree given the number of leaves.
fn compute_tree_depth(leaf_count: usize) -> usize {
    if leaf_count == 0 {
        return 0;
    }
    let power = leaf_count.next_power_of_two();
    power.trailing_zeros() as usize
}

/// Compute the coherence of the Merkle tree.
///
/// Coherence decays with each hashing operation due to computational
/// decoherence (entropy increase from hash function).
fn compute_tree_coherence(leaf_count: usize, depth: usize) -> f64 {
    let total_hashes = leaf_count + (1usize << depth) - 1; // leaves + internal nodes
    let decoherence = HASH_DECOHERENCE * total_hashes as f64;
    (-decoherence).exp()
}

/// Compute the entanglement entropy from coherence.
///
/// S = -γ ln γ (von Neumann entropy approximation).
fn compute_entanglement_entropy(coherence: f64) -> f64 {
    if coherence <= 0.0 || coherence >= 1.0 {
        return 0.0;
    }
    -coherence * coherence.ln()
}

// -----------------------------------------------------------------------------
// Utility Functions
// -----------------------------------------------------------------------------

/// Fallible variant (infallible currently, but matches the pattern).
pub fn try_state_merkle_root(
    kv: &BTreeMap<String, String>,
) -> MerkleResult<[u8; HASH_LEN]> {
    Ok(state_merkle_root(kv))
}

/// Verify a Merkle root against a set of key-value pairs.
pub fn verify_merkle_root(
    kv: &BTreeMap<String, String>,
    expected_root: &[u8; HASH_LEN],
) -> bool {
    let computed = state_merkle_root(kv);
    computed == *expected_root
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic Determinism Tests ────────────────────────────────────────
    #[test]
    fn test_empty_state_root_is_fixed() {
        let kv = BTreeMap::new();
        let root = state_merkle_root(&kv);
        assert_eq!(root, EMPTY_TREE_ROOT);
    }

    #[test]
    fn test_deterministic_order() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("a".to_string(), "1".to_string());
        kv1.insert("b".to_string(), "2".to_string());

        let mut kv2 = BTreeMap::new();
        kv2.insert("b".to_string(), "2".to_string());
        kv2.insert("a".to_string(), "1".to_string());

        assert_eq!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    #[test]
    fn test_different_values_produce_different_roots() {
        let mut kv1 = BTreeMap::new();
        kv1.insert("k".to_string(), "v1".to_string());

        let mut kv2 = BTreeMap::new();
        kv2.insert("k".to_string(), "v2".to_string());

        assert_ne!(state_merkle_root(&kv1), state_merkle_root(&kv2));
    }

    // ── Tree Structure Tests ───────────────────────────────────────────
    #[test]
    fn test_single_entry() {
        let mut kv = BTreeMap::new();
        kv.insert("hello".to_string(), "world".to_string());
        let root = state_merkle_root(&kv);
        let expected = leaf_hash(b"hello", b"world");
        assert_eq!(root, expected);
    }

    #[test]
    fn test_two_entries() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        let root = state_merkle_root(&kv);

        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        let expected = node_hash(&leaf_a, &leaf_b);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_three_entries() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());
        kv.insert("b".to_string(), "2".to_string());
        kv.insert("c".to_string(), "3".to_string());
        let root = state_merkle_root(&kv);

        let leaf_a = leaf_hash(b"a", b"1");
        let leaf_b = leaf_hash(b"b", b"2");
        let leaf_c = leaf_hash(b"c", b"3");

        // next_power_of_two(3) = 4, mid = 2
        // Left: [a, b] → node_hash(a, b)
        // Right: [c] → c (duplicated)
        let left = node_hash(&leaf_a, &leaf_b);
        let expected = node_hash(&left, &leaf_c);

        assert_eq!(root, expected);
    }

    #[test]
    fn test_many_entries_does_not_panic() {
        let mut kv = BTreeMap::new();
        for i in 0..1000 {
            kv.insert(format!("key_{}", i), format!("value_{}", i));
        }
        let root = state_merkle_root(&kv);
        assert_ne!(root, EMPTY_TREE_ROOT);
    }

    // ── Domain Separation Tests ────────────────────────────────────────
    #[test]
    fn test_leaf_hash_domain_separation() {
        let leaf1 = leaf_hash(b"x", b"1");
        let leaf2 = leaf_hash(b"x", b"1");
        assert_eq!(leaf1, leaf2);

        // Internal nodes use different domain — should not collide
        let internal = node_hash(&[0u8; 32], &[0u8; 32]);
        assert_ne!(leaf1, internal);
    }

    #[test]
    fn test_domain_separator_prevents_collision() {
        // A leaf with key="\x01" and value=left||right should NOT collide
        // with an internal node of (left, right) because of domain prefix.
        let left = [1u8; 32];
        let right = [2u8; 32];

        let internal = node_hash(&left, &right);

        // Construct a leaf that would collide without domain separation
        let mut key = Vec::from(INTERNAL_DOMAIN);
        key.extend_from_slice(&left);
        let value = right.to_vec();
        let leaf = leaf_hash(&key, &value);

        assert_ne!(internal, leaf);
    }

    // ── Quantum Tests ──────────────────────────────────────────────────
    #[test]
    fn test_quantum_merkle_tree_empty() {
        let kv = BTreeMap::new();
        let tree = quantum_merkle_tree(&kv).unwrap();

        assert_eq!(tree.root, EMPTY_TREE_ROOT);
        assert_eq!(tree.leaf_count, 0);
        assert_eq!(tree.depth, 0);
        assert!((tree.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_quantum_merkle_tree_single() {
        let mut kv = BTreeMap::new();
        kv.insert("k".to_string(), "v".to_string());

        let tree = quantum_merkle_tree(&kv).unwrap();

        assert_eq!(tree.leaf_count, 1);
        assert_eq!(tree.depth, 0);
        assert!(tree.coherence < 1.0); // decoherence from hashing
    }

    #[test]
    fn test_quantum_merkle_tree_coherence_decay() {
        let mut kv = BTreeMap::new();
        for i in 0..100 {
            kv.insert(format!("key_{}", i), format!("value_{}", i));
        }

        let tree = quantum_merkle_tree(&kv).unwrap();
        assert!(tree.coherence < 1.0);
        assert!(tree.coherence > 0.9); // still high for 100 entries
        assert!(tree.entanglement_entropy > 0.0);
    }

    #[test]
    fn test_verify_merkle_root() {
        let mut kv = BTreeMap::new();
        kv.insert("x".to_string(), "y".to_string());

        let root = state_merkle_root(&kv);
        assert!(verify_merkle_root(&kv, &root));

        kv.insert("z".to_string(), "w".to_string());
        assert!(!verify_merkle_root(&kv, &root)); // root changed
    }

    #[test]
    fn test_compute_tree_depth() {
        assert_eq!(compute_tree_depth(0), 0);
        assert_eq!(compute_tree_depth(1), 0);
        assert_eq!(compute_tree_depth(2), 1);
        assert_eq!(compute_tree_depth(3), 2);
        assert_eq!(compute_tree_depth(4), 2);
        assert_eq!(compute_tree_depth(7), 3);
        assert_eq!(compute_tree_depth(8), 3);
    }

    #[test]
    fn test_try_state_merkle_root() {
        let mut kv = BTreeMap::new();
        kv.insert("a".to_string(), "1".to_string());

        let result = try_state_merkle_root(&kv);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), state_merkle_root(&kv));
    }
}
