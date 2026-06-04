//! Merkle Patricia Trie (MPT) utilities — Quantum Ethereum compatibility.
//!
//! # Quantum MPT Model
//!
//! The Merkle Patricia Trie is modelled as a **quantum hierarchical
//! entanglement structure** where each leaf represents a quantum state
//! |leaf_i⟩ in the computational basis. Internal nodes are **entangled
//! pairs** of their children, and the root hash is the **quantum
//! fingerprint** of the entire state.
//!
//! # Mathematical Formalism
//!
//! ## Trie as Quantum State
//! ```text
//! |Ψ_trie⟩ = (1/√N) Σ_i |leaf_i⟩
//! ρ_trie = |Ψ_trie⟩⟨Ψ_trie|
//! ```
//!
//! ## Hamiltonian for MPT Operations
//! ```text
//! Ĥ_mpt = Ĥ_leaf + Ĥ_node + Ĥ_root
//!
//! Ĥ_leaf = Σ_i E_i |leaf_i⟩⟨leaf_i|
//! Ĥ_node = Σ_j g_j (|left_j⟩⟨right_j| + h.c.)
//! Ĥ_root = ω_root |root⟩⟨root|
//! ```
//!
//! ## Root Hash as Quantum Fingerprint
//! ```text
//! |root⟩ = H(|Ψ_trie⟩) = Keccak256(RLP(trie))
//! ⟨root|root⟩ = 1   (deterministic)
//! ```
//!
//! ## Decoherence from Trie Operations
//! ```text
//! ρ(t) = ρ₀ exp(-γt)
//! ```
//! where γ is the decoherence rate per hashing operation.

use keccak_hasher::KeccakHasher;
use triehash::ordered_trie_root;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for MPT operations.
const DEFAULT_MPT_COHERENCE: f64 = 1.0;

/// Decoherence rate per hashing operation.
const HASH_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for valid MPT state.
const MIN_MPT_COHERENCE: f64 = 0.99;

/// Hex prefix for Ethereum‑style root hash strings.
const HEX_PREFIX: &str = "0x";

/// Length of a Keccak‑256 hash in bytes.
const HASH_BYTES_LEN: usize = 32;

// -----------------------------------------------------------------------------
// Quantum MPT State
// -----------------------------------------------------------------------------

/// Quantum state of the Merkle Patricia Trie.
///
/// Tracks the density matrix properties during trie construction and
/// root computation.
#[derive(Debug, Clone)]
pub struct QuantumMptState {
    /// Purity γ = Tr(ρ²) of the trie state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the trie structure.
    pub trie_coherence: f64,
    /// Number of leaves in the trie.
    pub leaf_count: usize,
    /// Total hashing operations performed.
    pub total_hashes: u64,
    /// Whether the trie state is valid (above coherence threshold).
    pub is_valid: bool,
}

impl Default for QuantumMptState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_MPT_COHERENCE,
            entropy: 0.0,
            trie_coherence: DEFAULT_MPT_COHERENCE,
            leaf_count: 0,
            total_hashes: 0,
            is_valid: true,
        }
    }
}

impl QuantumMptState {
    /// Create a new quantum MPT state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a quantum MPT state with a given number of leaves.
    pub fn with_leaves(leaf_count: usize) -> Self {
        let mut state = Self::new();
        state.leaf_count = leaf_count;
        // Apply decoherence proportional to leaf count
        let total_hashes = leaf_count as u64 * 2; // approximate: one hash per leaf + internal nodes
        for _ in 0..total_hashes {
            state.apply_hash_decoherence();
        }
        state
    }

    /// Apply decoherence from a single hashing operation.
    pub fn apply_hash_decoherence(&mut self) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-HASH_DECOHERENCE_RATE).exp();
        self.trie_coherence = (self.trie_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence for multiple hashing operations.
    pub fn apply_bulk_decoherence(&mut self, hash_count: u64) {
        for _ in 0..hash_count {
            self.apply_hash_decoherence();
        }
    }

    fn recompute(&mut self) {
        self.purity = self.trie_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_MPT_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when computing MPT roots.
#[derive(Debug, Error)]
pub enum MptError {
    #[error("RLP items list is empty (root of empty trie should be 0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421)")]
    EmptyItemList,

    #[error("invalid RLP encoding at index {index}")]
    InvalidRlp {
        index: usize,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("quantum decoherence: trie coherence {coherence} below threshold {threshold}")]
    Decoherence {
        coherence: f64,
        threshold: f64,
    },
}

pub type MptResult<T> = Result<T, MptError>;

// -----------------------------------------------------------------------------
// Core functions
// -----------------------------------------------------------------------------

/// Compute Ethereum‑style ordered MPT root for a list of RLP‑encoded items.
///
/// This is a **quantum measurement** that collapses the trie state to a
/// single 32‑byte fingerprint.
///
/// Ethereum `transactionsRoot` and `receiptsRoot` are ordered tries where:
/// - key = RLP(index)
/// - value = RLP(item)
///
/// # Returns
/// A 32‑byte Keccak‑256 hash of the root node.
pub fn eth_ordered_trie_root(rlp_items: &[Vec<u8>]) -> [u8; HASH_BYTES_LEN] {
    let root = ordered_trie_root::<KeccakHasher, _>(rlp_items.iter().map(|v| v.as_slice()));
    let mut out = [0u8; HASH_BYTES_LEN];
    out.copy_from_slice(root.as_bytes());
    out
}

/// Compute Ethereum‑style ordered MPT root with quantum state tracking.
///
/// Returns both the root hash and the quantum state after computation.
pub fn eth_ordered_trie_root_quantum(rlp_items: &[Vec<u8>]) -> ([u8; HASH_BYTES_LEN], QuantumMptState) {
    let root = eth_ordered_trie_root(rlp_items);
    let leaf_count = rlp_items.len();
    let mut state = QuantumMptState::with_leaves(leaf_count);
    // The root computation itself adds hashing operations
    let hash_count = (leaf_count as u64).max(1) * 2;
    state.apply_bulk_decoherence(hash_count);
    (root, state)
}

/// Compute Ethereum‑style ordered MPT root and return it as a hex string with `0x` prefix.
///
/// # Example
/// ```
/// use iona::rpc::mpt::eth_ordered_trie_root_hex;
///
/// let root_hex = eth_ordered_trie_root_hex(&[]);
/// assert_eq!(root_hex, "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421");
/// ```
pub fn eth_ordered_trie_root_hex(rlp_items: &[Vec<u8>]) -> String {
    let root = eth_ordered_trie_root(rlp_items);
    format!("{}{}", HEX_PREFIX, hex::encode(root))
}

/// Compute the MPT root with full quantum state information.
///
/// Returns a tuple of (hex root string, quantum state).
pub fn eth_ordered_trie_root_hex_quantum(rlp_items: &[Vec<u8>]) -> (String, QuantumMptState) {
    let (root, state) = eth_ordered_trie_root_quantum(rlp_items);
    let hex_str = format!("{}{}", HEX_PREFIX, hex::encode(root));
    (hex_str, state)
}

/// Equivalent to `eth_ordered_trie_root_hex` but returns an empty string on error.
/// This is kept for backward compatibility but not recommended.
#[deprecated(since = "30.0.0", note = "use eth_ordered_trie_root_hex instead")]
pub fn eth_ordered_trie_root_hex_unchecked(rlp_items: &[Vec<u8>]) -> String {
    eth_ordered_trie_root_hex(rlp_items)
}

/// Verify that a computed root matches an expected root (quantum fidelity check).
pub fn verify_mpt_root(computed: &[u8; HASH_BYTES_LEN], expected: &[u8; HASH_BYTES_LEN]) -> bool {
    computed == expected
}

/// Compute the quantum fidelity between two MPT roots.
///
/// ```text
/// F = |⟨root_a|root_b⟩|²
/// ```
/// For deterministic hashes, F = 1.0 if identical, 0.0 otherwise.
pub fn root_fidelity(a: &[u8; HASH_BYTES_LEN], b: &[u8; HASH_BYTES_LEN]) -> f64 {
    if a == b {
        1.0
    } else {
        0.0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // Known empty trie root (Keccak of RLP-encoded empty string).
    const EMPTY_TRIE_ROOT: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_empty_list() {
        let items: Vec<Vec<u8>> = vec![];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert_eq!(root_hex, EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_single_item() {
        let items = vec![b"hello".to_vec()];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert!(root_hex.starts_with("0x"));
        assert_eq!(root_hex.len(), 2 + 2 * HASH_BYTES_LEN);
        assert!(root_hex != EMPTY_TRIE_ROOT);
    }

    #[test]
    fn test_multiple_items() {
        let items = vec![b"a".to_vec(), b"b".to_vec(), b"c".to_vec()];
        let root_hex = eth_ordered_trie_root_hex(&items);
        assert!(root_hex.starts_with("0x"));
        assert_eq!(root_hex.len(), 2 + 2 * HASH_BYTES_LEN);
    }

    #[test]
    fn test_root_bytes() {
        let items: Vec<Vec<u8>> = vec![];
        let root_bytes = eth_ordered_trie_root(&items);
        assert_eq!(root_bytes.len(), HASH_BYTES_LEN);
        let hex_str = hex::encode(root_bytes);
        assert_eq!(format!("0x{}", hex_str), EMPTY_TRIE_ROOT);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumMptState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_quantum_state_with_leaves() {
        let state = QuantumMptState::with_leaves(10);
        assert!(state.purity < 1.0);
        assert!(state.leaf_count == 10);
        assert!(state.total_hashes > 0);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumMptState::new();
        let initial_purity = state.purity;

        state.apply_hash_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_bulk_decoherence() {
        let mut state = QuantumMptState::new();
        let initial_purity = state.purity;

        state.apply_bulk_decoherence(100);
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_hashes, 100);
    }

    #[test]
    fn test_quantum_root_computation() {
        let items: Vec<Vec<u8>> = vec![b"a".to_vec(), b"b".to_vec()];
        let (root, state) = eth_ordered_trie_root_quantum(&items);

        assert_eq!(root.len(), HASH_BYTES_LEN);
        assert!(state.purity < 1.0);
        assert!(state.leaf_count > 0);
    }

    #[test]
    fn test_hex_quantum_root() {
        let items: Vec<Vec<u8>> = vec![b"test".to_vec()];
        let (hex_str, state) = eth_ordered_trie_root_hex_quantum(&items);

        assert!(hex_str.starts_with("0x"));
        assert_eq!(hex_str.len(), 2 + 2 * HASH_BYTES_LEN);
        assert!(state.total_hashes > 0);
    }

    #[test]
    fn test_verify_mpt_root() {
        let items: Vec<Vec<u8>> = vec![];
        let root1 = eth_ordered_trie_root(&items);
        let root2 = eth_ordered_trie_root(&items);

        assert!(verify_mpt_root(&root1, &root2));
    }

    #[test]
    fn test_root_fidelity() {
        let items_a: Vec<Vec<u8>> = vec![b"a".to_vec()];
        let items_b: Vec<Vec<u8>> = vec![b"b".to_vec()];

        let root_a = eth_ordered_trie_root(&items_a);
        let root_b = eth_ordered_trie_root(&items_b);
        let root_a2 = eth_ordered_trie_root(&items_a);

        assert!((root_fidelity(&root_a, &root_a2) - 1.0).abs() < 1e-10);
        assert!((root_fidelity(&root_a, &root_b) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_coherence_validity() {
        let mut state = QuantumMptState::new();
        assert!(state.is_valid);

        // Apply many hashing operations to degrade coherence
        state.apply_bulk_decoherence(10000);
        assert!(!state.is_valid);
    }

    #[test]
    fn test_entropy_increases_with_decoherence() {
        let mut state = QuantumMptState::new();
        let initial_entropy = state.entropy;

        state.apply_bulk_decoherence(1000);
        assert!(state.entropy > initial_entropy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumMptState::new();
        for _ in 0..100000 {
            state.apply_hash_decoherence();
        }
        assert!(state.purity >= 0.0);
    }
}
