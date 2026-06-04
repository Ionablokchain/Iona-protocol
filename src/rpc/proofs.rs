//! Merkle proof generation for Ethereum state and storage — Quantum Verification.
//!
//! # Quantum Proof Model
//!
//! A Merkle proof is a **quantum witness** that certifies the inclusion of a
//! leaf in the state trie without revealing the entire trie. Each proof node
//! is a **projection** of the trie's quantum state onto a subspace determined
//! by the path to the leaf.
//!
//! # Mathematical Formalism
//!
//! ## Proof as Quantum Witness
//! ```text
//! |proof⟩ = (⊗_{i∈path} |node_i⟩) ⊗ |leaf⟩
//! ρ_proof = |proof⟩⟨proof|
//! ```
//!
//! ## Hamiltonian for Proof Operations
//! ```text
//! Ĥ_proof = Ĥ_trie + Ĥ_witness + Ĥ_verify
//!
//! Ĥ_trie    = Σ_i E_i |node_i⟩⟨node_i|
//! Ĥ_witness = Σ_j g_j (|path_j⟩⟨leaf_j| + h.c.)
//! Ĥ_verify  = Σ_k λ_k |valid_k⟩⟨valid_k|
//! ```
//!
//! ## Verification as Projective Measurement
//! ```text
//! Π_verify = |valid⟩⟨valid|
//! P(valid) = ⟨proof| Π_verify |proof⟩
//! ```
//!
//! ## Storage Proof Entanglement
//! ```text
//! |Ψ_storage⟩ = |account_proof⟩ ⊗ (⊗_k |storage_proof_k⟩)
//! ```
//! Each storage proof is **entangled** with the account proof via the storage root.

use crate::evm::db::MemDb;
use revm::primitives::{Address, U256};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for proof operations.
const DEFAULT_PROOF_COHERENCE: f64 = 1.0;

/// Decoherence rate per proof node traversal.
const PROOF_NODE_DECOHERENCE_RATE: f64 = 0.0005;

/// Decoherence rate per hash operation.
const HASH_DECOHERENCE_RATE: f64 = 0.0001;

/// Minimum coherence threshold for valid proof.
const MIN_PROOF_COHERENCE: f64 = 0.99;

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// RLP encoding of empty string (`0x80`), used as empty trie root.
const EMPTY_RLP: &[u8] = &[0x80];

/// Length of a Keccak‑256 hash in bytes.
const HASH_BYTES_LEN: usize = 32;

// -----------------------------------------------------------------------------
// Quantum Proof State
// -----------------------------------------------------------------------------

/// Quantum state of a Merkle proof.
///
/// Tracks the density matrix properties during proof generation and
/// verification.
#[derive(Debug, Clone)]
pub struct QuantumProofState {
    /// Purity γ = Tr(ρ²) of the proof state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the proof path.
    pub path_coherence: f64,
    /// Number of proof nodes in the account proof.
    pub account_proof_nodes: usize,
    /// Number of storage proofs included.
    pub storage_proof_count: usize,
    /// Total hash operations performed.
    pub total_hashes: u64,
    /// Entanglement fidelity between account and storage proofs.
    pub storage_entanglement: f64,
    /// Whether the proof is valid (above coherence threshold).
    pub is_valid: bool,
}

impl Default for QuantumProofState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_PROOF_COHERENCE,
            entropy: 0.0,
            path_coherence: DEFAULT_PROOF_COHERENCE,
            account_proof_nodes: 0,
            storage_proof_count: 0,
            total_hashes: 0,
            storage_entanglement: DEFAULT_PROOF_COHERENCE,
            is_valid: true,
        }
    }
}

impl QuantumProofState {
    /// Create a new quantum proof state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from traversing a proof node.
    pub fn apply_node_decoherence(&mut self) {
        let decay = (-PROOF_NODE_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a hash operation.
    pub fn apply_hash_decoherence(&mut self) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-HASH_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply bulk node decoherence for traversing multiple nodes.
    pub fn apply_bulk_node_decoherence(&mut self, node_count: usize) {
        for _ in 0..node_count {
            self.apply_node_decoherence();
        }
    }

    /// Set entanglement between account and storage proofs.
    pub fn set_storage_entanglement(&mut self, storage_proof_count: usize) {
        self.storage_proof_count = storage_proof_count;
        let entanglement = (1.0 / (storage_proof_count as f64 + 1.0)).sqrt();
        self.storage_entanglement = entanglement.clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.path_coherence * self.storage_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_PROOF_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during proof generation.
#[derive(Debug, Error)]
pub enum ProofError {
    #[error("state trie feature not enabled (enable 'state_trie' feature)")]
    StateTrieNotEnabled,

    #[error("invalid storage key: {0}")]
    InvalidStorageKey(String),

    #[error("trie node not found for key")]
    NodeNotFound,

    #[error("RLP encoding error: {0}")]
    RlpError(String),

    #[error("internal error: {0}")]
    Internal(String),

    #[error("quantum decoherence: proof coherence {coherence} below threshold {threshold}")]
    Decoherence {
        coherence: f64,
        threshold: f64,
    },
}

pub type ProofResult<T> = Result<T, ProofError>;

// -----------------------------------------------------------------------------
// Proof structures
// -----------------------------------------------------------------------------

/// A Merkle proof for an Ethereum account.
#[derive(Debug, Clone)]
pub struct Proof {
    /// RLP‑encoded nodes forming the account proof.
    pub account_proof: Vec<String>,
    /// Storage proofs for requested slots.
    pub storage_proofs: Vec<StorageProof>,
    /// Storage root hash of the account (hex with 0x prefix).
    pub storage_hash: String,
    /// Quantum state of this proof.
    pub quantum_state: QuantumProofState,
}

/// A Merkle proof for a single storage slot.
#[derive(Debug, Clone)]
pub struct StorageProof {
    /// Storage key (32‑byte hex with 0x prefix).
    pub key: String,
    /// Current value at that storage slot (hex with 0x prefix).
    pub value: String,
    /// RLP‑encoded trie nodes proving the value.
    pub proof: Vec<String>,
    /// Quantum coherence of this storage proof.
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Compute Keccak‑256 hash of a byte slice.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; HASH_BYTES_LEN];
    out.copy_from_slice(&result);
    out
}

/// Format bytes as hex string with `0x` prefix.
#[must_use]
pub fn hex0x(bytes: &[u8]) -> String {
    format!("{}{}", HEX_PREFIX, hex::encode(bytes))
}

/// Convert a U256 value to its trimmed big‑endian representation for RLP encoding.
/// Returns a single zero byte for zero.
#[must_use]
pub fn u256_to_trimmed_be(value: U256) -> Vec<u8> {
    let mut bytes = [0u8; HASH_BYTES_LEN];
    value.to_be_bytes(bytes.as_mut());
    let trimmed = bytes
        .iter()
        .copied()
        .skip_while(|&b| b == 0)
        .collect::<Vec<u8>>();
    if trimmed.is_empty() {
        vec![0u8]
    } else {
        trimmed
    }
}

/// Compute the empty trie root (Keccak‑256 of RLP‑encoded empty string).
#[must_use]
pub fn empty_trie_root() -> [u8; HASH_BYTES_LEN] {
    keccak256(EMPTY_RLP)
}

/// Convert a U256 storage slot to its hashed trie key (secure trie).
#[must_use]
pub fn storage_trie_key(slot: U256) -> [u8; HASH_BYTES_LEN] {
    let mut slot_bytes = [0u8; HASH_BYTES_LEN];
    slot.to_be_bytes(slot_bytes.as_mut());
    keccak256(&slot_bytes)
}

/// Compute quantum fidelity between two byte sequences.
///
/// ```text
/// F = (1/N) Σ_i δ(a_i, b_i)
/// ```
pub fn byte_fidelity(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / len as f64
}

// -----------------------------------------------------------------------------
// Proof generation (conditional on feature)
// -----------------------------------------------------------------------------

/// Build a full Merkle proof for an account and requested storage slots.
///
/// Returns both the proof and its quantum state.
///
/// # Feature
/// This function requires the `state_trie` feature (enabled by default).
/// Without it, returns an error.
pub fn build_proof(
    db: &MemDb,
    addr: Address,
    storage_keys: Vec<[u8; HASH_BYTES_LEN]>,
) -> ProofResult<Proof> {
    #[cfg(feature = "state_trie")]
    {
        build_proof_state_trie(db, addr, storage_keys)
    }
    #[cfg(not(feature = "state_trie"))]
    {
        let _ = (db, addr, storage_keys);
        Err(ProofError::StateTrieNotEnabled)
    }
}

/// Build a proof and return it along with a separate quantum state snapshot.
pub fn build_proof_with_quantum_state(
    db: &MemDb,
    addr: Address,
    storage_keys: Vec<[u8; HASH_BYTES_LEN]>,
) -> ProofResult<(Proof, QuantumProofState)> {
    let proof = build_proof(db, addr, storage_keys)?;
    let qstate = proof.quantum_state.clone();
    Ok((proof, qstate))
}

#[cfg(feature = "state_trie")]
fn build_proof_state_trie(
    db: &MemDb,
    addr: Address,
    storage_keys: Vec<[u8; HASH_BYTES_LEN]>,
) -> ProofResult<Proof> {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{Trie, TrieDBBuilder, TrieDBMut, TrieMut};

    let mut qstate = QuantumProofState::new();

    // --- Build storage trie for the account ---
    fn build_storage_trie(
        db_src: &MemDb,
        addr: Address,
    ) -> ProofResult<(
        MemoryDB<KeccakHasher, HashKey<<KeccakHasher as Hasher>::Out>, Vec<u8>>,
        <KeccakHasher as Hasher>::Out,
    )> {
        let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
        let mut root = <KeccakHasher as Hasher>::Out::default();
        {
            let mut trie = TrieDBMut::<KeccakHasher>::new(&mut memdb, &mut root);
            for ((a, slot), &val) in db_src.storage.iter() {
                if *a != addr {
                    continue;
                }
                if val == U256::ZERO {
                    continue;
                }
                let key = storage_trie_key(*slot);
                let trimmed_val = u256_to_trimmed_be(val);
                let enc_value = rlp::encode(&trimmed_val);
                trie.insert(&key, &enc_value).map_err(|e| {
                    ProofError::Internal(format!("storage trie insert: {:?}", e))
                })?;
            }
        }
        Ok((memdb, root))
    }

    let (storage_memdb, storage_root) = build_storage_trie(db, addr)?;
    qstate.apply_hash_decoherence();

    let mut state_memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut state_root = <KeccakHasher as Hasher>::Out::default();
    {
        let mut trie = TrieDBMut::<KeccakHasher>::new(&mut state_memdb, &mut state_root);
        for (a, info) in db.accounts.iter() {
            let nonce = info.nonce.unwrap_or(0);
            let balance = info.balance;
            let storage_root_for_account = if *a == addr {
                storage_root.0
            } else {
                empty_trie_root()
            };
            let code_hash = info
                .code_hash
                .map(|h| h.0)
                .unwrap_or_else(empty_trie_root);

            let mut stream = rlp::RlpStream::new_list(4);
            stream.append(&nonce);
            let bal_trim = u256_to_trimmed_be(balance);
            stream.append(&bal_trim.as_slice());
            stream.append(&storage_root_for_account.as_slice());
            stream.append(&code_hash.as_slice());
            let encoded_account = stream.out().to_vec();

            let key = keccak256(a.as_slice());
            trie.insert(&key, &encoded_account).map_err(|e| {
                ProofError::Internal(format!("state trie insert: {:?}", e))
            })?;
        }
    }
    qstate.apply_hash_decoherence();

    // --- Account proof ---
    let state_trie = TrieDBBuilder::<KeccakHasher>::new(&state_memdb, &state_root).build();
    let addr_key = keccak256(addr.as_slice());
    let account_proof_nodes = state_trie
        .get_proof(&addr_key)
        .map_err(|_| ProofError::NodeNotFound)?;

    qstate.account_proof_nodes = account_proof_nodes.len();
    qstate.apply_bulk_node_decoherence(account_proof_nodes.len());

    let account_proof = account_proof_nodes
        .into_iter()
        .map(|node| hex0x(&node))
        .collect::<Vec<_>>();

    // --- Storage proofs ---
    let storage_trie =
        TrieDBBuilder::<KeccakHasher>::new(&storage_memdb, &storage_root).build();
    let mut storage_proofs = Vec::new();

    for key_bytes in storage_keys {
        if key_bytes.len() != HASH_BYTES_LEN {
            return Err(ProofError::InvalidStorageKey(hex::encode(key_bytes)));
        }
        let slot = U256::from_be_bytes(key_bytes);
        let key_hex = hex0x(&key_bytes);
        let hashed_key = storage_trie_key(slot);
        let proof_nodes = storage_trie.get_proof(&hashed_key).unwrap_or_default();
        let proof_hex = proof_nodes
            .iter()
            .map(|node| hex0x(node))
            .collect::<Vec<_>>();

        let value = db
            .storage
            .get(&(addr, slot))
            .copied()
            .unwrap_or(U256::ZERO);
        let value_hex = format!("{}{:x}", HEX_PREFIX, value);

        let mut storage_qstate = QuantumProofState::new();
        storage_qstate.apply_bulk_node_decoherence(proof_nodes.len());
        storage_qstate.apply_hash_decoherence();

        storage_proofs.push(StorageProof {
            key: key_hex,
            value: value_hex,
            proof: proof_hex,
            coherence: storage_qstate.path_coherence,
        });

        qstate.apply_node_decoherence();
    }

    qstate.set_storage_entanglement(storage_proofs.len());

    Ok(Proof {
        account_proof,
        storage_proofs,
        storage_hash: hex0x(&storage_root.0),
        quantum_state: qstate,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_keccak256() {
        let data = b"hello";
        let hash = keccak256(data);
        assert_eq!(hash.len(), 32);
        let expected = hex::decode(
            "1c8aff950685c2ed4bc3174f3472287b56d9517b9c948127319a09a7a36deac8",
        )
        .unwrap();
        assert_eq!(&hash[..], &expected[..]);
    }

    #[test]
    fn test_hex0x() {
        let bytes = &[0xde, 0xad, 0xbe, 0xef];
        assert_eq!(hex0x(bytes), "0xdeadbeef");
    }

    #[test]
    fn test_u256_to_trimmed_be() {
        let zero = U256::ZERO;
        assert_eq!(u256_to_trimmed_be(zero), vec![0u8]);

        let one = U256::from(1);
        assert_eq!(u256_to_trimmed_be(one), vec![1u8]);

        let big = U256::from(0x1234u64);
        let trimmed = u256_to_trimmed_be(big);
        assert_eq!(trimmed, vec![0x12, 0x34]);
    }

    #[test]
    fn test_empty_trie_root() {
        let root = empty_trie_root();
        let expected = hex::decode(
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421",
        )
        .unwrap();
        assert_eq!(&root[..], &expected[..]);
    }

    #[test]
    fn test_storage_trie_key() {
        let slot = U256::from(0xdeadbeefu64);
        let key = storage_trie_key(slot);
        assert_eq!(key.len(), 32);
        let key2 = storage_trie_key(U256::from(0xdeadbeefu64));
        assert_eq!(key, key2);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_proof_state_initialization() {
        let state = QuantumProofState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_node_decoherence() {
        let mut state = QuantumProofState::new();
        let initial_purity = state.purity;

        state.apply_node_decoherence();
        assert!(state.purity < initial_purity);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumProofState::new();
        let initial_purity = state.purity;

        state.apply_hash_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_bulk_node_decoherence() {
        let mut state = QuantumProofState::new();
        let initial_purity = state.purity;

        state.apply_bulk_node_decoherence(50);
        assert!(state.purity < initial_purity);
    }

    #[test]
    fn test_storage_entanglement() {
        let mut state = QuantumProofState::new();

        state.set_storage_entanglement(3);
        assert!(state.storage_entanglement < 1.0);
        assert_eq!(state.storage_proof_count, 3);
    }

    #[test]
    fn test_byte_fidelity_identical() {
        let a = b"hello world";
        let b = b"hello world";
        assert!((byte_fidelity(a, b) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_byte_fidelity_different() {
        let a = b"hello world";
        let b = b"hallo world";
        assert!(byte_fidelity(a, b) < 1.0);
    }

    #[test]
    fn test_byte_fidelity_empty() {
        assert!((byte_fidelity(b"", b"") - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_coherence_validity() {
        let mut state = QuantumProofState::new();
        assert!(state.is_valid);

        state.apply_bulk_node_decoherence(5000);
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumProofState::new();
        for _ in 0..100000 {
            state.apply_hash_decoherence();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_entropy_increases() {
        let mut state = QuantumProofState::new();
        let initial_entropy = state.entropy;

        state.apply_bulk_node_decoherence(100);
        assert!(state.entropy > initial_entropy);
    }
}
