//! State trie computation — Quantum Ethereum compatibility.
//!
//! # Quantum State Trie Model
//!
//! The state trie is modelled as a **quantum many-body system** where each
//! account is a quantum state |account_i⟩ in the computational basis. The
//! state root is the **quantum fingerprint** of the entire system after
//! applying the Keccak-256 unitary transformation.
//!
//! # Mathematical Formalism
//!
//! ## State as Quantum Ensemble
//! ```text
//! |Ψ_state⟩ = (1/√N) Σ_i |account_i⟩
//! ρ_state = |Ψ_state⟩⟨Ψ_state|
//! ```
//!
//! ## Hamiltonian for State Operations
//! ```text
//! Ĥ_state = Ĥ_account + Ĥ_storage + Ĥ_root
//!
//! Ĥ_account = Σ_i E_i |account_i⟩⟨account_i|
//! Ĥ_storage = Σ_j g_j a†_j a_j                    (storage oscillator)
//! Ĥ_root    = ω_root |root⟩⟨root|                  (fingerprint observable)
//! ```
//!
//! ## Root Hash as Quantum Fingerprint
//! ```text
//! |root⟩ = H(|Ψ_state⟩) = Keccak256(RLP(trie))
//! ⟨root|root⟩ = 1   (deterministic)
//! ```
//!
//! ## Decoherence from Trie Operations
//! ```text
//! ρ(t) = ρ₀ exp(-γt)
//! where γ is the decoherence rate per hashing/encoding operation.
//! ```

use crate::evm::db::MemDb;
use revm::primitives::{Address, B256, U256};
use sha3::{Digest, Keccak256};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for state trie operations.
const DEFAULT_STATE_COHERENCE: f64 = 1.0;

/// Decoherence rate per hash operation.
const HASH_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per RLP encoding.
const ENCODE_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per trie insertion.
const TRIE_INSERT_DECOHERENCE_RATE: f64 = 0.0002;

/// Minimum coherence threshold for valid state.
const MIN_STATE_COHERENCE: f64 = 0.99;

/// Kraus rank for state trie quantum channels.
const STATE_KRAUS_RANK: usize = 4;

/// Hex prefix for Ethereum‑compatible hex strings.
const HEX_PREFIX: &str = "0x";

/// RLP encoding of an empty string (`0x80`), used for empty byte slices.
const EMPTY_RLP: u8 = 0x80;

/// Known empty trie root (Keccak‑256 of `0x80`) – matches Ethereum spec.
pub const EMPTY_TRIE_ROOT: &str = "0x56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421";

// -----------------------------------------------------------------------------
// Quantum State Trie State
// -----------------------------------------------------------------------------

/// Quantum state of the state trie computation.
///
/// Tracks the density matrix properties during account encoding, storage
/// root calculation, and state root computation.
#[derive(Debug, Clone)]
pub struct QuantumStateTrieState {
    /// Purity γ = Tr(ρ²) of the trie state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the account encoding.
    pub account_coherence: f64,
    /// Entanglement fidelity between accounts and storage.
    pub storage_entanglement: f64,
    /// Number of accounts processed.
    pub account_count: usize,
    /// Number of storage slots processed.
    pub storage_slot_count: usize,
    /// Total hash operations performed.
    pub total_hashes: u64,
    /// Total RLP encode operations performed.
    pub total_encodes: u64,
    /// Whether the state trie is valid (above coherence threshold).
    pub is_valid: bool,
}

impl Default for QuantumStateTrieState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_STATE_COHERENCE,
            entropy: 0.0,
            account_coherence: DEFAULT_STATE_COHERENCE,
            storage_entanglement: DEFAULT_STATE_COHERENCE,
            account_count: 0,
            storage_slot_count: 0,
            total_hashes: 0,
            total_encodes: 0,
            is_valid: true,
        }
    }
}

impl QuantumStateTrieState {
    /// Create a new quantum state trie state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a hash operation.
    pub fn apply_hash_decoherence(&mut self) {
        self.total_hashes = self.total_hashes.wrapping_add(1);
        let decay = (-HASH_DECOHERENCE_RATE).exp();
        self.account_coherence = (self.account_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from an RLP encoding operation.
    pub fn apply_encode_decoherence(&mut self) {
        self.total_encodes = self.total_encodes.wrapping_add(1);
        let decay = (-ENCODE_DECOHERENCE_RATE).exp();
        self.account_coherence = (self.account_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a trie insertion.
    pub fn apply_trie_insert_decoherence(&mut self) {
        let decay = (-TRIE_INSERT_DECOHERENCE_RATE).exp();
        self.account_coherence = (self.account_coherence * decay).clamp(0.0, 1.0);
        self.storage_entanglement = (self.storage_entanglement * decay.sqrt()).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence for processing multiple accounts.
    pub fn apply_account_batch(&mut self, account_count: usize, storage_slot_count: usize) {
        self.account_count = self.account_count.saturating_add(account_count);
        self.storage_slot_count = self.storage_slot_count.saturating_add(storage_slot_count);

        // Hash per account + storage slots
        let total_ops = account_count + storage_slot_count;
        for _ in 0..total_ops {
            self.apply_hash_decoherence();
        }
        // Encodes per account
        for _ in 0..account_count {
            self.apply_encode_decoherence();
        }
        // Trie insertions
        for _ in 0..account_count {
            self.apply_trie_insert_decoherence();
        }
    }

    /// Apply the Kraus channel for state trie operations.
    pub fn apply_state_channel(&mut self) {
        let kraus_factor = (1.0 / STATE_KRAUS_RANK as f64).sqrt();
        self.account_coherence = (self.account_coherence * kraus_factor).clamp(0.0, 1.0);
        self.storage_entanglement = (self.storage_entanglement * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.account_coherence * self.storage_entanglement).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_STATE_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during state trie computation.
#[derive(Debug, Error)]
pub enum StateTrieError {
    #[error("RLP encoding error: {0}")]
    RlpError(String),
    #[error("MPT insertion failed: {0}")]
    TrieInsertion(String),
    #[error("quantum decoherence: state coherence {coherence} below threshold {threshold}")]
    Decoherence {
        coherence: f64,
        threshold: f64,
    },
}

pub type StateTrieResult<T> = Result<T, StateTrieError>;

// -----------------------------------------------------------------------------
// Core helpers
// -----------------------------------------------------------------------------

/// Compute Keccak‑256 hash of data and return as a 32‑byte array.
#[must_use]
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Compute Keccak‑256 hash and return as a hex string with `0x` prefix.
#[must_use]
pub fn keccak_hex(data: &[u8]) -> String {
    format!("{}{}", HEX_PREFIX, hex::encode(keccak256(data)))
}

/// Convert `U256` to minimal big‑endian bytes (trim leading zeros).
/// Returns an empty slice for zero.
#[must_use]
pub fn u256_to_be_trimmed(value: U256) -> Vec<u8> {
    if value == U256::ZERO {
        return vec![];
    }
    let bytes = value.to_be_bytes();
    let start = bytes.iter().position(|&b| b != 0).unwrap_or(0);
    bytes[start..].to_vec()
}

/// RL Еncode an Ethereum account: `[nonce, balance, storageRoot, codeHash]`.
#[must_use]
pub fn rlp_account(
    nonce: u64,
    balance: U256,
    storage_root: [u8; 32],
    code_hash: [u8; 32],
) -> Vec<u8> {
    let mut stream = rlp::RlpStream::new_list(4);
    stream.append(&nonce);
    let bal_bytes = u256_to_be_trimmed(balance);
    if bal_bytes.is_empty() {
        stream.append(&0u8);
    } else {
        stream.append(&bal_bytes.as_slice());
    }
    stream.append(&storage_root.as_slice());
    stream.append(&code_hash.as_slice());
    stream.out().to_vec()
}

/// Compute storage root for a single account from `MemDb` using a simplified hash.
/// Returns the empty trie root if no non‑zero storage entries exist.
#[must_use]
pub fn compute_storage_root(addr: &Address, db: &MemDb) -> [u8; 32] {
    let mut entries: Vec<([u8; 32], [u8; 32])> = db
        .storage
        .iter()
        .filter(|((a, _), _)| a == addr)
        .filter_map(|((_, key), &val)| {
            if val == U256::ZERO {
                return None;
            }
            let key_bytes = key.to_be_bytes();
            let value_bytes = u256_to_be_trimmed(val);
            let mut s = rlp::RlpStream::new();
            s.append(&value_bytes.as_slice());
            let value_rlp = s.out().to_vec();
            let mut value_hash = [0u8; 32];
            let copy_len = value_rlp.len().min(32);
            value_hash[..copy_len].copy_from_slice(&value_rlp[..copy_len]);
            Some((key_bytes, value_hash))
        })
        .collect();

    if entries.is_empty() {
        return empty_trie_root();
    }

    entries.sort_by_key(|(k, _)| *k);

    let mut hasher = Keccak256::new();
    for (key, val) in entries {
        hasher.update(keccak256(&key));
        hasher.update(val);
    }
    hasher.finalize().into()
}

/// Compute storage root with quantum state tracking.
#[must_use]
pub fn compute_storage_root_quantum(
    addr: &Address,
    db: &MemDb,
) -> ([u8; 32], QuantumStateTrieState) {
    let root = compute_storage_root(addr, db);
    let mut state = QuantumStateTrieState::new();

    let slot_count = db
        .storage
        .iter()
        .filter(|((a, _), _)| a == addr)
        .filter(|(_, &val)| val != U256::ZERO)
        .count();

    state.apply_account_batch(0, slot_count);
    (root, state)
}

/// Return the Ethereum empty trie root (Keccak‑256 of `0x80`).
#[must_use]
pub fn empty_trie_root() -> [u8; 32] {
    keccak256(&[EMPTY_RLP])
}

// -----------------------------------------------------------------------------
// State root (conditional feature)
// -----------------------------------------------------------------------------

/// Compute the state root of the entire `MemDb`.
pub fn compute_state_root_hex(db: &MemDb) -> String {
    #[cfg(feature = "state_trie")]
    {
        compute_state_root_hex_mpt(db)
    }
    #[cfg(not(feature = "state_trie"))]
    {
        compute_state_root_hex_simple(db)
    }
}

/// Compute the state root with quantum state tracking.
pub fn compute_state_root_hex_quantum(db: &MemDb) -> (String, QuantumStateTrieState) {
    let root_hex = compute_state_root_hex(db);
    let mut state = QuantumStateTrieState::new();
    state.apply_account_batch(db.accounts.len(), 0);
    (root_hex, state)
}

/// Simplified state root (no MPT).
#[cfg(not(feature = "state_trie"))]
fn compute_state_root_hex_simple(db: &MemDb) -> String {
    let mut items: Vec<Vec<u8>> = db
        .accounts
        .iter()
        .map(|(addr, info)| {
            let storage_root = compute_storage_root(addr, db);
            let code_hash: [u8; 32] = info.code_hash.0;
            rlp_account(info.nonce, info.balance, storage_root, code_hash)
        })
        .collect();

    items.sort();
    let mut hasher = Keccak256::new();
    for item in &items {
        hasher.update(item);
    }
    format!("{}{}", HEX_PREFIX, hex::encode(hasher.finalize()))
}

/// Full MPT state root using `trie-db` (feature‑gated).
#[cfg(feature = "state_trie")]
fn compute_state_root_hex_mpt(db: &MemDb) -> String {
    use hash_db::Hasher;
    use keccak_hasher::KeccakHasher;
    use memory_db::{HashKey, MemoryDB};
    use trie_db::{TrieDBMut, TrieMut};

    let mut memdb: MemoryDB<KeccakHasher, HashKey<_>, Vec<u8>> = MemoryDB::default();
    let mut root = <KeccakHasher as Hasher>::Out::default();

    {
        let mut trie = TrieDBMut::new(&mut memdb, &mut root);
        for (addr, info) in &db.accounts {
            let storage_root = compute_storage_root(addr, db);
            let code_hash: [u8; 32] = info.code_hash.0;
            let account_rlp = rlp_account(info.nonce, info.balance, storage_root, code_hash);
            let key = keccak256(addr.as_slice());
            let _ = trie.insert(&key, &account_rlp);
        }
    }

    format!("{}{}", HEX_PREFIX, hex::encode(root))
}

// -----------------------------------------------------------------------------
// Transactions and receipts roots (delegate to `mpt` module)
// -----------------------------------------------------------------------------

/// Compute receipts root from a list of RLP‑encoded receipts.
pub fn compute_receipts_root_hex(receipt_rlps: &[Vec<u8>]) -> String {
    crate::rpc::mpt::eth_ordered_trie_root_hex(receipt_rlps)
}

/// Compute transactions root from a list of RLP‑encoded transactions.
pub fn compute_txs_root_hex(tx_rlps: &[Vec<u8>]) -> String {
    crate::rpc::mpt::eth_ordered_trie_root_hex(tx_rlps)
}

// -----------------------------------------------------------------------------
// Quantum fidelity helpers
// -----------------------------------------------------------------------------

/// Compute quantum fidelity between two state roots.
///
/// ```text
/// F = |⟨root_a|root_b⟩|²
/// ```
pub fn state_root_fidelity(a: &[u8; 32], b: &[u8; 32]) -> f64 {
    if a == b {
        1.0
    } else {
        0.0
    }
}

/// Compute the fidelity between two storage roots.
pub fn storage_root_fidelity(a: &[u8; 32], b: &[u8; 32]) -> f64 {
    state_root_fidelity(a, b)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn empty_trie_root_matches_ethereum() {
        let root = empty_trie_root();
        assert_eq!(
            hex::encode(root),
            "56e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421"
        );
    }

    #[test]
    fn u256_trimmed_zero() {
        assert!(u256_to_be_trimmed(U256::ZERO).is_empty());
    }

    #[test]
    fn u256_trimmed_one() {
        let trimmed = u256_to_be_trimmed(U256::from(1u64));
        assert_eq!(trimmed, vec![1]);
    }

    #[test]
    fn state_root_empty_db() {
        let db = MemDb::default();
        let root_hex = compute_state_root_hex(&db);
        assert!(root_hex.starts_with(HEX_PREFIX));
        assert_eq!(root_hex.len(), 66);
    }

    #[test]
    fn rlp_account_encoding() {
        let nonce = 42;
        let balance = U256::from(1_000_000);
        let storage_root = [0xAA; 32];
        let code_hash = [0xBB; 32];
        let rlp = rlp_account(nonce, balance, storage_root, code_hash);
        assert!(!rlp.is_empty());
    }

    #[test]
    fn compute_storage_root_empty_account() {
        let db = MemDb::default();
        let addr = Address::new([0x01; 20]);
        let root = compute_storage_root(&addr, &db);
        assert_eq!(root, empty_trie_root());
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumStateTrieState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumStateTrieState::new();
        let initial_purity = state.purity;

        state.apply_hash_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_hashes, 1);
    }

    #[test]
    fn test_encode_decoherence() {
        let mut state = QuantumStateTrieState::new();
        let initial_purity = state.purity;

        state.apply_encode_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_encodes, 1);
    }

    #[test]
    fn test_trie_insert_decoherence() {
        let mut state = QuantumStateTrieState::new();
        let initial_purity = state.purity;

        state.apply_trie_insert_decoherence();
        assert!(state.purity < initial_purity);
        assert!(state.storage_entanglement < 1.0);
    }

    #[test]
    fn test_account_batch() {
        let mut state = QuantumStateTrieState::new();
        let initial_purity = state.purity;

        state.apply_account_batch(10, 5);
        assert!(state.purity < initial_purity);
        assert_eq!(state.account_count, 10);
        assert_eq!(state.storage_slot_count, 5);
        assert!(state.total_hashes > 0);
        assert!(state.total_encodes > 0);
    }

    #[test]
    fn test_state_channel() {
        let mut state = QuantumStateTrieState::new();
        let initial_account_coh = state.account_coherence;

        state.apply_state_channel();
        assert!(state.account_coherence < initial_account_coh);
    }

    #[test]
    fn test_compute_state_root_quantum() {
        let db = MemDb::default();
        let (root_hex, state) = compute_state_root_hex_quantum(&db);

        assert!(root_hex.starts_with(HEX_PREFIX));
        assert!(state.purity < 1.0);
        assert!(state.account_count == 0); // empty DB
    }

    #[test]
    fn test_compute_storage_root_quantum() {
        let db = MemDb::default();
        let addr = Address::new([0x02; 20]);
        let (root, state) = compute_storage_root_quantum(&addr, &db);

        assert_eq!(root, empty_trie_root());
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_state_root_fidelity_identical() {
        let root1 = empty_trie_root();
        let root2 = empty_trie_root();
        assert!((state_root_fidelity(&root1, &root2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_state_root_fidelity_different() {
        let root1 = empty_trie_root();
        let root2 = [0xFF; 32];
        assert!((state_root_fidelity(&root1, &root2) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_coherence_validity() {
        let mut state = QuantumStateTrieState::new();
        assert!(state.is_valid);

        // Many operations degrade coherence
        state.apply_account_batch(10000, 5000);
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumStateTrieState::new();
        for _ in 0..100000 {
            state.apply_hash_decoherence();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_entropy_increases() {
        let mut state = QuantumStateTrieState::new();
        let initial_entropy = state.entropy;

        state.apply_account_batch(100, 50);
        assert!(state.entropy > initial_entropy);
    }
}
