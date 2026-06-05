//! Core data types for IONA blockchain — Quantum Type System.
//!
//! # Quantum Type Model
//!
//! Each blockchain primitive (Tx, Block, Receipt) is modelled as a **quantum
//! state** in a computational basis. Hashing functions act as **quantum
//! fingerprints** that project states onto a lower‑dimensional Hilbert space.
//!
//! # Mathematical Formalism
//!
//! ## Types as Quantum States
//! ```text
//! |Tx⟩      = |pubkey⟩ ⊗ |from⟩ ⊗ |nonce⟩ ⊗ |fee⟩ ⊗ |payload⟩
//! |Block⟩   = |header⟩ ⊗ (⊗_i |tx_i⟩)
//! |Receipt⟩ = |tx_hash⟩ ⊗ |success⟩ ⊗ |gas⟩ ⊗ |fee⟩
//! ```
//!
//! ## Hashing as Quantum Fingerprint
//! ```text
//! H(|state⟩) = BLAKE3(encode(|state⟩))
//! |hash⟩ = H(|state⟩) ∈ ℋ_256
//! ```
//!
//! ## Hash32 as Quantum Observable
//! ```text
//! Ô_hash = Σ_h h |h⟩⟨h|
//! ⟨Ô_hash⟩ = Tr(ρ Ô_hash)
//! ```

use serde::{Deserialize, Serialize};
use std::fmt;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for hash operations.
const DEFAULT_HASH_COHERENCE: f64 = 1.0;

/// Decoherence rate per hash operation.
const HASH_DECOHERENCE_RATE: f64 = 0.00001;

/// Minimum coherence threshold for valid hash.
const MIN_HASH_COHERENCE: f64 = 0.99;

/// Kraus rank for hash quantum channels.
const HASH_KRAUS_RANK: usize = 4;

/// Prefix for block ID hashing (quantum subspace tag).
const BLOCK_ID_PREFIX: &[u8] = b"IONA_BLK";

/// Prefix for transaction hash.
const TX_HASH_PREFIX: &[u8] = b"IONA_TX";

/// Prefix for transaction root hash.
const TX_ROOT_PREFIX: &[u8] = b"IONA_TXROOT";

/// Prefix for receipts root hash.
const RECEIPTS_ROOT_PREFIX: &[u8] = b"IONA_RCPROOT";

/// Default chain ID (iona-testnet-1).
const DEFAULT_CHAIN_ID: u64 = 6126151;

/// Default protocol version (initial version).
const DEFAULT_PROTOCOL_VERSION: u32 = 1;

// -----------------------------------------------------------------------------
// Quantum Hash State
// -----------------------------------------------------------------------------

/// Quantum state of a hash operation.
///
/// Tracks the density matrix properties during hashing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumHashState {
    /// Purity γ = Tr(ρ²) of the hash state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the hash operation.
    pub hash_coherence: f64,
    /// Number of bytes hashed.
    pub bytes_hashed: u64,
    /// Whether the hash state is valid.
    pub is_valid: bool,
}

impl Default for QuantumHashState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_HASH_COHERENCE,
            entropy: 0.0,
            hash_coherence: DEFAULT_HASH_COHERENCE,
            bytes_hashed: 0,
            is_valid: true,
        }
    }
}

impl QuantumHashState {
    /// Create a new quantum hash state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from hashing bytes.
    pub fn apply_hash_decoherence(&mut self, byte_count: usize) {
        self.bytes_hashed = self.bytes_hashed.wrapping_add(byte_count as u64);
        let decay = (-HASH_DECOHERENCE_RATE * byte_count as f64).exp();
        self.hash_coherence = (self.hash_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply Kraus channel for hash operations.
    pub fn apply_hash_channel(&mut self) {
        let kraus_factor = (1.0 / HASH_KRAUS_RANK as f64).sqrt();
        self.hash_coherence = (self.hash_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.hash_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_HASH_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Basic type aliases
// -----------------------------------------------------------------------------

/// Block height (0 = genesis).
pub type Height = u64;

/// Consensus round number.
pub type Round = u32;

// -----------------------------------------------------------------------------
// Hash32 wrapper
// -----------------------------------------------------------------------------

/// A 32‑byte hash value — quantum fingerprint in ℋ_256.
///
/// Each Hash32 is a **projection** of a classical state onto the
/// 256‑bit hash subspace:
/// ```text
/// |hash⟩ = H(|state⟩) = BLAKE3(encode(|state⟩))
/// ```
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Create a zero‑filled hash (vacuum state |∅⟩).
    #[must_use]
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Create a hash from a 32‑byte array.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the inner bytes as a slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Return a mutable reference to the inner bytes.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Quantum fidelity between two hashes.
    ///
    /// ```text
    /// F = |⟨hash_a|hash_b⟩|² = δ(hash_a, hash_b)
    /// ```
    pub fn fidelity(&self, other: &Hash32) -> f64 {
        if self.0 == other.0 {
            1.0
        } else {
            0.0
        }
    }
}

impl fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash32({})", hex::encode(&self.0[..8]))
    }
}

impl fmt::Display for Hash32 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(&self.0[..8]))
    }
}

impl From<[u8; 32]> for Hash32 {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl AsRef<[u8]> for Hash32 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

// -----------------------------------------------------------------------------
// Transaction
// -----------------------------------------------------------------------------

/// A signed transaction — quantum state |Tx⟩.
///
/// ```text
/// |Tx⟩ = |pubkey⟩ ⊗ |from⟩ ⊗ |nonce⟩ ⊗ |fee⟩ ⊗ |gas⟩ ⊗ |payload⟩ ⊗ |sig⟩
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    /// Public key of the signer (Ed25519, 32 bytes).
    pub pubkey: Vec<u8>,
    /// Derived address (hex string of blake3(pubkey)[..20]).
    pub from: String,
    /// Sender's nonce (must increase sequentially — quantum number).
    pub nonce: u64,
    /// Maximum fee per gas (EIP‑1559).
    pub max_fee_per_gas: u64,
    /// Maximum priority fee per gas (tip to proposer).
    pub max_priority_fee_per_gas: u64,
    /// Gas limit for this transaction.
    pub gas_limit: u64,
    /// Transaction payload (e.g., "set key value", "vm deploy ...", "stake ...").
    pub payload: String,
    /// Ed25519 signature (64 bytes).
    pub signature: Vec<u8>,
    /// Chain ID (prevents replay across chains).
    pub chain_id: u64,
}

impl Tx {
    /// Check if the public key has the correct length (Ed25519 = 32 bytes).
    pub fn valid_pubkey_len(&self) -> bool {
        self.pubkey.len() == 32
    }

    /// Check if the signature has the correct length (Ed25519 = 64 bytes).
    pub fn valid_signature_len(&self) -> bool {
        self.signature.len() == 64
    }

    /// Quantum purity proxy — higher for valid transactions.
    pub fn quantum_purity(&self) -> f64 {
        let mut purity = 1.0;
        if !self.valid_pubkey_len() {
            purity *= 0.5;
        }
        if !self.valid_signature_len() {
            purity *= 0.5;
        }
        if self.payload.is_empty() {
            purity *= 0.9;
        }
        purity
    }
}

// -----------------------------------------------------------------------------
// Receipt
// -----------------------------------------------------------------------------

/// Execution receipt — quantum measurement outcome |Receipt⟩.
///
/// ```text
/// |Receipt⟩ = |tx_hash⟩ ⊗ |success⟩ ⊗ |gas_used⟩ ⊗ |fee⟩
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction.
    pub tx_hash: Hash32,
    /// Whether execution succeeded (eigenvalue: 1 = success, 0 = failure).
    pub success: bool,
    /// Total gas used (intrinsic + execution).
    pub gas_used: u64,
    /// Intrinsic cost (signature, envelope, etc.).
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    /// Execution gas (KV operations, VM, EVM).
    #[serde(default)]
    pub exec_gas_used: u64,
    /// VM‑specific gas (only for custom VM calls).
    #[serde(default)]
    pub vm_gas_used: u64,
    /// EVM‑specific gas (only for EVM calls).
    #[serde(default)]
    pub evm_gas_used: u64,
    /// Effective gas price paid (base_fee + tip).
    pub effective_gas_price: u64,
    /// Amount of base fee burned.
    pub burned: u64,
    /// Tip paid to the block proposer.
    pub tip: u64,
    /// Optional error message (on failure).
    pub error: Option<String>,
    /// Optional extra data (contract address on deploy, return data on call).
    pub data: Option<String>,
}

// -----------------------------------------------------------------------------
// BlockHeader
// -----------------------------------------------------------------------------

/// Header of a block — quantum observable eigenvalues.
///
/// ```text
/// |BlockHeader⟩ = |height⟩ ⊗ |round⟩ ⊗ |prev⟩ ⊗ |roots⟩ ⊗ |fees⟩
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    pub height: Height,
    pub round: Round,
    pub prev: Hash32,
    pub proposer_pk: Vec<u8>,
    pub tx_root: Hash32,
    pub receipts_root: Hash32,
    pub state_root: Hash32,
    pub base_fee_per_gas: u64,
    pub gas_used: u64,
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    #[serde(default)]
    pub exec_gas_used: u64,
    #[serde(default)]
    pub vm_gas_used: u64,
    #[serde(default)]
    pub evm_gas_used: u64,
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
}

// -----------------------------------------------------------------------------
// Block
// -----------------------------------------------------------------------------

/// A complete block — tensor product of header and transactions.
///
/// ```text
/// |Block⟩ = |header⟩ ⊗ (⊗_i |tx_i⟩)
/// ```
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Compute a deterministic block ID — quantum fingerprint.
    ///
    /// ```text
    /// |block_id⟩ = H(|Block⟩) = BLAKE3(encode(|header⟩))
    /// ```
    #[must_use]
    pub fn id(&self) -> Hash32 {
        let h = &self.header;
        let mut buf = Vec::with_capacity(
            8 + 8 + 4 + 32 + 2 + h.proposer_pk.len() + 32 + 32 + 32 + 8 + 8,
        );
        buf.extend_from_slice(BLOCK_ID_PREFIX);
        buf.extend_from_slice(&h.height.to_le_bytes());
        buf.extend_from_slice(&h.round.to_le_bytes());
        buf.extend_from_slice(&h.prev.0);
        buf.extend_from_slice(&(h.proposer_pk.len() as u16).to_le_bytes());
        buf.extend_from_slice(&h.proposer_pk);
        buf.extend_from_slice(&h.tx_root.0);
        buf.extend_from_slice(&h.receipts_root.0);
        buf.extend_from_slice(&h.state_root.0);
        buf.extend_from_slice(&h.base_fee_per_gas.to_le_bytes());
        buf.extend_from_slice(&h.gas_used.to_le_bytes());
        hash_bytes(&buf)
    }
}

// -----------------------------------------------------------------------------
// Hashing utilities (with quantum tracking)
// -----------------------------------------------------------------------------

/// Compute a Blake3 hash of arbitrary bytes, returning a `Hash32`.
#[must_use]
pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let h = blake3::hash(b);
    Hash32(*h.as_bytes())
}

/// Compute hash with quantum state tracking.
#[must_use]
pub fn hash_bytes_quantum(b: &[u8]) -> (Hash32, QuantumHashState) {
    let hash = hash_bytes(b);
    let mut state = QuantumHashState::new();
    state.apply_hash_decoherence(b.len());
    state.apply_hash_channel();
    (hash, state)
}

/// Deterministic transaction hash (over the content being signed, excluding signature).
///
/// ```text
/// |tx_hash⟩ = H("IONA_TX" || pubkey_len || pubkey || from_len || from ||
///                nonce || max_fee || max_prio || gas_limit || chain_id ||
///                payload_len || payload)
/// ```
#[must_use]
pub fn tx_hash(tx: &Tx) -> Hash32 {
    let payload_bytes = tx.payload.as_bytes();
    let from_bytes = tx.from.as_bytes();
    let mut buf = Vec::with_capacity(
        7 + 2 + tx.pubkey.len() + 2 + from_bytes.len() + 8 * 5 + 4 + payload_bytes.len(),
    );
    buf.extend_from_slice(TX_HASH_PREFIX);
    buf.extend_from_slice(&(tx.pubkey.len() as u16).to_le_bytes());
    buf.extend_from_slice(&tx.pubkey);
    buf.extend_from_slice(&(from_bytes.len() as u16).to_le_bytes());
    buf.extend_from_slice(from_bytes);
    buf.extend_from_slice(&tx.nonce.to_le_bytes());
    buf.extend_from_slice(&tx.max_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&tx.max_priority_fee_per_gas.to_le_bytes());
    buf.extend_from_slice(&tx.gas_limit.to_le_bytes());
    buf.extend_from_slice(&tx.chain_id.to_le_bytes());
    buf.extend_from_slice(&(payload_bytes.len() as u32).to_le_bytes());
    buf.extend_from_slice(payload_bytes);
    hash_bytes(&buf)
}

/// Compute tx hash with quantum state tracking.
#[must_use]
pub fn tx_hash_quantum(tx: &Tx) -> (Hash32, QuantumHashState) {
    let hash = tx_hash(tx);
    let mut state = QuantumHashState::new();
    let byte_count = 7 + 2 + tx.pubkey.len() + 2 + tx.from.len() + 8 * 5 + 4 + tx.payload.len();
    state.apply_hash_decoherence(byte_count);
    state.apply_hash_channel();
    (hash, state)
}

/// Compute the transaction root hash (Merkle‑like root over all transaction hashes).
///
/// ```text
/// |tx_root⟩ = H("IONA_TXROOT" || tx_count || tx_hash_0 || tx_hash_1 || ...)
/// ```
#[must_use]
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TX_ROOT_PREFIX);
    hasher.update(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        let h = tx_hash(tx);
        hasher.update(&h.0);
    }
    let h = hasher.finalize();
    Hash32(*h.as_bytes())
}

/// Compute the receipts root hash over all receipts.
///
/// ```text
/// |receipts_root⟩ = H("IONA_RCPROOT" || receipt_count || receipt_0 || ...)
/// ```
#[must_use]
pub fn receipts_root(receipts: &[Receipt]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(RECEIPTS_ROOT_PREFIX);
    hasher.update(&(receipts.len() as u32).to_le_bytes());
    for r in receipts {
        hasher.update(&r.tx_hash.0);
        hasher.update(&[r.success as u8]);
        hasher.update(&r.gas_used.to_le_bytes());
        hasher.update(&r.effective_gas_price.to_le_bytes());
        hasher.update(&r.burned.to_le_bytes());
        hasher.update(&r.tip.to_le_bytes());
    }
    let h = hasher.finalize();
    Hash32(*h.as_bytes())
}

// -----------------------------------------------------------------------------
// Default values helpers
// -----------------------------------------------------------------------------

#[inline]
const fn default_chain_id() -> u64 {
    DEFAULT_CHAIN_ID
}

#[inline]
const fn default_protocol_version() -> u32 {
    DEFAULT_PROTOCOL_VERSION
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx() -> Tx {
        Tx {
            pubkey: vec![0xAA; 32],
            from: "test_addr".into(),
            nonce: 42,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: "set a b".into(),
            signature: vec![0xBB; 64],
            chain_id: 1,
        }
    }

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_hash32_zero() {
        let zero = Hash32::zero();
        assert_eq!(zero.0, [0u8; 32]);
    }

    #[test]
    fn test_tx_hash_deterministic() {
        let tx1 = dummy_tx();
        let tx2 = dummy_tx();
        assert_eq!(tx_hash(&tx1), tx_hash(&tx2));
    }

    #[test]
    fn test_tx_root_deterministic() {
        let txs = vec![dummy_tx(), dummy_tx()];
        let root1 = tx_root(&txs);
        let root2 = tx_root(&txs);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_receipts_root_deterministic() {
        let receipt = Receipt {
            tx_hash: Hash32::zero(),
            success: true,
            gas_used: 1000,
            intrinsic_gas_used: 21000,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            effective_gas_price: 1,
            burned: 1,
            tip: 0,
            error: None,
            data: None,
        };
        let receipts = vec![receipt.clone(), receipt];
        let root1 = receipts_root(&receipts);
        let root2 = receipts_root(&receipts);
        assert_eq!(root1, root2);
    }

    #[test]
    fn test_block_id_deterministic() {
        let header = BlockHeader {
            height: 100,
            round: 5,
            prev: Hash32::zero(),
            proposer_pk: vec![0xAA; 32],
            tx_root: Hash32::zero(),
            receipts_root: Hash32::zero(),
            state_root: Hash32::zero(),
            base_fee_per_gas: 1,
            gas_used: 0,
            intrinsic_gas_used: 0,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            chain_id: DEFAULT_CHAIN_ID,
            timestamp: 123456,
            protocol_version: DEFAULT_PROTOCOL_VERSION,
        };
        let block = Block {
            header: header.clone(),
            txs: vec![],
        };
        let id1 = block.id();
        let block2 = Block { header, txs: vec![] };
        let id2 = block2.id();
        assert_eq!(id1, id2);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_hash_state_initialization() {
        let state = QuantumHashState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_hash_decoherence() {
        let mut state = QuantumHashState::new();
        let initial_purity = state.purity;

        state.apply_hash_decoherence(1000);
        assert!(state.purity < initial_purity);
        assert_eq!(state.bytes_hashed, 1000);
    }

    #[test]
    fn test_hash_channel() {
        let mut state = QuantumHashState::new();
        let initial_coherence = state.hash_coherence;

        state.apply_hash_channel();
        assert!(state.hash_coherence < initial_coherence);
    }

    #[test]
    fn test_hash_bytes_quantum() {
        let data = b"test data for quantum hashing";
        let (hash, state) = hash_bytes_quantum(data);

        assert_eq!(hash.0.len(), 32);
        assert!(state.bytes_hashed > 0);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_tx_hash_quantum() {
        let tx = dummy_tx();
        let (hash, state) = tx_hash_quantum(&tx);

        assert_eq!(hash.0.len(), 32);
        assert!(state.bytes_hashed > 0);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_hash_fidelity_identical() {
        let h1 = Hash32::from_bytes([0xAA; 32]);
        let h2 = Hash32::from_bytes([0xAA; 32]);
        assert!((h1.fidelity(&h2) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_hash_fidelity_different() {
        let h1 = Hash32::from_bytes([0xAA; 32]);
        let h2 = Hash32::from_bytes([0xBB; 32]);
        assert!((h1.fidelity(&h2) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_tx_quantum_purity() {
        let mut tx = dummy_tx();
        assert!(tx.quantum_purity() > 0.99);

        tx.pubkey = vec![0xCC; 31]; // invalid length
        assert!(tx.quantum_purity() < 1.0);

        tx.signature = vec![0xDD; 63]; // invalid length
        assert!(tx.quantum_purity() < 0.5);
    }

    #[test]
    fn test_health_after_many_hashes() {
        let mut state = QuantumHashState::new();
        assert!(state.is_valid);

        for _ in 0..10000 {
            state.apply_hash_decoherence(1000);
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumHashState::new();
        for _ in 0..100000 {
            state.apply_hash_decoherence(1000);
        }
        assert!(state.purity >= 0.0);
    }
}
