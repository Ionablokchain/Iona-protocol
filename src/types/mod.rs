//! Core data types for IONA blockchain.
//!
//! This module defines the fundamental types used throughout the node:
//! - `Height`, `Round` – block height and consensus round.
//! - `Hash32` – 32‑byte hash wrapper with common traits.
//! - `Tx`, `Receipt`, `BlockHeader`, `Block` – core blockchain structures.
//! - Deterministic hash functions for blocks, transactions, roots.

use serde::{Deserialize, Serialize};
use std::fmt;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Prefix for block ID hashing.
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
// Basic type aliases
// -----------------------------------------------------------------------------

/// Block height (0 = genesis).
pub type Height = u64;

/// Consensus round number.
pub type Round = u32;

// -----------------------------------------------------------------------------
// Hash32 wrapper
// -----------------------------------------------------------------------------

/// A 32‑byte hash value (e.g., Blake3 output).
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Create a zero-filled hash.
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

/// A signed transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    /// Public key of the signer (Ed25519, 32 bytes).
    pub pubkey: Vec<u8>,
    /// Derived address (hex string of blake3(pubkey)[..20]).
    pub from: String,
    /// Sender's nonce (must increase sequentially).
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
}

// -----------------------------------------------------------------------------
// Receipt
// -----------------------------------------------------------------------------

/// Execution receipt for a single transaction.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction.
    pub tx_hash: Hash32,
    /// Whether execution succeeded.
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

/// Header of a block (excludes transactions).
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

/// A complete block with header and transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Compute a deterministic block ID (hash of the raw binary data).
    ///
    /// The format is stable across serialisation changes:
    /// ```text
    /// "IONA_BLK" || height(8 LE) || round(4 LE) || prev(32) ||
    /// proposer_pk_len(2 LE) || proposer_pk || tx_root(32) ||
    /// receipts_root(32) || state_root(32) || base_fee(8 LE) || gas_used(8 LE)
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
// Hashing utilities
// -----------------------------------------------------------------------------

/// Compute a Blake3 hash of arbitrary bytes, returning a `Hash32`.
#[must_use]
pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let h = blake3::hash(b);
    Hash32(*h.as_bytes())
}

/// Deterministic transaction hash (over the content being signed, excluding signature).
///
/// Format:
/// ```text
/// "IONA_TX" || pubkey_len(2 LE) || pubkey || from_len(2 LE) || from ||
/// nonce(8 LE) || max_fee(8 LE) || max_prio(8 LE) || gas_limit(8 LE) ||
/// chain_id(8 LE) || payload_len(4 LE) || payload
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

/// Compute the transaction root hash (Merkle‑like root over all transaction hashes).
///
/// Format: `"IONA_TXROOT" || tx_count(4 LE) || tx_hash0 || tx_hash1 || ...`
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
/// Format per receipt:
/// `tx_hash(32) || success(1) || gas_used(8 LE) || effective_gas_price(8 LE) || burned(8 LE) || tip(8 LE)`
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
}
