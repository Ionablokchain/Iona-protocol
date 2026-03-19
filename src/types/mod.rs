//! Core data types for the Iona blockchain.
//!
//! This module defines the fundamental structures used throughout the protocol:
//! - `Hash32`: A 32-byte cryptographic hash
//! - `Tx`: A transaction
//! - `Receipt`: Execution receipt for a transaction
//! - `BlockHeader`: Header of a block
//! - `Block`: A complete block containing transactions
//!
//! All hashing functions are designed to be deterministic and stable across
//! platforms, Rust versions, and serialization formats. They use fixed binary
//! encodings (not JSON) to ensure consensus-critical reproducibility.

use serde::{Deserialize, Serialize};

// Re-export submodules
pub mod tx_vm;
pub mod tx_evm;

// ------------------------------
// Constants for hash domain separation
// ------------------------------

/// Prefix for block ID hash.
const BLOCK_ID_PREFIX: &[u8; 8] = b"IONA_BLK";

/// Prefix for transaction hash.
const TX_HASH_PREFIX: &[u8; 7] = b"IONA_TX";

/// Prefix for transaction root hash.
const TX_ROOT_PREFIX: &[u8; 11] = b"IONA_TXROOT";

/// Prefix for receipts root hash.
const RECEIPTS_ROOT_PREFIX: &[u8; 12] = b"IONA_RCPROOT";

/// Default chain ID (iona-testnet-1).
const DEFAULT_CHAIN_ID: u64 = 6126151;

/// Default protocol version (v1).
const DEFAULT_PROTOCOL_VERSION: u32 = 1;

// ------------------------------
// Hash32
// ------------------------------

/// A 32-byte cryptographic hash.
///
/// Used for block IDs, transaction hashes, Merkle roots, and state roots.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    /// Returns the zero hash (all zeros).
    pub const fn zero() -> Self {
        Self([0u8; 32])
    }

    /// Returns the hash as a byte slice.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts a hexadecimal string to a `Hash32`.
    ///
    /// # Panics
    /// Panics if the input is not exactly 64 hexadecimal characters.
    pub fn from_hex(hex: &str) -> Self {
        let mut bytes = [0u8; 32];
        hex::decode_to_slice(hex, &mut bytes).expect("invalid hex length");
        Self(bytes)
    }

    /// Returns the hash as a hexadecimal string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }
}

impl std::fmt::Display for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
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

// ------------------------------
// Transaction
// ------------------------------

/// A transaction submitted to the Iona network.
///
/// Transactions are signed by an account and contain a payload that is executed
/// by the VM (KV store, custom VM, or EVM). The signature is verified before
/// execution.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    /// Public key of the sender (32 bytes for Ed25519).
    pub pubkey: Vec<u8>,
    /// Human-readable account name (for testnets; in production this would be an address).
    pub from: String,
    /// Nonce for replay protection.
    pub nonce: u64,
    /// Maximum fee per gas the sender is willing to pay.
    pub max_fee_per_gas: u64,
    /// Maximum priority fee per gas (tip for validators).
    pub max_priority_fee_per_gas: u64,
    /// Gas limit for the transaction.
    pub gas_limit: u64,
    /// Transaction payload (interpretation depends on VM type).
    pub payload: String,
    /// Ed25519 signature over the transaction hash (see `tx_hash`).
    pub signature: Vec<u8>,
    /// Chain ID to prevent replay across different chains.
    pub chain_id: u64,
}

impl Tx {
    /// Returns the hash of this transaction (excluding signature).
    ///
    /// The hash is computed over a fixed binary format:
    /// `TX_HASH_PREFIX || pubkey_len(2 LE) || pubkey || from_len(2 LE) || from ||
    ///  nonce(8 LE) || max_fee(8 LE) || max_prio(8 LE) || gas_limit(8 LE) ||
    ///  chain_id(8 LE) || payload_len(4 LE) || payload`.
    ///
    /// Signature is intentionally excluded – this matches Ethereum's semantics
    /// where the hash covers the signed content, not the signature itself.
    pub fn hash(&self) -> Hash32 {
        tx_hash(self)
    }

    /// Basic validity checks (e.g., pubkey length, nonce range).
    /// This does **not** verify the signature.
    pub fn is_valid(&self) -> bool {
        // Ed25519 public keys are 32 bytes.
        if self.pubkey.len() != 32 {
            return false;
        }
        // Signature length should be 64 bytes.
        if self.signature.len() != 64 {
            return false;
        }
        // Nonce should be reasonable (not too large, but any u64 is fine).
        // Gas limit must be positive.
        if self.gas_limit == 0 {
            return false;
        }
        true
    }
}

// ------------------------------
// Receipt
// ------------------------------

/// Execution receipt for a transaction.
///
/// Contains the result of executing a transaction: success/failure, gas usage,
/// and optional error message or return data.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    /// Hash of the transaction this receipt belongs to.
    pub tx_hash: Hash32,
    /// Whether the transaction executed successfully.
    pub success: bool,
    /// Total gas used for this transaction.
    /// By convention: total = intrinsic_gas_used + exec_gas_used.
    pub gas_used: u64,
    /// Intrinsic/base transaction cost (e.g. signature + envelope).
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    /// Execution gas (KV/VM/EVM). For VM transactions this is the VM gas used.
    #[serde(default)]
    pub exec_gas_used: u64,
    /// VM execution gas (only for VM transactions).
    #[serde(default)]
    pub vm_gas_used: u64,
    /// EVM execution gas (only for EVM transactions).
    #[serde(default)]
    pub evm_gas_used: u64,
    /// Effective gas price paid (after any discounts).
    pub effective_gas_price: u64,
    /// Amount of gas burned (sent to treasury).
    pub burned: u64,
    /// Tip paid to the block producer.
    pub tip: u64,
    /// Error message if execution failed.
    pub error: Option<String>,
    /// For VM transactions: hex-encoded contract address (deploy) or return data (call).
    pub data: Option<String>,
}

// ------------------------------
// Block Header
// ------------------------------

/// Header of a block.
///
/// Contains all metadata necessary to verify the block's validity and link it
/// to the chain. The header is hashed to produce the block ID.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlockHeader {
    /// Block height (genesis = 0 or 1, depending on convention).
    pub height: Height,
    /// Consensus round (for Tendermint-style consensus).
    pub round: Round,
    /// Hash of the previous block.
    pub prev: Hash32,
    /// Public key of the block proposer.
    pub proposer_pk: Vec<u8>,
    /// Merkle root of the transaction list.
    pub tx_root: Hash32,
    /// Merkle root of the receipts.
    pub receipts_root: Hash32,
    /// Merkle root of the post-execution state.
    pub state_root: Hash32,
    /// Base fee per gas (EIP-1559 style).
    pub base_fee_per_gas: u64,
    /// Total gas used by all transactions in the block.
    /// By convention: total = intrinsic_gas_used + exec_gas_used.
    pub gas_used: u64,
    /// Intrinsic gas used by all transactions.
    #[serde(default)]
    pub intrinsic_gas_used: u64,
    /// Execution gas used by all transactions.
    #[serde(default)]
    pub exec_gas_used: u64,
    /// VM execution gas used by all transactions.
    #[serde(default)]
    pub vm_gas_used: u64,
    /// EVM execution gas used by all transactions.
    #[serde(default)]
    pub evm_gas_used: u64,
    /// Chain ID – used by the unified EVM executor to set the EVM environment.
    /// Defaults to 6126151 (iona-testnet-1) for blocks produced before this field was added.
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,
    /// Unix timestamp (seconds) of block proposal.
    /// Used by the EVM executor for `TIMESTAMP` opcode.
    #[serde(default)]
    pub timestamp: u64,
    /// Protocol version used to produce this block.
    /// Used for coordinated hard-fork upgrades (activation at a specific height).
    /// Defaults to 1 for blocks produced before this field was added.
    #[serde(default = "default_protocol_version")]
    pub protocol_version: u32,
}

fn default_chain_id() -> u64 { DEFAULT_CHAIN_ID }
fn default_protocol_version() -> u32 { DEFAULT_PROTOCOL_VERSION }

// ------------------------------
// Block
// ------------------------------

/// A complete block containing a header and a list of transactions.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Deterministic block ID using a fixed binary format.
    ///
    /// Format: `BLOCK_ID_PREFIX || height(8 LE) || round(4 LE) || prev(32) ||
    ///         proposer_pk_len(2 LE) || proposer_pk || tx_root(32) ||
    ///         receipts_root(32) || state_root(32) ||
    ///         base_fee(8 LE) || gas_used(8 LE)`
    ///
    /// This is stable across serde versions and JSON whitespace changes.
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

    /// Returns the hash of the block (same as `id()`).
    pub fn hash(&self) -> Hash32 {
        self.id()
    }
}

// ------------------------------
// Type aliases
// ------------------------------

pub type Height = u64;
pub type Round = u32;

// ------------------------------
// Hashing functions
// ------------------------------

/// Computes a BLAKE3 hash of the input bytes.
///
/// This is the primitive hash function used throughout Iona.
pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let h = blake3::hash(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    Hash32(out)
}

/// Deterministic transaction hash.
///
/// See `Tx::hash()` for format details.
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

/// Computes the Merkle root of a list of transactions.
///
/// The root is computed by hashing the concatenation of all transaction hashes,
/// prefixed with `TX_ROOT_PREFIX` and the number of transactions.
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(TX_ROOT_PREFIX);
    hasher.update(&(txs.len() as u32).to_le_bytes());
    for tx in txs {
        let h = tx.hash();
        hasher.update(&h.0);
    }
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    Hash32(out)
}

/// Computes the Merkle root of a list of receipts.
///
/// The root is computed by hashing a fixed binary encoding of each receipt:
/// `tx_hash(32) || success(1) || gas_used(8 LE) || effective_gas_price(8 LE) ||
///  burned(8 LE) || tip(8 LE)`
///
/// Optional fields (`error`, `data`) are not included in the root; they are
/// only for informational purposes and do not affect consensus.
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
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    Hash32(out)
}

// ------------------------------
// Tests
// ------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn hash32_hex_conversion() {
        let h = Hash32::from_hex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        assert_eq!(h.to_hex(), "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    }

    #[test]
    fn tx_hash_deterministic() {
        let tx = Tx {
            pubkey: vec![1u8; 32],
            from: "alice".into(),
            nonce: 42,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 21_000,
            payload: "set key value".into(),
            signature: vec![0u8; 64],
            chain_id: 6126151,
        };
        let h1 = tx.hash();
        let h2 = tx.hash();
        assert_eq!(h1, h2);

        // Golden vector (computed once, frozen)
        // Replace with actual value after first run.
        // let golden = Hash32::from_hex("...");
        // assert_eq!(h1, golden);
    }

    #[test]
    fn block_id_deterministic() {
        let header = BlockHeader {
            height: 1,
            round: 0,
            prev: Hash32::zero(),
            proposer_pk: vec![0u8; 32],
            tx_root: Hash32::zero(),
            receipts_root: Hash32::zero(),
            state_root: Hash32::zero(),
            base_fee_per_gas: 1,
            gas_used: 0,
            intrinsic_gas_used: 0,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            chain_id: 6126151,
            timestamp: 0,
            protocol_version: 1,
        };
        let block = Block { header, txs: vec![] };
        let id1 = block.id();
        let id2 = block.id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn tx_root_empty() {
        let root = tx_root(&[]);
        // Expected value for empty root (precomputed).
        // let expected = Hash32::from_hex("...");
        // assert_eq!(root, expected);
        let _ = root; // placeholder
    }

    #[test]
    fn receipts_root_empty() {
        let root = receipts_root(&[]);
        let _ = root;
    }

    #[test]
    fn tx_validity_check() {
        let valid_tx = Tx {
            pubkey: vec![1u8; 32],
            from: "bob".into(),
            nonce: 0,
            max_fee_per_gas: 10,
            max_priority_fee_per_gas: 5,
            gas_limit: 50_000,
            payload: "".into(),
            signature: vec![0u8; 64],
            chain_id: 1,
        };
        assert!(valid_tx.is_valid());

        let invalid_pubkey = Tx { pubkey: vec![1u8; 31], ..valid_tx.clone() };
        assert!(!invalid_pubkey.is_valid());

        let invalid_sig = Tx { signature: vec![0u8; 63], ..valid_tx.clone() };
        assert!(!invalid_sig.is_valid());

        let zero_gas = Tx { gas_limit: 0, ..valid_tx.clone() };
        assert!(!zero_gas.is_valid());
    }
}
