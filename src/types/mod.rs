use serde::{Deserialize, Serialize};

pub type Height = u64;
pub type Round = u32;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn zero() -> Self { Self([0u8; 32]) }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Tx {
    pub pubkey: Vec<u8>,
    pub from: String,
    pub nonce: u64,
    pub max_fee_per_gas: u64,
    pub max_priority_fee_per_gas: u64,
    pub gas_limit: u64,
    pub payload: String,
    pub signature: Vec<u8>,
    pub chain_id: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash32,
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
    pub effective_gas_price: u64,
    pub burned: u64,
    pub tip: u64,
    pub error: Option<String>,
    /// For VM transactions: hex-encoded contract address (deploy) or return data (call).
    pub data: Option<String>,
}

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
    /// Chain ID — used by the unified EVM executor to set the EVM environment.
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

fn default_chain_id() -> u64 { 6126151 }
fn default_protocol_version() -> u32 { 1 }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub txs: Vec<Tx>,
}

impl Block {
    /// Deterministic block ID using a fixed binary format.
    ///
    /// Format: "IONA_BLK" || height(8 LE) || round(4 LE) || prev(32) ||
    ///         proposer_pk_len(2 LE) || proposer_pk || tx_root(32) ||
    ///         receipts_root(32) || state_root(32) ||
    ///         base_fee(8 LE) || gas_used(8 LE)
    ///
    /// This is stable across serde versions and JSON whitespace changes.
    pub fn id(&self) -> Hash32 {
        let h = &self.header;
        let mut buf = Vec::with_capacity(8 + 8 + 4 + 32 + 2 + h.proposer_pk.len() + 32 + 32 + 32 + 8 + 8);
        buf.extend_from_slice(b"IONA_BLK");
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

pub fn hash_bytes(b: &[u8]) -> Hash32 {
    let h = blake3::hash(b);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    Hash32(out)
}

/// Deterministic tx hash using fixed binary format.
///
/// Format: "IONA_TX" || pubkey_len(2 LE) || pubkey || from_len(2 LE) || from ||
///         nonce(8 LE) || max_fee(8 LE) || max_prio(8 LE) || gas_limit(8 LE) ||
///         chain_id(8 LE) || payload_len(4 LE) || payload
///
/// Signature is intentionally excluded — tx hash is over the content being signed,
/// not the signature itself (mirrors ETH tx hash semantics).
pub fn tx_hash(tx: &Tx) -> Hash32 {
    let payload_bytes = tx.payload.as_bytes();
    let from_bytes    = tx.from.as_bytes();
    let mut buf = Vec::with_capacity(7 + 2 + tx.pubkey.len() + 2 + from_bytes.len() + 8*5 + 4 + payload_bytes.len());
    buf.extend_from_slice(b"IONA_TX");
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

/// tx_root: blake3 over concatenated tx hashes (already binary-stable via tx_hash).
pub fn tx_root(txs: &[Tx]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"IONA_TXROOT");
    hasher.update(&(txs.len() as u32).to_le_bytes());
    for t in txs {
        let h = tx_hash(t);
        hasher.update(&h.0);
    }
    let h = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(h.as_bytes());
    Hash32(out)
}

/// receipts_root: hash over binary-encoded receipts (no serde_json).
///
/// Format per receipt: tx_hash(32) || success(1) || gas_used(8 LE) ||
///                     effective_gas_price(8 LE) || burned(8 LE) || tip(8 LE)
pub fn receipts_root(receipts: &[Receipt]) -> Hash32 {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"IONA_RCPROOT");
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

// (state_root_kv removed — use KvState::root() which uses deterministic Merkle tree)

pub mod tx_vm;

pub mod tx_evm;
