use rlp::RlpStream;
use sha3::{Digest, Keccak256};

/// Minimal Ethereum-like block header scaffold.
/// This is NOT full consensus-correct, but matches Ethereum header structure and hashing approach.
///
/// Ethereum header fields (post-London) include:
/// parentHash, ommersHash, beneficiary, stateRoot, transactionsRoot, receiptsRoot,
/// logsBloom, difficulty, number, gasLimit, gasUsed, timestamp, extraData,
/// mixHash (pre-merge) / prevRandao (post-merge), nonce,
/// baseFeePerGas, withdrawalsRoot (post-Shanghai), blobGasUsed/excessBlobGas (post-Cancun), ...
///
/// We implement a conservative subset and keep placeholders for the rest.
#[derive(Debug, Clone)]
pub struct EthHeader {
    pub parent_hash: [u8; 32],
    pub ommers_hash: [u8; 32],
    pub beneficiary: [u8; 20],
    pub state_root: [u8; 32],
    pub transactions_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub logs_bloom: [u8; 256],
    pub difficulty: u64,
    pub number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: Vec<u8>,
    pub mix_hash: [u8; 32],
    pub nonce: [u8; 8],
    pub base_fee_per_gas: u64,
    pub withdrawals_root: [u8; 32],
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    let r = h.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&r);
    out
}

pub fn rlp_encode_header(h: &EthHeader) -> Vec<u8> {
    // Encode a subset of Ethereum header fields in the canonical order (London+).
    // For strict parity, difficulty/nonce/mixHash rules differ per fork; this is scaffold.
    let mut s = RlpStream::new_list(17);
    s.append(&h.parent_hash.as_slice());
    s.append(&h.ommers_hash.as_slice());
    s.append(&h.beneficiary.as_slice());
    s.append(&h.state_root.as_slice());
    s.append(&h.transactions_root.as_slice());
    s.append(&h.receipts_root.as_slice());
    s.append(&h.logs_bloom.as_slice());
    s.append(&h.difficulty);
    s.append(&h.number);
    s.append(&h.gas_limit);
    s.append(&h.gas_used);
    s.append(&h.timestamp);
    s.append(&h.extra_data.as_slice());
    s.append(&h.mix_hash.as_slice());
    s.append(&h.nonce.as_slice());
    s.append(&h.base_fee_per_gas);
    s.append(&h.withdrawals_root.as_slice());
    s.out().to_vec()
}

pub fn header_hash(h: &EthHeader) -> [u8; 32] {
    keccak256(&rlp_encode_header(h))
}

pub fn header_hash_hex(h: &EthHeader) -> String {
    format!("0x{}", hex::encode(header_hash(h)))
}

pub fn h256_from_hex(s: &str) -> [u8; 32] {
    let b = hex::decode(s.trim_start_matches("0x")).unwrap_or_default();
    let mut out = [0u8; 32];
    let start = 32 - b.len().min(32);
    out[start..].copy_from_slice(&b[b.len().saturating_sub(32)..]);
    out
}

pub fn bloom_from_hex(s: &str) -> [u8; 256] {
    let b = hex::decode(s.trim_start_matches("0x")).unwrap_or_default();
    let mut out = [0u8; 256];
    if b.len() == 256 {
        out.copy_from_slice(&b);
    }
    out
}


/// keccak256(RLP([])) - used for ommersHash when there are no ommers.
pub fn empty_ommers_hash() -> [u8;32] {
    // RLP empty list is 0xc0
    let mut h = Keccak256::new();
    h.update(&[0xc0]);
    let r = h.finalize();
    let mut out=[0u8;32];
    out.copy_from_slice(&r);
    out
}
