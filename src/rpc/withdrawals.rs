use rlp::RlpStream;
use serde::{Serialize, Deserialize};
use crate::rpc::mpt::eth_ordered_trie_root_hex;

/// Withdrawal (EIP-4895 / Shanghai) structure (execution layer representation).
#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: [u8;20],
    pub amount_gwei: u64,
}

pub fn rlp_encode_withdrawal(w: &Withdrawal) -> Vec<u8> {
    // RLP([index, validator_index, address, amount])
    let mut s = RlpStream::new_list(4);
    s.append(&w.index);
    s.append(&w.validator_index);
    s.append(&w.address.as_slice());
    s.append(&w.amount_gwei);
    s.out().to_vec()
}

/// withdrawalsRoot in the execution block header is an ordered MPT root over RLP(withdrawal)
/// (keys are RLP(index) implicitly via ordered trie).
pub fn withdrawals_root_hex(withdrawals: &[Withdrawal]) -> String {
    let items: Vec<Vec<u8>> = withdrawals.iter().map(rlp_encode_withdrawal).collect();
    eth_ordered_trie_root_hex(&items)
}
