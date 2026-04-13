use crate::rpc::mpt::eth_ordered_trie_root_hex;
use rlp::RlpStream;
use serde::{Deserialize, Serialize};

/// EIP-4895 withdrawal (Shanghai).
///
/// All four derives are required:
/// - `Serialize` / `Deserialize` — for JSON-RPC and persistence
/// - `Clone` — EthRpcState holds `Arc<Mutex<Vec<Withdrawal>>>`
/// - `Debug` — tracing and test output
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Withdrawal {
    /// Global index of this withdrawal (monotonically increasing).
    pub index: u64,
    /// Consensus-layer validator index.
    pub validator_index: u64,
    /// Target execution-layer address.
    pub address: [u8; 20],
    /// Amount in Gwei.
    pub amount_gwei: u64,
}

impl Withdrawal {
    /// Construct a new withdrawal.
    pub fn new(index: u64, validator_index: u64, address: [u8; 20], amount_gwei: u64) -> Self {
        Self {
            index,
            validator_index,
            address,
            amount_gwei,
        }
    }

    /// RLP-encode as `[index, validatorIndex, address, amount]`.
    pub fn rlp_encode(&self) -> Vec<u8> {
        let mut s = RlpStream::new_list(4);
        s.append(&self.index);
        s.append(&self.validator_index);
        s.append(&self.address.as_slice());
        s.append(&self.amount_gwei);
        s.out().to_vec()
    }
}

/// RLP-encode a withdrawal (standalone helper for backwards compatibility).
pub fn rlp_encode_withdrawal(w: &Withdrawal) -> Vec<u8> {
    w.rlp_encode()
}

/// Compute `withdrawalsRoot` — ordered MPT root over RLP-encoded withdrawals.
///
/// This matches the Ethereum spec: each leaf is `RLP(withdrawal)`, indexed
/// by the ordered trie key (RLP-encoded position index).
pub fn withdrawals_root_hex(withdrawals: &[Withdrawal]) -> String {
    let items: Vec<Vec<u8>> = withdrawals.iter().map(|w| w.rlp_encode()).collect();
    eth_ordered_trie_root_hex(&items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn withdrawal_derives() {
        let w = Withdrawal::new(0, 1, [0u8; 20], 1_000_000);
        let cloned = w.clone();
        let json = serde_json::to_string(&cloned).unwrap();
        let back: Withdrawal = serde_json::from_str(&json).unwrap();
        assert_eq!(back.index, 0);
        assert_eq!(back.amount_gwei, 1_000_000);
        // Debug must work
        let _ = format!("{:?}", w);
    }

    #[test]
    fn withdrawals_root_empty() {
        // Empty withdrawals root should be deterministic
        let root = withdrawals_root_hex(&[]);
        assert!(root.starts_with("0x"));
    }
}
