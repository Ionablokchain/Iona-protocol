use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};

/// Mempool entry (raw signed tx bytes + decoded metadata needed for ordering).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,      // 0x...
    pub nonce: u64,
    pub tx_type: u8,       // 0 legacy, 1, 2
    pub gas_limit: u64,
    pub gas_price: u128,                 // legacy/2930
    pub max_fee_per_gas: Option<u128>,   // 1559
    pub max_priority_fee_per_gas: Option<u128>, // 1559
    pub raw: Vec<u8>,
    pub inserted_at: u64, // unix seconds

}

impl PendingTx {
    /// Effective tip used for ordering. For EIP-1559, approximate with maxPriorityFeePerGas.
    pub fn priority(&self) -> u128 {
        self.max_priority_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Fee cap used for replacement (rough).
    pub fn fee_cap(&self) -> u128 {
        self.max_fee_per_gas.unwrap_or(self.gas_price)
    }
}

/// Txpool with per-sender nonce lanes and replacement rule.
#[derive(Default, Clone, Serialize, Deserialize)]
pub struct TxPool {
    // sender -> nonce -> tx
    pub(crate) by_sender: HashMap<String, BTreeMap<u64, PendingTx>>,
}

impl TxPool {
    pub fn len(&self) -> usize {
        self.by_sender.values().map(|m| m.len()).sum()
    }

    pub fn pending_for_sender(&self, sender: &str) -> usize {
        self.by_sender.get(sender).map(|m| m.len()).unwrap_or(0)
    }

    pub fn insert(&mut self, tx: PendingTx) -> Result<(), String> {
        let lane = self.by_sender.entry(tx.from.clone()).or_default();
        if let Some(existing) = lane.get(&tx.nonce) {
            // replacement: require strictly higher fee cap OR priority
            if tx.fee_cap() <= existing.fee_cap() && tx.priority() <= existing.priority() {
                return Err("replacement underpriced".into());
            }
        }
        lane.insert(tx.nonce, tx);
        Ok(())
    }

    /// Pop the next executable tx for each sender given current nonce.
    /// Returns a list sorted by priority (descending).
    pub fn drain_next_ready(&mut self, account_nonces: &HashMap<String, u64>, max: usize) -> Vec<PendingTx> {
        let mut ready: Vec<PendingTx> = vec![];

        for (sender, lane) in self.by_sender.iter_mut() {
            let expected = account_nonces.get(sender).copied().unwrap_or(0);
            if let Some(tx) = lane.remove(&expected) {
                ready.push(tx);
            }
        }

        ready.sort_by(|a, b| b.priority().cmp(&a.priority()));
        ready.truncate(max);
        ready
    }

    /// Count contiguous pending txs starting at `expected_nonce` (for "pending" nonce RPC).
    pub fn contiguous_from(&self, sender: &str, expected_nonce: u64) -> u64 {
        let Some(lane) = self.by_sender.get(sender) else { return 0; };
        let mut n = expected_nonce;
        let mut count = 0u64;
        while lane.contains_key(&n) {
            count += 1;
            n += 1;
        }
        count
    }
}


impl TxPool {
    /// Prune by age and total size. Evicts oldest first.
    pub fn prune(&mut self, now_secs: u64, max_age_secs: u64, max_total: usize) {
        // remove too-old
        for (_sender, lane) in self.by_sender.iter_mut() {
            let old: Vec<u64> = lane.iter().filter_map(|(n, tx)| {
                if now_secs.saturating_sub(tx.inserted_at) > max_age_secs { Some(*n) } else { None }
            }).collect();
            for n in old { lane.remove(&n); }
        }
        // remove empty lanes
        self.by_sender.retain(|_, lane| !lane.is_empty());

        // evict oldest globally until under max_total
        while self.len() > max_total {
            let mut oldest_sender: Option<String> = None;
            let mut oldest_nonce: u64 = 0;
            let mut oldest_time: u64 = u64::MAX;

            for (sender, lane) in self.by_sender.iter() {
                for (nonce, tx) in lane.iter() {
                    if tx.inserted_at < oldest_time {
                        oldest_time = tx.inserted_at;
                        oldest_sender = Some(sender.clone());
                        oldest_nonce = *nonce;
                    }
                }
            }
            if let Some(s) = oldest_sender {
                if let Some(lane) = self.by_sender.get_mut(&s) {
                    lane.remove(&oldest_nonce);
                }
                self.by_sender.retain(|_, lane| !lane.is_empty());
            } else {
                break;
            }
        }
    }
}
