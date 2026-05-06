//! Transaction pool for the Ethereum JSON‑RPC server.
//!
//! Provides per‑sender nonce‑ordered queues, replacement rules (fee bump),
//! age‑based pruning, and global eviction.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum age of a transaction in seconds (1 hour).
pub const DEFAULT_MAX_TX_AGE_SECS: u64 = 3600;

/// Default maximum total transactions in the pool (10,000).
pub const DEFAULT_MAX_POOL_SIZE: usize = 10_000;

/// Default maximum number of transactions per sender.
pub const DEFAULT_MAX_PER_SENDER: usize = 64;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when inserting a transaction into the pool.
#[derive(Debug, Error)]
pub enum TxPoolError {
    #[error("replacement transaction underpriced: existing fee_cap = {existing_fee_cap}, new fee_cap = {new_fee_cap}")]
    ReplacementUnderpriced { existing_fee_cap: u128, new_fee_cap: u128 },

    #[error("gas limit must be > 0, got {gas_limit}")]
    ZeroGasLimit { gas_limit: u64 },

    #[error("nonce overflow (max 2^64-1)")]
    NonceOverflow,

    #[error("sender address is empty")]
    EmptySender,

    #[error("invalid tx hash")]
    InvalidHash,
}

pub type TxPoolResult<T> = Result<T, TxPoolError>;

// -----------------------------------------------------------------------------
// PendingTx
// -----------------------------------------------------------------------------

/// Mempool entry (raw signed tx bytes + decoded metadata needed for ordering).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingTx {
    pub hash: String,
    pub from: String,
    pub nonce: u64,
    pub tx_type: u8,
    pub gas_limit: u64,
    pub gas_price: u128,
    pub max_fee_per_gas: Option<u128>,
    pub max_priority_fee_per_gas: Option<u128>,
    pub raw: Vec<u8>,
    pub inserted_at: u64,
}

impl PendingTx {
    /// Effective priority used for ordering (for EIP‑1559, use max_priority_fee_per_gas).
    pub fn priority(&self) -> u128 {
        self.max_priority_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Fee cap used for replacement detection.
    pub fn fee_cap(&self) -> u128 {
        self.max_fee_per_gas.unwrap_or(self.gas_price)
    }

    /// Validate the transaction fields (does not check signature).
    pub fn validate(&self) -> TxPoolResult<()> {
        if self.gas_limit == 0 {
            return Err(TxPoolError::ZeroGasLimit { gas_limit: self.gas_limit });
        }
        if self.from.is_empty() {
            return Err(TxPoolError::EmptySender);
        }
        if self.hash.is_empty() {
            return Err(TxPoolError::InvalidHash);
        }
        // Optional: check fee cap > 0
        if self.fee_cap() == 0 {
            // not an error, but could be logged
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// TxPool
// -----------------------------------------------------------------------------

/// Transaction pool with per‑sender nonce lanes and replacement rule.
#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct TxPool {
    /// sender → (nonce → tx)
    pub(crate) by_sender: HashMap<String, BTreeMap<u64, PendingTx>>,
}

impl TxPool {
    /// Create a new empty transaction pool.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.by_sender.values().map(|m| m.len()).sum()
    }

    /// Check if the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Number of pending transactions for a given sender.
    pub fn pending_for_sender(&self, sender: &str) -> usize {
        self.by_sender.get(sender).map(|m| m.len()).unwrap_or(0)
    }

    /// Total number of distinct senders.
    pub fn senders_count(&self) -> usize {
        self.by_sender.len()
    }

    /// Insert a transaction into the pool, replacing any existing transaction with the same nonce
    /// if the new transaction has a strictly higher fee cap OR higher priority.
    pub fn insert(&mut self, tx: PendingTx) -> TxPoolResult<()> {
        tx.validate()?;

        let lane = self.by_sender.entry(tx.from.clone()).or_default();
        if let Some(existing) = lane.get(&tx.nonce) {
            if tx.fee_cap() <= existing.fee_cap() && tx.priority() <= existing.priority() {
                return Err(TxPoolError::ReplacementUnderpriced {
                    existing_fee_cap: existing.fee_cap(),
                    new_fee_cap: tx.fee_cap(),
                });
            }
        }
        lane.insert(tx.nonce, tx);
        Ok(())
    }

    /// Remove and return the next executable transaction for each sender,
    /// respecting the given current nonce. Returns up to `max` transactions,
    /// sorted by descending priority.
    pub fn drain_next_ready(
        &mut self,
        account_nonces: &HashMap<String, u64>,
        max: usize,
    ) -> Vec<PendingTx> {
        let mut ready = Vec::new();
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

    /// Count how many contiguous pending transactions exist for a sender starting from
    /// `expected_nonce`. Used for the `eth_getTransactionCount` "pending" tag.
    pub fn contiguous_from(&self, sender: &str, expected_nonce: u64) -> u64 {
        let Some(lane) = self.by_sender.get(sender) else {
            return 0;
        };
        let mut count = 0u64;
        let mut nonce = expected_nonce;
        while lane.contains_key(&nonce) {
            count += 1;
            nonce += 1;
        }
        count
    }

    /// Prune transactions older than `max_age_secs` and evict the oldest
    /// transactions if the pool exceeds `max_total`.
    pub fn prune(&mut self, now_secs: u64, max_age_secs: u64, max_total: usize) {
        // 1. Remove expired transactions
        for lane in self.by_sender.values_mut() {
            let expired: Vec<u64> = lane
                .iter()
                .filter_map(|(&n, tx)| {
                    if now_secs.saturating_sub(tx.inserted_at) > max_age_secs {
                        Some(n)
                    } else {
                        None
                    }
                })
                .collect();
            for nonce in expired {
                lane.remove(&nonce);
            }
        }

        // 2. Remove empty lanes
        self.by_sender.retain(|_, lane| !lane.is_empty());

        // 3. Evict oldest globally until under max_total
        while self.len() > max_total {
            let mut oldest_sender: Option<String> = None;
            let mut oldest_nonce: u64 = 0;
            let mut oldest_time: u64 = u64::MAX;

            for (sender, lane) in self.by_sender.iter() {
                for (&nonce, tx) in lane.iter() {
                    if tx.inserted_at < oldest_time {
                        oldest_time = tx.inserted_at;
                        oldest_sender = Some(sender.clone());
                        oldest_nonce = nonce;
                    }
                }
            }

            if let Some(sender) = oldest_sender {
                if let Some(lane) = self.by_sender.get_mut(&sender) {
                    lane.remove(&oldest_nonce);
                }
                self.by_sender.retain(|_, lane| !lane.is_empty());
            } else {
                break;
            }
        }
    }

    /// Return current pool metrics as a JSON‑compatible struct.
    pub fn metrics(&self) -> TxPoolMetrics {
        TxPoolMetrics {
            total_txs: self.len(),
            total_senders: self.senders_count(),
            max_per_sender: self
                .by_sender
                .values()
                .map(|lane| lane.len())
                .max()
                .unwrap_or(0),
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Simple metrics about the transaction pool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxPoolMetrics {
    pub total_txs: usize,
    pub total_senders: usize,
    pub max_per_sender: usize,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(from: &str, nonce: u64, gas_price: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: format!("0x{}", hex::encode(&[nonce as u8; 32])),
            from: from.to_string(),
            nonce,
            tx_type: 0,
            gas_limit: 21_000,
            gas_price,
            max_fee_per_gas: None,
            max_priority_fee_per_gas: None,
            raw: vec![],
            inserted_at,
        }
    }

    fn dummy_eip1559_tx(from: &str, nonce: u64, max_fee: u128, priority: u128, inserted_at: u64) -> PendingTx {
        PendingTx {
            hash: format!("0x{}", hex::encode(&[nonce as u8; 32])),
            from: from.to_string(),
            nonce,
            tx_type: 2,
            gas_limit: 21_000,
            gas_price: 0,
            max_fee_per_gas: Some(max_fee),
            max_priority_fee_per_gas: Some(priority),
            raw: vec![],
            inserted_at,
        }
    }

    #[test]
    fn test_insert_and_replace() {
        let mut pool = TxPool::new();
        let tx1 = dummy_tx("alice", 0, 100, 10);
        assert!(pool.insert(tx1).is_ok());
        assert_eq!(pool.len(), 1);

        // Replacement with higher price = allowed
        let tx2 = dummy_tx("alice", 0, 110, 11);
        assert!(pool.insert(tx2).is_ok());
        assert_eq!(pool.len(), 1);

        // Replacement with lower price = rejected
        let tx3 = dummy_tx("alice", 0, 90, 12);
        let err = pool.insert(tx3).unwrap_err();
        assert!(matches!(err, TxPoolError::ReplacementUnderpriced { .. }));
    }

    #[test]
    fn test_drain_next_ready() {
        let mut pool = TxPool::new();
        let tx1 = dummy_tx("alice", 0, 100, 10);
        let tx2 = dummy_tx("bob", 0, 200, 20);
        pool.insert(tx1).unwrap();
        pool.insert(tx2).unwrap();

        let mut nonces = HashMap::new();
        nonces.insert("alice".to_string(), 0);
        nonces.insert("bob".to_string(), 0);

        let ready = pool.drain_next_ready(&nonces, 10);
        assert_eq!(ready.len(), 2);
        // bob has higher priority (200)
        assert_eq!(ready[0].from, "bob");
        assert_eq!(ready[1].from, "alice");
    }

    #[test]
    fn test_contiguous_from() {
        let mut pool = TxPool::new();
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("alice", 1, 100, 11)).unwrap();
        pool.insert(dummy_tx("alice", 2, 100, 12)).unwrap();

        assert_eq!(pool.contiguous_from("alice", 0), 3);
        assert_eq!(pool.contiguous_from("alice", 1), 2);
        assert_eq!(pool.contiguous_from("alice", 3), 0);
        assert_eq!(pool.contiguous_from("bob", 0), 0);
    }

    #[test]
    fn test_prune_by_age() {
        let mut pool = TxPool::new();
        pool.insert(dummy_tx("alice", 0, 100, 100)).unwrap();
        pool.insert(dummy_tx("bob", 0, 100, 200)).unwrap();
        pool.prune(250, 100, 100);
        // alice tx inserted at 100, now 250 → age 150 > 100 → removed
        assert_eq!(pool.len(), 1);
        assert!(pool.by_sender.contains_key("bob"));
    }

    #[test]
    fn test_prune_by_total() {
        let mut pool = TxPool::new();
        for i in 0..10 {
            pool.insert(dummy_tx(&format!("sender_{}", i % 2), i, 100, i as u64)).unwrap();
        }
        assert_eq!(pool.len(), 10);
        pool.prune(1000, 3600, 5);
        assert_eq!(pool.len(), 5);
    }

    #[test]
    fn test_metrics() {
        let mut pool = TxPool::new();
        pool.insert(dummy_tx("alice", 0, 100, 10)).unwrap();
        pool.insert(dummy_tx("alice", 1, 100, 11)).unwrap();
        pool.insert(dummy_tx("bob", 0, 100, 12)).unwrap();

        let m = pool.metrics();
        assert_eq!(m.total_txs, 3);
        assert_eq!(m.total_senders, 2);
        assert_eq!(m.max_per_sender, 2);
    }

    #[test]
    fn test_eip1559_priority() {
        let tx = dummy_eip1559_tx("alice", 0, 1000, 50, 10);
        assert_eq!(tx.priority(), 50);
        assert_eq!(tx.fee_cap(), 1000);
    }
}
