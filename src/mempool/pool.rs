//! Standard mempool for IONA.
//!
//! This is a production-ready transaction pool that implements:
//! - Per-sender nonce-ordered queues (ensures transaction sequence integrity)
//! - Replace-by-fee (RBF): re-submitting same nonce with >=10% higher tip replaces the old tx
//! - TTL: transactions expire after `TTL_BLOCKS` blocks
//! - Admission: rejects tx if sender's pending count exceeds `MAX_PENDING_PER_SENDER`
//! - Eviction: when pool is full, drops lowest-priority tx from other senders
//! - Metrics: exposes counters for admitted/rejected/evicted/expired
//!
//! The pool is designed to be used with the `Mempool` trait, allowing seamless
//! integration with the rest of the node.

use crate::execution::intrinsic_gas;
use crate::mempool::{Mempool as MempoolTrait, MempoolError};
use crate::types::{Height, Tx};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

// Constants
const TTL_BLOCKS: u64 = 300;
const MAX_PENDING_PER_SENDER: usize = 64;
const RBF_BUMP_PERCENT: u64 = 10;

// -----------------------------------------------------------------------------
// Pending transaction (internal)
// -----------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct PendingTx {
    tx: Tx,
    score: u128,              // higher is better
    inserted_height: Height,
}

impl PendingTx {
    /// Create a new pending transaction, computing its priority score.
    ///
    /// Score = (effective_tip * 1_000_000) / size, where size is payload length + 128.
    /// This favours high‑tip, small transactions.
    fn new(tx: Tx, current_height: Height, base_fee: u64) -> Self {
        let gas = intrinsic_gas(&tx) as u128;
        // Effective tip = min(max_priority_fee, max_fee - base_fee)   (EIP‑1559)
        let tip = if tx.max_fee_per_gas > base_fee {
            tx.max_priority_fee_per_gas.min(tx.max_fee_per_gas - base_fee) as u128
        } else {
            0
        };
        let tip_gas = tip.saturating_mul(gas);
        let size = (tx.payload.len() as u128 + 128).max(1);
        let score = tip_gas.saturating_mul(1_000_000) / size;
        Self {
            tx,
            score,
            inserted_height: current_height,
        }
    }

    fn is_expired(&self, current_height: Height) -> bool {
        current_height.saturating_sub(self.inserted_height) > TTL_BLOCKS
    }
}

// -----------------------------------------------------------------------------
// Heap entry for priority queue
// -----------------------------------------------------------------------------

#[derive(Clone)]
struct HeapEntry {
    score: u128,
    nonce: u64,
    sender: String,
}

impl PartialEq for HeapEntry {
    fn eq(&self, other: &Self) -> bool {
        self.score == other.score
    }
}

impl Eq for HeapEntry {}

impl PartialOrd for HeapEntry {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for HeapEntry {
    fn cmp(&self, other: &Self) -> Ordering {
        // Higher score first, then lower nonce (to favour earlier transactions)
        self.score
            .cmp(&other.score)
            .then_with(|| other.nonce.cmp(&self.nonce))
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the standard mempool.
#[derive(Default, Debug, Clone, Serialize)]
pub struct MempoolMetrics {
    pub admitted: u64,
    pub rejected_dup: u64,
    pub rejected_full: u64,
    pub rejected_sender_limit: u64,
    pub evicted: u64,
    pub expired: u64,
    pub rbf_replaced: u64,
}

// -----------------------------------------------------------------------------
// Mempool
// -----------------------------------------------------------------------------

/// Standard mempool with per‑sender nonce queues, RBF, TTL, and eviction.
pub struct Mempool {
    cap: usize,
    current_height: Height,
    /// Sender → (nonce → pending tx)
    queues: HashMap<String, BTreeMap<u64, PendingTx>>,
    pub metrics: MempoolMetrics,
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new(200_000)
    }
}

impl Mempool {
    /// Create a new mempool with the given capacity (max number of transactions).
    pub fn new(cap: usize) -> Self {
        Self {
            cap,
            current_height: 0,
            queues: HashMap::new(),
            metrics: MempoolMetrics::default(),
        }
    }

    /// Total number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.queues.values().map(|q| q.len()).sum()
    }

    /// Number of distinct senders with pending transactions.
    pub fn sender_count(&self) -> usize {
        self.queues.len()
    }

    /// Advance the height, expiring old transactions.
    pub fn advance_height(&mut self, height: Height) {
        self.current_height = height;
        let h = self.current_height;
        let metrics = &mut self.metrics;
        self.queues.retain(|_, queue| {
            let before = queue.len();
            queue.retain(|_, ptx| !ptx.is_expired(h));
            metrics.expired += (before - queue.len()) as u64;
            !queue.is_empty()
        });
    }

    /// Remove transactions that have been confirmed (nonces below `committed_nonce`).
    pub fn remove_confirmed(&mut self, sender: &str, committed_nonce: u64) {
        if let Some(queue) = self.queues.get_mut(sender) {
            queue.retain(|&nonce, _| nonce >= committed_nonce);
            if queue.is_empty() {
                self.queues.remove(sender);
            }
        }
    }

    /// Submit a transaction, using the given current block base fee.
    ///
    /// Returns `Ok(true)` if the transaction was added,
    /// `Ok(false)` if it replaced an existing transaction (RBF),
    /// or `Err` with a reason.
    pub fn push_with_base_fee(&mut self, tx: Tx, base_fee: u64) -> Result<bool, MempoolError> {
        // EIP‑1559: reject if max_fee < base_fee
        if tx.max_fee_per_gas < base_fee {
            self.metrics.rejected_dup += 1;
            return Err(MempoolError::FeeTooLow {
                max_fee: tx.max_fee_per_gas,
                base_fee,
            });
        }
        self.push(tx, base_fee)
    }

    /// Submit a transaction using the default base fee (0). Prefer `push_with_base_fee`.
    pub fn push(&mut self, tx: Tx, base_fee: u64) -> Result<bool, MempoolError> {
        let sender = tx.from.clone();
        if sender.is_empty() {
            return Err(MempoolError::MissingSender);
        }

        let queue = self.queues.entry(sender.clone()).or_default();

        // RBF check
        if let Some(existing) = queue.get(&tx.nonce) {
            let existing_tip = existing.tx.max_priority_fee_per_gas;
            let required = existing_tip.saturating_add(
                (existing_tip.saturating_mul(RBF_BUMP_PERCENT) / 100).max(1),
            );
            if tx.max_priority_fee_per_gas < required {
                self.metrics.rejected_dup += 1;
                return Err(MempoolError::RbfTooLow {
                    existing_tip,
                    required,
                });
            }
            // Replace
            queue.insert(
                tx.nonce,
                PendingTx::new(tx, self.current_height, base_fee),
            );
            self.metrics.rbf_replaced += 1;
            return Ok(false);
        }

        // Per‑sender cap
        if queue.len() >= MAX_PENDING_PER_SENDER {
            self.metrics.rejected_sender_limit += 1;
            return Err(MempoolError::SenderQueueFull);
        }

        // Global cap with eviction
        if self.len() >= self.cap {
            if !self.evict_worst(&sender) {
                self.metrics.rejected_full += 1;
                return Err(MempoolError::MempoolFull);
            }
        }

        // Insert new transaction
        let ptx = PendingTx::new(tx, self.current_height, base_fee);
        self.queues
            .entry(sender)
            .or_default()
            .insert(ptx.tx.nonce, ptx);
        self.metrics.admitted += 1;
        Ok(true)
    }

    /// Try to evict the lowest‑priority transaction from a different sender.
    fn evict_worst(&mut self, protect_sender: &str) -> bool {
        let worst = self
            .queues
            .iter()
            .filter(|(s, _)| s.as_str() != protect_sender)
            .flat_map(|(s, q)| q.iter().map(move |(n, p)| (p.score, s.clone(), *n)))
            .min_by_key(|(score, _, _)| *score);

        if let Some((_, sender, nonce)) = worst {
            if let Some(q) = self.queues.get_mut(&sender) {
                q.remove(&nonce);
                if q.is_empty() {
                    self.queues.remove(&sender);
                }
            }
            self.metrics.evicted += 1;
            true
        } else {
            false
        }
    }

    /// Drain up to `n` transactions in priority order, respecting per‑sender nonce ordering.
    pub fn drain_best(&mut self, n: usize) -> Vec<Tx> {
        let mut heap: BinaryHeap<HeapEntry> = self
            .queues
            .iter()
            .filter_map(|(sender, queue)| {
                queue.values().next().map(|ptx| HeapEntry {
                    score: ptx.score,
                    nonce: ptx.tx.nonce,
                    sender: sender.clone(),
                })
            })
            .collect();

        let mut result = Vec::with_capacity(n);
        while result.len() < n {
            let entry = match heap.pop() {
                Some(e) => e,
                None => break,
            };
            let queue = match self.queues.get_mut(&entry.sender) {
                Some(q) => q,
                None => continue,
            };
            let ptx = match queue.remove(&entry.nonce) {
                Some(p) => p,
                None => continue,
            };
            result.push(ptx.tx);
            if let Some(next) = queue.values().next() {
                heap.push(HeapEntry {
                    score: next.score,
                    nonce: next.tx.nonce,
                    sender: entry.sender.clone(),
                });
            } else {
                self.queues.remove(&entry.sender);
            }
        }
        result
    }

    /// Return current metrics as JSON.
    pub fn metrics_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.metrics).unwrap_or(serde_json::Value::Null)
    }
}

// -----------------------------------------------------------------------------
// Implement the unified Mempool trait
// -----------------------------------------------------------------------------

impl MempoolTrait for Mempool {
    type Error = MempoolError;

    fn submit_tx(&mut self, tx: Tx) -> Result<(), Self::Error> {
        // For compatibility, we use base_fee = 0 (no base fee check).
        // In practice, the node should call `push_with_base_fee` with the correct base fee.
        self.push(tx, 0).map(|_| ())
    }

    fn drain(&mut self, n: usize) -> Vec<Tx> {
        self.drain_best(n)
    }

    fn advance_height(&mut self, height: Height, _block_hash: &crate::types::Hash32) {
        self.advance_height(height);
    }

    fn pending_count(&self) -> usize {
        self.len()
    }

    fn metrics(&self) -> Option<serde_json::Value> {
        Some(self.metrics_json())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tx;

    fn dummy_tx(from: &str, nonce: u64, tip: u64, max_fee: u64, payload: &str) -> Tx {
        Tx {
            pubkey: vec![0; 32],
            from: from.to_string(),
            nonce,
            max_fee_per_gas: max_fee,
            max_priority_fee_per_gas: tip,
            gas_limit: 100_000,
            payload: payload.to_string(),
            signature: vec![0; 64],
            chain_id: 1,
        }
    }

    #[test]
    fn test_push_and_drain() {
        let mut pool = Mempool::new(10);
        let tx = dummy_tx("alice", 0, 100, 200, "test");
        let base_fee = 50;

        assert!(pool.push_with_base_fee(tx.clone(), base_fee).unwrap());
        assert_eq!(pool.len(), 1);

        let drained = pool.drain_best(1);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].from, "alice");
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_rbf() {
        let mut pool = Mempool::new(10);
        let tx1 = dummy_tx("alice", 0, 100, 200, "first");
        let tx2 = dummy_tx("alice", 0, 111, 250, "second"); // 11% bump

        let base_fee = 50;
        pool.push_with_base_fee(tx1, base_fee).unwrap();
        let replaced = pool.push_with_base_fee(tx2, base_fee).unwrap();
        assert!(!replaced); // replaced returns false
        assert_eq!(pool.len(), 1);

        // Check that the transaction is indeed the second one
        let drained = pool.drain_best(1);
        assert_eq!(drained[0].payload, "second");
        assert_eq!(pool.metrics.rbf_replaced, 1);
    }

    #[test]
    fn test_sender_queue_full() {
        let mut pool = Mempool::new(100);
        let base_fee = 0;
        for i in 0..MAX_PENDING_PER_SENDER {
            let tx = dummy_tx("alice", i as u64, 100, 200, &format!("tx{}", i));
            pool.push_with_base_fee(tx, base_fee).unwrap();
        }
        // Next tx should be rejected
        let tx_extra = dummy_tx("alice", MAX_PENDING_PER_SENDER as u64, 100, 200, "extra");
        let res = pool.push_with_base_fee(tx_extra, base_fee);
        assert!(res.is_err());
        assert_eq!(pool.metrics.rejected_sender_limit, 1);
    }

    #[test]
    fn test_eviction() {
        let mut pool = Mempool::new(2);
        let base_fee = 0;

        // Add two transactions from different senders
        let tx1 = dummy_tx("alice", 0, 100, 200, "high");
        let tx2 = dummy_tx("bob", 0, 50, 150, "low");
        pool.push_with_base_fee(tx1, base_fee).unwrap();
        pool.push_with_base_fee(tx2, base_fee).unwrap();

        // Pool is full; adding a third should evict the lowest priority (bob)
        let tx3 = dummy_tx("carol", 0, 80, 180, "medium");
        pool.push_with_base_fee(tx3, base_fee).unwrap();

        assert_eq!(pool.len(), 2); // One evicted
        assert_eq!(pool.metrics.evicted, 1);

        let drained = pool.drain_best(2);
        assert!(drained.iter().any(|tx| tx.from == "alice"));
        assert!(drained.iter().any(|tx| tx.from == "carol"));
        assert!(!drained.iter().any(|tx| tx.from == "bob"));
    }

    #[test]
    fn test_expiry() {
        let mut pool = Mempool::new(10);
        let base_fee = 0;
        let tx = dummy_tx("alice", 0, 100, 200, "test");
        pool.push_with_base_fee(tx, base_fee).unwrap();

        // Advance far enough to expire
        pool.advance_height(TTL_BLOCKS + 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.metrics.expired, 1);
    }

    #[test]
    fn test_remove_confirmed() {
        let mut pool = Mempool::new(10);
        let base_fee = 0;
        pool.push_with_base_fee(dummy_tx("alice", 0, 100, 200, "tx0"), base_fee).unwrap();
        pool.push_with_base_fee(dummy_tx("alice", 1, 100, 200, "tx1"), base_fee).unwrap();

        pool.remove_confirmed("alice", 1);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.queues.get("alice").unwrap().len(), 1);
        assert!(pool.queues.get("alice").unwrap().contains_key(&1));
    }

    #[test]
    fn test_fee_too_low() {
        let mut pool = Mempool::new(10);
        let tx = dummy_tx("alice", 0, 100, 150, "test");
        let base_fee = 200; // higher than max_fee
        let res = pool.push_with_base_fee(tx, base_fee);
        assert!(res.is_err());
        assert_eq!(pool.metrics.rejected_dup, 1);
    }
}
