//! Standard FIFO mempool for IONA.
//!
//! A simple in‑memory queue for pending transactions, with configurable
//! capacity, duplicate detection, and metrics.

use crate::types::{Hash32, Tx, tx_hash};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the standard mempool.
#[derive(Debug, Clone)]
pub struct StandardMempoolConfig {
    /// Maximum number of transactions in the mempool.
    pub capacity: usize,
    /// Whether to enable duplicate detection (default: true).
    pub enable_dedup: bool,
    /// Whether to track metrics (default: true).
    pub track_metrics: bool,
}

impl Default for StandardMempoolConfig {
    fn default() -> Self {
        Self {
            capacity: 200_000,
            enable_dedup: true,
            track_metrics: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur in the standard mempool.
#[derive(Debug, Error)]
pub enum StandardMempoolError {
    #[error("mempool is full (capacity {capacity})")]
    Full { capacity: usize },

    #[error("duplicate transaction")]
    Duplicate,

    #[error("invalid transaction: {0}")]
    InvalidTx(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type StandardResult<T> = Result<T, StandardMempoolError>;

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the standard mempool.
#[derive(Debug, Clone, Default)]
pub struct StandardMempoolMetrics {
    pub inserted: u64,
    pub drained: u64,
    pub evicted: u64,
    pub duplicates_rejected: u64,
    pub full_events: u64,
    pub empty_events: u64,
    pub current_size: AtomicU64,
}

impl StandardMempoolMetrics {
    pub fn record_insert(&self) {
        self.inserted += 1;
        self.current_size.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_drain(&self, count: usize) {
        self.drained += count as u64;
        self.current_size.fetch_sub(count as u64, Ordering::Relaxed);
    }

    pub fn record_evict(&self, count: usize) {
        self.evicted += count as u64;
        self.current_size.fetch_sub(count as u64, Ordering::Relaxed);
    }

    pub fn record_duplicate(&self) {
        self.duplicates_rejected += 1;
    }

    pub fn record_full(&self) {
        self.full_events += 1;
    }

    pub fn record_empty(&self) {
        self.empty_events += 1;
    }

    pub fn size(&self) -> u64 {
        self.current_size.load(Ordering::Relaxed)
    }
}

// -----------------------------------------------------------------------------
// Standard Mempool
// -----------------------------------------------------------------------------

/// A simple FIFO mempool with configurable capacity and duplicate detection.
#[derive(Debug)]
pub struct StandardMempool {
    config: StandardMempoolConfig,
    queue: VecDeque<Tx>,
    hash_index: HashMap<Hash32, usize>, // tx_hash → index in queue (for O(1) dedup)
    metrics: StandardMempoolMetrics,
}

impl StandardMempool {
    /// Create a new standard mempool with default configuration.
    pub fn new(capacity: usize) -> Self {
        let config = StandardMempoolConfig {
            capacity,
            ..Default::default()
        };
        Self::with_config(config)
    }

    /// Create a new standard mempool with the given configuration.
    pub fn with_config(config: StandardMempoolConfig) -> Self {
        Self {
            config,
            queue: VecDeque::with_capacity(config.capacity),
            hash_index: HashMap::with_capacity(config.capacity),
            metrics: StandardMempoolMetrics::default(),
        }
    }

    /// Insert a transaction into the mempool.
    pub fn insert(&mut self, tx: Tx) -> StandardResult<()> {
        let tx_hash = tx_hash(&tx);

        // Duplicate detection
        if self.config.enable_dedup && self.hash_index.contains_key(&tx_hash) {
            self.metrics.record_duplicate();
            return Err(StandardMempoolError::Duplicate);
        }

        // Check capacity
        if self.queue.len() >= self.config.capacity {
            self.metrics.record_full();
            return Err(StandardMempoolError::Full {
                capacity: self.config.capacity,
            });
        }

        // Insert
        let idx = self.queue.len();
        self.queue.push_back(tx);
        self.hash_index.insert(tx_hash, idx);
        self.metrics.record_insert();
        Ok(())
    }

    /// Drain up to `n` transactions from the front of the queue.
    pub fn drain(&mut self, n: usize) -> Vec<Tx> {
        if self.queue.is_empty() {
            self.metrics.record_empty();
            return Vec::new();
        }

        let n = n.min(self.queue.len());
        let mut result = Vec::with_capacity(n);
        for _ in 0..n {
            let tx = self.queue.pop_front().unwrap();
            let tx_hash = tx_hash(&tx);
            self.hash_index.remove(&tx_hash);
            result.push(tx);
        }
        self.metrics.record_drain(n);
        result
    }

    /// Get the current number of transactions.
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Get the capacity of the mempool.
    pub fn capacity(&self) -> usize {
        self.config.capacity
    }

    /// Get the metrics.
    pub fn metrics(&self) -> &StandardMempoolMetrics {
        &self.metrics
    }

    /// Clear all transactions.
    pub fn clear(&mut self) {
        self.queue.clear();
        self.hash_index.clear();
        self.metrics.record_evict(self.queue.len());
    }

    /// Check if a transaction exists by hash.
    pub fn contains(&self, tx_hash: &Hash32) -> bool {
        self.hash_index.contains_key(tx_hash)
    }

    /// Peek at the front transaction without removing it.
    pub fn peek(&self) -> Option<&Tx> {
        self.queue.front()
    }

    /// Peek at the last transaction without removing it.
    pub fn peek_back(&self) -> Option<&Tx> {
        self.queue.back()
    }

    /// Drain all transactions.
    pub fn drain_all(&mut self) -> Vec<Tx> {
        let result = self.queue.drain(..).collect();
        self.hash_index.clear();
        self.metrics.record_drain(result.len());
        result
    }

    /// Update the mempool configuration (e.g., capacity) – not supported in production.
    pub fn set_capacity(&mut self, new_capacity: usize) -> Result<(), StandardMempoolError> {
        if new_capacity < self.queue.len() {
            return Err(StandardMempoolError::Internal(
                "new capacity less than current size".into(),
            ));
        }
        self.config.capacity = new_capacity;
        // Optionally resize the queue if needed (but VecDeque handles it).
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Mempool trait implementation
// -----------------------------------------------------------------------------

use crate::mempool::{Mempool, MempoolError, MempoolMetrics, QuantumMempoolState};
use std::any::Any;

impl Mempool for StandardMempool {
    fn insert(&mut self, tx: crate::types::Tx) -> MempoolResult<()> {
        self.insert(tx).map_err(|e| MempoolError::Standard(e))
    }

    fn drain(&mut self, n: usize) -> Vec<crate::types::Tx> {
        self.drain(n)
    }

    fn len(&self) -> usize {
        self.len()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn capacity(&self) -> usize {
        self.capacity()
    }

    fn metrics(&self) -> MempoolMetrics {
        // Convert from StandardMempoolMetrics to MempoolMetrics
        MempoolMetrics {
            inserted: self.metrics.inserted,
            drained: self.metrics.drained,
            evicted: self.metrics.evicted,
            duplicates_rejected: self.metrics.duplicates_rejected,
            full_events: self.metrics.full_events,
            empty_events: self.metrics.empty_events,
            size: self.metrics.current_size,
        }
    }

    fn quantum_state(&self) -> QuantumMempoolState {
        // For the standard mempool, we compute a simplified quantum state based on size.
        // In a real implementation, we'd track operations and coherence.
        let mut state = QuantumMempoolState::new();
        state.apply_operation_decoherence();
        state
    }

    fn clear(&mut self) {
        self.clear();
    }

    fn contains(&self, tx_hash: &crate::types::Hash32) -> bool {
        self.contains(tx_hash)
    }

    fn as_any(&self) -> &dyn Any {
        self
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Tx;

    fn dummy_tx(from: &str, nonce: u64, payload: &str) -> Tx {
        Tx {
            pubkey: vec![0; 32],
            from: from.to_string(),
            nonce,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: payload.to_string(),
            signature: vec![0; 64],
            chain_id: 1,
        }
    }

    #[test]
    fn test_insert_and_drain() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, "hello");
        pool.insert(tx.clone()).unwrap();
        assert_eq!(pool.len(), 1);
        let drained = pool.drain(1);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, "hello");
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_duplicate_detection() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, "hello");
        pool.insert(tx.clone()).unwrap();
        let err = pool.insert(tx).unwrap_err();
        assert!(matches!(err, StandardMempoolError::Duplicate));
    }

    #[test]
    fn test_capacity_limit() {
        let mut pool = StandardMempool::new(2);
        pool.insert(dummy_tx("alice", 0, "tx1")).unwrap();
        pool.insert(dummy_tx("bob", 0, "tx2")).unwrap();
        let err = pool.insert(dummy_tx("charlie", 0, "tx3")).unwrap_err();
        assert!(matches!(err, StandardMempoolError::Full { capacity: 2 }));
    }

    #[test]
    fn test_clear() {
        let mut pool = StandardMempool::new(10);
        pool.insert(dummy_tx("alice", 0, "hello")).unwrap();
        pool.clear();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_contains() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, "hello");
        let hash = tx_hash(&tx);
        pool.insert(tx).unwrap();
        assert!(pool.contains(&hash));
    }

    #[test]
    fn test_peek() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, "hello");
        pool.insert(tx).unwrap();
        let peeked = pool.peek().unwrap();
        assert_eq!(peeked.payload, "hello");
    }

    #[test]
    fn test_drain_all() {
        let mut pool = StandardMempool::new(10);
        pool.insert(dummy_tx("alice", 0, "tx1")).unwrap();
        pool.insert(dummy_tx("bob", 0, "tx2")).unwrap();
        let all = pool.drain_all();
        assert_eq!(all.len(), 2);
        assert_eq!(pool.len(), 0);
    }
}
