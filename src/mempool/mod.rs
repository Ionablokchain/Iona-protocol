//! Standard FIFO mempool for IONA.
//!
//! A simple in‑memory queue for pending transactions, with configurable
//! capacity, duplicate detection, and metrics.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                     Standard Mempool Module                            │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (StdCfg)    │ (StdError)   │ (StdMetrics)  │ (Tx, Hash)              │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Mempool   │   Manager    │    Legacy     │                          │
//! │ (StdMempool)│ (StdManager) │ (global fns)  │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::mempool::standard::{StandardManager, StandardConfig};
//!
//! let config = StandardConfig::default();
//! let manager = StandardManager::new(config);
//! manager.insert(tx)?;
//! let txs = manager.drain(10);
//! ```

#![allow(dead_code)]

use crate::types::{Hash32, Tx, tx_hash};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the standard mempool.
    use serde::{Deserialize, Serialize};

    /// Configuration for the standard mempool.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StandardConfig {
        pub capacity: usize,
        pub enable_dedup: bool,
        pub track_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for StandardConfig {
        fn default() -> Self {
            Self {
                capacity: 200_000,
                enable_dedup: true,
                track_metrics: true,
                log_operations: false,
            }
        }
    }

    impl StandardConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.capacity == 0 {
                return Err("capacity must be > 0");
            }
            Ok(())
        }

        pub fn with_capacity(mut self, cap: usize) -> Self {
            self.capacity = cap;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.track_metrics = true;
            self
        }

        pub fn with_logging(mut self) -> Self {
            self.log_operations = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the standard mempool.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum StandardError {
        #[error("mempool is full (capacity {capacity})")]
        Full { capacity: usize },

        #[error("duplicate transaction")]
        Duplicate,

        #[error("invalid transaction: {0}")]
        InvalidTx(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),
    }

    pub type StandardResult<T> = Result<T, StandardError>;
}

pub mod metrics {
    //! Metrics for the standard mempool.
    use serde::{Deserialize, Serialize};
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Clone, Default, Serialize, Deserialize)]
    pub struct StandardMetrics {
        pub inserted: u64,
        pub drained: u64,
        pub evicted: u64,
        pub duplicates_rejected: u64,
        pub full_events: u64,
        pub empty_events: u64,
        pub current_size: AtomicU64,
    }

    impl StandardMetrics {
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

        pub fn snapshot(&self) -> StandardMetricsSnapshot {
            StandardMetricsSnapshot {
                inserted: self.inserted,
                drained: self.drained,
                evicted: self.evicted,
                duplicates_rejected: self.duplicates_rejected,
                full_events: self.full_events,
                empty_events: self.empty_events,
                current_size: self.size(),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct StandardMetricsSnapshot {
        pub inserted: u64,
        pub drained: u64,
        pub evicted: u64,
        pub duplicates_rejected: u64,
        pub full_events: u64,
        pub empty_events: u64,
        pub current_size: u64,
    }
}

pub mod mempool {
    //! Core standard mempool implementation.
    use super::{
        config::StandardConfig,
        error::{StandardError, StandardResult},
        metrics::StandardMetrics,
    };
    use crate::types::{Hash32, Tx, tx_hash};
    use std::collections::{HashMap, VecDeque};
    use std::sync::atomic::Ordering;
    use tracing::{debug, trace, warn};

    /// A simple FIFO mempool with configurable capacity and duplicate detection.
    #[derive(Debug)]
    pub struct StandardMempool {
        config: StandardConfig,
        queue: VecDeque<Tx>,
        hash_index: HashMap<Hash32, usize>, // tx_hash → index in queue
        metrics: StandardMetrics,
    }

    impl StandardMempool {
        pub fn new(config: StandardConfig) -> Self {
            config.validate().expect("invalid StandardConfig");
            Self {
                config,
                queue: VecDeque::with_capacity(config.capacity),
                hash_index: HashMap::with_capacity(config.capacity),
                metrics: StandardMetrics::default(),
            }
        }

        pub fn with_defaults() -> Self {
            Self::new(StandardConfig::default())
        }

        pub fn config(&self) -> &StandardConfig {
            &self.config
        }

        pub fn metrics(&self) -> &StandardMetrics {
            &self.metrics
        }

        /// Insert a transaction into the mempool.
        pub fn insert(&mut self, tx: Tx) -> StandardResult<()> {
            let tx_hash = tx_hash(&tx);

            if self.config.enable_dedup && self.hash_index.contains_key(&tx_hash) {
                self.metrics.record_duplicate();
                if self.config.log_operations {
                    trace!("duplicate tx rejected");
                }
                return Err(StandardError::Duplicate);
            }

            if self.queue.len() >= self.config.capacity {
                self.metrics.record_full();
                if self.config.log_operations {
                    warn!("mempool full (capacity {})", self.config.capacity);
                }
                return Err(StandardError::Full {
                    capacity: self.config.capacity,
                });
            }

            let idx = self.queue.len();
            self.queue.push_back(tx);
            self.hash_index.insert(tx_hash, idx);
            self.metrics.record_insert();

            if self.config.log_operations {
                trace!("tx inserted, size: {}", self.queue.len());
            }
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
            if self.config.log_operations {
                trace!("drained {} txs", n);
            }
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

        /// Clear all transactions.
        pub fn clear(&mut self) {
            let count = self.queue.len();
            self.queue.clear();
            self.hash_index.clear();
            self.metrics.record_evict(count);
            if self.config.log_operations {
                trace!("cleared {} txs", count);
            }
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
            let count = result.len();
            self.hash_index.clear();
            self.metrics.record_drain(count);
            if self.config.log_operations {
                trace!("drained all {} txs", count);
            }
            result
        }

        /// Update the mempool configuration (e.g., capacity).
        pub fn set_config(&mut self, config: StandardConfig) -> StandardResult<()> {
            config.validate().map_err(|e| StandardError::Config(e.into()))?;
            if config.capacity < self.queue.len() {
                return Err(StandardError::Internal(
                    "new capacity less than current size".into(),
                ));
            }
            self.config = config;
            // Optionally resize the queue if needed.
            Ok(())
        }

        /// Get a metrics snapshot.
        pub fn metrics_snapshot(&self) -> super::metrics::StandardMetricsSnapshot {
            self.metrics.snapshot()
        }
    }
}

pub mod manager {
    //! Centralised manager for the standard mempool.
    use super::{
        config::StandardConfig,
        error::StandardResult,
        mempool::StandardMempool,
        metrics::StandardMetrics,
    };
    use crate::types::{Hash32, Tx};
    use std::sync::Arc;

    /// Manager for the standard mempool.
    pub struct StandardManager {
        mempool: StandardMempool,
    }

    impl StandardManager {
        pub fn new(config: StandardConfig) -> Self {
            let mempool = StandardMempool::new(config);
            Self { mempool }
        }

        pub fn with_defaults() -> Self {
            Self::new(StandardConfig::default())
        }

        pub fn config(&self) -> &StandardConfig {
            self.mempool.config()
        }

        pub fn metrics(&self) -> &StandardMetrics {
            self.mempool.metrics()
        }

        pub fn insert(&mut self, tx: Tx) -> StandardResult<()> {
            self.mempool.insert(tx)
        }

        pub fn drain(&mut self, n: usize) -> Vec<Tx> {
            self.mempool.drain(n)
        }

        pub fn drain_all(&mut self) -> Vec<Tx> {
            self.mempool.drain_all()
        }

        pub fn len(&self) -> usize {
            self.mempool.len()
        }

        pub fn is_empty(&self) -> bool {
            self.mempool.is_empty()
        }

        pub fn capacity(&self) -> usize {
            self.mempool.capacity()
        }

        pub fn clear(&mut self) {
            self.mempool.clear()
        }

        pub fn contains(&self, tx_hash: &Hash32) -> bool {
            self.mempool.contains(tx_hash)
        }

        pub fn peek(&self) -> Option<&Tx> {
            self.mempool.peek()
        }

        pub fn peek_back(&self) -> Option<&Tx> {
            self.mempool.peek_back()
        }

        pub fn set_config(&mut self, config: StandardConfig) -> StandardResult<()> {
            self.mempool.set_config(config)
        }

        pub fn metrics_snapshot(&self) -> super::metrics::StandardMetricsSnapshot {
            self.mempool.metrics_snapshot()
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::StandardConfig;
pub use error::{StandardError, StandardResult};
pub use metrics::{StandardMetrics, StandardMetricsSnapshot};
pub use mempool::StandardMempool;
pub use manager::StandardManager;

// -----------------------------------------------------------------------------
// Legacy global API (backward compatibility)
// -----------------------------------------------------------------------------

/// Create a new standard mempool with default configuration.
pub fn new_mempool() -> StandardMempool {
    StandardMempool::with_defaults()
}

/// Create a new standard mempool with custom configuration.
pub fn new_mempool_with_config(config: StandardConfig) -> StandardMempool {
    StandardMempool::new(config)
}

// -----------------------------------------------------------------------------
// Mempool trait implementation (optional, for compatibility with MEV mempool)
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
        let mut pool = StandardMempool::new(StandardConfig::default());
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
        let mut pool = StandardMempool::new(StandardConfig::default());
        let tx = dummy_tx("alice", 0, "hello");
        pool.insert(tx.clone()).unwrap();
        let err = pool.insert(tx).unwrap_err();
        assert!(matches!(err, StandardError::Duplicate));
    }

    #[test]
    fn test_capacity_limit() {
        let config = StandardConfig {
            capacity: 2,
            ..Default::default()
        };
        let mut pool = StandardMempool::new(config);
        pool.insert(dummy_tx("alice", 0, "tx1")).unwrap();
        pool.insert(dummy_tx("bob", 0, "tx2")).unwrap();
        let err = pool.insert(dummy_tx("charlie", 0, "tx3")).unwrap_err();
        assert!(matches!(err, StandardError::Full { capacity: 2 }));
    }

    #[test]
    fn test_clear() {
        let mut pool = StandardMempool::with_defaults();
        pool.insert(dummy_tx("alice", 0, "hello")).unwrap();
        pool.clear();
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_contains() {
        let mut pool = StandardMempool::with_defaults();
        let tx = dummy_tx("alice", 0, "hello");
        let hash = tx_hash(&tx);
        pool.insert(tx).unwrap();
        assert!(pool.contains(&hash));
    }

    #[test]
    fn test_peek() {
        let mut pool = StandardMempool::with_defaults();
        let tx = dummy_tx("alice", 0, "hello");
        pool.insert(tx).unwrap();
        let peeked = pool.peek().unwrap();
        assert_eq!(peeked.payload, "hello");
    }

    #[test]
    fn test_drain_all() {
        let mut pool = StandardMempool::with_defaults();
        pool.insert(dummy_tx("alice", 0, "tx1")).unwrap();
        pool.insert(dummy_tx("bob", 0, "tx2")).unwrap();
        let all = pool.drain_all();
        assert_eq!(all.len(), 2);
        assert_eq!(pool.len(), 0);
    }

    #[test]
    fn test_metrics() {
        let mut pool = StandardMempool::with_defaults();
        pool.insert(dummy_tx("alice", 0, "tx1")).unwrap();
        pool.insert(dummy_tx("bob", 0, "tx2")).unwrap();
        let metrics = pool.metrics();
        assert_eq!(metrics.inserted, 2);
        assert_eq!(metrics.size(), 2);

        pool.drain(1);
        assert_eq!(metrics.size(), 1);
    }

    #[test]
    fn test_config_validation() {
        let config = StandardConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = config.clone();
        bad.capacity = 0;
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_manager() {
        let config = StandardConfig::default();
        let mut manager = StandardManager::new(config);
        manager.insert(dummy_tx("alice", 0, "hello")).unwrap();
        assert_eq!(manager.len(), 1);
        let drained = manager.drain(1);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, "hello");
    }
}
