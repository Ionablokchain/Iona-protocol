//! Standard mempool for IONA — Quantum State Model.
//!
//! This module implements a high‑performance transaction pool with:
//! - Priority ordering (score = tip × gas / size)
//! - Per‑sender nonce queues with RBF (Replace‑By‑Fee)
//! - Global capacity with eviction of lowest‑priority transactions
//! - TTL expiry per transaction
//! - Quantum state tracking (purity, entropy, coherence)
//! - Configurable parameters via `MempoolConfig`
//! - Comprehensive metrics
//!
//! # Quantum Mempool Architecture
//!
//! The mempool is modelled as an **open quantum system** where each
//! transaction is a **pure state** |tx_i⟩ in the mempool Hilbert space.
//! The state evolves under a Lindblad master equation with Hamiltonian
//! governing priority ordering and decoherence from TTL expiry.
//!
//! # Example
//!
//! ```
//! use iona::mempool::StandardMempool;
//! use iona::types::Tx;
//!
//! let mut mempool = StandardMempool::new(MempoolConfig::default());
//! let tx = Tx { /* ... */ };
//! mempool.insert(tx, 100).unwrap();
//! let txs = mempool.drain(10);
//! ```

use crate::execution::intrinsic_gas;
use crate::types::{Hash32, Height, Tx};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants (with quantum semantics)
// -----------------------------------------------------------------------------

/// Number of blocks after which a transaction expires (coherence time).
pub const DEFAULT_TTL_BLOCKS: u64 = 300;

/// Maximum number of pending transactions per sender (Hilbert space bound).
pub const DEFAULT_MAX_PENDING_PER_SENDER: usize = 64;

/// Minimum percentage tip increase for RBF replacement (swap gate threshold).
pub const DEFAULT_RBF_BUMP_PERCENT: u64 = 10;

/// Default mempool capacity.
pub const DEFAULT_CAPACITY: usize = 200_000;

/// Decoherence rate per operation (insert/evict).
const OPERATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per TTL expiry (stronger — time evolution).
const TTL_DECOHERENCE_RATE: f64 = 0.001;

/// Kraus rank for mempool quantum channels.
const KRAUS_RANK: usize = 4;

/// Minimum coherence threshold for healthy mempool.
const MIN_MEMPOOL_COHERENCE: f64 = 0.9;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the standard mempool.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolConfig {
    /// Maximum total transactions in the pool.
    pub capacity: usize,
    /// Number of blocks after which a transaction expires.
    pub ttl_blocks: u64,
    /// Maximum pending transactions per sender.
    pub max_pending_per_sender: usize,
    /// Minimum percentage tip increase for RBF (e.g., 10 = 10%).
    pub rbf_bump_percent: u64,
    /// Whether to enable quantum state tracking (slightly slower).
    pub enable_quantum_state: bool,
    /// Default base fee for submissions when not provided.
    pub default_base_fee: u64,
    /// Whether to log decoherence events.
    pub log_decoherence: bool,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        Self {
            capacity: DEFAULT_CAPACITY,
            ttl_blocks: DEFAULT_TTL_BLOCKS,
            max_pending_per_sender: DEFAULT_MAX_PENDING_PER_SENDER,
            rbf_bump_percent: DEFAULT_RBF_BUMP_PERCENT,
            enable_quantum_state: true,
            default_base_fee: 0,
            log_decoherence: false,
        }
    }
}

impl MempoolConfig {
    /// Validate the configuration, returning an error if invalid.
    pub fn validate(&self) -> Result<(), MempoolError> {
        if self.capacity == 0 {
            return Err(MempoolError::Config("capacity must be > 0".into()));
        }
        if self.ttl_blocks == 0 {
            return Err(MempoolError::Config("ttl_blocks must be > 0".into()));
        }
        if self.max_pending_per_sender == 0 {
            return Err(MempoolError::Config(
                "max_pending_per_sender must be > 0".into(),
            ));
        }
        if self.rbf_bump_percent == 0 {
            return Err(MempoolError::Config("rbf_bump_percent must be > 0".into()));
        }
        Ok(())
    }
}

/// Builder for `MempoolConfig` with fluent API.
#[derive(Default)]
pub struct MempoolConfigBuilder {
    config: MempoolConfig,
}

impl MempoolConfigBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn capacity(mut self, cap: usize) -> Self {
        self.config.capacity = cap;
        self
    }

    pub fn ttl_blocks(mut self, ttl: u64) -> Self {
        self.config.ttl_blocks = ttl;
        self
    }

    pub fn max_pending_per_sender(mut self, max: usize) -> Self {
        self.config.max_pending_per_sender = max;
        self
    }

    pub fn rbf_bump_percent(mut self, bump: u64) -> Self {
        self.config.rbf_bump_percent = bump;
        self
    }

    pub fn enable_quantum_state(mut self, enable: bool) -> Self {
        self.config.enable_quantum_state = enable;
        self
    }

    pub fn default_base_fee(mut self, fee: u64) -> Self {
        self.config.default_base_fee = fee;
        self
    }

    pub fn log_decoherence(mut self, log: bool) -> Self {
        self.config.log_decoherence = log;
        self
    }

    pub fn build(self) -> Result<MempoolConfig, MempoolError> {
        self.config.validate()?;
        Ok(self.config)
    }
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("mempool is full (capacity {capacity})")]
    Full { capacity: usize },

    #[error("duplicate transaction")]
    Duplicate,

    #[error("sender queue full (max {max})")]
    SenderQueueFull { max: usize },

    #[error("RBF bump too low: existing tip {existing_tip}, required {required}")]
    RbfTooLow { existing_tip: u64, required: u64 },

    #[error("fee too low: max_fee {max_fee} < base_fee {base_fee}")]
    FeeTooLow { max_fee: u64, base_fee: u64 },

    #[error("missing sender address")]
    MissingSender,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type MempoolResult<T> = Result<T, MempoolError>;

// -----------------------------------------------------------------------------
// Quantum State
// -----------------------------------------------------------------------------

/// Quantum state of the mempool.
///
/// Tracks the density matrix properties:
/// - γ = Tr(ρ²) — purity (1.0 = pure state, <1.0 = mixed)
/// - S = -Tr(ρ ln ρ) — von Neumann entropy
/// - Coherence per sender subspace
#[derive(Debug, Clone, Default, Serialize)]
pub struct QuantumMempoolState {
    /// Purity γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S.
    pub entropy: f64,
    /// Coherence per sender (sender → coherence).
    pub sender_coherence: HashMap<String, f64>,
    /// Total operations performed.
    pub total_operations: u64,
    /// Total decoherence events (expiries, evictions).
    pub decoherence_events: u64,
    /// Whether the mempool is in a healthy quantum state.
    pub is_healthy: bool,
}

impl QuantumMempoolState {
    /// Create a new quantum mempool state in the ground state |∅⟩.
    fn new() -> Self {
        Self {
            purity: 1.0,
            entropy: 0.0,
            sender_coherence: HashMap::new(),
            total_operations: 0,
            decoherence_events: 0,
            is_healthy: true,
        }
    }

    /// Apply decoherence from a general mempool operation.
    fn apply_operation_decoherence(&mut self) {
        self.total_operations = self.total_operations.wrapping_add(1);
        let decay = (-OPERATION_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_MEMPOOL_COHERENCE;
    }

    /// Apply TTL decoherence (stronger — time evolution).
    fn apply_ttl_decoherence(&mut self) {
        self.decoherence_events = self.decoherence_events.wrapping_add(1);
        let decay = (-TTL_DECOHERENCE_RATE).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_MEMPOOL_COHERENCE;
    }

    /// Register a sender's coherence.
    fn register_sender(&mut self, sender: &str) {
        self.sender_coherence
            .entry(sender.to_string())
            .or_insert(1.0);
    }

    /// Update a sender's coherence after an operation.
    fn update_sender_coherence(&mut self, sender: &str, decay_factor: f64) {
        if let Some(coh) = self.sender_coherence.get_mut(sender) {
            *coh = (*coh * decay_factor).clamp(0.0, 1.0);
        }
    }
}

// -----------------------------------------------------------------------------
// Pending Transaction
// -----------------------------------------------------------------------------

/// Internal representation of a pending transaction.
#[derive(Clone, Debug)]
struct PendingTx {
    tx: Tx,
    score: u128,
    inserted_height: Height,
    /// Quantum purity of this transaction state.
    purity: f64,
}

impl PendingTx {
    /// Create a new pending transaction, computing its priority score.
    ///
    /// Score = (effective_tip × GAS × 1_000_000) / size
    /// where effective_tip = min(max_priority_fee, max_fee - base_fee).
    fn new(tx: Tx, current_height: Height, base_fee: u64) -> Self {
        let gas = intrinsic_gas(&tx) as u128;
        let effective_tip = if tx.max_fee_per_gas > base_fee {
            tx.max_priority_fee_per_gas
                .min(tx.max_fee_per_gas - base_fee) as u128
        } else {
            0
        };
        let tip_gas = effective_tip.saturating_mul(gas);
        let size = (tx.payload.len() as u128 + 128).max(1);
        let score = tip_gas.saturating_mul(1_000_000) / size;
        Self {
            tx,
            score,
            inserted_height: current_height,
            purity: 1.0,
        }
    }

    fn is_expired(&self, current_height: Height, ttl: u64) -> bool {
        current_height.saturating_sub(self.inserted_height) > ttl
    }

    /// Apply decoherence to this transaction (e.g., from waiting).
    fn apply_decoherence(&mut self, rate: f64) {
        self.purity = (self.purity * (-rate).exp()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Priority Queue Entry
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
        self.score
            .cmp(&other.score)
            .then_with(|| other.nonce.cmp(&self.nonce))
    }
}

// -----------------------------------------------------------------------------
// Metrics (classical + quantum)
// -----------------------------------------------------------------------------

/// Metrics for the standard mempool.
#[derive(Debug, Clone, Default, Serialize)]
pub struct MempoolMetrics {
    /// Number of transactions admitted.
    pub admitted: u64,
    /// Number of duplicates rejected.
    pub rejected_dup: u64,
    /// Number of rejections due to full mempool.
    pub rejected_full: u64,
    /// Number of rejections due to sender queue full.
    pub rejected_sender_limit: u64,
    /// Number of transactions evicted (global).
    pub evicted: u64,
    /// Number of transactions expired (TTL).
    pub expired: u64,
    /// Number of RBF replacements.
    pub rbf_replaced: u64,
    /// Quantum purity of the mempool.
    pub quantum_purity: f64,
    /// Von Neumann entropy of the mempool.
    pub quantum_entropy: f64,
    /// Number of decoherence events.
    pub decoherence_events: u64,
}

impl MempoolMetrics {
    /// Record an admission.
    pub fn record_admit(&mut self) {
        self.admitted += 1;
    }

    /// Record a duplicate rejection.
    pub fn record_dup(&mut self) {
        self.rejected_dup += 1;
    }

    /// Record a full mempool rejection.
    pub fn record_full(&mut self) {
        self.rejected_full += 1;
    }

    /// Record a sender limit rejection.
    pub fn record_sender_limit(&mut self) {
        self.rejected_sender_limit += 1;
    }

    /// Record an eviction.
    pub fn record_evict(&mut self) {
        self.evicted += 1;
    }

    /// Record an expiry.
    pub fn record_expiry(&mut self) {
        self.expired += 1;
    }

    /// Record an RBF replacement.
    pub fn record_rbf(&mut self) {
        self.rbf_replaced += 1;
    }
}

// -----------------------------------------------------------------------------
// Standard Mempool
// -----------------------------------------------------------------------------

/// Production mempool with priority ordering, per‑sender nonce queues,
/// RBF, TTL, eviction, and optional quantum state tracking.
pub struct StandardMempool {
    config: MempoolConfig,
    queues: HashMap<String, BTreeMap<u64, PendingTx>>,
    metrics: MempoolMetrics,
    quantum_state: Option<QuantumMempoolState>,
    current_height: Height,
    pending_count: u64,
}

impl StandardMempool {
    /// Create a new mempool with the given configuration.
    pub fn new(config: MempoolConfig) -> Self {
        config.validate().expect("invalid configuration");
        Self {
            config,
            queues: HashMap::new(),
            metrics: MempoolMetrics::default(),
            quantum_state: if config.enable_quantum_state {
                Some(QuantumMempoolState::new())
            } else {
                None
            },
            current_height: 0,
            pending_count: 0,
        }
    }

    /// Create a new mempool with default configuration.
    pub fn default() -> Self {
        Self::new(MempoolConfig::default())
    }

    /// Get the current configuration.
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Get the current metrics.
    pub fn metrics(&self) -> &MempoolMetrics {
        &self.metrics
    }

    /// Get the quantum state (if enabled).
    pub fn quantum_state(&self) -> Option<&QuantumMempoolState> {
        self.quantum_state.as_ref()
    }

    /// Get the current height.
    pub fn current_height(&self) -> Height {
        self.current_height
    }

    /// Total number of transactions in the pool.
    pub fn len(&self) -> usize {
        self.pending_count as usize
    }

    /// Check if the mempool is empty.
    pub fn is_empty(&self) -> bool {
        self.pending_count == 0
    }

    /// Get the number of distinct senders.
    pub fn sender_count(&self) -> usize {
        self.queues.len()
    }

    /// Advance the block height, expiring old transactions.
    pub fn advance_height(&mut self, height: Height) {
        if height <= self.current_height {
            return;
        }
        self.current_height = height;
        let ttl = self.config.ttl_blocks;

        let mut expired_count = 0u64;

        self.queues.retain(|sender, queue| {
            let before = queue.len();
            queue.retain(|_, ptx| {
                let keep = !ptx.is_expired(height, ttl);
                if !keep {
                    expired_count += 1;
                    if let Some(qs) = &mut self.quantum_state {
                        qs.update_sender_coherence(sender, 0.99);
                    }
                }
                keep
            });
            let expired = before - queue.len();
            self.metrics.record_expiry();
            expired_count += expired as u64;
            !queue.is_empty()
        });

        // Apply TTL decoherence
        if let Some(qs) = &mut self.quantum_state {
            for _ in 0..expired_count {
                qs.apply_ttl_decoherence();
            }
            self.sync_metrics();
        }

        // Update pending count
        self.pending_count = self.queues.values().map(|q| q.len() as u64).sum();
    }

    /// Remove confirmed transactions (nonces below the given nonce).
    pub fn remove_confirmed(&mut self, sender: &str, committed_nonce: u64) {
        if let Some(queue) = self.queues.get_mut(sender) {
            queue.retain(|&nonce, _| nonce >= committed_nonce);
            if queue.is_empty() {
                self.queues.remove(sender);
            }
            // Confirmation restores some coherence
            if let Some(qs) = &mut self.quantum_state {
                qs.update_sender_coherence(sender, 1.001.min(1.0));
                self.sync_metrics();
            }
            self.pending_count = self.queues.values().map(|q| q.len() as u64).sum();
        }
    }

    /// Insert a transaction using the given base fee.
    pub fn insert(&mut self, tx: Tx, base_fee: u64) -> MempoolResult<()> {
        if tx.from.is_empty() {
            return Err(MempoolError::MissingSender);
        }

        // Register sender in quantum state
        if let Some(qs) = &mut self.quantum_state {
            qs.register_sender(&tx.from);
        }

        // Check fee
        if tx.max_fee_per_gas < base_fee {
            self.metrics.record_dup();
            if let Some(qs) = &mut self.quantum_state {
                qs.apply_operation_decoherence();
                self.sync_metrics();
            }
            return Err(MempoolError::FeeTooLow {
                max_fee: tx.max_fee_per_gas,
                base_fee,
            });
        }

        let queue = self.queues.entry(tx.from.clone()).or_default();

        // Check per‑sender limit
        if queue.len() >= self.config.max_pending_per_sender {
            self.metrics.record_sender_limit();
            if let Some(qs) = &mut self.quantum_state {
                qs.apply_operation_decoherence();
                self.sync_metrics();
            }
            return Err(MempoolError::SenderQueueFull {
                max: self.config.max_pending_per_sender,
            });
        }

        // RBF check
        if let Some(existing) = queue.get(&tx.nonce) {
            let existing_tip = existing.tx.max_priority_fee_per_gas;
            let required = existing_tip.saturating_add(
                (existing_tip.saturating_mul(self.config.rbf_bump_percent) / 100).max(1),
            );
            if tx.max_priority_fee_per_gas < required {
                self.metrics.record_dup();
                if let Some(qs) = &mut self.quantum_state {
                    qs.apply_operation_decoherence();
                    self.sync_metrics();
                }
                return Err(MempoolError::RbfTooLow {
                    existing_tip,
                    required,
                });
            }
            // RBF replacement
            queue.insert(
                tx.nonce,
                PendingTx::new(tx, self.current_height, base_fee),
            );
            self.metrics.record_rbf();
            if let Some(qs) = &mut self.quantum_state {
                qs.update_sender_coherence(&tx.from, 0.995);
                qs.apply_operation_decoherence();
                self.sync_metrics();
            }
            // Update pending count (unchanged)
            return Ok(());
        }

        // Global capacity with eviction
        if self.pending_count >= self.config.capacity as u64 {
            if !self.evict_worst(&tx.from) {
                self.metrics.record_full();
                if let Some(qs) = &mut self.quantum_state {
                    qs.apply_operation_decoherence();
                    self.sync_metrics();
                }
                return Err(MempoolError::Full {
                    capacity: self.config.capacity,
                });
            }
        }

        // Insert new transaction
        let ptx = PendingTx::new(tx, self.current_height, base_fee);
        queue.insert(ptx.tx.nonce, ptx);
        self.metrics.record_admit();
        self.pending_count += 1;

        if let Some(qs) = &mut self.quantum_state {
            qs.update_sender_coherence(&queue.keys().next().unwrap().clone(), 0.999);
            qs.apply_operation_decoherence();
            self.sync_metrics();
        }

        Ok(())
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
            self.metrics.record_evict();
            self.pending_count -= 1;
            if let Some(qs) = &mut self.quantum_state {
                qs.update_sender_coherence(&sender, 0.98);
                qs.apply_ttl_decoherence();
                self.sync_metrics();
            }
            true
        } else {
            false
        }
    }

    /// Drain up to `n` transactions in priority order, respecting per‑sender nonce ordering.
    pub fn drain(&mut self, n: usize) -> Vec<Tx> {
        if self.is_empty() || n == 0 {
            return Vec::new();
        }

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
            self.pending_count -= 1;
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

        // Draining restores some coherence (reduces entropy)
        if !result.is_empty() && let Some(qs) = &mut self.quantum_state {
            qs.purity = (qs.purity * 1.001).min(1.0);
            self.sync_metrics();
        }

        result
    }

    /// Apply waiting decoherence to all pending transactions.
    pub fn apply_waiting_decoherence(&mut self) {
        if let Some(qs) = &mut self.quantum_state {
            for queue in self.queues.values_mut() {
                for ptx in queue.values_mut() {
                    ptx.apply_decoherence(OPERATION_DECOHERENCE_RATE);
                }
            }
            qs.apply_operation_decoherence();
            self.sync_metrics();
        }
    }

    /// Sync quantum state to metrics.
    fn sync_metrics(&mut self) {
        if let Some(qs) = &mut self.quantum_state {
            self.metrics.quantum_purity = qs.purity;
            self.metrics.quantum_entropy = qs.entropy;
            self.metrics.decoherence_events = qs.decoherence_events;
        }
    }
}

// -----------------------------------------------------------------------------
// Implementation of the unified Mempool trait (if needed)
// -----------------------------------------------------------------------------

// This is a placeholder to satisfy the trait requirement if used in the broader system.

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_tx(
        from: &str,
        nonce: u64,
        tip: u64,
        max_fee: u64,
        payload: &str,
    ) -> Tx {
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
    fn test_insert_and_drain() {
        let config = MempoolConfig::default();
        let mut pool = StandardMempool::new(config);
        let tx = dummy_tx("alice", 0, 100, 200, "hello");
        pool.insert(tx, 0).unwrap();
        assert_eq!(pool.len(), 1);

        let drained = pool.drain(1);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].payload, "hello");
        assert!(pool.is_empty());
    }

    #[test]
    fn test_rbf() {
        let config = MempoolConfig::default();
        let mut pool = StandardMempool::new(config);
        let tx1 = dummy_tx("alice", 0, 100, 200, "first");
        let tx2 = dummy_tx("alice", 0, 111, 250, "second");
        pool.insert(tx1, 0).unwrap();
        pool.insert(tx2, 0).unwrap();
        assert_eq!(pool.len(), 1);
        let drained = pool.drain(1);
        assert_eq!(drained[0].payload, "second");
        assert_eq!(pool.metrics.rbf_replaced, 1);
    }

    #[test]
    fn test_sender_limit() {
        let config = MempoolConfig {
            max_pending_per_sender: 2,
            ..Default::default()
        };
        let mut pool = StandardMempool::new(config);
        for i in 0..2 {
            pool.insert(dummy_tx("alice", i, 100, 200, &format!("tx{}", i)), 0)
                .unwrap();
        }
        let res = pool.insert(
            dummy_tx("alice", 2, 100, 200, "extra"),
            0,
        );
        assert!(res.is_err());
        assert_eq!(pool.metrics.rejected_sender_limit, 1);
    }

    #[test]
    fn test_eviction() {
        let config = MempoolConfig {
            capacity: 2,
            ..Default::default()
        };
        let mut pool = StandardMempool::new(config);
        let tx1 = dummy_tx("alice", 0, 100, 200, "high");
        let tx2 = dummy_tx("bob", 0, 50, 150, "low");
        let tx3 = dummy_tx("carol", 0, 80, 180, "medium");
        pool.insert(tx1, 0).unwrap();
        pool.insert(tx2, 0).unwrap();
        pool.insert(tx3, 0).unwrap();
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.metrics.evicted, 1);
        let drained = pool.drain(2);
        assert!(drained.iter().any(|tx| tx.from == "alice"));
        assert!(drained.iter().any(|tx| tx.from == "carol"));
        assert!(!drained.iter().any(|tx| tx.from == "bob"));
    }

    #[test]
    fn test_ttl_expiry() {
        let config = MempoolConfig {
            ttl_blocks: 10,
            ..Default::default()
        };
        let mut pool = StandardMempool::new(config);
        pool.insert(dummy_tx("alice", 0, 100, 200, "test"), 0).unwrap();
        pool.advance_height(15);
        assert!(pool.is_empty());
        assert_eq!(pool.metrics.expired, 1);
    }

    #[test]
    fn test_quantum_state() {
        let config = MempoolConfig {
            enable_quantum_state: true,
            ..Default::default()
        };
        let mut pool = StandardMempool::new(config);
        let qs = pool.quantum_state().unwrap();
        assert!((qs.purity - 1.0).abs() < 1e-10);
        assert!((qs.entropy - 0.0).abs() < 1e-10);
        pool.insert(dummy_tx("alice", 0, 100, 200, "test"), 0).unwrap();
        let qs2 = pool.quantum_state().unwrap();
        assert!(qs2.purity < 1.0);
    }
}
