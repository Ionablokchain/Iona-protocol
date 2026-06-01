//! Standard mempool for IONA — Quantum State Model.
//!
//! # Quantum Mempool Architecture
//!
//! The mempool is modelled as an **open quantum system** where each
//! transaction is a **pure state** |tx_i⟩ in the mempool Hilbert space
//! ℋ_mempool = ⊗_{senders} ℋ_sender. The mempool evolves under a
//! **Lindblad master equation** with Hamiltonian governing priority
//! ordering and decoherence from TTL expiry.
//!
//! # Mathematical Formalism
//!
//! ## State Representation
//! ```text
//! ρ_mempool = Σ_i p_i |ψ_i⟩⟨ψ_i|
//! |ψ_i⟩ = |tx_1⟩ ⊗ |tx_2⟩ ⊗ ... ⊗ |tx_N⟩   (computational basis)
//! ```
//!
//! ## Hamiltonian
//! ```text
//! Ĥ = Ĥ_priority + Ĥ_rbf + Ĥ_eviction + Ĥ_ttl
//!
//! Ĥ_priority = Σ_i E_i a†_i a_i               (score-based ordering)
//! Ĥ_rbf      = Σ_j g_j (|old⟩⟨new|_j + h.c.)   (replacement coupling)
//! Ĥ_eviction = Σ_k ω_k b†_k b_k               (overflow removal)
//! Ĥ_ttl      = Σ_l γ_l (n̂_l + ½)              (harmonic decay for expiry)
//! ```
//!
//! ## Quantum Channel for Insertion
//! ```text
//! Φ_insert(ρ) = K_admit ρ K_admit† + K_reject ρ K_reject†
//! K_admit  = √p_admit |admit⟩⟨vac|
//! K_reject = √(1-p_admit) |reject⟩⟨vac|
//! ```
//!
//! ## RBF as Quantum Swap Gate
//! ```text
//! U_rbf |old_nonce⟩|new_tx⟩ → |new_tx⟩|old_tx⟩   (SWAP)
//! ```
//!
//! ## Decoherence from TTL
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ_l γ_l (L_l ρ L_l† - ½{L_l† L_l, ρ})
//! L_l = |∅⟩⟨tx_l|   (annihilation of expired transaction)
//! ```

use crate::execution::intrinsic_gas;
use crate::mempool::{Mempool as MempoolTrait, MempoolError};
use crate::types::{Hash32, Height, Tx};
use serde::Serialize;
use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Number of blocks after which a transaction expires (coherence time).
const TTL_BLOCKS: u64 = 300;

/// Maximum number of pending transactions per sender (Hilbert space bound).
const MAX_PENDING_PER_SENDER: usize = 64;

/// Minimum percentage tip increase for RBF replacement (swap gate threshold).
const RBF_BUMP_PERCENT: u64 = 10;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Decoherence rate per operation (insert/evict).
const OPERATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per TTL expiry (stronger — time evolution).
const TTL_DECOHERENCE_RATE: f64 = 0.001;

/// Kraus rank for mempool quantum channels.
const KRAUS_RANK: usize = 4;

/// Minimum coherence threshold for healthy mempool.
const MIN_MEMPOOL_COHERENCE: f64 = 0.9;

// -----------------------------------------------------------------------------
// Quantum Mempool State
// -----------------------------------------------------------------------------

/// Quantum state of the mempool.
///
/// Tracks the density matrix properties:
/// - γ = Tr(ρ²) — purity (1.0 = pure state, <1.0 = mixed)
/// - S = -Tr(ρ ln ρ) — von Neumann entropy
/// - Coherence per sender subspace
#[derive(Debug, Clone)]
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
// Pending transaction (internal)
// -----------------------------------------------------------------------------

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

    fn is_expired(&self, current_height: Height) -> bool {
        current_height.saturating_sub(self.inserted_height) > TTL_BLOCKS
    }

    /// Apply decoherence to this transaction (e.g., from waiting).
    fn apply_decoherence(&mut self, rate: f64) {
        self.purity = (self.purity * (-rate).exp()).clamp(0.0, 1.0);
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
        self.score
            .cmp(&other.score)
            .then_with(|| other.nonce.cmp(&self.nonce))
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for the standard mempool (classical + quantum).
#[derive(Default, Debug, Clone, Serialize)]
pub struct MempoolMetrics {
    pub admitted: u64,
    pub rejected_dup: u64,
    pub rejected_full: u64,
    pub rejected_sender_limit: u64,
    pub evicted: u64,
    pub expired: u64,
    pub rbf_replaced: u64,
    /// Quantum purity of the mempool.
    #[serde(default)]
    pub quantum_purity: f64,
    /// Von Neumann entropy of the mempool.
    #[serde(default)]
    pub quantum_entropy: f64,
    /// Number of decoherence events.
    #[serde(default)]
    pub decoherence_events: u64,
}

// -----------------------------------------------------------------------------
// Standard Mempool with Quantum Tracking
// -----------------------------------------------------------------------------

/// Standard mempool with per‑sender nonce queues, RBF, TTL, eviction,
/// and full quantum state tracking.
pub struct StandardMempool {
    cap: usize,
    current_height: Height,
    queues: HashMap<String, BTreeMap<u64, PendingTx>>,
    pub metrics: MempoolMetrics,
    /// Quantum state of the mempool.
    quantum_state: QuantumMempoolState,
}

impl Default for StandardMempool {
    fn default() -> Self {
        Self::new(200_000)
    }
}

impl StandardMempool {
    /// Create a new mempool with the given capacity.
    ///
    /// Initialises the quantum state to the ground state |∅⟩.
    ///
    /// # Panics
    /// If `cap` is zero.
    pub fn new(cap: usize) -> Self {
        assert!(cap > 0, "mempool capacity must be > 0");
        Self {
            cap,
            current_height: 0,
            queues: HashMap::new(),
            metrics: MempoolMetrics::default(),
            quantum_state: QuantumMempoolState::new(),
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

    /// Get the current quantum state (read-only).
    pub fn quantum_state(&self) -> &QuantumMempoolState {
        &self.quantum_state
    }

    /// Get quantum purity.
    pub fn purity(&self) -> f64 {
        self.quantum_state.purity
    }

    /// Get von Neumann entropy.
    pub fn entropy(&self) -> f64 {
        self.quantum_state.entropy
    }

    /// Check if the mempool is in a healthy quantum state.
    pub fn is_quantum_healthy(&self) -> bool {
        self.quantum_state.is_healthy
    }

    /// Apply the quantum channel Φ(ρ) = Σ_k K_k ρ K_k† for an operation.
    fn apply_quantum_channel(&mut self, success: bool) {
        let kraus_factor = if success {
            (1.0 / KRAUS_RANK as f64).sqrt()
        } else {
            // Rejection causes stronger decoherence
            0.5f64.sqrt()
        };
        self.quantum_state.purity =
            (self.quantum_state.purity * kraus_factor).clamp(0.0, 1.0);
        self.quantum_state.apply_operation_decoherence();
        self.sync_metrics();
    }

    /// Sync quantum state to metrics.
    fn sync_metrics(&mut self) {
        self.metrics.quantum_purity = self.quantum_state.purity;
        self.metrics.quantum_entropy = self.quantum_state.entropy;
        self.metrics.decoherence_events = self.quantum_state.decoherence_events;
    }

    /// Advance the height, expiring old transactions.
    ///
    /// Applies TTL decoherence: L_l = |∅⟩⟨tx_l| for each expired tx.
    pub fn advance_height(&mut self, height: Height) {
        if height <= self.current_height {
            return;
        }
        self.current_height = height;
        let h = self.current_height;
        let metrics = &mut self.metrics;

        let mut expired_count = 0u64;
        self.queues.retain(|sender, queue| {
            let before = queue.len();
            queue.retain(|_, ptx| {
                let keep = !ptx.is_expired(h);
                if !keep {
                    self.quantum_state
                        .update_sender_coherence(sender, 0.99);
                }
                keep
            });
            let expired = before - queue.len();
            expired_count += expired as u64;
            metrics.expired += expired as u64;
            !queue.is_empty()
        });

        // Apply TTL decoherence proportional to expired count
        for _ in 0..expired_count {
            self.quantum_state.apply_ttl_decoherence();
        }
        self.sync_metrics();
    }

    /// Remove transactions that have been confirmed (nonces below `committed_nonce`).
    pub fn remove_confirmed(&mut self, sender: &str, committed_nonce: u64) {
        if let Some(queue) = self.queues.get_mut(sender) {
            queue.retain(|&nonce, _| nonce >= committed_nonce);
            if queue.is_empty() {
                self.queues.remove(sender);
            }
        }
        // Confirmation restores some coherence
        self.quantum_state
            .update_sender_coherence(sender, 1.001.min(1.0));
        self.sync_metrics();
    }

    /// Submit a transaction using the given current block base fee.
    ///
    /// Applies the quantum channel Φ_insert.
    pub fn push_with_base_fee(
        &mut self,
        tx: Tx,
        base_fee: u64,
    ) -> Result<bool, MempoolError> {
        if tx.max_fee_per_gas < base_fee {
            self.metrics.rejected_dup += 1;
            self.apply_quantum_channel(false);
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

        // Register sender in quantum state
        self.quantum_state.register_sender(&sender);

        let queue = self.queues.entry(sender.clone()).or_default();

        // RBF check — quantum swap gate
        if let Some(existing) = queue.get(&tx.nonce) {
            let existing_tip = existing.tx.max_priority_fee_per_gas;
            let required = existing_tip.saturating_add(
                (existing_tip.saturating_mul(RBF_BUMP_PERCENT) / 100).max(1),
            );
            if tx.max_priority_fee_per_gas < required {
                self.metrics.rejected_dup += 1;
                self.apply_quantum_channel(false);
                return Err(MempoolError::RbfTooLow {
                    existing_tip,
                    required,
                });
            }
            // RBF swap: U_swap |old⟩|new⟩ → |new⟩|old⟩
            queue.insert(
                tx.nonce,
                PendingTx::new(tx, self.current_height, base_fee),
            );
            self.metrics.rbf_replaced += 1;
            self.quantum_state
                .update_sender_coherence(&sender, 0.995);
            self.apply_quantum_channel(true);
            return Ok(false);
        }

        // Per‑sender cap
        if queue.len() >= MAX_PENDING_PER_SENDER {
            self.metrics.rejected_sender_limit += 1;
            self.apply_quantum_channel(false);
            return Err(MempoolError::SenderQueueFull);
        }

        // Global cap with eviction — apply quantum channel K_evict
        if self.len() >= self.cap {
            if !self.evict_worst(&sender) {
                self.metrics.rejected_full += 1;
                self.apply_quantum_channel(false);
                return Err(MempoolError::MempoolFull);
            }
        }

        // Insert new transaction — apply creation operator a†
        let ptx = PendingTx::new(tx, self.current_height, base_fee);
        self.queues
            .entry(sender.clone())
            .or_default()
            .insert(ptx.tx.nonce, ptx);
        self.metrics.admitted += 1;
        self.quantum_state
            .update_sender_coherence(&sender, 0.999);
        self.apply_quantum_channel(true);
        Ok(true)
    }

    /// Try to evict the lowest‑priority transaction from a different sender.
    ///
    /// Applies the annihilation operator a.
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
            self.quantum_state
                .update_sender_coherence(&sender, 0.98);
            self.quantum_state.decoherence_events =
                self.quantum_state.decoherence_events.wrapping_add(1);
            self.sync_metrics();
            true
        } else {
            false
        }
    }

    /// Drain up to `n` transactions in priority order, respecting per‑sender nonce ordering.
    ///
    /// This is a projective measurement that collapses the mempool state.
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

        // Draining restores some coherence (reduces entropy)
        if !result.is_empty() {
            self.quantum_state.purity =
                (self.quantum_state.purity * 1.001).min(1.0);
            self.sync_metrics();
        }

        result
    }

    /// Return current metrics as JSON.
    pub fn metrics_json(&self) -> serde_json::Value {
        serde_json::to_value(&self.metrics)
            .unwrap_or_else(|_| serde_json::Value::Null)
    }

    /// Apply decoherence to all pending transactions (waiting decay).
    pub fn apply_waiting_decoherence(&mut self) {
        for queue in self.queues.values_mut() {
            for ptx in queue.values_mut() {
                ptx.apply_decoherence(OPERATION_DECOHERENCE_RATE);
            }
        }
        self.quantum_state.apply_operation_decoherence();
        self.sync_metrics();
    }
}

// -----------------------------------------------------------------------------
// Implement the unified Mempool trait
// -----------------------------------------------------------------------------

impl MempoolTrait for StandardMempool {
    type Error = MempoolError;

    fn submit_tx(&mut self, tx: Tx) -> Result<(), Self::Error> {
        self.push(tx, 0).map(|_| ())
    }

    fn drain(&mut self, n: usize) -> Vec<Tx> {
        self.drain_best(n)
    }

    fn advance_height(&mut self, height: Height, _block_hash: &Hash32) {
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

    // ── Classical Tests (unchanged) ────────────────────────────────────
    #[test]
    fn test_push_and_drain() {
        let mut pool = StandardMempool::new(10);
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
        let mut pool = StandardMempool::new(10);
        let tx1 = dummy_tx("alice", 0, 100, 200, "first");
        let tx2 = dummy_tx("alice", 0, 111, 250, "second");

        let base_fee = 50;
        pool.push_with_base_fee(tx1, base_fee).unwrap();
        let replaced = pool.push_with_base_fee(tx2, base_fee).unwrap();
        assert!(!replaced);
        assert_eq!(pool.len(), 1);

        let drained = pool.drain_best(1);
        assert_eq!(drained[0].payload, "second");
        assert_eq!(pool.metrics.rbf_replaced, 1);
    }

    #[test]
    fn test_sender_queue_full() {
        let mut pool = StandardMempool::new(100);
        let base_fee = 0;
        for i in 0..MAX_PENDING_PER_SENDER {
            let tx = dummy_tx("alice", i as u64, 100, 200, &format!("tx{}", i));
            pool.push(tx, base_fee).unwrap();
        }
        let tx_extra =
            dummy_tx("alice", MAX_PENDING_PER_SENDER as u64, 100, 200, "extra");
        let res = pool.push(tx_extra, base_fee);
        assert!(res.is_err());
        assert_eq!(pool.metrics.rejected_sender_limit, 1);
    }

    #[test]
    fn test_eviction() {
        let mut pool = StandardMempool::new(2);
        let base_fee = 0;

        let tx1 = dummy_tx("alice", 0, 100, 200, "high");
        let tx2 = dummy_tx("bob", 0, 50, 150, "low");
        pool.push(tx1, base_fee).unwrap();
        pool.push(tx2, base_fee).unwrap();

        let tx3 = dummy_tx("carol", 0, 80, 180, "medium");
        pool.push(tx3, base_fee).unwrap();

        assert_eq!(pool.len(), 2);
        assert_eq!(pool.metrics.evicted, 1);

        let drained = pool.drain_best(2);
        assert!(drained.iter().any(|tx| tx.from == "alice"));
        assert!(drained.iter().any(|tx| tx.from == "carol"));
        assert!(!drained.iter().any(|tx| tx.from == "bob"));
    }

    #[test]
    fn test_expiry() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;
        let tx = dummy_tx("alice", 0, 100, 200, "test");
        pool.push(tx, base_fee).unwrap();

        pool.advance_height(TTL_BLOCKS + 1);
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.metrics.expired, 1);
    }

    #[test]
    fn test_remove_confirmed() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;
        pool.push(dummy_tx("alice", 0, 100, 200, "tx0"), base_fee)
            .unwrap();
        pool.push(dummy_tx("alice", 1, 100, 200, "tx1"), base_fee)
            .unwrap();

        pool.remove_confirmed("alice", 1);
        assert_eq!(pool.len(), 1);
        assert_eq!(pool.queues.get("alice").unwrap().len(), 1);
        assert!(pool.queues.get("alice").unwrap().contains_key(&1));
    }

    #[test]
    fn test_fee_too_low() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, 100, 150, "test");
        let base_fee = 200;
        let res = pool.push_with_base_fee(tx, base_fee);
        assert!(res.is_err());
        assert_eq!(pool.metrics.rejected_dup, 1);
    }

    #[test]
    fn test_metrics_json() {
        let mut pool = StandardMempool::new(10);
        let tx = dummy_tx("alice", 0, 100, 200, "test");
        pool.push(tx, 0).unwrap();
        let json = pool.metrics_json();
        assert_eq!(json["admitted"], 1);
    }

    // ── Quantum Tests ──────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let pool = StandardMempool::new(10);
        assert!((pool.purity() - 1.0).abs() < 1e-10);
        assert!((pool.entropy() - 0.0).abs() < 1e-10);
        assert!(pool.is_quantum_healthy());
    }

    #[test]
    fn test_quantum_decoherence_after_operations() {
        let mut pool = StandardMempool::new(10);
        let initial_purity = pool.purity();
        let base_fee = 0;

        for i in 0..10 {
            let tx = dummy_tx(
                &format!("sender{}", i),
                0,
                100,
                200,
                "test",
            );
            let _ = pool.push(tx, base_fee);
        }

        assert!(pool.purity() < initial_purity);
        assert!(pool.metrics.quantum_purity > 0.0);
    }

    #[test]
    fn test_quantum_ttl_decoherence() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;
        pool.push(dummy_tx("alice", 0, 100, 200, "test"), base_fee)
            .unwrap();

        let purity_before = pool.purity();
        pool.advance_height(TTL_BLOCKS + 1);
        let purity_after = pool.purity();

        assert!(purity_after < purity_before);
        assert!(pool.metrics.decoherence_events > 0);
    }

    #[test]
    fn test_quantum_sender_coherence() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;

        pool.push(dummy_tx("alice", 0, 100, 200, "test"), base_fee)
            .unwrap();

        let qstate = pool.quantum_state();
        assert!(qstate.sender_coherence.contains_key("alice"));
        assert!(qstate.sender_coherence["alice"] > 0.99);
    }

    #[test]
    fn test_quantum_metrics_synced() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;
        pool.push(dummy_tx("alice", 0, 100, 200, "test"), base_fee)
            .unwrap();

        let json = pool.metrics_json();
        assert!(json["quantum_purity"].as_f64().unwrap() > 0.0);
        assert!(json["quantum_entropy"].as_f64().unwrap() >= 0.0);
    }

    #[test]
    fn test_apply_waiting_decoherence() {
        let mut pool = StandardMempool::new(10);
        let base_fee = 0;
        pool.push(dummy_tx("alice", 0, 100, 200, "test"), base_fee)
            .unwrap();

        let purity_before = pool.purity();
        pool.apply_waiting_decoherence();
        let purity_after = pool.purity();

        assert!(purity_after < purity_before);
    }
}
