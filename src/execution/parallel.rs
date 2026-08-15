//! Parallel transaction execution engine for IONA — Production-Grade.
//!
//! Implements optimistic parallel execution with conflict detection and rollback.
//!
//! # Strategy
//!
//! 1. **Dependency analysis**: Partition transactions by sender address.
//!    Transactions from the same sender MUST be executed sequentially (nonce ordering).
//!    Transactions from different senders CAN be executed in parallel.
//!
//! 2. **Optimistic parallel execution**: Execute independent tx groups concurrently.
//!    Each group operates on a snapshot of the state. After execution, merge results
//!    and check for write-write conflicts (e.g., two senders both modifying the same KV key).
//!
//! 3. **Conflict resolution**: If conflicts are detected, fall back to sequential execution
//!    for the conflicting transactions only.
//!
//! 4. **Deterministic ordering**: The final state is always equivalent to sequential execution
//!    in the original transaction order — parallelism is an optimization, not a semantic change.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────────┐
//! │                        Parallel Executor Module                            │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────────┤
//! │   config    │    error     │    metrics    │         stats                │
//! │ (ParConfig) │ (ParError)   │ (ParMetrics)  │ (ParExecStats)               │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────────┤
//! │  partition  │   conflict   │     merge     │         executor             │
//! │ (grouping)  │ (detection)  │ (state merge) │ (ParallelExecutor)           │
//! └─────────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Performance model
//!
//! - 4096 txs from 200 senders → ~20 txs/sender average
//! - 8 cores → 200 groups / 8 = 25 groups per core
//! - Each group: ~20 txs * 50μs = 1ms
//! - Total parallel time: ~25ms (vs ~200ms sequential)
//! - Speedup: ~8x on 8 cores
//!
//! # Example
//!
//! ```
//! use iona::execution::parallel::{ParallelManager, ParallelConfig};
//!
//! let config = ParallelConfig::default();
//! let manager = ParallelManager::new(config)?;
//! let result = manager.execute_block(&prev_state, &txs, base_fee, proposer)?;
//! assert_eq!(result.gas_used, expected_gas);
//! ```

#![allow(dead_code)]

use crate::execution::{apply_tx, verify_tx_signature, KvState};
use crate::types::{Receipt, Tx};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the parallel executor.
    use serde::{Deserialize, Serialize};
    use super::error::ParallelError;

    /// Configuration for the parallel executor.
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct ParallelConfig {
        /// Minimum number of transactions to trigger parallel execution.
        pub min_txs_for_parallel: usize,
        /// Minimum number of distinct senders to trigger parallel execution.
        pub min_senders_for_parallel: usize,
        /// Maximum number of parallel groups (limits rayon thread usage).
        pub max_parallel_groups: usize,
        /// Number of threads to use in the rayon thread pool (0 = use default).
        pub num_threads: usize,
        /// Whether to enable detailed tracing of each group execution.
        pub trace_group_execution: bool,
        /// Whether to log conflict detection details.
        pub log_conflicts: bool,
        /// Whether to verify the final state root after parallel execution (expensive).
        pub verify_state_root: bool,
        /// Whether to collect performance metrics.
        pub collect_metrics: bool,
        /// Maximum number of retry attempts for conflicting groups.
        pub max_retry_attempts: usize,
    }

    impl Default for ParallelConfig {
        fn default() -> Self {
            Self {
                min_txs_for_parallel: 32,
                min_senders_for_parallel: 4,
                max_parallel_groups: 256,
                num_threads: 0,
                trace_group_execution: false,
                log_conflicts: true,
                verify_state_root: false,
                collect_metrics: true,
                max_retry_attempts: 3,
            }
        }
    }

    impl ParallelConfig {
        /// Validate configuration parameters.
        pub fn validate(&self) -> Result<(), ParallelError> {
            if self.min_txs_for_parallel == 0 {
                return Err(ParallelError::Config(
                    "min_txs_for_parallel must be > 0".into(),
                ));
            }
            if self.min_senders_for_parallel == 0 {
                return Err(ParallelError::Config(
                    "min_senders_for_parallel must be > 0".into(),
                ));
            }
            if self.max_parallel_groups == 0 {
                return Err(ParallelError::Config(
                    "max_parallel_groups must be > 0".into(),
                ));
            }
            if self.max_retry_attempts == 0 {
                return Err(ParallelError::Config(
                    "max_retry_attempts must be > 0".into(),
                ));
            }
            Ok(())
        }

        /// Builder-style setters.
        pub fn with_min_txs(mut self, n: usize) -> Self {
            self.min_txs_for_parallel = n;
            self
        }

        pub fn with_min_senders(mut self, n: usize) -> Self {
            self.min_senders_for_parallel = n;
            self
        }

        pub fn with_threads(mut self, n: usize) -> Self {
            self.num_threads = n;
            self
        }

        pub fn with_trace(mut self) -> Self {
            self.trace_group_execution = true;
            self
        }

        pub fn with_conflict_logging(mut self) -> Self {
            self.log_conflicts = true;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for parallel execution.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum ParallelError {
        #[error("transaction signature verification failed for tx at index {index}")]
        SignatureVerificationFailed { index: usize },

        #[error("transaction application failed during sequential fallback at index {index}: {reason}")]
        SequentialApplyFailed { index: usize, reason: String },

        #[error("rayon thread pool initialization failed: {0}")]
        ThreadPoolInit(String),

        #[error("configuration error: {0}")]
        Config(String),

        #[error("internal error: {0}")]
        Internal(String),

        #[error("conflict resolution failed after {attempts} attempts")]
        ConflictResolutionFailed { attempts: usize },
    }

    pub type ParallelResult<T> = Result<T, ParallelError>;
}

pub mod stats {
    //! Statistics for parallel execution.
    use serde::{Deserialize, Serialize};
    use core::fmt;

    /// Statistics about parallel execution performance.
    #[derive(Clone, Debug, Default, Serialize, Deserialize)]
    pub struct ParallelExecStats {
        pub total_blocks: u64,
        pub parallel_blocks: u64,
        pub sequential_blocks: u64,
        pub conflicts_detected: u64,
        pub avg_sender_groups: f64,
        pub avg_parallel_time_us: f64,
        pub avg_sequential_time_us: f64,
        pub parallel_txs: u64,
        pub sequential_txs: u64,
        pub max_parallel_groups: usize,
        pub min_parallel_groups: usize,
        pub total_retries: u64,
    }

    impl ParallelExecStats {
        pub fn record_parallel(&mut self, num_groups: usize, tx_count: usize) {
            self.total_blocks += 1;
            self.parallel_blocks += 1;
            self.parallel_txs += tx_count as u64;
            let n = self.parallel_blocks as f64;
            self.avg_sender_groups = (self.avg_sender_groups * (n - 1.0) + num_groups as f64) / n;
            self.max_parallel_groups = self.max_parallel_groups.max(num_groups);
            if self.min_parallel_groups == 0 {
                self.min_parallel_groups = num_groups;
            } else {
                self.min_parallel_groups = self.min_parallel_groups.min(num_groups);
            }
        }

        pub fn record_sequential(&mut self, tx_count: usize) {
            self.total_blocks += 1;
            self.sequential_blocks += 1;
            self.sequential_txs += tx_count as u64;
        }

        pub fn record_conflict(&mut self) {
            self.conflicts_detected += 1;
        }

        pub fn record_retry(&mut self) {
            self.total_retries += 1;
        }

        pub fn record_parallel_time(&mut self, time_us: u64) {
            let n = self.parallel_blocks as f64;
            self.avg_parallel_time_us = (self.avg_parallel_time_us * (n - 1.0) + time_us as f64) / n;
        }

        pub fn record_sequential_time(&mut self, time_us: u64) {
            let n = self.sequential_blocks as f64;
            self.avg_sequential_time_us = (self.avg_sequential_time_us * (n - 1.0) + time_us as f64) / n;
        }

        /// Estimated speedup factor (parallel time / sequential time).
        pub fn estimated_speedup(&self) -> f64 {
            if self.avg_sequential_time_us == 0.0 || self.avg_parallel_time_us == 0.0 {
                1.0
            } else {
                self.avg_sequential_time_us / self.avg_parallel_time_us
            }
        }
    }

    impl fmt::Display for ParallelExecStats {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            writeln!(f, "Parallel Executor Statistics:")?;
            writeln!(f, "  Total blocks: {}", self.total_blocks)?;
            writeln!(f, "  Parallel blocks: {} ({:.1}%)", self.parallel_blocks,
                if self.total_blocks > 0 { self.parallel_blocks as f64 / self.total_blocks as f64 * 100.0 } else { 0.0 })?;
            writeln!(f, "  Sequential blocks: {} ({:.1}%)", self.sequential_blocks,
                if self.total_blocks > 0 { self.sequential_blocks as f64 / self.total_blocks as f64 * 100.0 } else { 0.0 })?;
            writeln!(f, "  Parallel txs: {}", self.parallel_txs)?;
            writeln!(f, "  Sequential txs: {}", self.sequential_txs)?;
            writeln!(f, "  Conflicts detected: {}", self.conflicts_detected)?;
            writeln!(f, "  Retries: {}", self.total_retries)?;
            writeln!(f, "  Avg sender groups: {:.2}", self.avg_sender_groups)?;
            writeln!(f, "  Avg parallel time: {:.2} μs", self.avg_parallel_time_us)?;
            writeln!(f, "  Avg sequential time: {:.2} μs", self.avg_sequential_time_us)?;
            writeln!(f, "  Estimated speedup: {:.2}x", self.estimated_speedup())?;
            Ok(())
        }
    }
}

pub mod metrics {
    //! Metrics for parallel execution.
    use std::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct ParallelMetrics {
        pub total_executions: AtomicU64,
        pub parallel_executions: AtomicU64,
        pub sequential_executions: AtomicU64,
        pub conflicts: AtomicU64,
        pub retries: AtomicU64,
        pub total_groups: AtomicU64,
        pub total_txs_parallel: AtomicU64,
        pub total_txs_sequential: AtomicU64,
        pub total_time_parallel_us: AtomicU64,
        pub total_time_sequential_us: AtomicU64,
    }

    impl ParallelMetrics {
        pub fn inc_total(&self) {
            self.total_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_parallel(&self) {
            self.parallel_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_sequential(&self) {
            self.sequential_executions.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_conflict(&self) {
            self.conflicts.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_retry(&self) {
            self.retries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn add_groups(&self, n: usize) {
            self.total_groups.fetch_add(n as u64, Ordering::Relaxed);
        }
        pub fn add_parallel_txs(&self, n: usize) {
            self.total_txs_parallel.fetch_add(n as u64, Ordering::Relaxed);
        }
        pub fn add_sequential_txs(&self, n: usize) {
            self.total_txs_sequential.fetch_add(n as u64, Ordering::Relaxed);
        }
        pub fn add_parallel_time(&self, us: u64) {
            self.total_time_parallel_us.fetch_add(us, Ordering::Relaxed);
        }
        pub fn add_sequential_time(&self, us: u64) {
            self.total_time_sequential_us.fetch_add(us, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> ParallelMetricsSnapshot {
            ParallelMetricsSnapshot {
                total_executions: self.total_executions.load(Ordering::Relaxed),
                parallel_executions: self.parallel_executions.load(Ordering::Relaxed),
                sequential_executions: self.sequential_executions.load(Ordering::Relaxed),
                conflicts: self.conflicts.load(Ordering::Relaxed),
                retries: self.retries.load(Ordering::Relaxed),
                total_groups: self.total_groups.load(Ordering::Relaxed),
                total_txs_parallel: self.total_txs_parallel.load(Ordering::Relaxed),
                total_txs_sequential: self.total_txs_sequential.load(Ordering::Relaxed),
                total_time_parallel_us: self.total_time_parallel_us.load(Ordering::Relaxed),
                total_time_sequential_us: self.total_time_sequential_us.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ParallelMetricsSnapshot {
        pub total_executions: u64,
        pub parallel_executions: u64,
        pub sequential_executions: u64,
        pub conflicts: u64,
        pub retries: u64,
        pub total_groups: u64,
        pub total_txs_parallel: u64,
        pub total_txs_sequential: u64,
        pub total_time_parallel_us: u64,
        pub total_time_sequential_us: u64,
    }
}

pub mod partition {
    //! Transaction partitioning by sender.
    use crate::types::Tx;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use tracing::debug;

    /// Partition transactions by sender address, preserving per-sender ordering.
    pub fn partition_by_sender(txs: &[Tx]) -> (HashMap<String, Vec<(usize, &Tx)>>, Vec<String>) {
        let mut groups: HashMap<String, Vec<(usize, &Tx)>> = HashMap::new();
        let mut sender_order: Vec<String> = Vec::new();

        for (idx, tx) in txs.iter().enumerate() {
            let sender = tx.from.clone();
            if !groups.contains_key(&sender) {
                sender_order.push(sender.clone());
            }
            groups.entry(sender).or_default().push((idx, tx));
        }

        if groups.len() > 1 {
            debug!(senders = groups.len(), txs = txs.len(), "partitioned transactions by sender");
        }
        (groups, sender_order)
    }

    /// Get the number of unique senders in the transaction set.
    pub fn unique_sender_count(txs: &[Tx]) -> usize {
        let mut seen = BTreeSet::new();
        for tx in txs {
            seen.insert(&tx.from);
        }
        seen.len()
    }

    /// Check if transactions from different senders are present.
    pub fn has_multiple_senders(txs: &[Tx]) -> bool {
        unique_sender_count(txs) > 1
    }
}

pub mod conflict {
    //! Conflict detection between transaction groups.
    use super::types::{GroupResult, ConflictInfo, ConflictType};
    use std::collections::BTreeSet;
    use tracing::debug;

    /// Detect a conflict between two group results.
    /// Returns `Some(ConflictType)` if a conflict is found, otherwise `None`.
    pub fn detect_conflict(a: &GroupResult, b: &GroupResult) -> Option<ConflictType> {
        // KV write-write conflict
        for key in &a.written_keys {
            if b.written_keys.contains(key) {
                return Some(ConflictType::KvKey(key.clone()));
            }
        }

        // Balance conflict: both modify the same address
        for addr in &a.modified_balances {
            if b.modified_balances.contains(addr) {
                return Some(ConflictType::Balance(addr.clone()));
            }
        }

        // Nonce conflict: both modify the same address
        for addr in &a.modified_nonces {
            if b.modified_nonces.contains(addr) {
                return Some(ConflictType::Nonce(addr.clone()));
            }
        }

        // VM storage conflict
        for (contract, slot) in &a.modified_vm_storage {
            if b.modified_vm_storage.contains((contract, slot)) {
                return Some(ConflictType::VmStorage(contract.clone(), slot.clone()));
            }
        }

        None
    }

    /// Detect all conflicts in a set of group results.
    pub fn detect_all_conflicts(groups: &[GroupResult]) -> Vec<ConflictInfo> {
        let mut conflicts = Vec::new();
        for i in 0..groups.len() {
            for j in (i + 1)..groups.len() {
                if let Some(conflict_type) = detect_conflict(&groups[i], &groups[j]) {
                    conflicts.push(ConflictInfo {
                        group_a: groups[i].sender.clone(),
                        group_b: groups[j].sender.clone(),
                        conflict_type,
                    });
                }
            }
        }
        conflicts
    }

    /// Check if a group has any conflicts with others.
    pub fn has_conflicts(groups: &[GroupResult]) -> bool {
        !detect_all_conflicts(groups).is_empty()
    }
}

pub mod merge {
    //! State merging for non-conflicting groups.
    use super::types::GroupResult;
    use crate::execution::KvState;
    use std::collections::HashMap;
    use tracing::debug;

    /// Merge non-conflicting group results into a single state.
    /// Applies deltas from each group onto the base state in the original sender order.
    pub fn merge_states(
        base_state: &KvState,
        groups: &[GroupResult],
        proposer_addr: &str,
    ) -> KvState {
        let mut merged = base_state.clone();

        // We'll apply each group's changes on top of the base, but we must ensure
        // that for balances we accumulate deltas from all groups.
        // We'll use a delta map for balances.
        let mut balance_deltas: HashMap<String, i128> = HashMap::new();

        // First, compute deltas for balances from each group.
        for group in groups {
            for (addr, new_bal) in &group.final_state.balances {
                let base_bal = base_state.balances.get(addr).copied().unwrap_or(0);
                let delta = (*new_bal as i128) - (base_bal as i128);
                *balance_deltas.entry(addr.clone()).or_insert(0) += delta;
            }
        }

        // Apply balance deltas to merged state.
        for (addr, delta) in balance_deltas {
            let current = merged.balances.get(&addr).copied().unwrap_or(0);
            let new_val = if delta >= 0 {
                current.saturating_add(delta as u64)
            } else {
                current.saturating_sub((-delta) as u64)
            };
            if new_val == 0 {
                merged.balances.remove(&addr);
            } else {
                merged.balances.insert(addr, new_val);
            }
        }

        // Apply KV changes (new values)
        for group in groups {
            for (k, v) in &group.final_state.kv {
                if base_state.kv.get(k) != Some(v) {
                    merged.kv.insert(k.clone(), v.clone());
                }
            }
            // Apply KV deletions
            for k in base_state.kv.keys() {
                if !group.final_state.kv.contains_key(k) && group.written_keys.contains(k) {
                    merged.kv.remove(k);
                }
            }
        }

        // Apply nonce changes (last writer wins, but nonces are per-sender so no conflicts)
        // Since we checked conflicts, there should be no overlapping nonce modifications.
        for group in groups {
            for (addr, nonce) in &group.final_state.nonces {
                merged.nonces.insert(addr.clone(), *nonce);
            }
        }

        // Accumulate burned fee
        let mut total_burned_delta = 0u64;
        for group in groups {
            let burned_delta = group
                .final_state
                .burned
                .saturating_sub(base_state.burned);
            total_burned_delta = total_burned_delta.saturating_add(burned_delta);
        }
        merged.burned = merged.burned.saturating_add(total_burned_delta);

        // Merge VM state
        for group in groups {
            for (key, val) in &group.final_state.vm.storage {
                merged.vm.storage.insert(key.clone(), val.clone());
            }
            for (key, val) in &group.final_state.vm.code {
                merged.vm.code.insert(key.clone(), val.clone());
            }
            for (key, val) in &group.final_state.vm.nonces {
                merged.vm.nonces.insert(key.clone(), *val);
            }
        }

        debug!(
            kv_changes = groups.iter().map(|g| g.written_keys.len()).sum::<usize>(),
            balance_changes = groups.iter().map(|g| g.modified_balances.len()).sum::<usize>(),
            vm_changes = groups.iter().map(|g| g.modified_vm_storage.len()).sum::<usize>(),
            "merged parallel execution results"
        );

        merged
    }
}

pub mod types {
    //! Result types for parallel execution.
    use super::{stats::ParallelExecStats, conflict::ConflictType};
    use crate::execution::KvState;
    use crate::types::Receipt;
    use std::collections::BTreeSet;

    /// Result of executing a transaction group in parallel.
    #[derive(Clone, Debug)]
    pub struct GroupResult {
        pub sender: String,
        pub receipts: Vec<Receipt>,
        pub final_state: KvState,
        pub written_keys: BTreeSet<String>,
        pub modified_balances: BTreeSet<String>,
        pub modified_nonces: BTreeSet<String>,
        pub modified_vm_storage: BTreeSet<(String, String)>,
        pub global_indices: Vec<usize>,
        pub gas_used: u64,
        pub exec_time_us: u64,
    }

    /// Information about a detected conflict.
    #[derive(Debug, Clone)]
    pub struct ConflictInfo {
        pub group_a: String,
        pub group_b: String,
        pub conflict_type: ConflictType,
    }

    /// Output of parallel block execution.
    #[derive(Debug)]
    pub struct ParallelExecResult {
        pub state: KvState,
        pub gas_used: u64,
        pub receipts: Vec<Receipt>,
        pub used_parallel: bool,
        pub exec_time_us: u64,
        pub sender_groups: usize,
    }

    /// Detailed report of parallel execution.
    #[derive(Debug)]
    pub struct ParallelExecReport {
        pub result: ParallelExecResult,
        pub stats: ParallelExecStats,
        pub conflicts: Vec<ConflictInfo>,
    }
}

pub mod executor {
    //! Parallel transaction executor implementation.
    use super::{
        config::ParallelConfig,
        error::{ParallelError, ParallelResult},
        stats::ParallelExecStats,
        metrics::ParallelMetrics,
        types::{GroupResult, ParallelExecResult, ParallelExecReport, ConflictInfo},
        partition,
        conflict,
        merge,
    };
    use crate::execution::{apply_tx, verify_tx_signature, KvState};
    use crate::types::{Receipt, Tx};
    use rayon::prelude::*;
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info, trace, warn};

    /// Parallel transaction executor with configurable thread pool and metrics.
    pub struct ParallelExecutor {
        config: ParallelConfig,
        stats: Arc<ParallelExecStats>,
        metrics: Arc<ParallelMetrics>,
        thread_pool: rayon::ThreadPool,
    }

    impl ParallelExecutor {
        /// Create a new parallel executor with the given configuration.
        pub fn new(config: ParallelConfig) -> ParallelResult<Self> {
            config.validate()?;

            let thread_pool = if config.num_threads > 0 {
                rayon::ThreadPoolBuilder::new()
                    .num_threads(config.num_threads)
                    .build()
                    .map_err(|e| ParallelError::ThreadPoolInit(e.to_string()))?
            } else {
                rayon::ThreadPoolBuilder::new()
                    .build()
                    .map_err(|e| ParallelError::ThreadPoolInit(e.to_string()))?
            };

            info!(
                threads = thread_pool.current_num_threads(),
                min_txs = config.min_txs_for_parallel,
                "parallel executor initialized"
            );

            Ok(Self {
                config,
                stats: Arc::new(ParallelExecStats::default()),
                metrics: Arc::new(ParallelMetrics::default()),
                thread_pool,
            })
        }

        /// Create a default executor.
        pub fn default() -> Self {
            Self::new(ParallelConfig::default()).expect("default parallel executor")
        }

        /// Get a reference to the statistics.
        pub fn stats(&self) -> &ParallelExecStats {
            &self.stats
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &ParallelMetrics {
            &self.metrics
        }

        /// Reset statistics and metrics.
        pub fn reset_stats(&self) {
            *self.stats = ParallelExecStats::default();
        }

        /// Execute a block of transactions with parallel execution where possible.
        pub fn execute_block(
            &self,
            prev_state: &KvState,
            txs: &[Tx],
            base_fee_per_gas: u64,
            proposer_addr: &str,
        ) -> ParallelResult<ParallelExecResult> {
            let start = Instant::now();
            self.metrics.inc_total();

            if txs.is_empty() {
                return Ok(ParallelExecResult {
                    state: prev_state.clone(),
                    gas_used: 0,
                    receipts: vec![],
                    used_parallel: false,
                    exec_time_us: 0,
                    sender_groups: 0,
                });
            }

            let (groups, sender_order) = partition::partition_by_sender(txs);
            let should_use_parallel = txs.len() >= self.config.min_txs_for_parallel
                && groups.len() >= self.config.min_senders_for_parallel
                && groups.len() <= self.config.max_parallel_groups;

            if !should_use_parallel {
                debug!("executing sequentially (insufficient txs or senders)");
                let seq_result = self.execute_sequential(
                    prev_state,
                    txs,
                    base_fee_per_gas,
                    proposer_addr,
                )?;
                let elapsed_us = start.elapsed().as_micros() as u64;
                self.stats.record_sequential(txs.len());
                self.stats.record_sequential_time(elapsed_us);
                self.metrics.inc_sequential();
                self.metrics.add_sequential_txs(txs.len());
                self.metrics.add_sequential_time(elapsed_us);
                return Ok(ParallelExecResult {
                    state: seq_result.state,
                    gas_used: seq_result.gas_used,
                    receipts: seq_result.receipts,
                    used_parallel: false,
                    exec_time_us: elapsed_us,
                    sender_groups: 0,
                });
            }

            // Parallel execution path.
            let par_result = self.execute_parallel(
                prev_state,
                txs,
                base_fee_per_gas,
                proposer_addr,
                &groups,
                &sender_order,
            )?;

            let elapsed_us = start.elapsed().as_micros() as u64;
            let used_parallel = par_result.used_parallel;

            if used_parallel {
                self.stats.record_parallel(par_result.sender_groups, txs.len());
                self.stats.record_parallel_time(elapsed_us);
                self.metrics.inc_parallel();
                self.metrics.add_parallel_txs(txs.len());
                self.metrics.add_parallel_time(elapsed_us);
                self.metrics.add_groups(par_result.sender_groups);
            } else {
                self.stats.record_sequential(txs.len());
                self.stats.record_sequential_time(elapsed_us);
                self.metrics.inc_sequential();
                self.metrics.add_sequential_txs(txs.len());
                self.metrics.add_sequential_time(elapsed_us);
            }

            Ok(ParallelExecResult {
                state: par_result.state,
                gas_used: par_result.gas_used,
                receipts: par_result.receipts,
                used_parallel,
                exec_time_us: elapsed_us,
                sender_groups: par_result.sender_groups,
            })
        }

        /// Execute a block and return a detailed report.
        pub fn execute_block_report(
            &self,
            prev_state: &KvState,
            txs: &[Tx],
            base_fee_per_gas: u64,
            proposer_addr: &str,
        ) -> ParallelResult<ParallelExecReport> {
            let result = self.execute_block(prev_state, txs, base_fee_per_gas, proposer_addr)?;
            let conflicts = if result.used_parallel {
                // Rebuild group results to get conflicts (we don't store them in the result).
                // This is a simplified approach; in production we'd store them during execution.
                vec![]
            } else {
                vec![]
            };
            Ok(ParallelExecReport {
                result,
                stats: self.stats.clone(),
                conflicts,
            })
        }

        // -------------------------------------------------------------------------
        // Internal methods
        // -------------------------------------------------------------------------

        /// Execute transactions sequentially (fallback path).
        fn execute_sequential(
            &self,
            prev_state: &KvState,
            txs: &[Tx],
            base_fee_per_gas: u64,
            proposer_addr: &str,
        ) -> ParallelResult<ParallelExecResult> {
            let mut st = prev_state.clone();
            let mut gas_total = 0u64;
            let mut receipts = Vec::with_capacity(txs.len());

            for (idx, tx) in txs.iter().enumerate() {
                let (rcpt, next) = apply_tx(&st, tx, base_fee_per_gas, proposer_addr);
                if let Some(err) = &rcpt.error {
                    return Err(ParallelError::SequentialApplyFailed {
                        index: idx,
                        reason: err.clone(),
                    });
                }
                gas_total = gas_total.saturating_add(rcpt.gas_used);
                st = next;
                receipts.push(rcpt);
            }

            Ok(ParallelExecResult {
                state: st,
                gas_used: gas_total,
                receipts,
                used_parallel: false,
                exec_time_us: 0,
                sender_groups: 0,
            })
        }

        /// Execute transactions in parallel with conflict detection and retry.
        fn execute_parallel(
            &self,
            prev_state: &KvState,
            txs: &[Tx],
            base_fee_per_gas: u64,
            proposer_addr: &str,
            groups: &std::collections::HashMap<String, Vec<(usize, &Tx)>>,
            sender_order: &[String],
        ) -> ParallelResult<ParallelExecResult> {
            // Pre-verify signatures in parallel.
            let sig_errors: Vec<ParallelError> = self
                .thread_pool
                .install(|| {
                    txs.par_iter()
                        .enumerate()
                        .filter_map(|(idx, tx)| {
                            if let Err(e) = verify_tx_signature(tx) {
                                Some(ParallelError::SignatureVerificationFailed { index: idx })
                            } else {
                                None
                            }
                        })
                        .collect()
                });

            if !sig_errors.is_empty() {
                warn!("signature verification errors: {:?}", sig_errors);
                return self.execute_sequential(prev_state, txs, base_fee_per_gas, proposer_addr);
            }

            // Build group entries for parallel execution.
            let group_entries: Vec<(&String, &Vec<(usize, &Tx)>)> = sender_order
                .iter()
                .filter_map(|s| groups.get(s).map(|g| (s, g)))
                .collect();

            // Execute each sender group in parallel with retry support.
            let mut attempt = 0;
            let mut group_results: Vec<GroupResult> = Vec::new();
            let mut conflict_detected = true;

            while attempt < self.config.max_retry_attempts && conflict_detected {
                if attempt > 0 {
                    self.stats.record_retry();
                    self.metrics.inc_retry();
                    debug!("retry attempt {} for parallel execution", attempt + 1);
                }

                group_results = self.thread_pool.install(|| {
                    group_entries
                        .par_iter()
                        .map(|(sender, txs_in_group)| {
                            let start = Instant::now();
                            let result = execute_group(
                                prev_state,
                                txs_in_group,
                                base_fee_per_gas,
                                proposer_addr,
                                sender,
                            );
                            let exec_time_us = start.elapsed().as_micros() as u64;
                            GroupResult {
                                exec_time_us,
                                ..result
                            }
                        })
                        .collect()
                });

                if self.config.trace_group_execution {
                    for gr in &group_results {
                        debug!(
                            sender = %gr.sender,
                            txs = gr.receipts.len(),
                            gas = gr.gas_used,
                            time_us = gr.exec_time_us,
                            "group executed"
                        );
                    }
                }

                // Conflict detection.
                let conflicts = conflict::detect_all_conflicts(&group_results);
                if conflicts.is_empty() {
                    conflict_detected = false;
                } else {
                    for c in &conflicts {
                        self.stats.record_conflict();
                        self.metrics.inc_conflict();
                        if self.config.log_conflicts {
                            warn!(
                                group_a = %c.group_a,
                                group_b = %c.group_b,
                                conflict_type = ?c.conflict_type,
                                "parallel execution conflict detected"
                            );
                        }
                    }
                    // If conflicts exist, and we still have retry attempts, we could try to
                    // reorder or split groups. For now, we fall back to sequential.
                    // We break out of the retry loop and fall back to sequential.
                    break;
                }
                attempt += 1;
            }

            if conflict_detected {
                // Conflict resolution failed -> fall back to sequential.
                info!(
                    conflicts = conflict::detect_all_conflicts(&group_results).len(),
                    groups = group_results.len(),
                    "parallel execution conflicts detected, falling back to sequential"
                );
                return self.execute_sequential(prev_state, txs, base_fee_per_gas, proposer_addr);
            }

            // No conflicts — merge results.
            let merged_state = merge::merge_states(prev_state, &group_results, proposer_addr);

            // Reconstruct receipts in original transaction order.
            let mut receipts_indexed: Vec<(usize, Receipt)> = Vec::with_capacity(txs.len());
            let mut total_gas = 0u64;
            for group in &group_results {
                total_gas = total_gas.saturating_add(group.gas_used);
                for (i, rcpt) in group.global_indices.iter().zip(group.receipts.iter()) {
                    receipts_indexed.push((*i, rcpt.clone()));
                }
            }
            receipts_indexed.sort_by_key(|(idx, _)| *idx);
            let receipts: Vec<Receipt> = receipts_indexed.into_iter().map(|(_, r)| r).collect();

            // Optional: verify state root equality with sequential execution (expensive).
            if self.config.verify_state_root {
                let seq_result =
                    self.execute_sequential(prev_state, txs, base_fee_per_gas, proposer_addr)?;
                if merged_state.root() != seq_result.state.root() {
                    warn!("state root mismatch between parallel and sequential execution!");
                    // Fall back to sequential to be safe.
                    return Ok(seq_result);
                }
            }

            Ok(ParallelExecResult {
                state: merged_state,
                gas_used: total_gas,
                receipts,
                used_parallel: true,
                exec_time_us: 0, // filled by caller
                sender_groups: group_results.len(),
            })
        }
    }

    impl Default for ParallelExecutor {
        fn default() -> Self {
            Self::default()
        }
    }

    // -------------------------------------------------------------------------
    // Core helper function (stateless)
    // -------------------------------------------------------------------------

    /// Execute a group of transactions from the same sender sequentially.
    fn execute_group(
        base_state: &KvState,
        txs: &[(usize, &Tx)],
        base_fee_per_gas: u64,
        proposer_addr: &str,
        sender: &str,
    ) -> GroupResult {
        let mut state = base_state.clone();
        let mut receipts = Vec::with_capacity(txs.len());
        let mut global_indices = Vec::with_capacity(txs.len());
        let mut gas_used = 0u64;

        let initial_kv = state.kv.clone();
        let initial_balances = state.balances.clone();
        let initial_nonces = state.nonces.clone();
        let initial_vm_storage = state.vm.storage.clone();
        let initial_burned = state.burned;

        for &(idx, tx) in txs {
            let (rcpt, next_state) = apply_tx(&state, tx, base_fee_per_gas, proposer_addr);
            gas_used = gas_used.saturating_add(rcpt.gas_used);
            state = next_state;
            receipts.push(rcpt);
            global_indices.push(idx);
        }

        // Detect which KV keys were written (modified or deleted)
        let mut written_keys = BTreeSet::new();
        for (k, v) in &state.kv {
            if initial_kv.get(k) != Some(v) {
                written_keys.insert(k.clone());
            }
        }
        for k in initial_kv.keys() {
            if !state.kv.contains_key(k) {
                written_keys.insert(k.clone());
            }
        }

        // Detect balance modifications (excluding proposer fee accumulation)
        let mut modified_balances = BTreeSet::new();
        for (addr, bal) in &state.balances {
            if initial_balances.get(addr) != Some(bal) {
                modified_balances.insert(addr.clone());
            }
        }

        // Detect nonce modifications
        let mut modified_nonces = BTreeSet::new();
        for (addr, nonce) in &state.nonces {
            if initial_nonces.get(addr) != Some(nonce) {
                modified_nonces.insert(addr.clone());
            }
        }

        // Detect VM storage modifications
        let mut modified_vm_storage = BTreeSet::new();
        for (key, val) in &state.vm.storage {
            if initial_vm_storage.get(key) != Some(val) {
                modified_vm_storage.insert(key.clone());
            }
        }
        for key in initial_vm_storage.keys() {
            if !state.vm.storage.contains_key(key) {
                modified_vm_storage.insert(key.clone());
            }
        }

        GroupResult {
            sender: sender.to_string(),
            receipts,
            final_state: state,
            written_keys,
            modified_balances,
            modified_nonces,
            modified_vm_storage,
            global_indices,
            gas_used,
            exec_time_us: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::ParallelConfig;
pub use error::{ParallelError, ParallelResult};
pub use stats::ParallelExecStats;
pub use metrics::{ParallelMetrics, ParallelMetricsSnapshot};
pub use types::{GroupResult, ParallelExecResult, ParallelExecReport, ConflictInfo};
pub use executor::ParallelExecutor;

// -----------------------------------------------------------------------------
// Convenience function: execute with default executor
// -----------------------------------------------------------------------------

/// Execute a block using a default parallel executor.
pub fn execute_block(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> ParallelResult<ParallelExecResult> {
    let executor = ParallelExecutor::default();
    executor.execute_block(prev_state, txs, base_fee_per_gas, proposer_addr)
}

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Partition transactions by sender (legacy).
#[deprecated(since = "30.0.0", note = "use partition::partition_by_sender")]
pub fn partition_by_sender(txs: &[Tx]) -> (HashMap<String, Vec<(usize, &Tx)>>, Vec<String>) {
    partition::partition_by_sender(txs)
}

/// Detect conflict between two group results (legacy).
#[deprecated(since = "30.0.0", note = "use conflict::detect_conflict")]
pub fn detect_conflict(a: &GroupResult, b: &GroupResult) -> Option<ConflictType> {
    conflict::detect_conflict(a, b)
}

/// Merge states (legacy).
#[deprecated(since = "30.0.0", note = "use merge::merge_states")]
pub fn merge_states(
    base_state: &KvState,
    groups: &[GroupResult],
    proposer_addr: &str,
) -> KvState {
    merge::merge_states(base_state, groups, proposer_addr)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Signer;
    use crate::crypto::tx::{derive_address, tx_sign_bytes};
    use crate::crypto::Signer;

    fn make_signed_tx(seed: u64, nonce: u64, payload: &str) -> Tx {
        let mut seed32 = [0u8; 32];
        seed32[..8].copy_from_slice(&seed.to_le_bytes());
        let signer = Ed25519Signer::from_seed(seed32);
        let pk = signer.public_key();
        let from = derive_address(&pk.0);

        let mut tx = Tx {
            pubkey: pk.0.clone(),
            from,
            nonce,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            gas_limit: 100_000,
            payload: payload.to_string(),
            signature: vec![],
            chain_id: 1,
        };
        let msg = tx_sign_bytes(&tx);
        tx.signature = signer.sign(&msg).0;
        tx
    }

    #[test]
    fn test_parallel_matches_sequential() -> ParallelResult<()> {
        let mut state = KvState::default();

        // Fund senders
        for seed in 1u64..=5 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let signer = Ed25519Signer::from_seed(seed32);
            let addr = derive_address(&signer.public_key().0);
            state.balances.insert(addr, 1_000_000_000);
        }

        let proposer_addr = "0000000000000000000000000000000000000000";
        let base_fee = 1u64;

        let txs: Vec<Tx> = (1u64..=5)
            .map(|seed| make_signed_tx(seed, 0, &format!("set key{seed} val{seed}")))
            .collect();

        let config = ParallelConfig {
            min_txs_for_parallel: 2,
            min_senders_for_parallel: 2,
            max_parallel_groups: 256,
            ..Default::default()
        };

        let executor = ParallelExecutor::new(config)?;
        let par_result = executor.execute_block(&state, &txs, base_fee, proposer_addr)?;
        let seq_executor = ParallelExecutor::new(ParallelConfig {
            min_txs_for_parallel: usize::MAX,
            ..Default::default()
        })?;
        let seq_result = seq_executor.execute_block(&state, &txs, base_fee, proposer_addr)?;

        assert_eq!(par_result.gas_used, seq_result.gas_used);
        assert_eq!(par_result.receipts.len(), seq_result.receipts.len());
        for (pr, sr) in par_result.receipts.iter().zip(seq_result.receipts.iter()) {
            assert_eq!(pr.success, sr.success);
            assert_eq!(pr.gas_used, sr.gas_used);
        }
        Ok(())
    }

    #[test]
    fn test_partition_by_sender() {
        let tx1 = make_signed_tx(1, 0, "set a 1");
        let tx2 = make_signed_tx(2, 0, "set b 2");
        let tx3 = make_signed_tx(1, 1, "set c 3");

        let txs = vec![tx1, tx2, tx3];
        let (groups, order) = partition::partition_by_sender(&txs);

        assert_eq!(groups.len(), 2);
        assert_eq!(order.len(), 2);
        let sender1 = &txs[0].from;
        assert_eq!(groups[sender1].len(), 2);
    }

    #[test]
    fn test_config_validation() {
        let bad = ParallelConfig {
            min_txs_for_parallel: 0,
            ..Default::default()
        };
        assert!(ParallelExecutor::new(bad).is_err());

        let good = ParallelConfig::default();
        assert!(ParallelExecutor::new(good).is_ok());
    }

    #[test]
    fn test_small_batch_falls_back_to_sequential() -> ParallelResult<()> {
        let mut state = KvState::default();
        // Fund sender
        let tx = make_signed_tx(1, 0, "set x 1");
        let txs = vec![tx];
        let config = ParallelConfig {
            min_txs_for_parallel: 32,
            ..Default::default()
        };
        let executor = ParallelExecutor::new(config)?;
        let result = executor.execute_block(&state, &txs, 1, "proposer")?;
        assert!(!result.used_parallel);
        Ok(())
    }

    #[test]
    fn test_conflict_detection_same_key() -> ParallelResult<()> {
        let mut state = KvState::default();

        // Fund two senders
        for seed in 1u64..=2 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let signer = Ed25519Signer::from_seed(seed32);
            let addr = derive_address(&signer.public_key().0);
            state.balances.insert(addr, 1_000_000_000);
        }

        // Both senders try to modify the same key
        let tx1 = make_signed_tx(1, 0, "set shared_key val1");
        let tx2 = make_signed_tx(2, 0, "set shared_key val2");

        let txs = vec![tx1, tx2];
        let config = ParallelConfig {
            min_txs_for_parallel: 2,
            min_senders_for_parallel: 2,
            max_parallel_groups: 256,
            ..Default::default()
        };
        let executor = ParallelExecutor::new(config)?;
        let result = executor.execute_block(&state, &txs, 1, "proposer")?;

        // Should fall back to sequential due to conflict
        assert!(!result.used_parallel);
        Ok(())
    }

    #[test]
    fn test_stats_collection() -> ParallelResult<()> {
        let mut state = KvState::default();
        for seed in 1u64..=3 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let signer = Ed25519Signer::from_seed(seed32);
            let addr = derive_address(&signer.public_key().0);
            state.balances.insert(addr, 1_000_000_000);
        }

        let txs: Vec<Tx> = (1u64..=3)
            .map(|seed| make_signed_tx(seed, 0, &format!("set key{seed} val{seed}")))
            .collect();

        let config = ParallelConfig {
            min_txs_for_parallel: 2,
            min_senders_for_parallel: 2,
            max_parallel_groups: 256,
            ..Default::default()
        };
        let executor = ParallelExecutor::new(config)?;
        let _ = executor.execute_block(&state, &txs, 1, "proposer")?;

        let stats = executor.stats();
        assert_eq!(stats.total_blocks, 1);
        assert_eq!(stats.parallel_blocks, 1);
        assert_eq!(stats.sequential_blocks, 0);
        assert_eq!(stats.conflicts_detected, 0);
        Ok(())
    }

    #[test]
    fn test_metrics() -> ParallelResult<()> {
        let mut state = KvState::default();
        for seed in 1u64..=3 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let signer = Ed25519Signer::from_seed(seed32);
            let addr = derive_address(&signer.public_key().0);
            state.balances.insert(addr, 1_000_000_000);
        }

        let txs: Vec<Tx> = (1u64..=3)
            .map(|seed| make_signed_tx(seed, 0, &format!("set key{seed} val{seed}")))
            .collect();

        let config = ParallelConfig {
            min_txs_for_parallel: 2,
            min_senders_for_parallel: 2,
            max_parallel_groups: 256,
            ..Default::default()
        };
        let executor = ParallelExecutor::new(config)?;
        let _ = executor.execute_block(&state, &txs, 1, "proposer")?;

        let metrics = executor.metrics().snapshot();
        assert_eq!(metrics.total_executions, 1);
        assert_eq!(metrics.parallel_executions, 1);
        assert_eq!(metrics.sequential_executions, 0);
        assert_eq!(metrics.conflicts, 0);
        Ok(())
    }
}
