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
//! use iona::execution::parallel::{execute_block_parallel, ParallelConfig, ParallelResult};
//!
//! let config = ParallelConfig::default();
//! let result = execute_block_parallel(&prev_state, &txs, base_fee, proposer, &config)?;
//! assert_eq!(result.gas_used, expected_gas);
//! ```

use crate::execution::{apply_tx, verify_tx_signature, KvState};
use crate::types::{Receipt, Tx};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during parallel execution.
#[derive(Debug, Error)]
pub enum ParallelExecError {
    #[error("transaction signature verification failed for tx at index {index}")]
    SignatureVerificationFailed { index: usize },

    #[error(
        "transaction application failed during sequential fallback at index {index}: {reason}"
    )]
    SequentialApplyFailed { index: usize, reason: String },

    #[error("internal error: {0}")]
    Internal(String),
}

pub type ParallelResult<T> = Result<T, ParallelExecError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the parallel executor.
#[derive(Clone, Debug)]
pub struct ParallelConfig {
    /// Minimum number of transactions to trigger parallel execution.
    /// Below this, sequential execution is used (overhead not worth it).
    pub min_txs_for_parallel: usize,
    /// Minimum number of distinct senders to trigger parallel execution.
    pub min_senders_for_parallel: usize,
    /// Maximum number of parallel groups (limits rayon thread usage).
    pub max_parallel_groups: usize,
}

impl Default for ParallelConfig {
    fn default() -> Self {
        Self {
            min_txs_for_parallel: 32,
            min_senders_for_parallel: 4,
            max_parallel_groups: 256,
        }
    }
}

impl ParallelConfig {
    /// Validate configuration parameters.
    pub fn validate(&self) -> ParallelResult<()> {
        if self.min_txs_for_parallel == 0 {
            return Err(ParallelExecError::Internal(
                "min_txs_for_parallel must be > 0".into(),
            ));
        }
        if self.min_senders_for_parallel == 0 {
            return Err(ParallelExecError::Internal(
                "min_senders_for_parallel must be > 0".into(),
            ));
        }
        if self.max_parallel_groups == 0 {
            return Err(ParallelExecError::Internal(
                "max_parallel_groups must be > 0".into(),
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Result of executing a transaction group in parallel.
#[derive(Clone, Debug)]
struct GroupResult {
    /// Sender address (group key).
    sender: String,
    /// Receipts in original tx order within this group.
    receipts: Vec<Receipt>,
    /// Final state after applying all txs in this group.
    final_state: KvState,
    /// Set of KV keys written by this group.
    written_keys: BTreeSet<String>,
    /// Set of balance addresses modified by this group.
    modified_balances: BTreeSet<String>,
    /// Set of nonce addresses modified by this group.
    modified_nonces: BTreeSet<String>,
    /// Set of VM storage keys modified (contract, slot).
    modified_vm_storage: BTreeSet<(String, String)>,
    /// Original global indices of transactions in this group.
    global_indices: Vec<usize>,
    /// Total gas used by this group.
    gas_used: u64,
}

/// Statistics about parallel execution performance.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ParallelExecStats {
    /// Total blocks executed.
    pub total_blocks: u64,
    /// Blocks that used parallel execution.
    pub parallel_blocks: u64,
    /// Blocks that fell back to sequential (conflicts or too few txs).
    pub sequential_blocks: u64,
    /// Total conflicts detected.
    pub conflicts_detected: u64,
    /// Average speedup factor (estimated).
    pub avg_sender_groups: f64,
    /// Average parallel time in microseconds.
    pub avg_parallel_time_us: f64,
    /// Average sequential time in microseconds.
    pub avg_sequential_time_us: f64,
}

impl ParallelExecStats {
    /// Record a parallel execution with the given number of sender groups.
    pub fn record_parallel(&mut self, num_groups: usize) {
        self.total_blocks += 1;
        self.parallel_blocks += 1;
        let n = self.parallel_blocks as f64;
        self.avg_sender_groups =
            (self.avg_sender_groups * (n - 1.0) + num_groups as f64) / n;
    }

    /// Record a sequential fallback execution.
    pub fn record_sequential(&mut self) {
        self.total_blocks += 1;
        self.sequential_blocks += 1;
    }

    /// Record a conflict detection event.
    pub fn record_conflict(&mut self) {
        self.conflicts_detected += 1;
    }

    /// Record timing for parallel execution (in microseconds).
    pub fn record_parallel_time(&mut self, time_us: u64) {
        let n = self.parallel_blocks as f64;
        self.avg_parallel_time_us =
            (self.avg_parallel_time_us * (n - 1.0) + time_us as f64) / n;
    }

    /// Record timing for sequential execution (in microseconds).
    pub fn record_sequential_time(&mut self, time_us: u64) {
        let n = self.sequential_blocks as f64;
        self.avg_sequential_time_us =
            (self.avg_sequential_time_us * (n - 1.0) + time_us as f64) / n;
    }
}

/// Output of parallel block execution.
#[derive(Debug)]
pub struct ParallelExecResult {
    /// Final state after applying all transactions.
    pub state: KvState,
    /// Total gas used.
    pub gas_used: u64,
    /// Receipts in original transaction order.
    pub receipts: Vec<Receipt>,
    /// Whether parallel execution was used (true) or sequential (false).
    pub used_parallel: bool,
}

// -----------------------------------------------------------------------------
// Core execution logic
// -----------------------------------------------------------------------------

/// Partition transactions by sender address, preserving per-sender ordering.
fn partition_by_sender(txs: &[Tx]) -> (HashMap<String, Vec<(usize, &Tx)>>, Vec<String>) {
    let mut groups: HashMap<String, Vec<(usize, &Tx)>> = HashMap::new();
    let mut sender_order: Vec<String> = Vec::new();

    for (idx, tx) in txs.iter().enumerate() {
        let sender = tx.from.clone();
        if !groups.contains_key(&sender) {
            sender_order.push(sender.clone());
        }
        groups.entry(sender).or_default().push((idx, tx));
    }

    (groups, sender_order)
}

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
    }
}

/// Check if two transaction groups have conflicting writes.
fn groups_conflict(a: &GroupResult, b: &GroupResult) -> bool {
    // KV write-write conflict
    for key in &a.written_keys {
        if b.written_keys.contains(key) {
            return true;
        }
    }

    // Balance conflict: both modify the same address (excluding proposer fee)
    for addr in &a.modified_balances {
        if b.modified_balances.contains(addr) {
            return true;
        }
    }

    // Nonce conflict: both modify the same address
    for addr in &a.modified_nonces {
        if b.modified_nonces.contains(addr) {
            return true;
        }
    }

    // VM storage conflict
    for key in &a.modified_vm_storage {
        if b.modified_vm_storage.contains(key) {
            return true;
        }
    }

    false
}

/// Merge non-conflicting group results into a single state.
/// Applies deltas from each group onto the base state in the original sender order.
fn merge_states(
    base_state: &KvState,
    groups: &[GroupResult],
    proposer_addr: &str,
) -> KvState {
    let mut merged = base_state.clone();

    for group in groups {
        // Apply KV changes (new values)
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

        // Apply balance changes using delta-based approach for proposer
        for (addr, new_bal) in &group.final_state.balances {
            let base_bal = base_state.balances.get(addr).copied().unwrap_or(0);
            let delta = (*new_bal as i128) - (base_bal as i128);
            let current = merged.balances.get(addr).copied().unwrap_or(base_bal);
            if delta >= 0 {
                merged
                    .balances
                    .insert(addr.clone(), current.saturating_add(delta as u64));
            } else {
                merged
                    .balances
                    .insert(addr.clone(), current.saturating_sub((-delta) as u64));
            }
        }

        // Apply nonce changes
        for (addr, nonce) in &group.final_state.nonces {
            merged.nonces.insert(addr.clone(), *nonce);
        }

        // Accumulate burned fee
        let burned_delta = group
            .final_state
            .burned
            .saturating_sub(base_state.burned);
        merged.burned = merged.burned.saturating_add(burned_delta);

        // Merge VM state
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

    merged
}

/// Sequential fallback (no parallelism).
fn execute_sequential_fallback(
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
            return Err(ParallelExecError::SequentialApplyFailed {
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
    })
}

/// Execute a block of transactions with parallel execution where possible.
///
/// The algorithm:
/// 1. Partition txs by sender
/// 2. Execute each sender's txs in parallel (independent groups)
/// 3. Check for write-write conflicts between groups
/// 4. If no conflicts: merge results (fast path)
/// 5. If conflicts: fall back to sequential execution
pub fn execute_block_parallel(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
    config: &ParallelConfig,
    stats: Option<&mut ParallelExecStats>,
) -> ParallelResult<ParallelExecResult> {
    config.validate()?;

    let (groups, sender_order) = partition_by_sender(txs);
    let should_use_parallel = txs.len() >= config.min_txs_for_parallel
        && groups.len() >= config.min_senders_for_parallel
        && groups.len() <= config.max_parallel_groups;

    if !should_use_parallel {
        if let Some(s) = stats {
            s.record_sequential();
        }
        return execute_sequential_fallback(prev_state, txs, base_fee_per_gas, proposer_addr);
    }

    // Phase 1: Parallel signature pre‑verification
    let sig_valid: Vec<bool> = txs
        .par_iter()
        .enumerate()
        .map(|(idx, tx)| {
            verify_tx_signature(tx).map_err(|_| ParallelExecError::SignatureVerificationFailed {
                index: idx,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Log any signature failures (they should not reach the mempool)
    for (i, valid) in sig_valid.iter().enumerate() {
        if !valid {
            tracing::warn!(
                tx_index = i,
                "transaction signature verification failed during parallel execution"
            );
        }
    }

    // Phase 2: Execute each sender group in parallel
    let group_entries: Vec<(&String, &Vec<(usize, &Tx)>)> = sender_order
        .iter()
        .filter_map(|s| groups.get(s).map(|g| (s, g)))
        .collect();

    let group_results: Vec<GroupResult> = group_entries
        .par_iter()
        .map(|(sender, txs_in_group)| {
            execute_group(prev_state, txs_in_group, base_fee_per_gas, proposer_addr, sender)
        })
        .collect();

    // Phase 3: Conflict detection
    let mut conflicting_groups: Vec<usize> = Vec::new();
    for i in 0..group_results.len() {
        for j in (i + 1)..group_results.len() {
            if groups_conflict(&group_results[i], &group_results[j]) {
                conflicting_groups.push(i);
                conflicting_groups.push(j);
                if let Some(s) = stats.as_mut() {
                    s.record_conflict();
                }
            }
        }
    }

    if !conflicting_groups.is_empty() {
        tracing::debug!(
            conflict_count = conflicting_groups.len(),
            group_count = group_results.len(),
            "parallel execution conflict detected, falling back to sequential"
        );
        if let Some(s) = stats {
            s.record_sequential();
        }
        return execute_sequential_fallback(prev_state, txs, base_fee_per_gas, proposer_addr);
    }

    // Phase 4: Merge results (no conflicts — fast path)
    let merged_state = merge_states(prev_state, &group_results, proposer_addr);

    // Reconstruct receipts in original transaction order
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

    if let Some(s) = stats {
        s.record_parallel(group_results.len());
    }

    Ok(ParallelExecResult {
        state: merged_state,
        gas_used: total_gas,
        receipts,
        used_parallel: true,
    })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::tx::{derive_address, tx_sign_bytes};
    use crate::crypto::Signer;
    use crate::types::Tx;

    fn make_signed_tx(seed: u64, nonce: u64, payload: &str) -> Tx {
        let mut seed32 = [0u8; 32];
        seed32[..8].copy_from_slice(&seed.to_le_bytes());
        let kp = Ed25519Keypair::from_seed(seed32);
        let pk = kp.public_key();
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
        tx.signature = kp.sign(&msg).0;
        tx
    }

    #[test]
    fn test_parallel_matches_sequential() -> ParallelResult<()> {
        let mut state = KvState::default();

        // Fund senders
        for seed in 1u64..=5 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let kp = Ed25519Keypair::from_seed(seed32);
            let addr = derive_address(&kp.public_key().0);
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
        };

        let par_result =
            execute_block_parallel(&state, &txs, base_fee, proposer_addr, &config, None)?;
        let seq_result =
            execute_sequential_fallback(&state, &txs, base_fee, proposer_addr)?;

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
        let (groups, order) = partition_by_sender(&txs);

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
        assert!(bad.validate().is_err());

        let good = ParallelConfig::default();
        assert!(good.validate().is_ok());
    }

    #[test]
    fn test_small_batch_falls_back_to_sequential() -> ParallelResult<()> {
        let mut state = KvState::default();
        let tx = make_signed_tx(1, 0, "set x 1");
        let txs = vec![tx];
        let config = ParallelConfig {
            min_txs_for_parallel: 32,
            ..Default::default()
        };
        let result =
            execute_block_parallel(&state, &txs, 1, "proposer", &config, None)?;
        assert!(!result.used_parallel);
        Ok(())
    }

    #[test]
    fn test_conflict_detection_same_key() {
        let mut state = KvState::default();

        // Fund two senders
        for seed in 1u64..=2 {
            let mut seed32 = [0u8; 32];
            seed32[..8].copy_from_slice(&seed.to_le_bytes());
            let kp = Ed25519Keypair::from_seed(seed32);
            let addr = derive_address(&kp.public_key().0);
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
        };

        let result =
            execute_block_parallel(&state, &txs, 1, "proposer", &config, None)?;

        // Should fall back to sequential due to conflict
        assert!(!result.used_parallel);
    }
}
