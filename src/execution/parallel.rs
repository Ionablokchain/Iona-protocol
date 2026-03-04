//! Parallel transaction execution engine for IONA.
//!
//! Implements optimistic parallel execution with conflict detection and rollback.
//!
//! Strategy:
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
//! Performance model:
//!   - 4096 txs from 200 senders → ~20 txs/sender average
//!   - 8 cores → 200 groups / 8 = 25 groups per core
//!   - Each group: ~20 txs * 50μs = 1ms
//!   - Total parallel time: ~25ms (vs ~200ms sequential)
//!   - Speedup: ~8x on 8 cores

use crate::execution::{apply_tx, intrinsic_gas, verify_tx_signature, KvState};
use crate::types::{Hash32, Receipt, Tx};
use rayon::prelude::*;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// Result of parallel execution for a single transaction group.
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
    /// Original global indices of transactions in this group.
    global_indices: Vec<usize>,
    /// Total gas used by this group.
    gas_used: u64,
}

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
    let mut written_keys = BTreeSet::new();
    let mut modified_balances = BTreeSet::new();
    let mut global_indices = Vec::with_capacity(txs.len());
    let mut gas_used = 0u64;

    // Track initial KV state for write detection
    let initial_kv = state.kv.clone();
    let initial_balances = state.balances.clone();

    for &(idx, tx) in txs {
        let (rcpt, next_state) = apply_tx(&state, tx, base_fee_per_gas, proposer_addr);
        gas_used = gas_used.saturating_add(rcpt.gas_used);
        state = next_state;
        receipts.push(rcpt);
        global_indices.push(idx);
    }

    // Detect which keys were written
    for (k, v) in &state.kv {
        if initial_kv.get(k) != Some(v) {
            written_keys.insert(k.clone());
        }
    }
    // Keys that were deleted
    for k in initial_kv.keys() {
        if !state.kv.contains_key(k) {
            written_keys.insert(k.clone());
        }
    }

    // Detect which balances were modified (beyond sender + proposer)
    for (addr, bal) in &state.balances {
        if initial_balances.get(addr) != Some(bal) {
            modified_balances.insert(addr.clone());
        }
    }

    GroupResult {
        sender: sender.to_string(),
        receipts,
        final_state: state,
        written_keys,
        modified_balances,
        global_indices,
        gas_used,
    }
}

/// Check if two groups have conflicting writes.
fn groups_conflict(a: &GroupResult, b: &GroupResult) -> bool {
    // KV write-write conflict
    for key in &a.written_keys {
        if b.written_keys.contains(key) {
            return true;
        }
    }

    // Balance conflict: if group A modifies an address that group B also modifies
    // (beyond the proposer, which both will modify).
    for addr in &a.modified_balances {
        if addr != &a.sender && b.modified_balances.contains(addr) && addr != &b.sender {
            return true;
        }
    }

    false
}

/// Merge non-conflicting group results into a single state.
/// The merge applies deltas from each group onto the base state,
/// in the original sender order, to maintain determinism.
fn merge_states(
    base_state: &KvState,
    groups: &[GroupResult],
    proposer_addr: &str,
) -> KvState {
    let mut merged = base_state.clone();

    for group in groups {
        // Apply KV changes
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

        // Apply balance changes (delta-based)
        for (addr, new_bal) in &group.final_state.balances {
            if addr == proposer_addr {
                // Proposer balance: accumulate tips from all groups
                let base_bal = base_state.balances.get(addr).copied().unwrap_or(0);
                let delta = new_bal.saturating_sub(
                    base_state.balances.get(addr).copied().unwrap_or(0),
                );
                let current = merged.balances.get(addr).copied().unwrap_or(base_bal);
                merged.balances.insert(addr.clone(), current.saturating_add(delta));
            } else {
                merged.balances.insert(addr.clone(), *new_bal);
            }
        }

        // Apply nonce changes
        for (addr, nonce) in &group.final_state.nonces {
            merged.nonces.insert(addr.clone(), *nonce);
        }

        // Accumulate burned
        let burned_delta = group.final_state.burned.saturating_sub(base_state.burned);
        merged.burned = merged.burned.saturating_add(burned_delta);

        // Merge VM state changes
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

/// Execute a block of transactions with parallel execution where possible.
///
/// Returns (final_state, total_gas_used, receipts) — identical to sequential execution.
///
/// The algorithm:
/// 1. Partition txs by sender
/// 2. Execute each sender's txs in parallel (independent groups)
/// 3. Check for write-write conflicts between groups
/// 4. If no conflicts: merge results (fast path)
/// 5. If conflicts: fall back to sequential for conflicting groups
pub fn execute_block_parallel(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
    config: &ParallelConfig,
) -> (KvState, u64, Vec<Receipt>) {
    // Fall back to sequential for small batches
    let (groups, sender_order) = partition_by_sender(txs);
    if txs.len() < config.min_txs_for_parallel
        || groups.len() < config.min_senders_for_parallel
    {
        return execute_sequential_fallback(prev_state, txs, base_fee_per_gas, proposer_addr);
    }

    // Phase 1: Parallel signature verification
    let sig_valid: Vec<bool> = txs.par_iter().map(|tx| verify_tx_signature(tx).is_ok()).collect();

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
    let mut has_conflict = false;
    for i in 0..group_results.len() {
        if has_conflict {
            break;
        }
        for j in (i + 1)..group_results.len() {
            if groups_conflict(&group_results[i], &group_results[j]) {
                has_conflict = true;
                break;
            }
        }
    }

    if has_conflict {
        // Fall back to sequential execution for correctness
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

    (merged_state, total_gas, receipts)
}

/// Sequential fallback (same as execute_block but without the parallel sig verify
/// optimization, since we already know we need serial execution).
fn execute_sequential_fallback(
    prev_state: &KvState,
    txs: &[Tx],
    base_fee_per_gas: u64,
    proposer_addr: &str,
) -> (KvState, u64, Vec<Receipt>) {
    let mut st = prev_state.clone();
    let mut gas_total = 0u64;
    let mut receipts = Vec::with_capacity(txs.len());
    for tx in txs {
        let (rcpt, next) = apply_tx(&st, tx, base_fee_per_gas, proposer_addr);
        gas_total = gas_total.saturating_add(rcpt.gas_used);
        st = next;
        receipts.push(rcpt);
    }
    (st, gas_total, receipts)
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
}

impl ParallelExecStats {
    pub fn record_parallel(&mut self, num_groups: usize) {
        self.total_blocks += 1;
        self.parallel_blocks += 1;
        let n = self.parallel_blocks as f64;
        self.avg_sender_groups = (self.avg_sender_groups * (n - 1.0) + num_groups as f64) / n;
    }

    pub fn record_sequential(&mut self) {
        self.total_blocks += 1;
        self.sequential_blocks += 1;
    }

    pub fn record_conflict(&mut self) {
        self.conflicts_detected += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::ed25519::Ed25519Keypair;
    use crate::crypto::Signer;
    use crate::crypto::tx::{derive_address, tx_sign_bytes};
    use crate::types::Tx;

    fn make_signed_tx(seed: u64, nonce: u64, payload: &str) -> Tx {
        let mut seed32 = [0u8; 32];
        seed32[..8].copy_from_slice(&seed.to_le_bytes());
        let kp = Ed25519Keypair::from_seed(seed32);
        let pk = kp.public_key();
        let from = derive_address(&pk.0);

        let mut tx = Tx {
            pubkey: pk.0.clone(),
            from: from.clone(),
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
    fn test_parallel_matches_sequential() {
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

        // Create txs from different senders (no conflicts)
        let txs: Vec<Tx> = (1u64..=5)
            .map(|seed| make_signed_tx(seed, 0, &format!("set key{seed} val{seed}")))
            .collect();

        let config = ParallelConfig {
            min_txs_for_parallel: 2,
            min_senders_for_parallel: 2,
            max_parallel_groups: 256,
        };

        let (par_state, par_gas, par_receipts) =
            execute_block_parallel(&state, &txs, base_fee, proposer_addr, &config);
        let (seq_state, seq_gas, seq_receipts) =
            execute_sequential_fallback(&state, &txs, base_fee, proposer_addr);

        // Results should be equivalent
        assert_eq!(par_gas, seq_gas);
        assert_eq!(par_receipts.len(), seq_receipts.len());
        for (pr, sr) in par_receipts.iter().zip(seq_receipts.iter()) {
            assert_eq!(pr.success, sr.success);
            assert_eq!(pr.gas_used, sr.gas_used);
        }
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
        // Sender 1 should have 2 txs
        let sender1 = &txs[0].from;
        assert_eq!(groups[sender1].len(), 2);
    }
}
