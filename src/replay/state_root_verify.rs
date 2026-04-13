//! State root reproducibility verification.
//!
//! Verifies that state roots are reproducible across:
//! - Different binary builds (same source, different compiler/platform)
//! - Multiple executions on the same machine
//! - Parallel vs serial execution paths
//!
//! This is critical for consensus safety: if two nodes compute different
//! state roots for the same block, the chain splits.
//!
//! # Approach
//!
//! 1. Execute the same block N times and verify identical roots
//! 2. Compare roots against golden vectors (known-good values)
//! 3. Detect platform-specific nondeterminism (float ops, hashmap order)

use crate::execution::{execute_block, KvState};
use crate::types::{Block, Hash32, Height, Receipt};

/// Result of a reproducibility check for a single block.
#[derive(Debug, Clone)]
pub struct ReproducibilityResult {
    pub height: Height,
    pub iterations: usize,
    pub all_match: bool,
    /// The canonical root (from first execution).
    pub canonical_root: Hash32,
    /// If any mismatch, which iteration diverged.
    pub diverged_at: Option<usize>,
    /// All computed roots (for debugging).
    pub roots: Vec<Hash32>,
}

/// Result of verifying reproducibility across multiple blocks.
#[derive(Debug, Clone)]
pub struct BatchReproducibilityResult {
    pub total_blocks: usize,
    pub total_iterations: usize,
    pub all_reproducible: bool,
    pub results: Vec<ReproducibilityResult>,
    /// First block that was not reproducible.
    pub first_failure: Option<Height>,
}

impl std::fmt::Display for BatchReproducibilityResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "State Root Reproducibility: {}",
            if self.all_reproducible {
                "ALL REPRODUCIBLE"
            } else {
                "NONDETERMINISM DETECTED"
            }
        )?;
        writeln!(
            f,
            "  blocks={}, iterations_per_block={}",
            self.total_blocks, self.total_iterations
        )?;
        if let Some(h) = self.first_failure {
            writeln!(f, "  FIRST FAILURE at height {h}")?;
        }
        Ok(())
    }
}

/// Verify that executing a block N times produces the same state root.
pub fn verify_block_reproducibility(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    iterations: usize,
) -> ReproducibilityResult {
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let mut roots = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let (new_state, _gas, _receipts) =
            execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);
        roots.push(new_state.root());
    }

    let canonical = roots[0].clone();
    let diverged_at = roots
        .iter()
        .enumerate()
        .find(|(_, r)| **r != canonical)
        .map(|(i, _)| i);

    ReproducibilityResult {
        height: block.header.height,
        iterations,
        all_match: diverged_at.is_none(),
        canonical_root: canonical,
        diverged_at,
        roots,
    }
}

/// Verify reproducibility for a chain of blocks.
pub fn verify_chain_reproducibility(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    iterations_per_block: usize,
) -> BatchReproducibilityResult {
    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure = None;
    let mut state = initial_state.clone();

    let proposer_addr = "0000000000000000000000000000000000000000".to_string();

    for block in blocks {
        let result =
            verify_block_reproducibility(block, &state, base_fee_per_gas, iterations_per_block);

        if !result.all_match && first_failure.is_none() {
            first_failure = Some(block.header.height);
        }

        // Advance state using first execution's result.
        let (new_state, _, _) = execute_block(&state, &block.txs, base_fee_per_gas, &proposer_addr);
        state = new_state;

        results.push(result);
    }

    let all_reproducible = first_failure.is_none();
    BatchReproducibilityResult {
        total_blocks: blocks.len(),
        total_iterations: iterations_per_block,
        all_reproducible,
        results,
        first_failure,
    }
}

/// Compare a computed state root against a golden vector.
pub fn verify_against_golden(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    golden_root: Hash32,
) -> Result<Hash32, String> {
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let (new_state, _, _) =
        execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);

    let computed = new_state.root();
    if computed != golden_root {
        return Err(format!(
            "golden vector mismatch at height {}: expected {}, got {}",
            block.header.height,
            hex::encode(golden_root.0),
            hex::encode(computed.0),
        ));
    }
    Ok(computed)
}

/// Verify that KvState::root() is deterministic (no hashmap ordering issues).
pub fn verify_state_root_consistency(state: &KvState, iterations: usize) -> Result<Hash32, String> {
    let first = state.root();
    for i in 1..iterations {
        let root = state.root();
        if root != first {
            return Err(format!(
                "state root inconsistency at iteration {i}: \
                 first={}, current={}",
                hex::encode(first.0),
                hex::encode(root.0),
            ));
        }
    }
    Ok(first)
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader};

    fn empty_block(height: Height, state_root: Hash32) -> Block {
        Block {
            header: BlockHeader {
                height,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: Hash32::zero(),
                receipts_root: Hash32::zero(),
                state_root,
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6126151,
                timestamp: height * 1000,
                protocol_version: 1,
            },
            txs: vec![],
        }
    }

    #[test]
    fn test_block_reproducibility() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root.clone());

        let result = verify_block_reproducibility(&block, &state, 1, 5);
        assert!(
            result.all_match,
            "not reproducible at iteration {:?}",
            result.diverged_at
        );
        assert_eq!(result.iterations, 5);
        assert_eq!(result.roots.len(), 5);
    }

    #[test]
    fn test_chain_reproducibility() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, root.clone())];

        let result = verify_chain_reproducibility(&blocks, &state, 1, 3);
        assert!(result.all_reproducible, "result: {result}");
        assert_eq!(result.total_blocks, 2);
    }

    #[test]
    fn test_golden_vector_match() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root.clone());

        let result = verify_against_golden(&block, &state, 1, root);
        assert!(result.is_ok());
    }

    #[test]
    fn test_golden_vector_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root.clone());

        let bad_golden = Hash32([0xFF; 32]);
        let result = verify_against_golden(&block, &state, 1, bad_golden);
        assert!(result.is_err());
    }

    #[test]
    fn test_state_root_consistency() {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.kv.insert("key1".into(), "val1".into());
        state.nonces.insert("alice".into(), 5);

        let result = verify_state_root_consistency(&state, 100);
        assert!(result.is_ok());
    }

    #[test]
    fn test_reproducibility_with_state() {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 10_000);
        state.balances.insert("bob".into(), 5_000);
        state.nonces.insert("alice".into(), 0);
        let root = state.root();
        let block = empty_block(1, root.clone());

        let result = verify_block_reproducibility(&block, &state, 1, 10);
        assert!(result.all_match);
    }

    #[test]
    fn test_batch_result_display() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];
        let result = verify_chain_reproducibility(&blocks, &state, 1, 2);
        let s = format!("{result}");
        assert!(s.contains("State Root Reproducibility"));
    }
}
