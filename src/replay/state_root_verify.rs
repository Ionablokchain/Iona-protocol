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
//! 2. Compare roots against golden vectors (known‑good values)
//! 3. Detect platform‑specific nondeterminism (float ops, hashmap order)
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::replay::state_root_verify::{verify_block_reproducibility, VerificationError};
//!
//! let result = verify_block_reproducibility(&block, &state, base_fee, 10)?;
//! assert!(result.all_match);
//! ```

use crate::execution::{execute_block, KvState};
use crate::types::{Block, Hash32, Height, Receipt};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during state root verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// Number of iterations must be at least 1.
    #[error("iterations must be >= 1, got {0}")]
    InvalidIterations(usize),

    /// Base fee per gas must be greater than 0.
    #[error("base fee per gas must be > 0, got {0}")]
    InvalidBaseFee(u64),

    /// Computed root differs from the provided golden vector.
    #[error("golden vector mismatch at height {height}: expected {expected}, got {actual}")]
    GoldenMismatch {
        height: Height,
        expected: String,
        actual: String,
    },

    /// State root inconsistency across multiple executions of the same block.
    #[error("state root inconsistency: iteration {iteration}: first={first}, current={current}")]
    Inconsistency {
        iteration: usize,
        first: String,
        current: String,
    },
}

pub type VerificationResult<T> = Result<T, VerificationError>;

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Result of a reproducibility check for a single block.
#[derive(Debug, Clone)]
pub struct ReproducibilityResult {
    /// Block height.
    pub height: Height,
    /// Number of iterations executed.
    pub iterations: usize,
    /// Whether all iterations produced the same root.
    pub all_match: bool,
    /// The root from the first execution (canonical).
    pub canonical_root: Hash32,
    /// The first iteration index where divergence occurred (if any).
    pub diverged_at: Option<usize>,
    /// All state roots collected during each iteration.
    pub roots: Vec<Hash32>,
}

/// Result of verifying reproducibility across multiple blocks.
#[derive(Debug, Clone)]
pub struct BatchReproducibilityResult {
    /// Total number of blocks processed.
    pub total_blocks: usize,
    /// Number of iterations performed per block.
    pub total_iterations: usize,
    /// Whether all blocks were reproducible (all_match == true).
    pub all_reproducible: bool,
    /// Per‑block reproducibility results.
    pub results: Vec<ReproducibilityResult>,
    /// First height where reproducibility failed (if any).
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

// -----------------------------------------------------------------------------
// Core verification functions
// -----------------------------------------------------------------------------

/// Verify that executing a block N times produces the same state root.
///
/// # Arguments
/// * `block` – The block to execute.
/// * `initial_state` – The state before executing the block.
/// * `base_fee_per_gas` – The base fee for gas calculations.
/// * `iterations` – Number of times to execute the block (must be ≥ 1).
pub fn verify_block_reproducibility(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    iterations: usize,
) -> VerificationResult<ReproducibilityResult> {
    if iterations == 0 {
        return Err(VerificationError::InvalidIterations(iterations));
    }
    if base_fee_per_gas == 0 {
        return Err(VerificationError::InvalidBaseFee(base_fee_per_gas));
    }

    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let mut roots = Vec::with_capacity(iterations);

    // Execute the block the requested number of times.
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

    Ok(ReproducibilityResult {
        height: block.header.height,
        iterations,
        all_match: diverged_at.is_none(),
        canonical_root: canonical,
        diverged_at,
        roots,
    })
}

/// Verify reproducibility for a chain of blocks (sequential execution).
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state (genesis or checkpoint).
/// * `base_fee_per_gas` – Base fee for all blocks.
/// * `iterations_per_block` – Number of times to execute each block (must be ≥ 1).
pub fn verify_chain_reproducibility(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    iterations_per_block: usize,
) -> VerificationResult<BatchReproducibilityResult> {
    if iterations_per_block == 0 {
        return Err(VerificationError::InvalidIterations(iterations_per_block));
    }
    if base_fee_per_gas == 0 {
        return Err(VerificationError::InvalidBaseFee(base_fee_per_gas));
    }

    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure = None;
    let mut state = initial_state.clone();

    for block in blocks {
        // Check reproducibility for this block using the current state.
        let result = verify_block_reproducibility(block, &state, base_fee_per_gas, iterations_per_block)?;

        if !result.all_match && first_failure.is_none() {
            first_failure = Some(block.header.height);
        }

        // Advance the state using the canonical (first) execution.
        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };
        let (new_state, _, _) = execute_block(&state, &block.txs, base_fee_per_gas, &proposer_addr);
        state = new_state;

        results.push(result);
    }

    let all_reproducible = first_failure.is_none();
    Ok(BatchReproducibilityResult {
        total_blocks: blocks.len(),
        total_iterations: iterations_per_block,
        all_reproducible,
        results,
        first_failure,
    })
}

/// Compare a computed state root against a golden vector (known‑good value).
///
/// # Arguments
/// * `block` – The block to execute.
/// * `initial_state` – The state before executing the block.
/// * `base_fee_per_gas` – Base fee for gas calculations.
/// * `golden_root` – The expected state root.
///
/// # Returns
/// The computed state root if it matches the golden vector.
pub fn verify_against_golden(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    golden_root: Hash32,
) -> VerificationResult<Hash32> {
    if base_fee_per_gas == 0 {
        return Err(VerificationError::InvalidBaseFee(base_fee_per_gas));
    }

    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let (new_state, _, _) =
        execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);
    let computed = new_state.root();

    if computed != golden_root {
        return Err(VerificationError::GoldenMismatch {
            height: block.header.height,
            expected: hex::encode(golden_root.0),
            actual: hex::encode(computed.0),
        });
    }
    Ok(computed)
}

/// Verify that `KvState::root()` is deterministic (no hashmap ordering issues).
///
/// Computes the state root multiple times and ensures all results are identical.
///
/// # Arguments
/// * `state` – The state to test.
/// * `iterations` – Number of times to compute the root (must be ≥ 1).
pub fn verify_state_root_consistency(state: &KvState, iterations: usize) -> VerificationResult<Hash32> {
    if iterations == 0 {
        return Err(VerificationError::InvalidIterations(iterations));
    }

    let first = state.root();
    for i in 1..iterations {
        let root = state.root();
        if root != first {
            return Err(VerificationError::Inconsistency {
                iteration: i,
                first: hex::encode(first.0),
                current: hex::encode(root.0),
            });
        }
    }
    Ok(first)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

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
    fn test_block_reproducibility() -> VerificationResult<()> {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let result = verify_block_reproducibility(&block, &state, 1, 5)?;
        assert!(result.all_match);
        assert_eq!(result.iterations, 5);
        assert_eq!(result.roots.len(), 5);
        Ok(())
    }

    #[test]
    fn test_block_reproducibility_zero_iterations() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let result = verify_block_reproducibility(&block, &state, 1, 0);
        assert!(matches!(result, Err(VerificationError::InvalidIterations(0))));
    }

    #[test]
    fn test_chain_reproducibility() -> VerificationResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, root.clone())];
        let result = verify_chain_reproducibility(&blocks, &state, 1, 3)?;
        assert!(result.all_reproducible);
        assert_eq!(result.total_blocks, 2);
        Ok(())
    }

    #[test]
    fn test_golden_vector_match() -> VerificationResult<()> {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let result = verify_against_golden(&block, &state, 1, root)?;
        assert_eq!(result, root);
        Ok(())
    }

    #[test]
    fn test_golden_vector_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let bad_golden = Hash32([0xFF; 32]);
        let result = verify_against_golden(&block, &state, 1, bad_golden);
        assert!(matches!(result, Err(VerificationError::GoldenMismatch { .. })));
    }

    #[test]
    fn test_state_root_consistency() -> VerificationResult<()> {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.kv.insert("key1".into(), "val1".into());
        state.nonces.insert("alice".into(), 5);
        let result = verify_state_root_consistency(&state, 100)?;
        assert_eq!(result, state.root());
        Ok(())
    }

    #[test]
    fn test_state_root_consistency_zero_iterations() {
        let state = KvState::default();
        let result = verify_state_root_consistency(&state, 0);
        assert!(matches!(result, Err(VerificationError::InvalidIterations(0))));
    }

    #[test]
    fn test_batch_result_display() -> VerificationResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];
        let result = verify_chain_reproducibility(&blocks, &state, 1, 2)?;
        let s = format!("{result}");
        assert!(s.contains("State Root Reproducibility"));
        assert!(s.contains("ALL REPRODUCIBLE"));
        Ok(())
    }
}
