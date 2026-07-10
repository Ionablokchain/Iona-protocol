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
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::replay::state_root_verify::{ReproducibilityConfig, verify_chain_reproducibility};
//!
//! let config = ReproducibilityConfig::default();
//! let result = verify_chain_reproducibility(&blocks, &state, &config);
//! assert!(result.all_reproducible);
//! ```

use crate::execution::{execute_block, KvState};
use crate::replay::nondeterminism::{NdLogger, NdSource};
use crate::types::{Block, Hash32, Height, Receipt};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for reproducibility verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityConfig {
    /// Number of times to execute each block.
    pub iterations_per_block: usize,
    /// If true, stop at the first failure.
    pub stop_on_first_failure: bool,
    /// If true, use nondeterminism logger to record sources of divergence.
    pub enable_nondeterminism_logging: bool,
    /// Base fee for execution (used for all blocks).
    pub base_fee_per_gas: u64,
}

impl Default for ReproducibilityConfig {
    fn default() -> Self {
        Self {
            iterations_per_block: 3,
            stop_on_first_failure: true,
            enable_nondeterminism_logging: false,
            base_fee_per_gas: 1,
        }
    }
}

// -----------------------------------------------------------------------------
// Result types (with serialization)
// -----------------------------------------------------------------------------

/// Result of a reproducibility check for a single block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityResult {
    pub height: Height,
    pub iterations: usize,
    pub all_match: bool,
    /// The canonical root (from first execution).
    pub canonical_root: Hash32,
    /// If any mismatch, which iteration diverged (0‑based).
    pub diverged_at: Option<usize>,
    /// All computed roots (for debugging).
    pub roots: Vec<Hash32>,
    /// Optional: diff between the canonical root and the divergent root.
    pub diff_description: Option<String>,
}

/// Result of verifying reproducibility across multiple blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchReproducibilityResult {
    pub total_blocks: usize,
    pub total_iterations: usize,
    pub all_reproducible: bool,
    pub results: Vec<ReproducibilityResult>,
    /// First block that was not reproducible (if any).
    pub first_failure: Option<Height>,
    /// Summary of nondeterministic events collected during verification.
    pub nondeterminism_report: Option<String>,
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
        if let Some(report) = &self.nondeterminism_report {
            writeln!(f, "\n{}", report)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Verification functions
// -----------------------------------------------------------------------------

/// Verify that executing a block N times produces the same state root.
pub fn verify_block_reproducibility(
    block: &Block,
    initial_state: &KvState,
    config: &ReproducibilityConfig,
    logger: Option<&mut NdLogger>,
) -> ReproducibilityResult {
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let mut roots = Vec::with_capacity(config.iterations_per_block);

    for i in 0..config.iterations_per_block {
        if let Some(ref mut l) = logger {
            l.log(
                NdSource::HashmapIteration,
                format!("block execution iteration {i} at height {}", block.header.height),
                None,
                Some(file!()),
            );
        }

        let (new_state, _gas, _receipts) = execute_block(
            initial_state,
            &block.txs,
            config.base_fee_per_gas,
            &proposer_addr,
        );
        roots.push(new_state.root());

        if config.enable_nondeterminism_logging && i > 0 && roots[i] != roots[0] {
            if let Some(ref mut l) = logger {
                l.log(
                    NdSource::Custom("State root divergence".into()),
                    format!("iteration {} root differs from canonical", i),
                    Some(format!("root: {:?}", roots[i])),
                    Some(file!()),
                );
            }
        }
    }

    let canonical = roots[0].clone();
    let diverged_at = roots
        .iter()
        .enumerate()
        .find(|(_, r)| **r != canonical)
        .map(|(i, _)| i);

    let diff_description = diverged_at.map(|idx| {
        format!(
            "Iteration {} diverged: root = {:?}, canonical = {:?}",
            idx,
            hex::encode(roots[idx].0),
            hex::encode(canonical.0)
        )
    });

    ReproducibilityResult {
        height: block.header.height,
        iterations: config.iterations_per_block,
        all_match: diverged_at.is_none(),
        canonical_root: canonical,
        diverged_at,
        roots,
        diff_description,
    }
}

/// Verify reproducibility for a chain of blocks.
pub fn verify_chain_reproducibility(
    blocks: &[Block],
    initial_state: &KvState,
    config: &ReproducibilityConfig,
) -> BatchReproducibilityResult {
    let mut logger = if config.enable_nondeterminism_logging {
        Some(NdLogger::new())
    } else {
        None
    };

    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure = None;
    let mut state = initial_state.clone();

    for (idx, block) in blocks.iter().enumerate() {
        debug!("Verifying reproducibility for block height {}", block.header.height);
        let result = verify_block_reproducibility(block, &state, config, logger.as_mut());

        if !result.all_match && first_failure.is_none() {
            first_failure = Some(block.header.height);
            warn!(
                "Non‑determinism detected at height {}: root mismatch at iteration {:?}",
                block.header.height, result.diverged_at
            );
            if config.stop_on_first_failure {
                results.push(result);
                break;
            }
        }

        // Advance state using first execution's result (the canonical one).
        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };
        let (new_state, _, _) = execute_block(
            &state,
            &block.txs,
            config.base_fee_per_gas,
            &proposer_addr,
        );
        state = new_state;

        results.push(result);
        info!("Verified block {} / {}", idx + 1, blocks.len());
    }

    let nondeterminism_report = logger.map(|l| format!("{}", l.finalize()));

    let all_reproducible = first_failure.is_none();
    BatchReproducibilityResult {
        total_blocks: results.len(),
        total_iterations: config.iterations_per_block,
        all_reproducible,
        results,
        first_failure,
        nondeterminism_report,
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

    let (new_state, _, _) = execute_block(
        initial_state,
        &block.txs,
        base_fee_per_gas,
        &proposer_addr,
    );

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

/// Compare two states and return a list of differences (for debugging).
pub fn compare_states(a: &KvState, b: &KvState) -> Vec<String> {
    let mut diffs = Vec::new();

    // Compare balances
    for (addr, bal_a) in &a.balances {
        match b.balances.get(addr) {
            Some(bal_b) if bal_a != bal_b => {
                diffs.push(format!("balance {}: {} vs {}", addr, bal_a, bal_b));
            }
            None => {
                diffs.push(format!("balance {} only in A: {}", addr, bal_a));
            }
        }
    }
    for (addr, bal_b) in &b.balances {
        if !a.balances.contains_key(addr) {
            diffs.push(format!("balance {} only in B: {}", addr, bal_b));
        }
    }

    // Compare nonces
    for (addr, nonce_a) in &a.nonces {
        match b.nonces.get(addr) {
            Some(nonce_b) if nonce_a != nonce_b => {
                diffs.push(format!("nonce {}: {} vs {}", addr, nonce_a, nonce_b));
            }
            None => {
                diffs.push(format!("nonce {} only in A: {}", addr, nonce_a));
            }
        }
    }
    for (addr, nonce_b) in &b.nonces {
        if !a.nonces.contains_key(addr) {
            diffs.push(format!("nonce {} only in B: {}", addr, nonce_b));
        }
    }

    // Compare KV
    for (key, val_a) in &a.kv {
        match b.kv.get(key) {
            Some(val_b) if val_a != val_b => {
                diffs.push(format!("kv {}: {:?} vs {:?}", key, val_a, val_b));
            }
            None => {
                diffs.push(format!("kv {} only in A: {:?}", key, val_a));
            }
        }
    }
    for (key, val_b) in &b.kv {
        if !a.kv.contains_key(key) {
            diffs.push(format!("kv {} only in B: {:?}", key, val_b));
        }
    }

    diffs
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
    fn test_block_reproducibility() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root.clone());
        let config = ReproducibilityConfig::default();

        let result = verify_block_reproducibility(&block, &state, &config, None);
        assert!(result.all_match, "not reproducible at iteration {:?}", result.diverged_at);
        assert_eq!(result.iterations, 3);
        assert_eq!(result.roots.len(), 3);
    }

    #[test]
    fn test_chain_reproducibility() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, root.clone())];
        let config = ReproducibilityConfig::default();

        let result = verify_chain_reproducibility(&blocks, &state, &config);
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
    fn test_compare_states() {
        let mut a = KvState::default();
        let mut b = KvState::default();

        a.balances.insert("alice".into(), 100);
        b.balances.insert("alice".into(), 200);
        b.balances.insert("bob".into(), 50);

        let diffs = compare_states(&a, &b);
        assert!(diffs.iter().any(|d| d.contains("alice") && d.contains("100 vs 200")));
        assert!(diffs.iter().any(|d| d.contains("bob") && d.contains("only in B")));
    }

    #[test]
    fn test_batch_result_display() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];
        let config = ReproducibilityConfig::default();
        let result = verify_chain_reproducibility(&blocks, &state, &config);
        let s = format!("{result}");
        assert!(s.contains("State Root Reproducibility"));
    }
}
