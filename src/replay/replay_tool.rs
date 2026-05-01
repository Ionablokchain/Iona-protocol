//! STEP 1 — Deterministic replay tool.
//!
//! Provides the `iona replay --from 1 --to N --verify-root` CLI logic.
//! Replays blocks from stored chain data, re-executes each block,
//! verifies state roots, and reports any divergence.
//!
//! This is the primary tool for:
//! - Validating that a new binary produces identical results on old blocks
//! - Auditing the chain after a suspected bug or divergence
//! - Detecting nondeterminism across builds
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::replay::replay_tool::{replay, ReplayOpts, ReplayError};
//!
//! fn main() -> Result<(), ReplayError> {
//!     let result = replay(&blocks, &initial_state, &opts, None)?;
//!     println!("{result}");
//!     Ok(())
//! }
//! ```

use crate::execution::{execute_block, KvState};
use crate::replay::nondeterminism::NdLogger;
use crate::types::{Block, Hash32, Height};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during replay.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("invalid height range: from={from} > to={to}")]
    InvalidHeightRange { from: Height, to: Height },
    #[error("determinism check count must be > 0, got {0}")]
    InvalidDeterminismCount(usize),
    #[error("base fee per gas must be > 0, got {0}")]
    InvalidBaseFee(u64),
    #[error("block execution failed at height {height}: {reason}")]
    ExecutionFailed { height: Height, reason: String },
}

pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/// Options for the replay command.
#[derive(Debug, Clone)]
pub struct ReplayOpts {
    pub from: Height,
    pub to: Height,
    pub verify_root: bool,
    pub log_roots: bool,
    pub determinism_check: usize,
    pub base_fee_per_gas: u64,
}

impl Default for ReplayOpts {
    fn default() -> Self {
        Self {
            from: 1,
            to: u64::MAX,
            verify_root: true,
            log_roots: true,
            determinism_check: 0,
            base_fee_per_gas: 1,
        }
    }
}

impl ReplayOpts {
    /// Validate options.
    pub fn validate(&self) -> ReplayResult<()> {
        if self.from > self.to {
            return Err(ReplayError::InvalidHeightRange {
                from: self.from,
                to: self.to,
            });
        }
        if self.base_fee_per_gas == 0 {
            return Err(ReplayError::InvalidBaseFee(self.base_fee_per_gas));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Per-block replay result with state root logging (STEP 5).
#[derive(Debug, Clone)]
pub struct BlockReplayEntry {
    pub height: Height,
    pub state_root: Hash32,
    pub expected_root: Hash32,
    pub root_match: bool,
    pub gas_used: u64,
    pub deterministic: bool,
}

impl std::fmt::Display for BlockReplayEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.root_match { "OK" } else { "MISMATCH" };
        let det = if self.deterministic {
            ""
        } else {
            " NONDETERMINISTIC"
        };
        write!(
            f,
            "height={} root=0x{} expected=0x{} status={}{} gas={}",
            self.height,
            hex::encode(&self.state_root.0[..8]),
            hex::encode(&self.expected_root.0[..8]),
            status,
            det,
            self.gas_used,
        )
    }
}

/// Full replay result.
#[derive(Debug, Clone)]
pub struct ReplayResult {
    pub entries: Vec<BlockReplayEntry>,
    pub success: bool,
    pub total_blocks: usize,
    pub total_gas: u64,
    pub first_mismatch: Option<Height>,
    pub first_nondeterministic: Option<Height>,
}

impl std::fmt::Display for ReplayResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.success { "PASS" } else { "FAIL" };
        writeln!(
            f,
            "Replay Result: {} ({} blocks, {} gas)",
            status, self.total_blocks, self.total_gas
        )?;
        if let Some(h) = self.first_mismatch {
            writeln!(f, "  FIRST MISMATCH at height {h}")?;
        }
        if let Some(h) = self.first_nondeterministic {
            writeln!(f, "  FIRST NONDETERMINISM at height {h}")?;
        }
        for entry in &self.entries {
            writeln!(f, "  {entry}")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Core replay function
// -----------------------------------------------------------------------------

/// Execute the replay tool on a set of blocks.
///
/// This is the core of `iona replay --from <from> --to <to> --verify-root`.
pub fn replay(
    blocks: &[Block],
    initial_state: &KvState,
    opts: &ReplayOpts,
    nd_logger: Option<&NdLogger>,
) -> ReplayResult<ReplayResult> {
    opts.validate()?;

    let mut state = initial_state.clone();
    let mut entries = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;
    let mut first_mismatch = None;
    let mut first_nondeterministic = None;

    for block in blocks {
        let h = block.header.height;
        if h < opts.from || h > opts.to {
            continue;
        }

        // Log height for nondeterminism tracking.
        if let Some(logger) = nd_logger {
            logger.set_height(h);
        }

        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };

        // Execute block.
        let (new_state, gas_used, _receipts) =
            execute_block(&state, &block.txs, opts.base_fee_per_gas, &proposer_addr);

        let state_root = new_state.root();
        let expected_root = block.header.state_root;
        let root_match = if opts.verify_root {
            state_root == expected_root
        } else {
            true
        };

        // Determinism check: run N more times and compare roots.
        let mut deterministic = true;
        if opts.determinism_check > 0 {
            for _ in 0..opts.determinism_check {
                let (check_state, _, _) =
                    execute_block(&state, &block.txs, opts.base_fee_per_gas, &proposer_addr);
                if check_state.root() != state_root {
                    deterministic = false;
                    break;
                }
            }
        }

        if !root_match && first_mismatch.is_none() {
            first_mismatch = Some(h);
        }
        if !deterministic && first_nondeterministic.is_none() {
            first_nondeterministic = Some(h);
        }

        total_gas += gas_used;
        entries.push(BlockReplayEntry {
            height: h,
            state_root,
            expected_root,
            root_match,
            gas_used,
            deterministic,
        });

        state = new_state;
    }

    let success = first_mismatch.is_none() && first_nondeterministic.is_none();
    let total_blocks = entries.len();

    Ok(ReplayResult {
        entries,
        success,
        total_blocks,
        total_gas,
        first_mismatch,
        first_nondeterministic,
    })
}

// -----------------------------------------------------------------------------
// Cross-node comparison (STEP 6)
// -----------------------------------------------------------------------------

/// Root mismatch between two nodes.
#[derive(Debug, Clone)]
pub struct RootMismatch {
    pub height: Height,
    pub root_a: Hash32,
    pub root_b: Hash32,
}

/// Result of cross-node comparison.
#[derive(Debug, Clone)]
pub struct CompareResult {
    pub node_a: String,
    pub node_b: String,
    pub common_heights: usize,
    pub mismatches: Vec<RootMismatch>,
    pub only_in_a: Vec<Height>,
    pub only_in_b: Vec<Height>,
    pub agree: bool,
}

impl std::fmt::Display for CompareResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.agree { "AGREE" } else { "DIVERGENCE" };
        writeln!(
            f,
            "Compare {} vs {}: {} ({} common heights)",
            self.node_a, self.node_b, status, self.common_heights
        )?;
        for m in &self.mismatches {
            writeln!(
                f,
                "  height {}: {} root=0x{} vs 0x{}",
                m.height,
                "MISMATCH",
                hex::encode(&m.root_a.0[..8]),
                hex::encode(&m.root_b.0[..8])
            )?;
        }
        if !self.only_in_a.is_empty() {
            writeln!(f, "  only in {}: {:?}", self.node_a, self.only_in_a)?;
        }
        if !self.only_in_b.is_empty() {
            writeln!(f, "  only in {}: {:?}", self.node_b, self.only_in_b)?;
        }
        Ok(())
    }
}

/// Compare state roots from two nodes to find divergence.
pub fn compare_nodes(
    node_a_id: &str,
    node_a_roots: &BTreeMap<Height, Hash32>,
    node_b_id: &str,
    node_b_roots: &BTreeMap<Height, Hash32>,
) -> CompareResult {
    let mut mismatches = Vec::new();

    for (&height, root_a) in node_a_roots {
        if let Some(root_b) = node_b_roots.get(&height) {
            if root_a != root_b {
                mismatches.push(RootMismatch {
                    height,
                    root_a: root_a.clone(),
                    root_b: root_b.clone(),
                });
            }
        }
    }

    let only_a: Vec<Height> = node_a_roots
        .keys()
        .filter(|h| !node_b_roots.contains_key(h))
        .copied()
        .collect();

    let only_b: Vec<Height> = node_b_roots
        .keys()
        .filter(|h| !node_a_roots.contains_key(h))
        .copied()
        .collect();

    let common_heights = node_a_roots
        .keys()
        .filter(|h| node_b_roots.contains_key(h))
        .count();

    let agree = mismatches.is_empty() && only_a.is_empty() && only_b.is_empty();

    CompareResult {
        node_a: node_a_id.to_string(),
        node_b: node_b_id.to_string(),
        common_heights,
        mismatches,
        only_in_a: only_a,
        only_in_b: only_b,
        agree,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::BlockHeader;

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
    fn test_opts_validation() {
        let bad = ReplayOpts {
            from: 10,
            to: 5,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let zero_fee = ReplayOpts {
            base_fee_per_gas: 0,
            ..Default::default()
        };
        assert!(zero_fee.validate().is_err());

        let good = ReplayOpts::default();
        assert!(good.validate().is_ok());
    }

    #[test]
    fn test_replay_basic() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
            empty_block(3, root.clone()),
        ];

        let opts = ReplayOpts {
            from: 1,
            to: 3,
            verify_root: true,
            log_roots: true,
            determinism_check: 0,
            base_fee_per_gas: 1,
        };

        let result = replay(&blocks, &state, &opts, None)?;
        assert!(result.success);
        assert_eq!(result.total_blocks, 3);
        Ok(())
    }

    #[test]
    fn test_replay_root_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let bad_root = Hash32([0xFF; 32]);
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, bad_root)];

        let opts = ReplayOpts {
            from: 1,
            to: 2,
            verify_root: true,
            ..Default::default()
        };

        let result = replay(&blocks, &state, &opts, None)?;
        assert!(!result.success);
        assert_eq!(result.first_mismatch, Some(2));
        Ok(())
    }

    #[test]
    fn test_replay_with_range_filter() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
            empty_block(3, root.clone()),
        ];

        let opts = ReplayOpts {
            from: 2,
            to: 2,
            verify_root: true,
            ..Default::default()
        };

        let result = replay(&blocks, &state, &opts, None)?;
        assert_eq!(result.total_blocks, 1);
        Ok(())
    }

    #[test]
    fn test_replay_determinism_check() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];

        let opts = ReplayOpts {
            from: 1,
            to: 1,
            verify_root: true,
            determinism_check: 5,
            ..Default::default()
        };

        let result = replay(&blocks, &state, &opts, None)?;
        assert!(result.success);
        assert!(result.entries[0].deterministic);
        Ok(())
    }

    #[test]
    fn test_compare_nodes_agree() {
        let mut roots_a = BTreeMap::new();
        let mut roots_b = BTreeMap::new();
        let root = Hash32([1u8; 32]);

        roots_a.insert(1, root.clone());
        roots_a.insert(2, root.clone());
        roots_b.insert(1, root.clone());
        roots_b.insert(2, root.clone());

        let result = compare_nodes("val1", &roots_a, "val2", &roots_b);
        assert!(result.agree);
        assert_eq!(result.common_heights, 2);
        assert!(result.mismatches.is_empty());
    }

    #[test]
    fn test_compare_nodes_divergence() {
        let mut roots_a = BTreeMap::new();
        let mut roots_b = BTreeMap::new();

        roots_a.insert(1, Hash32([1u8; 32]));
        roots_a.insert(2, Hash32([2u8; 32]));
        roots_b.insert(1, Hash32([1u8; 32]));
        roots_b.insert(2, Hash32([9u8; 32]));

        let result = compare_nodes("val1", &roots_a, "val2", &roots_b);
        assert!(!result.agree);
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].height, 2);
    }
}
