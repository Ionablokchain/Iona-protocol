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

use crate::execution::{execute_block, KvState};
use crate::replay::nondeterminism::NdLogger;
use crate::types::{Block, Hash32, Height};
use std::collections::BTreeMap;

/// Options for the replay command.
#[derive(Debug, Clone)]
pub struct ReplayOpts {
    /// Starting block height (inclusive).
    pub from: Height,
    /// Ending block height (inclusive).
    pub to: Height,
    /// Whether to verify state roots against block headers.
    pub verify_root: bool,
    /// Whether to log state roots per block (STEP 5).
    pub log_roots: bool,
    /// Whether to detect nondeterminism (run each block N times).
    pub determinism_check: usize,
    /// Base fee per gas (simplified; in production would be computed per-block).
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

/// Per-block replay result with state root logging (STEP 5).
#[derive(Debug, Clone)]
pub struct BlockReplayEntry {
    pub height: Height,
    pub state_root: Hash32,
    pub expected_root: Hash32,
    pub root_match: bool,
    pub gas_used: u64,
    /// If determinism_check > 0, whether all N runs produced identical roots.
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

/// Execute the replay tool on a set of blocks.
///
/// This is the core of `iona replay --from <from> --to <to> --verify-root`.
pub fn replay(
    blocks: &[Block],
    initial_state: &KvState,
    opts: &ReplayOpts,
    nd_logger: Option<&NdLogger>,
) -> ReplayResult {
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
        let expected_root = block.header.state_root.clone();
        let root_match = if opts.verify_root {
            state_root == expected_root
        } else {
            true // Skip verification.
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
            state_root: state_root.clone(),
            expected_root,
            root_match,
            gas_used,
            deterministic,
        });

        state = new_state;
    }

    let success = first_mismatch.is_none() && first_nondeterministic.is_none();
    let total_blocks = entries.len();
    ReplayResult {
        entries,
        success,
        total_blocks,
        total_gas,
        first_mismatch,
        first_nondeterministic,
    }
}

/// STEP 6 — Cross-node comparison tool.
///
/// `iona compare val1 val2` — compares state root logs from two nodes.
/// Takes two sets of (height, state_root) pairs and finds divergence.
pub fn compare_nodes(
    node_a_id: &str,
    node_a_roots: &BTreeMap<Height, Hash32>,
    node_b_id: &str,
    node_b_roots: &BTreeMap<Height, Hash32>,
) -> CompareResult {
    let mut mismatches = Vec::new();

    // Check all heights present in both.
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

    // Heights only in A.
    let only_a: Vec<Height> = node_a_roots
        .keys()
        .filter(|h| !node_b_roots.contains_key(h))
        .copied()
        .collect();

    // Heights only in B.
    let only_b: Vec<Height> = node_b_roots
        .keys()
        .filter(|h| !node_a_roots.contains_key(h))
        .copied()
        .collect();

    let agree = mismatches.is_empty();
    let common_heights = node_a_roots
        .keys()
        .filter(|h| node_b_roots.contains_key(h))
        .count();

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

/// A state root mismatch between two nodes at a specific height.
#[derive(Debug, Clone)]
pub struct RootMismatch {
    pub height: Height,
    pub root_a: Hash32,
    pub root_b: Hash32,
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

// ─── Tests ──────────────────────────────────────────────────────────────────

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
    fn test_replay_basic() {
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

        let result = replay(&blocks, &state, &opts, None);
        assert!(result.success, "replay failed: {result}");
        assert_eq!(result.total_blocks, 3);
    }

    #[test]
    fn test_replay_root_mismatch() {
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

        let result = replay(&blocks, &state, &opts, None);
        assert!(!result.success);
        assert_eq!(result.first_mismatch, Some(2));
    }

    #[test]
    fn test_replay_with_range_filter() {
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

        let result = replay(&blocks, &state, &opts, None);
        // Only block 2 replayed (but state starts from genesis, so block 1 is skipped
        // and block 2 runs on initial state).
        assert_eq!(result.total_blocks, 1);
    }

    #[test]
    fn test_replay_determinism_check() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];

        let opts = ReplayOpts {
            from: 1,
            to: 1,
            verify_root: true,
            determinism_check: 5, // Run 5 extra times.
            ..Default::default()
        };

        let result = replay(&blocks, &state, &opts, None);
        assert!(result.success);
        assert!(result.entries[0].deterministic);
    }

    #[test]
    fn test_replay_with_nd_logger() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];
        let logger = NdLogger::new(true);

        let opts = ReplayOpts::default();
        let result = replay(&blocks, &state, &opts, Some(&logger));
        assert!(result.success);
    }

    #[test]
    fn test_replay_entry_display() {
        let entry = BlockReplayEntry {
            height: 42,
            state_root: Hash32([0xAB; 32]),
            expected_root: Hash32([0xAB; 32]),
            root_match: true,
            gas_used: 1000,
            deterministic: true,
        };
        let s = format!("{entry}");
        assert!(s.contains("height=42"));
        assert!(s.contains("OK"));
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
        roots_b.insert(2, Hash32([9u8; 32])); // Different!

        let result = compare_nodes("val1", &roots_a, "val2", &roots_b);
        assert!(!result.agree);
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].height, 2);
    }

    #[test]
    fn test_compare_nodes_missing_heights() {
        let mut roots_a = BTreeMap::new();
        let mut roots_b = BTreeMap::new();

        roots_a.insert(1, Hash32([1u8; 32]));
        roots_a.insert(2, Hash32([2u8; 32]));
        roots_b.insert(1, Hash32([1u8; 32]));
        // Height 2 missing from B, height 3 only in B.
        roots_b.insert(3, Hash32([3u8; 32]));

        let result = compare_nodes("val1", &roots_a, "val2", &roots_b);
        assert!(result.agree); // No mismatches on common heights.
        assert_eq!(result.only_in_a, vec![2]);
        assert_eq!(result.only_in_b, vec![3]);
    }

    #[test]
    fn test_compare_result_display() {
        let mut roots_a = BTreeMap::new();
        let mut roots_b = BTreeMap::new();
        roots_a.insert(1, Hash32([1u8; 32]));
        roots_b.insert(1, Hash32([2u8; 32]));

        let result = compare_nodes("val1", &roots_a, "val2", &roots_b);
        let s = format!("{result}");
        assert!(s.contains("DIVERGENCE"));
        assert!(s.contains("MISMATCH"));
    }

    #[test]
    fn test_replay_result_display() {
        let result = ReplayResult {
            entries: vec![],
            success: true,
            total_blocks: 0,
            total_gas: 0,
            first_mismatch: None,
            first_nondeterministic: None,
        };
        let s = format!("{result}");
        assert!(s.contains("PASS"));
    }
}
