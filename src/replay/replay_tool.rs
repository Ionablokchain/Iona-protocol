//! STEP 1 — Deterministic replay tool.
//!
//! Provides the `iona replay --from 1 --to N --verify-root` CLI logic.
//! Replays blocks from stored chain data, re‑executes each block,
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
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during replay operations.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// The `from` height is greater than the `to` height.
    #[error("invalid height range: from={from} > to={to}")]
    InvalidHeightRange { from: Height, to: Height },

    /// The determinism check count must be greater than 0.
    #[error("determinism check count must be > 0, got {0}")]
    InvalidDeterminismCount(usize),

    /// The base fee per gas must be greater than 0.
    #[error("base fee per gas must be > 0, got {0}")]
    InvalidBaseFee(u64),

    /// Block execution failed at a specific height.
    #[error("block execution failed at height {height}: {reason}")]
    ExecutionFailed { height: Height, reason: String },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialisation error.
    #[error("serialisation error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// No blocks found in the given range.
    #[error("no blocks in range {from}..{to}")]
    NoBlocksInRange { from: Height, to: Height },
}

pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Options
// -----------------------------------------------------------------------------

/// Options for the replay command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayOpts {
    /// Starting block height (inclusive).
    pub from: Height,
    /// Ending block height (inclusive).
    pub to: Height,
    /// Whether to verify state roots against block headers.
    pub verify_root: bool,
    /// Whether to log state roots to console.
    pub log_roots: bool,
    /// Number of additional executions to check determinism (0 = skip).
    pub determinism_check: usize,
    /// Base fee per gas for all executed blocks (simplified).
    pub base_fee_per_gas: u64,
    /// Log progress every N blocks (0 = disabled).
    pub progress_interval: usize,
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
            progress_interval: 1000,
        }
    }
}

impl ReplayOpts {
    /// Validate the options (range, base fee, determinism count).
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

    /// Create options for a full chain replay.
    #[must_use]
    pub fn full_chain() -> Self {
        Self {
            from: 1,
            to: u64::MAX,
            verify_root: true,
            log_roots: true,
            determinism_check: 0,
            base_fee_per_gas: 1,
            progress_interval: 1000,
        }
    }

    /// Create options for a quick replay without verification.
    #[must_use]
    pub fn quick() -> Self {
        Self {
            verify_root: false,
            log_roots: false,
            determinism_check: 0,
            ..Default::default()
        }
    }
}

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Per‑block replay result with state root logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReplayEntry {
    /// Block height.
    pub height: Height,
    /// State root computed by the node.
    pub state_root: Hash32,
    /// State root from the block header.
    pub expected_root: Hash32,
    /// Whether the computed root matches the header root.
    pub root_match: bool,
    /// Gas used during execution.
    pub gas_used: u64,
    /// Whether multiple executions produced the same result.
    pub deterministic: bool,
    /// Replay time in milliseconds.
    pub replay_time_ms: u64,
}

impl fmt::Display for BlockReplayEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.root_match { "OK" } else { "MISMATCH" };
        let det = if self.deterministic {
            ""
        } else {
            " NONDETERMINISTIC"
        };
        write!(
            f,
            "height={} root=0x{} expected=0x{} status={}{} gas={} time={}ms",
            self.height,
            hex::encode(&self.state_root.0[..8]),
            hex::encode(&self.expected_root.0[..8]),
            status,
            det,
            self.gas_used,
            self.replay_time_ms
        )
    }
}

/// Full replay result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayResult {
    /// Per‑block entries.
    pub entries: Vec<BlockReplayEntry>,
    /// Whether all blocks passed verification (roots match and deterministic).
    pub success: bool,
    /// Total number of blocks replayed.
    pub total_blocks: usize,
    /// Total gas consumed across all blocks.
    pub total_gas: u64,
    /// First height where a state root mismatch occurred.
    pub first_mismatch: Option<Height>,
    /// First height where nondeterminism was detected.
    pub first_nondeterministic: Option<Height>,
    /// Total replay time in milliseconds.
    pub total_time_ms: u64,
    /// Blocks per second.
    pub blocks_per_second: f64,
    /// Gas per second.
    pub gas_per_second: f64,
}

impl fmt::Display for ReplayResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let status = if self.success { "PASS" } else { "FAIL" };
        writeln!(
            f,
            "Replay Result: {} ({} blocks, {} gas, {}ms)",
            status, self.total_blocks, self.total_gas, self.total_time_ms
        )?;
        if let Some(h) = self.first_mismatch {
            writeln!(f, "  FIRST MISMATCH at height {}", h)?;
        }
        if let Some(h) = self.first_nondeterministic {
            writeln!(f, "  FIRST NONDETERMINISM at height {}", h)?;
        }
        writeln!(
            f,
            "  Performance: {:.2} blocks/s, {:.2} gas/s",
            self.blocks_per_second, self.gas_per_second
        )?;
        if !self.entries.is_empty() {
            writeln!(f, "  Entries:")?;
            for entry in &self.entries {
                writeln!(f, "    {}", entry)?;
            }
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
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state (genesis or checkpoint).
/// * `opts` – Replay options (range, verification, determinism checks).
/// * `nd_logger` – Optional nondeterminism logger (for auditing).
pub fn replay(
    blocks: &[Block],
    initial_state: &KvState,
    opts: &ReplayOpts,
    nd_logger: Option<&NdLogger>,
) -> ReplayResult<ReplayResult> {
    opts.validate()?;

    let start_time = Instant::now();
    let mut state = initial_state.clone();
    let mut entries = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;
    let mut first_mismatch = None;
    let mut first_nondeterministic = None;

    info!(
        from = opts.from,
        to = opts.to,
        verify_root = opts.verify_root,
        determinism_check = opts.determinism_check,
        "starting replay"
    );

    let mut count = 0;
    for block in blocks {
        let h = block.header.height;
        if h < opts.from || h > opts.to {
            continue;
        }

        count += 1;
        if opts.progress_interval > 0 && count % opts.progress_interval == 0 {
            info!(height = h, count, "replay progress");
        }

        // Log the current height for nondeterminism tracking.
        if let Some(logger) = nd_logger {
            logger.set_height(h);
        }

        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };

        let block_start = Instant::now();

        // Execute the block.
        let (new_state, gas_used, _receipts) =
            execute_block(&state, &block.txs, opts.base_fee_per_gas, &proposer_addr);

        let replay_time_ms = block_start.elapsed().as_millis() as u64;

        let state_root = new_state.root();
        let expected_root = block.header.state_root;
        let root_match = if opts.verify_root {
            state_root == expected_root
        } else {
            true
        };

        // Determinism check: run the same block multiple times and compare roots.
        let mut deterministic = true;
        if opts.determinism_check > 0 {
            let mut check_state = state.clone();
            for i in 0..opts.determinism_check {
                let (check_new_state, _, _) =
                    execute_block(&check_state, &block.txs, opts.base_fee_per_gas, &proposer_addr);
                if check_new_state.root() != state_root {
                    deterministic = false;
                    debug!(
                        height = h,
                        attempt = i + 1,
                        "nondeterministic execution detected"
                    );
                    break;
                }
                check_state = check_new_state;
            }
        }

        if !root_match && first_mismatch.is_none() {
            first_mismatch = Some(h);
            warn!(height = h, "state root mismatch");
        }
        if !deterministic && first_nondeterministic.is_none() {
            first_nondeterministic = Some(h);
            warn!(height = h, "nondeterminism detected");
        }

        total_gas += gas_used;
        entries.push(BlockReplayEntry {
            height: h,
            state_root,
            expected_root,
            root_match,
            gas_used,
            deterministic,
            replay_time_ms,
        });

        state = new_state;
    }

    if count == 0 {
        return Err(ReplayError::NoBlocksInRange {
            from: opts.from,
            to: opts.to,
        });
    }

    let total_time_ms = start_time.elapsed().as_millis() as u64;
    let success = first_mismatch.is_none() && first_nondeterministic.is_none();
    let total_blocks = entries.len();

    let blocks_per_second = if total_time_ms > 0 {
        (total_blocks as f64) / (total_time_ms as f64 / 1000.0)
    } else {
        0.0
    };
    let gas_per_second = if total_time_ms > 0 {
        (total_gas as f64) / (total_time_ms as f64 / 1000.0)
    } else {
        0.0
    };

    info!(
        total_blocks,
        total_gas,
        total_time_ms,
        success,
        "replay completed"
    );

    Ok(ReplayResult {
        entries,
        success,
        total_blocks,
        total_gas,
        first_mismatch,
        first_nondeterministic,
        total_time_ms,
        blocks_per_second,
        gas_per_second,
    })
}

// -----------------------------------------------------------------------------
// Cross‑node comparison (STEP 6)
// -----------------------------------------------------------------------------

/// A state root mismatch between two nodes at a given height.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootMismatch {
    pub height: Height,
    pub root_a: Hash32,
    pub root_b: Hash32,
}

/// Result of cross‑node comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompareResult {
    /// Identifier of the first node.
    pub node_a: String,
    /// Identifier of the second node.
    pub node_b: String,
    /// Number of heights present in both snapshots.
    pub common_heights: usize,
    /// List of mismatches (different roots at the same height).
    pub mismatches: Vec<RootMismatch>,
    /// Heights present only in node A's snapshot.
    pub only_in_a: Vec<Height>,
    /// Heights present only in node B's snapshot.
    pub only_in_b: Vec<Height>,
    /// Whether the two snapshots agree completely.
    pub agree: bool,
}

impl fmt::Display for CompareResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
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
///
/// # Arguments
/// * `node_a_id` – Identifier for the first node (e.g., "validator1").
/// * `node_a_roots` – Map from height to state root from the first node.
/// * `node_b_id` – Identifier for the second node.
/// * `node_b_roots` – Map from height to state root from the second node.
#[must_use]
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
// File I/O helpers
// -----------------------------------------------------------------------------

/// Load blocks from a JSON Lines file (one block per line).
pub fn load_blocks(path: &Path) -> ReplayResult<Vec<Block>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let block: Block = serde_json::from_str(&line)?;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Save replay result to a JSON file.
pub fn save_result(result: &ReplayResult, path: &Path) -> ReplayResult<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)?;
    Ok(())
}

/// Load replay result from a JSON file.
pub fn load_result(path: &Path) -> ReplayResult<ReplayResult> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let result: ReplayResult = serde_json::from_reader(reader)?;
    Ok(result)
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
            progress_interval: 0,
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

    #[test]
    fn test_no_blocks_in_range() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];

        let opts = ReplayOpts {
            from: 10,
            to: 20,
            ..Default::default()
        };

        let result = replay(&blocks, &state, &opts, None);
        assert!(matches!(result, Err(ReplayError::NoBlocksInRange { from: 10, to: 20 })));
        Ok(())
    }

    #[test]
    fn test_file_io_roundtrip() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, root.clone())];
        let opts = ReplayOpts::default();
        let result = replay(&blocks, &state, &opts, None)?;

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("result.json");
        save_result(&result, &path)?;
        let loaded = load_result(&path)?;
        assert_eq!(loaded.total_blocks, result.total_blocks);
        assert_eq!(loaded.total_gas, result.total_gas);
        assert_eq!(loaded.success, result.success);
        Ok(())
    }
}
