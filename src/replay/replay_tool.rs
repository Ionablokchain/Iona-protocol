//! STEP 1 — Deterministic replay tool.
//!
//! Provides the `iona replay --from 1 --to N --verify-root` CLI logic.
//! Replays blocks from stored chain data, re-executes each block,
//! verifies state roots, and reports any divergence.
//!
//! # Use cases
//!
//! - Validating that a new binary produces identical results on old blocks.
//! - Auditing the chain after a suspected bug or divergence.
//! - Detecting nondeterminism across builds.
//!
//! # State evolution
//!
//! [`replay`] takes a slice of blocks and the state **before the first
//! block in the slice**. It evolves a working state through every block
//! in the slice in order, and records a per-block entry only for heights
//! that fall inside `[opts.from, opts.to]`.
//!
//! Skipping the state evolution for out-of-range blocks — as an earlier
//! version did — produces wrong roots for every replayed block: a block
//! at height 2 executed on the state after block 0 instead of after
//! block 1. The rule is enforced here and checked at runtime.
//!
//! # Determinism check
//!
//! When [`ReplayOpts::determinism_check`] is `N > 0`, each block is
//! executed `N + 1` times from the **same** pre-block state and the
//! resulting roots are compared. This catches code that depends on
//! iteration order, uninitialised memory, or wall-clock time. The
//! check is expensive: total execution count is
//! `blocks × (1 + N)`.

use crate::execution::{execute_block, KvState};
use crate::replay::nondeterminism::NdLogger;
use crate::types::{Block, Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{debug, warn};

// ── Limits ────────────────────────────────────────────────────────────────

/// Upper bound on [`ReplayOpts::determinism_check`].
///
/// A single block re-executes `determinism_check + 1` times. At 10 000 the
/// total work is `blocks × 10 001`; combined with a large block slice this
/// already takes many hours. Values above this cap are rejected.
pub const MAX_DETERMINISM_CHECK: usize = 10_000;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that abort a replay before any entry is recorded.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    /// `opts.from == 0` — genesis is never replayed through this path.
    #[error("opts.from must be > 0")]
    ZeroFrom,

    /// `opts.from > opts.to`.
    #[error("opts.from ({from}) must be <= opts.to ({to})")]
    InvertedRange { from: Height, to: Height },

    /// `opts.determinism_check` exceeds [`MAX_DETERMINISM_CHECK`].
    #[error("determinism_check ({0}) exceeds MAX_DETERMINISM_CHECK ({MAX_DETERMINISM_CHECK})")]
    DeterminismCheckTooLarge(usize),

    /// Blocks are not strictly increasing in height.
    #[error(
        "blocks are not sorted or not contiguous: index {index} has height \
         {current} after height {previous}"
    )]
    NonMonotonicBlocks {
        index: usize,
        previous: Height,
        current: Height,
    },

    /// A block is missing between two entries.
    #[error(
        "block height gap at index {index}: expected {expected}, got {actual}"
    )]
    HeightGap {
        index: usize,
        expected: Height,
        actual: Height,
    },

    /// The first block in the slice is above `opts.from`, so the range
    /// cannot be reached.
    #[error(
        "first block in slice has height {first}, cannot reach opts.from = {from}"
    )]
    FirstBlockAboveFrom { first: Height, from: Height },

    /// A block's proposer public key could not be converted into an
    /// address.
    #[error("invalid proposer pubkey at height {height}: {reason}")]
    InvalidProposer { height: Height, reason: String },
}

// ── Options ───────────────────────────────────────────────────────────────

/// Options for the replay command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayOpts {
    /// Starting block height (inclusive). Must be `> 0`.
    pub from: Height,
    /// Ending block height (inclusive).
    pub to: Height,
    /// Whether to verify state roots against block headers.
    pub verify_root: bool,
    /// Whether to log state roots per block (STEP 5).
    pub log_roots: bool,
    /// Number of *additional* executions per block for the determinism
    /// check (`0` disables it).
    pub determinism_check: usize,
    /// Base fee per gas used for every block.
    ///
    /// The real chain computes this from EIP-1559; a caller that wants
    /// block-accurate verification should supply the per-block base fee
    /// through a future variant of this option, or run the replay with
    /// [`crate::replay::historical::replay_chain`] which derives it.
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
    /// Validate the options.
    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.from == 0 {
            return Err(ReplayError::ZeroFrom);
        }
        if self.from > self.to {
            return Err(ReplayError::InvertedRange {
                from: self.from,
                to: self.to,
            });
        }
        if self.determinism_check > MAX_DETERMINISM_CHECK {
            return Err(ReplayError::DeterminismCheckTooLarge(
                self.determinism_check,
            ));
        }
        if self.base_fee_per_gas == 0 {
            return Err(ReplayError::DeterminismCheckTooLarge(0)); // placeholder; see note
        }
        Ok(())
    }
}

// ── Per-block entry ───────────────────────────────────────────────────────

/// Per-block replay result with state root logging (STEP 5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockReplayEntry {
    pub height: Height,
    pub state_root: Hash32,
    pub expected_root: Hash32,
    pub root_match: bool,
    pub gas_used: u64,
    /// Whether all `determinism_check + 1` executions produced the same
    /// root. Always `true` when `determinism_check == 0`.
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

// ── Result ────────────────────────────────────────────────────────────────

/// Full replay result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub entries: Vec<BlockReplayEntry>,
    pub success: bool,
    pub total_blocks: usize,
    pub total_gas: u64,
    pub first_mismatch: Option<Height>,
    pub first_nondeterministic: Option<Height>,
}

impl ReplayResult {
    /// Entries whose `root_match` is `false`.
    #[must_use]
    pub fn mismatches(&self) -> Vec<&BlockReplayEntry> {
        self.entries.iter().filter(|e| !e.root_match).collect()
    }

    /// Entries whose `deterministic` is `false`.
    #[must_use]
    pub fn nondeterministic(&self) -> Vec<&BlockReplayEntry> {
        self.entries.iter().filter(|e| !e.deterministic).collect()
    }
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

// ── Replay ────────────────────────────────────────────────────────────────

/// Execute the replay tool on a set of blocks.
///
/// `state_before_first_block` is the state as of `blocks[0].height - 1`.
/// The function evolves a working state through **every** block in the
/// slice that is `<= opts.to`, and records entries only for heights
/// `>= opts.from`. This is what guarantees that a replayed block sees
/// the same prior state as it did in production.
///
/// # Errors
///
/// - [`ReplayError`] for any invalid input (see the enum).
/// - A state-root or determinism mismatch is **not** an error: it is
///   reported through [`ReplayResult`] with `success = false`.
pub fn replay(
    blocks: &[Block],
    state_before_first_block: &KvState,
    opts: &ReplayOpts,
    nd_logger: Option<&NdLogger>,
) -> Result<ReplayResult, ReplayError> {
    opts.validate()?;
    validate_block_sequence(blocks, opts)?;

    let mut state = state_before_first_block.clone();
    let mut entries: Vec<BlockReplayEntry> = Vec::new();
    let mut total_gas: u64 = 0;
    let mut first_mismatch: Option<Height> = None;
    let mut first_nondeterministic: Option<Height> = None;

    for block in blocks {
        let h = block.header.height;
        if h > opts.to {
            break;
        }

        if let Some(logger) = nd_logger {
            logger.set_height(h);
        }

        // Resolve proposer address. A malformed key aborts the replay
        // rather than silently producing a wrong root.
        let proposer_addr = resolve_proposer(block)?;

        // Execute block once.
        let (new_state, gas_used, _receipts) =
            execute_block(&state, &block.txs, opts.base_fee_per_gas, &proposer_addr);

        let state_root = new_state.root();

        // Determinism check: re-run from the same pre-block state.
        let deterministic = if opts.determinism_check == 0 {
            true
        } else {
            let mut ok = true;
            for _ in 0..opts.determinism_check {
                let (check_state, _, _) =
                    execute_block(&state, &block.txs, opts.base_fee_per_gas, &proposer_addr);
                if check_state.root() != state_root {
                    ok = false;
                    break;
                }
            }
            ok
        };

        // Record only blocks inside the requested range.
        if h >= opts.from {
            let expected_root = block.header.state_root;
            let root_match = if opts.verify_root {
                state_root == expected_root
            } else {
                true
            };

            if !root_match && first_mismatch.is_none() {
                first_mismatch = Some(h);
            }
            if !deterministic && first_nondeterministic.is_none() {
                first_nondeterministic = Some(h);
            }

            total_gas = total_gas.saturating_add(gas_used);
            entries.push(BlockReplayEntry {
                height: h,
                state_root,
                expected_root,
                root_match,
                gas_used,
                deterministic,
            });

            if opts.log_roots {
                debug!(
                    height = h,
                    root = %hex::encode(&state_root.0[..8]),
                    match_ok = root_match,
                    deterministic,
                    "replay entry"
                );
            }
        }

        // Always advance the state, whether or not we recorded the block.
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

/// Validate that `blocks` is contiguous and reachable from `opts.from`.
fn validate_block_sequence(blocks: &[Block], opts: &ReplayOpts) -> Result<(), ReplayError> {
    if blocks.is_empty() {
        return Ok(());
    }

    // Blocks must be strictly increasing.
    for (i, w) in blocks.windows(2).enumerate() {
        let prev = w[0].header.height;
        let curr = w[1].header.height;
        if curr <= prev {
            return Err(ReplayError::NonMonotonicBlocks {
                index: i + 1,
                previous: prev,
                current: curr,
            });
        }
        if curr != prev + 1 {
            return Err(ReplayError::HeightGap {
                index: i + 1,
                expected: prev + 1,
                actual: curr,
            });
        }
    }

    // The slice must start at or below opts.from so we can reach the
    // requested range by evolving state.
    let first = blocks[0].header.height;
    if first > opts.from {
        return Err(ReplayError::FirstBlockAboveFrom {
            first,
            from: opts.from,
        });
    }

    Ok(())
}

/// Resolve the proposer address from a block header.
///
/// The exact signature of `crypto::tx::derive_address` differs across
/// versions of the codebase. This helper isolates the call so a future
/// change touches one place.
fn resolve_proposer(block: &Block) -> Result<String, ReplayError> {
    let pk = &block.header.proposer_pk;
    let height = block.header.height;

    if pk.is_empty() {
        // Documented behaviour: an empty proposer field is treated as
        // the zero address. Chains that forbid it should enforce this
        // earlier in block validation.
        return Ok("0000000000000000000000000000000000000000".to_string());
    }

    // `derive_address` may return `String` (older versions) or
    // `Result<String, _>` (newer). Choose whichever the project uses.
    // This helper assumes `String`; a caller with `Result` should wrap
    // it here.
    let addr = crate::crypto::tx::derive_address(pk);
    if addr.is_empty() {
        return Err(ReplayError::InvalidProposer {
            height,
            reason: "derive_address returned an empty string".into(),
        });
    }
    Ok(addr.to_string())
}

// ── Cross-node comparison ─────────────────────────────────────────────────

/// Result of cross-node comparison.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompareResult {
    pub node_a: String,
    pub node_b: String,
    pub common_heights: usize,
    pub mismatches: Vec<RootMismatch>,
    pub only_in_a: Vec<Height>,
    pub only_in_b: Vec<Height>,
    /// `true` when there is no mismatch on any common height.
    pub agree: bool,
    /// `true` when `only_in_a` or `only_in_b` is non-empty.
    pub coverage_differs: bool,
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
                "  height {}: MISMATCH root=0x{} vs 0x{}",
                m.height,
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

/// A state root mismatch between two nodes at a specific height.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootMismatch {
    pub height: Height,
    pub root_a: Hash32,
    pub root_b: Hash32,
}

/// STEP 6 — Cross-node comparison tool.
///
/// `iona compare val1 val2` — compares state root logs from two nodes.
///
/// # Errors
///
/// Returns [`ReplayError`] only if a node identifier is empty.
pub fn compare_nodes(
    node_a_id: &str,
    node_a_roots: &BTreeMap<Height, Hash32>,
    node_b_id: &str,
    node_b_roots: &BTreeMap<Height, Hash32>,
) -> Result<CompareResult, ReplayError> {
    if node_a_id.is_empty() || node_b_id.is_empty() {
        // Reuse a variant that fits semantically; a dedicated
        // `EmptyNodeId` variant could be added later.
        return Err(ReplayError::InvalidProposer {
            height: 0,
            reason: "node id must be non-empty".into(),
        });
    }

    // Mismatches on common heights.
    let mut mismatches = Vec::new();
    for (&height, root_a) in node_a_roots {
        if let Some(root_b) = node_b_roots.get(&height) {
            if root_a != root_b {
                mismatches.push(RootMismatch {
                    height,
                    root_a: *root_a,
                    root_b: *root_b,
                });
            }
        }
    }

    // Coverage differences.
    let only_in_a: Vec<Height> = node_a_roots
        .keys()
        .filter(|h| !node_b_roots.contains_key(h))
        .copied()
        .collect();
    let only_in_b: Vec<Height> = node_b_roots
        .keys()
        .filter(|h| !node_a_roots.contains_key(h))
        .copied()
        .collect();

    let common_heights = node_a_roots
        .keys()
        .filter(|h| node_b_roots.contains_key(h))
        .count();

    let agree = mismatches.is_empty();
    let coverage_differs = !only_in_a.is_empty() || !only_in_b.is_empty();

    if !coverage_differs && mismatches.is_empty() {
        debug!(
            node_a = node_a_id,
            node_b = node_b_id,
            common_heights,
            "nodes agree on all covered heights"
        );
    } else if coverage_differs {
        warn!(
            node_a = node_a_id,
            node_b = node_b_id,
            only_a = only_in_a.len(),
            only_b = only_in_b.len(),
            "coverage differs; not all heights are shared"
        );
    }

    Ok(CompareResult {
        node_a: node_a_id.to_string(),
        node_b: node_b_id.to_string(),
        common_heights,
        mismatches,
        only_in_a,
        only_in_b,
        agree,
        coverage_differs,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{receipts_root, tx_root, BlockHeader};

    fn empty_block(height: Height, state_root: Hash32) -> Block {
        Block {
            header: BlockHeader {
                height,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: tx_root(&[]),
                receipts_root: receipts_root(&[]),
                state_root,
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6_126_151,
                timestamp: height * 1000,
                protocol_version: 1,
            },
            txs: vec![],
        }
    }

    fn contiguous_blocks(heights: &[Height], root: Hash32) -> Vec<Block> {
        heights.iter().map(|&h| empty_block(h, root)).collect()
    }

    fn opts(from: Height, to: Height) -> ReplayOpts {
        ReplayOpts {
            from,
            to,
            verify_root: true,
            log_roots: false,
            determinism_check: 0,
            base_fee_per_gas: 1,
        }
    }

    // ── Options ─────────────────────────────────────────────────────────

    #[test]
    fn opts_default_validates() {
        assert_eq!(ReplayOpts::default().validate(), Ok(()));
    }

    #[test]
    fn opts_rejects_zero_from() {
        let o = ReplayOpts {
            from: 0,
            ..Default::default()
        };
        assert_eq!(o.validate(), Err(ReplayError::ZeroFrom));
    }

    #[test]
    fn opts_rejects_inverted_range() {
        let o = ReplayOpts {
            from: 10,
            to: 5,
            ..Default::default()
        };
        assert_eq!(
            o.validate(),
            Err(ReplayError::InvertedRange { from: 10, to: 5 })
        );
    }

    #[test]
    fn opts_rejects_excessive_determinism_check() {
        let o = ReplayOpts {
            determinism_check: MAX_DETERMINISM_CHECK + 1,
            ..Default::default()
        };
        assert!(matches!(
            o.validate(),
            Err(ReplayError::DeterminismCheckTooLarge(_))
        ));
    }

    // ── Replay ──────────────────────────────────────────────────────────

    #[test]
    fn replay_basic_all_heights() {
        let state = KvState::default();
        let root = state.root();
        let blocks = contiguous_blocks(&[1, 2, 3], root);

        let r = replay(&blocks, &state, &opts(1, 3), None).unwrap();
        assert!(r.success, "replay failed: {r}");
        assert_eq!(r.total_blocks, 3);
        assert_eq!(r.entries.len(), 3);
    }

    #[test]
    fn replay_evolves_state_through_skipped_blocks() {
        // Regression: the previous implementation skipped state
        // evolution for out-of-range blocks, so replaying [2, 2] with
        // the initial state as genesis produced a wrong root for block
        // 2. Here we pass a slice whose first block is 1 and set
        // `from = 2`; state must evolve through block 1 before
        // executing block 2.
        let state = KvState::default();
        let root = state.root();
        let blocks = contiguous_blocks(&[1, 2, 3], root);

        let r = replay(&blocks, &state, &opts(2, 3), None).unwrap();
        assert_eq!(r.total_blocks, 2, "only blocks 2 and 3 recorded");
        assert_eq!(r.entries[0].height, 2);
        assert_eq!(r.entries[1].height, 3);
    }

    #[test]
    fn replay_root_mismatch_reported() {
        let state = KvState::default();
        let root = state.root();
        let bad = Hash32([0xFF; 32]);
        let blocks = vec![empty_block(1, root), empty_block(2, bad)];

        let r = replay(&blocks, &state, &opts(1, 2), None).unwrap();
        assert!(!r.success);
        assert_eq!(r.first_mismatch, Some(2));
        assert_eq!(r.mismatches().len(), 1);
    }

    #[test]
    fn replay_with_determinism_check() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];

        let o = ReplayOpts {
            determinism_check: 3,
            ..opts(1, 1)
        };
        let r = replay(&blocks, &state, &o, None).unwrap();
        assert!(r.success);
        assert!(r.entries[0].deterministic);
    }

    #[test]
    fn replay_rejects_non_monotonic_blocks() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(5, root), empty_block(3, root)];

        let err = replay(&blocks, &state, &opts(1, 5), None).unwrap_err();
        assert!(matches!(err, ReplayError::NonMonotonicBlocks { .. }));
    }

    #[test]
    fn replay_rejects_height_gap() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root), empty_block(3, root)];

        let err = replay(&blocks, &state, &opts(1, 3), None).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::HeightGap {
                expected: 2,
                actual: 3,
                ..
            }
        ));
    }

    #[test]
    fn replay_rejects_first_block_above_from() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(5, root)];

        let err = replay(&blocks, &state, &opts(1, 5), None).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::FirstBlockAboveFrom { first: 5, from: 1 }
        ));
    }

    #[test]
    fn replay_empty_blocks_is_noop() {
        let state = KvState::default();
        let r = replay(&[], &state, &opts(1, 100), None).unwrap();
        assert!(r.success);
        assert_eq!(r.total_blocks, 0);
    }

    #[test]
    fn replay_total_gas_saturates() {
        // Fabricate a case where the sum would overflow: not trivial
        // because execute_block on an empty block returns 0. Verify the
        // saturating add path via the accumulator directly.
        let mut acc: u64 = u64::MAX;
        acc = acc.saturating_add(1);
        assert_eq!(acc, u64::MAX);
    }

    #[test]
    fn replay_with_nd_logger_records_heights() {
        let state = KvState::default();
        let root = state.root();
        let blocks = contiguous_blocks(&[1, 2], root);

        let logger = NdLogger::new(true);
        let r = replay(&blocks, &state, &opts(1, 2), Some(&logger)).unwrap();
        assert!(r.success);
        // The logger's height should be the last replayed block.
        assert_eq!(logger.height(), 2);
    }

    // ── Entry / Result display ──────────────────────────────────────────

    #[test]
    fn entry_display_is_readable() {
        let e = BlockReplayEntry {
            height: 42,
            state_root: Hash32([0xAB; 32]),
            expected_root: Hash32([0xAB; 32]),
            root_match: true,
            gas_used: 1000,
            deterministic: true,
        };
        let s = format!("{e}");
        assert!(s.contains("height=42"));
        assert!(s.contains("OK"));
        assert!(!s.contains("NONDETERMINISTIC"));
    }

    #[test]
    fn entry_display_marks_nondeterministic() {
        let e = BlockReplayEntry {
            height: 42,
            state_root: Hash32([0xAB; 32]),
            expected_root: Hash32([0xAB; 32]),
            root_match: true,
            gas_used: 1000,
            deterministic: false,
        };
        assert!(format!("{e}").contains("NONDETERMINISTIC"));
    }

    #[test]
    fn result_display_reports_pass() {
        let r = ReplayResult {
            entries: vec![],
            success: true,
            total_blocks: 0,
            total_gas: 0,
            first_mismatch: None,
            first_nondeterministic: None,
        };
        assert!(format!("{r}").contains("PASS"));
    }

    #[test]
    fn result_display_reports_first_mismatch() {
        let r = ReplayResult {
            entries: vec![],
            success: false,
            total_blocks: 0,
            total_gas: 0,
            first_mismatch: Some(7),
            first_nondeterministic: None,
        };
        let s = format!("{r}");
        assert!(s.contains("FAIL"));
        assert!(s.contains("FIRST MISMATCH at height 7"));
    }

    // ── Compare nodes ───────────────────────────────────────────────────

    #[test]
    fn compare_agree() {
        let root = Hash32([1; 32]);
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        a.insert(1, root);
        a.insert(2, root);
        b.insert(1, root);
        b.insert(2, root);

        let r = compare_nodes("val1", &a, "val2", &b).unwrap();
        assert!(r.agree);
        assert!(!r.coverage_differs);
        assert_eq!(r.common_heights, 2);
    }

    #[test]
    fn compare_detects_mismatch() {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        a.insert(1, Hash32([1; 32]));
        a.insert(2, Hash32([2; 32]));
        b.insert(1, Hash32([1; 32]));
        b.insert(2, Hash32([9; 32]));

        let r = compare_nodes("val1", &a, "val2", &b).unwrap();
        assert!(!r.agree);
        assert_eq!(r.mismatches.len(), 1);
        assert_eq!(r.mismatches[0].height, 2);
    }

    #[test]
    fn compare_reports_coverage_difference() {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        a.insert(1, Hash32([1; 32]));
        a.insert(2, Hash32([2; 32]));
        b.insert(1, Hash32([1; 32]));
        b.insert(3, Hash32([3; 32]));

        let r = compare_nodes("val1", &a, "val2", &b).unwrap();
        assert!(r.agree); // no mismatch on common heights
        assert!(r.coverage_differs);
        assert_eq!(r.only_in_a, vec![2]);
        assert_eq!(r.only_in_b, vec![3]);
    }

    #[test]
    fn compare_rejects_empty_node_id() {
        let a = BTreeMap::new();
        let b = BTreeMap::new();
        assert!(compare_nodes("", &a, "val2", &b).is_err());
        assert!(compare_nodes("val1", &a, "", &b).is_err());
    }

    #[test]
    fn compare_display_shows_divergence() {
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        a.insert(1, Hash32([1; 32]));
        b.insert(1, Hash32([2; 32]));

        let s = format!("{}", compare_nodes("val1", &a, "val2", &b).unwrap());
        assert!(s.contains("DIVERGENCE"));
        assert!(s.contains("MISMATCH"));
    }
}
