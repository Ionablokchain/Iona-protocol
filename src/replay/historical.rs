//! Replaying historical blocks.
//!
//! Re-executes a chain of blocks from a known starting state, verifying
//! that each state transition produces the expected state root and other
//! block-header fields.
//!
//! # Use cases
//!
//! - Validating that a new binary produces identical results on old blocks.
//! - Auditing the chain after a suspected bug or divergence.
//! - Regression testing after code changes.
//!
//! # Contract
//!
//! [`replay_chain`] performs the following checks, in order, for each block:
//!
//! 1. The block's height is strictly greater than the previous block's (or,
//!    on the first block, `> 0`).
//! 2. The block's `base_fee_per_gas` equals the value the EIP-1559 formula
//!    produces from the previous block's gas usage (or `initial_base_fee`
//!    for the first block).
//! 3. When [`ReplayConfig::verify_roots`] is `true`: `state_root`,
//!    `tx_root`, and `receipts_root` match the recomputed values.
//! 4. When [`ReplayConfig::verify_gas_used`] is `true`: `gas_used`
//!    matches the execution total.
//!
//! Any failure aborts the replay and returns
//! `Err(`[`ReplayError`]`)` describing **which** invariant broke, at
//! **which** height.
//!
//! # Base fee continuity
//!
//! [`resume_replay`] requires the caller to supply the base fee that was
//! in effect *before* the first replayed block. Deriving it from
//! `config.initial_base_fee` — as the previous implementation did — is
//! incorrect for any checkpoint past the first block and produces
//! spurious root mismatches.
//!
//! # Configuration
//!
//! [`ReplayConfig::validate`] rejects a `gas_target` of `0`, an
//! `initial_base_fee` of `0`, and any `progress_interval` that would
//! divide by zero. Callers that construct the config by hand should call
//! `validate` before passing it in.
//!
//! # Determinism
//!
//! The replay is single-threaded and side-effect-free: it reads the input
//! blocks, produces a new [`KvState`], and returns a structured report.
//! Nothing in this module touches IONAFS or the network.

use crate::execution::{execute_block, next_base_fee, KvState};
use crate::types::{receipts_root, tx_root, Block, Hash32, Height, Receipt};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors that can abort a replay.
///
/// Each variant carries the height at which the failure occurred so a
/// caller can map it back to a block.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReplayError {
    /// The first block in the input has `height == 0`.
    #[error("first block has height 0; heights must be > 0")]
    ZeroHeight,

    /// Blocks are not sorted by strictly increasing height.
    #[error(
        "blocks out of order at index {index}: previous height {previous}, \
         current height {current}"
    )]
    NonMonotonicHeight {
        index: usize,
        previous: Height,
        current: Height,
    },

    /// `base_fee_per_gas` in the header does not match the EIP-1559 value.
    #[error(
        "base fee mismatch at height {height}: header {header}, computed {computed}"
    )]
    BaseFeeMismatch {
        height: Height,
        header: u64,
        computed: u64,
    },

    /// State root does not match after execution.
    #[error(
        "state root mismatch at height {height}: expected {expected}, got {actual}"
    )]
    StateRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },

    /// Transaction root does not match.
    #[error("tx_root mismatch at height {height}")]
    TxRootMismatch { height: Height },

    /// Receipts root does not match.
    #[error("receipts_root mismatch at height {height}")]
    ReceiptsRootMismatch { height: Height },

    /// Gas used does not match after execution.
    #[error(
        "gas_used mismatch at height {height}: header {header}, execution {executed}"
    )]
    GasUsedMismatch {
        height: Height,
        header: u64,
        executed: u64,
    },

    /// The external expected root for `height` differs from the replayed one.
    #[error(
        "external root mismatch at height {height}: expected {expected}, got {actual}"
    )]
    ExternalRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },

    /// The requested `start_height` is not present in the block list.
    #[error("start height {0} not found in the block list")]
    StartHeightMissing(Height),

    /// The configuration is invalid.
    #[error("invalid ReplayConfig: {0}")]
    InvalidConfig(&'static str),

    /// The block's proposer public key is malformed.
    #[error("invalid proposer public key at height {height}: {reason}")]
    InvalidProposer { height: Height, reason: String },
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration options for the replay engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplayConfig {
    /// Base fee for the first replayed block. Must be `> 0`.
    pub initial_base_fee: u64,
    /// Target gas per block for EIP-1559 adjustment. Must be `> 0`.
    pub gas_target: u64,
    /// Maximum number of blocks to replay (`0` = all).
    pub max_blocks: usize,
    /// If `true`, verify `tx_root` and `receipts_root`.
    pub verify_roots: bool,
    /// If `true`, verify `gas_used` against the header.
    pub verify_gas_used: bool,
    /// If `true`, verify `base_fee_per_gas` against the EIP-1559 formula.
    pub verify_base_fee: bool,
    /// If `true`, retain receipts in each [`BlockReplayResult`].
    pub store_receipts: bool,
    /// Emit a progress log every N blocks (`0` = disabled).
    pub progress_interval: u64,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            initial_base_fee: 1,
            gas_target: 10_000_000,
            max_blocks: 0,
            verify_roots: true,
            verify_gas_used: true,
            verify_base_fee: true,
            store_receipts: false,
            progress_interval: 10_000,
        }
    }
}

impl ReplayConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ReplayError> {
        if self.initial_base_fee == 0 {
            return Err(ReplayError::InvalidConfig(
                "initial_base_fee must be > 0",
            ));
        }
        if self.gas_target == 0 {
            return Err(ReplayError::InvalidConfig("gas_target must be > 0"));
        }
        // `progress_interval` may be 0 (disabled); no check needed.
        Ok(())
    }
}

// ── Per-block result ──────────────────────────────────────────────────────

/// Result of replaying a single block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockReplayResult {
    pub height: Height,
    /// State root observed after execution.
    pub state_root: Hash32,
    /// State root the header committed to.
    pub expected_root: Hash32,
    /// Whether `state_root == expected_root`.
    pub state_root_match: bool,
    /// Whether `tx_root` matches the header.
    pub tx_root_match: bool,
    /// Whether `receipts_root` matches the header.
    pub receipts_root_match: bool,
    /// Whether `gas_used` matches the header.
    pub gas_match: bool,
    /// Whether `base_fee_per_gas` matches the EIP-1559 formula.
    pub base_fee_match: bool,
    /// Gas used by execution.
    pub gas_used: u64,
    /// Gas used according to the header.
    pub expected_gas: u64,
    /// Base fee in effect for this block.
    pub base_fee: u64,
    /// Retained receipts. `Some` only when `store_receipts = true`.
    pub receipts: Option<Vec<Receipt>>,
}

impl BlockReplayResult {
    /// Whether every applicable check passed.
    #[must_use]
    pub fn all_ok(&self) -> bool {
        self.state_root_match
            && self.tx_root_match
            && self.receipts_root_match
            && self.gas_match
            && self.base_fee_match
    }
}

// ── Chain result ──────────────────────────────────────────────────────────

/// Result of replaying an entire chain segment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainReplayResult {
    pub success: bool,
    pub failed_at: Option<Height>,
    pub blocks: Vec<BlockReplayResult>,
    pub total_blocks: usize,
    pub total_gas: u64,
    pub mismatch: Option<String>,
    pub final_state: Option<KvState>,
}

impl ChainReplayResult {
    /// Build a failure result.
    ///
    /// `state` is the state as of **before** the failing block — i.e. the
    /// state the caller may safely re-execute from once the underlying
    /// issue is understood.
    #[must_use]
    pub fn failure(
        failed_at: Height,
        err: &ReplayError,
        results: Vec<BlockReplayResult>,
        state_before_failing_block: KvState,
    ) -> Self {
        let total_gas = sum_gas(&results);
        Self {
            success: false,
            failed_at: Some(failed_at),
            total_blocks: results.len(),
            blocks: results,
            total_gas,
            mismatch: Some(err.to_string()),
            final_state: Some(state_before_failing_block),
        }
    }

    /// Build a success result.
    #[must_use]
    pub fn success(results: Vec<BlockReplayResult>, final_state: KvState) -> Self {
        let total_gas = sum_gas(&results);
        Self {
            success: true,
            failed_at: None,
            total_blocks: results.len(),
            blocks: results,
            total_gas,
            mismatch: None,
            final_state: Some(final_state),
        }
    }

    /// Number of blocks whose per-block check failed.
    ///
    /// Only meaningful when `success == true` but the caller disabled
    /// some checks. When `success == false`, aborts early and this is `0`.
    #[must_use]
    pub fn blocks_with_failed_checks(&self) -> usize {
        self.blocks.iter().filter(|b| !b.all_ok()).count()
    }
}

fn sum_gas(results: &[BlockReplayResult]) -> u64 {
    results
        .iter()
        .fold(0u64, |acc, r| acc.saturating_add(r.gas_used))
}

impl std::fmt::Display for ChainReplayResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Chain Replay Result: {}",
            if self.success { "SUCCESS" } else { "FAILURE" }
        )?;
        writeln!(f, "  Blocks replayed: {}", self.total_blocks)?;
        writeln!(f, "  Total gas used: {}", self.total_gas)?;
        if let Some(h) = self.failed_at {
            writeln!(f, "  Failed at height: {h}")?;
        }
        if let Some(m) = &self.mismatch {
            writeln!(f, "  Reason: {m}")?;
        }
        Ok(())
    }
}

// ── Single-block replay ───────────────────────────────────────────────────

/// Replay a single block from `state`, using `base_fee`.
///
/// Returns the block result and the new state. The function does **not**
/// abort on a mismatch: it returns a [`BlockReplayResult`] with the flags
/// set, and lets [`replay_chain`] decide whether the mismatch is fatal.
pub fn replay_block(
    block: &Block,
    state: &KvState,
    base_fee: u64,
    config: &ReplayConfig,
) -> Result<(BlockReplayResult, KvState), ReplayError> {
    let height = block.header.height;

    // Derive the proposer address. A malformed pubkey is a hard error:
    // silently zeroing the address would produce a valid-looking but
    // wrong state root.
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk).ok_or_else(|| {
            ReplayError::InvalidProposer {
                height,
                reason: format!("pubkey length {}", block.header.proposer_pk.len()),
            }
        })?
    };

    // Execute.
    let (new_state, gas_used, receipts) = execute_block(state, &block.txs, base_fee, &proposer_addr);

    let state_root = new_state.root();

    // ── State root ──────────────────────────────────────────────────────
    let state_root_match = if config.verify_roots {
        state_root == block.header.state_root
    } else {
        true
    };

    // ── Transaction root ────────────────────────────────────────────────
    let tx_root_match = if config.verify_roots {
        tx_root(&block.txs) == block.header.tx_root
    } else {
        true
    };

    // ── Receipts root ───────────────────────────────────────────────────
    let receipts_root_match = if config.verify_roots {
        receipts_root(&receipts) == block.header.receipts_root
    } else {
        true
    };

    // ── Gas used ────────────────────────────────────────────────────────
    let gas_match = if config.verify_gas_used {
        gas_used == block.header.gas_used
    } else {
        true
    };

    // ── Base fee ────────────────────────────────────────────────────────
    let base_fee_match = if config.verify_base_fee {
        base_fee == block.header.base_fee_per_gas
    } else {
        true
    };

    // ── Retain receipts ─────────────────────────────────────────────────
    let receipts_option = if config.store_receipts {
        Some(receipts)
    } else {
        None
    };

    let result = BlockReplayResult {
        height,
        state_root,
        expected_root: block.header.state_root,
        state_root_match,
        tx_root_match,
        receipts_root_match,
        gas_match,
        base_fee_match,
        gas_used,
        expected_gas: block.header.gas_used,
        base_fee,
        receipts: receipts_option,
    };

    Ok((result, new_state))
}

// ── Chain replay ──────────────────────────────────────────────────────────

/// Replay a chain of blocks sequentially, computing the base fee per block.
///
/// # Errors
///
/// - [`ReplayError::InvalidConfig`] when `config.validate()` fails.
/// - [`ReplayError::NonMonotonicHeight`] when input heights are not
///   strictly increasing.
/// - [`ReplayError::BaseFeeMismatch`] when `verify_base_fee` is set and a
///   header's base fee disagrees with the EIP-1559 formula.
/// - [`ReplayError::StateRootMismatch`] / [`ReplayError::TxRootMismatch`] /
///   [`ReplayError::ReceiptsRootMismatch`] / [`ReplayError::GasUsedMismatch`]
///   for the corresponding verification failures.
pub fn replay_chain(
    blocks: &[Block],
    initial_state: &KvState,
    config: &ReplayConfig,
) -> Result<ChainReplayResult, ReplayError> {
    config.validate()?;

    let mut state = initial_state.clone();
    let cap = if config.max_blocks == 0 {
        blocks.len()
    } else {
        blocks.len().min(config.max_blocks)
    };
    let mut results = Vec::with_capacity(cap);
    let mut base_fee = config.initial_base_fee;
    let mut prev_height: Option<Height> = None;

    for (idx, block) in blocks.iter().enumerate() {
        if config.max_blocks > 0 && idx >= config.max_blocks {
            break;
        }
        let height = block.header.height;

        // ── Monotonicity ────────────────────────────────────────────────
        if let Some(prev) = prev_height {
            if height <= prev {
                return Err(ReplayError::NonMonotonicHeight {
                    index: idx,
                    previous: prev,
                    current: height,
                });
            }
        } else if height == 0 {
            return Err(ReplayError::ZeroHeight);
        }
        prev_height = Some(height);

        // ── Progress ────────────────────────────────────────────────────
        if config.progress_interval > 0
            && idx > 0
            && idx as u64 % config.progress_interval == 0
        {
            info!(
                blocks = idx,
                height,
                "replay progress"
            );
        }

        // ── Per-block replay ────────────────────────────────────────────
        let (result, new_state) = replay_block(block, &state, base_fee, config)?;

        // Base-fee continuity check.
        if config.verify_base_fee && !result.base_fee_match {
            let err = ReplayError::BaseFeeMismatch {
                height,
                header: block.header.base_fee_per_gas,
                computed: base_fee,
            };
            return Err(err);
        }

        // State root.
        if config.verify_roots && !result.state_root_match {
            let err = ReplayError::StateRootMismatch {
                height,
                expected: hex::encode(result.expected_root.0),
                actual: hex::encode(result.state_root.0),
            };
            return Err(err);
        }

        // Tx root.
        if config.verify_roots && !result.tx_root_match {
            return Err(ReplayError::TxRootMismatch { height });
        }

        // Receipts root.
        if config.verify_roots && !result.receipts_root_match {
            return Err(ReplayError::ReceiptsRootMismatch { height });
        }

        // Gas used.
        if config.verify_gas_used && !result.gas_match {
            return Err(ReplayError::GasUsedMismatch {
                height,
                header: result.expected_gas,
                executed: result.gas_used,
            });
        }

        // Advance.
        base_fee = next_base_fee(base_fee, result.gas_used, config.gas_target);
        results.push(result);
        state = new_state;
    }

    Ok(ChainReplayResult::success(results, state))
}

// ── Replay against external roots ─────────────────────────────────────────

/// Replay a chain and additionally compare each state root against
/// `expected_roots`.
///
/// Heights absent from `expected_roots` are not checked — the map is
/// allowed to be sparse.
pub fn replay_and_verify_roots(
    blocks: &[Block],
    initial_state: &KvState,
    config: &ReplayConfig,
    expected_roots: &BTreeMap<Height, Hash32>,
) -> Result<ChainReplayResult, ReplayError> {
    config.validate()?;

    let mut state = initial_state.clone();
    let cap = if config.max_blocks == 0 {
        blocks.len()
    } else {
        blocks.len().min(config.max_blocks)
    };
    let mut results = Vec::with_capacity(cap);
    let mut base_fee = config.initial_base_fee;
    let mut prev_height: Option<Height> = None;

    for (idx, block) in blocks.iter().enumerate() {
        if config.max_blocks > 0 && idx >= config.max_blocks {
            break;
        }
        let height = block.header.height;

        if let Some(prev) = prev_height {
            if height <= prev {
                return Err(ReplayError::NonMonotonicHeight {
                    index: idx,
                    previous: prev,
                    current: height,
                });
            }
        } else if height == 0 {
            return Err(ReplayError::ZeroHeight);
        }
        prev_height = Some(height);

        let (result, new_state) = replay_block(block, &state, base_fee, config)?;

        // External root check.
        if let Some(ext) = expected_roots.get(&height) {
            if result.state_root != *ext {
                return Err(ReplayError::ExternalRootMismatch {
                    height,
                    expected: hex::encode(ext.0),
                    actual: hex::encode(result.state_root.0),
                });
            }
        }

        base_fee = next_base_fee(base_fee, result.gas_used, config.gas_target);
        results.push(result);
        state = new_state;
    }

    Ok(ChainReplayResult::success(results, state))
}

// ── Resume from checkpoint ────────────────────────────────────────────────

/// Resume replay from a saved checkpoint.
///
/// # Parameters
///
/// - `blocks` — the full block list, sorted by height ascending.
/// - `start_height` — the height of the **first block to replay**. Must
///   be present in `blocks`.
/// - `state_before_start` — the state as of `start_height - 1`. This is
///   the checkpoint the caller saved.
/// - `base_fee_before_start` — the base fee in effect **before**
///   `start_height`. The EIP-1559 formula advances the base fee from the
///   previous block's gas usage, so a caller that supplies
///   `config.initial_base_fee` (as a naive resume would) will compute
///   wrong roots for every block past height 1.
/// - `config` — the replay configuration. `config.verify_base_fee` is
///   still applied; supply the correct `base_fee_before_start` or disable
///   the check.
///
/// # Errors
///
/// - [`ReplayError::StartHeightMissing`] when `start_height` is not in
///   `blocks`.
/// - Any error returned by [`replay_chain`].
pub fn resume_replay(
    blocks: &[Block],
    start_height: Height,
    state_before_start: KvState,
    base_fee_before_start: u64,
    config: &ReplayConfig,
) -> Result<ChainReplayResult, ReplayError> {
    config.validate()?;

    let start_idx = blocks
        .iter()
        .position(|b| b.header.height == start_height)
        .ok_or(ReplayError::StartHeightMissing(start_height))?;

    // Build a config whose `initial_base_fee` matches the caller-supplied
    // resume point. Every other field is preserved.
    let resumed_config = ReplayConfig {
        initial_base_fee: base_fee_before_start,
        ..config.clone()
    };

    replay_chain(&blocks[start_idx..], &state_before_start, &resumed_config)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader, Tx};

    fn empty_block(height: Height, state_root: Hash32, gas_used: u64) -> Block {
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
                gas_used,
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

    /// A block whose `base_fee_per_gas` matches `base_fee` and whose other
    /// header fields are consistent with an empty block at `state_root`.
    fn empty_block_with_fee(
        height: Height,
        state_root: Hash32,
        base_fee: u64,
    ) -> Block {
        let mut b = empty_block(height, state_root, 0);
        b.header.base_fee_per_gas = base_fee;
        b
    }

    fn cfg() -> ReplayConfig {
        ReplayConfig {
            initial_base_fee: 1,
            gas_target: 10_000_000,
            ..Default::default()
        }
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_default_validates() {
        assert!(ReplayConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_gas_target() {
        let c = ReplayConfig {
            gas_target: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReplayError::InvalidConfig(_))
        ));
    }

    #[test]
    fn config_rejects_zero_initial_base_fee() {
        let c = ReplayConfig {
            initial_base_fee: 0,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReplayError::InvalidConfig(_))
        ));
    }

    // ── Single block ────────────────────────────────────────────────────

    #[test]
    fn replay_block_empty_block() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block_with_fee(1, root, 1);
        let (result, new_state) = replay_block(&block, &state, 1, &cfg()).unwrap();
        assert!(result.state_root_match);
        assert!(result.tx_root_match);
        assert!(result.receipts_root_match);
        assert!(result.gas_match);
        assert!(result.base_fee_match);
        assert!(result.all_ok());
        assert_eq!(result.gas_used, 0);
        assert_eq!(new_state.root(), root);
    }

    // ── Chain ───────────────────────────────────────────────────────────

    #[test]
    fn replay_chain_empty_blocks() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, root, 1),
            empty_block_with_fee(3, root, 1),
        ];
        let r = replay_chain(&blocks, &state, &cfg()).unwrap();
        assert!(r.success);
        assert_eq!(r.total_blocks, 3);
        assert_eq!(r.total_gas, 0);
    }

    #[test]
    fn replay_chain_state_root_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, Hash32([0xFF; 32]), 1),
        ];
        let err = replay_chain(&blocks, &state, &cfg()).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::StateRootMismatch { height: 2, .. }
        ));
    }

    #[test]
    fn replay_chain_rejects_non_monotonic_heights() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(5, root, 1),
            empty_block_with_fee(3, root, 1),
        ];
        let err = replay_chain(&blocks, &state, &cfg()).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::NonMonotonicHeight { index: 1, previous: 5, current: 3 }
        ));
    }

    #[test]
    fn replay_chain_rejects_duplicate_heights() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(1, root, 1),
        ];
        let err = replay_chain(&blocks, &state, &cfg()).unwrap_err();
        assert!(matches!(err, ReplayError::NonMonotonicHeight { .. }));
    }

    #[test]
    fn replay_chain_rejects_zero_height() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block_with_fee(0, root, 1)];
        let err = replay_chain(&blocks, &state, &cfg()).unwrap_err();
        assert_eq!(err, ReplayError::ZeroHeight);
    }

    #[test]
    fn replay_chain_gas_used_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block_with_fee(1, root, 1)].into_iter().map(|mut b| {
            b.header.gas_used = 42; // wrong: empty block uses 0
            b
        }).collect::<Vec<_>>();
        let err = replay_chain(&blocks, &state, &cfg()).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::GasUsedMismatch { height: 1, header: 42, executed: 0 }
        ));
    }

    #[test]
    fn replay_chain_base_fee_mismatch() {
        let state = KvState::default();
        let root = state.root();
        // Header claims base fee 99; computed is 1.
        let mut b = empty_block(1, root, 0);
        b.header.base_fee_per_gas = 99;
        let err = replay_chain(&[b], &state, &cfg()).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::BaseFeeMismatch { height: 1, header: 99, computed: 1 }
        ));
    }

    #[test]
    fn replay_chain_skips_base_fee_check_when_disabled() {
        let state = KvState::default();
        let root = state.root();
        let mut b = empty_block(1, root, 0);
        b.header.base_fee_per_gas = 99;
        let c = ReplayConfig {
            verify_base_fee: false,
            ..cfg()
        };
        let r = replay_chain(&[b], &state, &c).unwrap();
        assert!(r.success);
    }

    #[test]
    fn replay_chain_verify_roots_disabled() {
        // A wrong header root is tolerated when verify_roots is false.
        let state = KvState::default();
        let blocks = vec![empty_block_with_fee(1, Hash32([0xFF; 32]), 1)];
        let c = ReplayConfig {
            verify_roots: false,
            ..cfg()
        };
        let r = replay_chain(&blocks, &state, &c).unwrap();
        assert!(r.success);
        assert!(!r.blocks[0].state_root_match); // still recorded
    }

    #[test]
    fn replay_chain_respects_max_blocks() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, root, 1),
            empty_block_with_fee(3, root, 1),
        ];
        let c = ReplayConfig {
            max_blocks: 2,
            ..cfg()
        };
        let r = replay_chain(&blocks, &state, &c).unwrap();
        assert_eq!(r.total_blocks, 2);
    }

    // ── External roots ──────────────────────────────────────────────────

    #[test]
    fn replay_and_verify_roots_ok() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, root, 1),
        ];
        let mut expected = BTreeMap::new();
        expected.insert(1, root);
        expected.insert(2, root);
        let r = replay_and_verify_roots(&blocks, &state, &cfg(), &expected).unwrap();
        assert!(r.success);
    }

    #[test]
    fn replay_and_verify_roots_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block_with_fee(1, root, 1)];
        let mut expected = BTreeMap::new();
        expected.insert(1, Hash32([0xAA; 32]));
        let err = replay_and_verify_roots(&blocks, &state, &cfg(), &expected).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::ExternalRootMismatch { height: 1, .. }
        ));
    }

    #[test]
    fn replay_and_verify_roots_sparse_map() {
        // Heights absent from the map are simply not checked.
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, root, 1),
            empty_block_with_fee(3, root, 1),
        ];
        let mut expected = BTreeMap::new();
        expected.insert(2, root); // only height 2 checked
        let r = replay_and_verify_roots(&blocks, &state, &cfg(), &expected).unwrap();
        assert_eq!(r.total_blocks, 3);
    }

    // ── Resume ──────────────────────────────────────────────────────────

    #[test]
    fn resume_replay_from_missing_height() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block_with_fee(5, root, 1)];
        let err = resume_replay(&blocks, 42, state, 1, &cfg()).unwrap_err();
        assert_eq!(err, ReplayError::StartHeightMissing(42));
    }

    #[test]
    fn resume_replay_starts_at_requested_height() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block_with_fee(1, root, 1),
            empty_block_with_fee(2, root, 1),
            empty_block_with_fee(3, root, 1),
        ];
        // Resume from height 2 with a base fee of 1.
        let r = resume_replay(&blocks, 2, state, 1, &cfg()).unwrap();
        assert_eq!(r.total_blocks, 2);
        assert_eq!(r.blocks[0].height, 2);
        assert_eq!(r.blocks[1].height, 3);
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    #[test]
    fn sum_gas_saturates_on_overflow() {
        let mk = |gas: u64| BlockReplayResult {
            height: 1,
            state_root: Hash32::zero(),
            expected_root: Hash32::zero(),
            state_root_match: true,
            tx_root_match: true,
            receipts_root_match: true,
            gas_match: true,
            base_fee_match: true,
            gas_used: gas,
            expected_gas: gas,
            base_fee: 1,
            receipts: None,
        };
        let results = vec![mk(u64::MAX), mk(u64::MAX)];
        assert_eq!(sum_gas(&results), u64::MAX);
    }

    #[test]
    fn block_result_all_ok_requires_every_flag() {
        let mut r = BlockReplayResult {
            height: 1,
            state_root: Hash32::zero(),
            expected_root: Hash32::zero(),
            state_root_match: true,
            tx_root_match: true,
            receipts_root_match: true,
            gas_match: true,
            base_fee_match: true,
            gas_used: 0,
            expected_gas: 0,
            base_fee: 1,
            receipts: None,
        };
        assert!(r.all_ok());
        r.base_fee_match = false;
        assert!(!r.all_ok());
    }

    #[test]
    fn chain_result_display_includes_reason() {
        let r = ChainReplayResult::failure(
            42,
            &ReplayError::StateRootMismatch {
                height: 42,
                expected: "aa".into(),
                actual: "bb".into(),
            },
            Vec::new(),
            KvState::default(),
        );
        let s = format!("{r}");
        assert!(s.contains("FAILURE"));
        assert!(s.contains("Failed at height: 42"));
        assert!(s.contains("state root mismatch"));
    }
}
