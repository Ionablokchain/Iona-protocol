//! Replaying historical blocks.
//!
//! Re‑executes a chain of blocks from a known starting state, verifying
//! that each state transition produces the expected state root. This is
//! the primary tool for:
//!
//! - Validating that a new binary produces identical results on old blocks
//! - Auditing the chain after a suspected bug or divergence
//! - Regression testing after code changes
//!
//! # Usage
//!
//! ```ignore
//! let result = replay_chain(&blocks, &genesis_state, 1)?;
//! assert!(result.success, "replay failed at height {}", result.failed_at.unwrap());
//! ```

use crate::execution::{execute_block, KvState};
use crate::types::{Block, Hash32, Height, Receipt};
use std::collections::BTreeMap;
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during block replay.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ReplayError {
    /// State root mismatch between computed and block header.
    #[error("state root mismatch at height {height}: expected {expected}, got {actual}")]
    StateRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },
    /// External root mismatch (against provided expected roots map).
    #[error("external root mismatch at height {height}: expected {expected}, got {actual}")]
    ExternalRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },
    /// Blocks must be sorted by height in ascending order.
    #[error("blocks must be sorted by height in ascending order (found height {prev} followed by {current})")]
    UnsortedBlocks { prev: Height, current: Height },
    /// Empty block list provided.
    #[error("empty block list provided")]
    EmptyBlockList,
}

/// Result type for replay operations.
pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Result of replaying a single block.
#[derive(Debug, Clone)]
pub struct BlockReplayResult {
    /// Height of the replayed block.
    pub height: Height,
    /// State root after executing this block.
    pub state_root: Hash32,
    /// Expected state root from the block header.
    pub expected_root: Hash32,
    /// Whether the computed root matches the header root.
    pub match_ok: bool,
    /// Receipts produced during replay.
    pub receipts: Vec<Receipt>,
    /// Gas used during replay.
    pub gas_used: u64,
}

impl BlockReplayResult {
    /// Create a new block replay result.
    #[must_use]
    pub fn new(
        height: Height,
        state_root: Hash32,
        expected_root: Hash32,
        receipts: Vec<Receipt>,
        gas_used: u64,
    ) -> Self {
        Self {
            height,
            state_root,
            expected_root,
            match_ok: state_root == expected_root,
            receipts,
            gas_used,
        }
    }
}

/// Result of replaying an entire chain segment.
#[derive(Debug, Clone)]
pub struct ChainReplayResult {
    /// Whether all blocks replayed successfully.
    pub success: bool,
    /// Height where replay failed (if any).
    pub failed_at: Option<Height>,
    /// Per‑block results.
    pub blocks: Vec<BlockReplayResult>,
    /// Total number of blocks replayed.
    pub total_blocks: usize,
    /// Total gas consumed across all replayed blocks.
    pub total_gas: u64,
    /// Mismatch details (if any).
    pub mismatch: Option<String>,
}

impl ChainReplayResult {
    /// Create a successful replay result.
    #[must_use]
    pub fn success(blocks: Vec<BlockReplayResult>, total_gas: u64) -> Self {
        let total_blocks = blocks.len();
        Self {
            success: true,
            failed_at: None,
            blocks,
            total_blocks,
            total_gas,
            mismatch: None,
        }
    }

    /// Create a failed replay result.
    #[must_use]
    pub fn failure(
        failed_at: Height,
        blocks: Vec<BlockReplayResult>,
        total_gas: u64,
        mismatch: String,
    ) -> Self {
        let total_blocks = blocks.len();
        Self {
            success: false,
            failed_at: Some(failed_at),
            blocks,
            total_blocks,
            total_gas,
            mismatch: Some(mismatch),
        }
    }
}

// -----------------------------------------------------------------------------
// Core replay functions
// -----------------------------------------------------------------------------

/// Replay a single block from a given state.
///
/// Returns the replay result and the new state after execution.
/// This function does not return a `Result` – mismatches are recorded in the
/// `match_ok` field of `BlockReplayResult`.
#[must_use]
pub fn replay_block(
    block: &Block,
    state: &KvState,
    base_fee_per_gas: u64,
) -> (BlockReplayResult, KvState) {
    // Derive proposer address from public key, or use zero address if empty.
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    debug!(height = block.header.height, "replaying block");

    let (new_state, gas_used, receipts) =
        execute_block(state, &block.txs, base_fee_per_gas, &proposer_addr);

    let state_root = new_state.root();
    let expected_root = block.header.state_root;
    let match_ok = state_root == expected_root;

    if !match_ok {
        warn!(
            height = block.header.height,
            expected = %hex::encode(expected_root.0),
            actual = %hex::encode(state_root.0),
            "state root mismatch during replay"
        );
    }

    let result = BlockReplayResult::new(
        block.header.height,
        state_root,
        expected_root,
        receipts,
        gas_used,
    );

    (result, new_state)
}

/// Replay a chain of blocks sequentially from a starting state.
///
/// Blocks must be sorted by height in ascending order.
/// `base_fee_per_gas` is used for all blocks (simplified; in production
/// it would be computed per‑block).
///
/// Returns `ReplayError` if blocks are unsorted or empty.
/// Returns a `ChainReplayResult` with `success = false` on state root mismatch.
pub fn replay_chain(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
) -> ReplayResult<ChainReplayResult> {
    if blocks.is_empty() {
        return Err(ReplayError::EmptyBlockList);
    }

    // Validate ascending order.
    for i in 1..blocks.len() {
        let prev = blocks[i - 1].header.height;
        let curr = blocks[i].header.height;
        if curr <= prev {
            return Err(ReplayError::UnsortedBlocks {
                prev,
                current: curr,
            });
        }
    }

    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;

    info!(total_blocks = blocks.len(), "starting chain replay");

    for block in blocks {
        let (result, new_state) = replay_block(block, &state, base_fee_per_gas);
        total_gas += result.gas_used;

        if !result.match_ok {
            let mismatch = format!(
                "state root mismatch at height {}: expected {}, got {}",
                result.height,
                hex::encode(result.expected_root.0),
                hex::encode(result.state_root.0),
            );
            results.push(result);
            info!(
                failed_at = result.height,
                "chain replay failed due to state root mismatch"
            );
            return Ok(ChainReplayResult::failure(
                result.height,
                results,
                total_gas,
                mismatch,
            ));
        }

        state = new_state;
        results.push(result);
    }

    info!(total_blocks = results.len(), total_gas, "chain replay completed successfully");
    Ok(ChainReplayResult::success(results, total_gas))
}

/// Replay a chain and compare against a list of expected state roots.
///
/// `expected_roots` maps height → expected state root.
/// Returns `ReplayError` on ordering violations or empty list.
/// Returns a `ChainReplayResult` with `success = false` on any mismatch
/// (either internal header root or external expected root).
pub fn replay_and_verify(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    expected_roots: &BTreeMap<Height, Hash32>,
) -> ReplayResult<ChainReplayResult> {
    if blocks.is_empty() {
        return Err(ReplayError::EmptyBlockList);
    }

    // Validate ascending order.
    for i in 1..blocks.len() {
        let prev = blocks[i - 1].header.height;
        let curr = blocks[i].header.height;
        if curr <= prev {
            return Err(ReplayError::UnsortedBlocks {
                prev,
                current: curr,
            });
        }
    }

    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;

    info!(total_blocks = blocks.len(), "starting replay with external verification");

    for block in blocks {
        let (result, new_state) = replay_block(block, &state, base_fee_per_gas);
        total_gas += result.gas_used;

        // Check external expected root if provided.
        if let Some(ext_root) = expected_roots.get(&block.header.height) {
            if result.state_root != *ext_root {
                let mismatch = format!(
                    "external root mismatch at height {}: expected {}, got {}",
                    result.height,
                    hex::encode(ext_root.0),
                    hex::encode(result.state_root.0),
                );
                results.push(result);
                warn!(height = result.height, "external root mismatch");
                return Ok(ChainReplayResult::failure(
                    result.height,
                    results,
                    total_gas,
                    mismatch,
                ));
            }
        }

        // Also check internal block header root.
        if !result.match_ok {
            let mismatch = format!(
                "state root mismatch at height {}: expected {}, got {}",
                result.height,
                hex::encode(result.expected_root.0),
                hex::encode(result.state_root.0),
            );
            results.push(result);
            warn!(height = result.height, "state root mismatch");
            return Ok(ChainReplayResult::failure(
                result.height,
                results,
                total_gas,
                mismatch,
            ));
        }

        state = new_state;
        results.push(result);
    }

    info!(total_blocks = results.len(), total_gas, "replay with external verification completed successfully");
    Ok(ChainReplayResult::success(results, total_gas))
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
    fn test_replay_empty_block() -> ReplayResult<()> {
        let state = KvState::default();
        let expected_root = state.root();
        let block = empty_block(1, expected_root);

        let (result, new_state) = replay_block(&block, &state, 1);
        assert!(result.match_ok);
        assert_eq!(result.gas_used, 0);
        assert_eq!(new_state.root(), expected_root);
        Ok(())
    }

    #[test]
    fn test_replay_chain_empty_blocks() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
            empty_block(3, root),
        ];

        let result = replay_chain(&blocks, &state, 1)?;
        assert!(result.success);
        assert_eq!(result.total_blocks, 3);
        assert_eq!(result.total_gas, 0);
        Ok(())
    }

    #[test]
    fn test_replay_chain_root_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let bad_root = Hash32([0xFF; 32]);
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, bad_root), // mismatch
        ];

        let result = replay_chain(&blocks, &state, 1)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(2));
        assert!(result.mismatch.is_some());
        Ok(())
    }

    #[test]
    fn test_unsorted_blocks_error() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(2, root),
            empty_block(1, root), // out of order
        ];
        let err = replay_chain(&blocks, &state, 1).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::UnsortedBlocks { prev: 2, current: 1 }
        ));
    }

    #[test]
    fn test_empty_block_list_error() {
        let state = KvState::default();
        let blocks = vec![];
        let err = replay_chain(&blocks, &state, 1).unwrap_err();
        assert!(matches!(err, ReplayError::EmptyBlockList));
    }

    #[test]
    fn test_replay_and_verify_with_external_roots() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
        ];

        let mut expected = BTreeMap::new();
        expected.insert(1, root);
        expected.insert(2, root);

        let result = replay_and_verify(&blocks, &state, 1, &expected)?;
        assert!(result.success);
        Ok(())
    }

    #[test]
    fn test_replay_and_verify_external_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];

        let mut expected = BTreeMap::new();
        expected.insert(1, Hash32([0xAA; 32]));

        let result = replay_and_verify(&blocks, &state, 1, &expected)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(1));
        Ok(())
    }
}
