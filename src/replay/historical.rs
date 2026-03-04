//! Replaying historical blocks.
//!
//! Re-executes a chain of blocks from a known starting state, verifying
//! that each state transition produces the expected state root.  This is
//! the primary tool for:
//!
//! - Validating that a new binary produces identical results on old blocks
//! - Auditing the chain after a suspected bug or divergence
//! - Regression testing after code changes
//!
//! # Usage
//!
//! ```ignore
//! let result = replay_chain(&blocks, &genesis_state, 1);
//! assert!(result.success, "replay failed at height {}", result.failed_at.unwrap());
//! ```

use crate::execution::{execute_block, KvState};
use crate::types::{Block, Hash32, Height, Receipt};

/// Result of replaying a single block.
#[derive(Debug, Clone)]
pub struct BlockReplayResult {
    pub height: Height,
    /// State root after executing this block.
    pub state_root: Hash32,
    /// Expected state root from the block header.
    pub expected_root: Hash32,
    /// Whether the roots match.
    pub match_ok: bool,
    /// Receipts produced during replay.
    pub receipts: Vec<Receipt>,
    /// Gas used during replay.
    pub gas_used: u64,
}

/// Result of replaying an entire chain segment.
#[derive(Debug, Clone)]
pub struct ChainReplayResult {
    /// Whether all blocks replayed successfully.
    pub success: bool,
    /// Height where replay failed (if any).
    pub failed_at: Option<Height>,
    /// Per-block results.
    pub blocks: Vec<BlockReplayResult>,
    /// Total blocks replayed.
    pub total_blocks: usize,
    /// Total gas consumed across all replayed blocks.
    pub total_gas: u64,
    /// Mismatch details (if any).
    pub mismatch: Option<String>,
}

/// Replay a single block from a given state.
///
/// Returns the replay result and the new state after execution.
pub fn replay_block(
    block: &Block,
    state: &KvState,
    base_fee_per_gas: u64,
) -> (BlockReplayResult, KvState) {
    // Derive proposer address from header.
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let (new_state, gas_used, receipts) = execute_block(
        state,
        &block.txs,
        base_fee_per_gas,
        &proposer_addr,
    );

    let state_root = new_state.root();
    let expected_root = block.header.state_root.clone();
    let match_ok = state_root == expected_root;

    let result = BlockReplayResult {
        height: block.header.height,
        state_root,
        expected_root,
        match_ok,
        receipts,
        gas_used,
    };

    (result, new_state)
}

/// Replay a chain of blocks sequentially from a starting state.
///
/// Blocks must be sorted by height in ascending order.
/// `base_fee_per_gas` is used for all blocks (simplified; in production
/// it would be computed per-block).
pub fn replay_chain(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
) -> ChainReplayResult {
    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;

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
            results.push(result.clone());
            let total_blocks = results.len();
            return ChainReplayResult {
                success: false,
                failed_at: Some(result.height),
                blocks: results,
                total_blocks,
                total_gas,
                mismatch: Some(mismatch),
            };
        }

        state = new_state;
        results.push(result);
    }

    let total_blocks = results.len();
    ChainReplayResult {
        success: true,
        failed_at: None,
        blocks: results,
        total_blocks,
        total_gas,
        mismatch: None,
    }
}

/// Replay a chain and compare against a list of expected state roots.
///
/// `expected_roots` maps height -> expected state root.
pub fn replay_and_verify(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    expected_roots: &std::collections::BTreeMap<Height, Hash32>,
) -> ChainReplayResult {
    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;

    for block in blocks {
        let (result, new_state) = replay_block(block, &state, base_fee_per_gas);
        total_gas += result.gas_used;

        // Check against external expected root (if provided for this height).
        if let Some(ext_root) = expected_roots.get(&block.header.height) {
            if result.state_root != *ext_root {
                let mismatch = format!(
                    "external root mismatch at height {}: expected {}, got {}",
                    result.height,
                    hex::encode(ext_root.0),
                    hex::encode(result.state_root.0),
                );
                results.push(result);
                let total_blocks = results.len();
                return ChainReplayResult {
                    success: false,
                    failed_at: Some(block.header.height),
                    blocks: results,
                    total_blocks,
                    total_gas,
                    mismatch: Some(mismatch),
                };
            }
        }

        state = new_state;
        results.push(result);
    }

    let total_blocks = results.len();
    ChainReplayResult {
        success: true,
        failed_at: None,
        blocks: results,
        total_blocks,
        total_gas,
        mismatch: None,
    }
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
    fn test_replay_empty_block() {
        let state = KvState::default();
        let expected_root = state.root();
        let block = empty_block(1, expected_root.clone());

        let (result, new_state) = replay_block(&block, &state, 1);
        assert!(result.match_ok, "root mismatch");
        assert_eq!(result.gas_used, 0);
        assert_eq!(new_state.root(), expected_root);
    }

    #[test]
    fn test_replay_chain_empty_blocks() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
            empty_block(3, root.clone()),
        ];

        let result = replay_chain(&blocks, &state, 1);
        assert!(result.success, "mismatch: {:?}", result.mismatch);
        assert_eq!(result.total_blocks, 3);
        assert_eq!(result.total_gas, 0);
    }

    #[test]
    fn test_replay_chain_root_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let bad_root = Hash32([0xFF; 32]);
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, bad_root), // mismatch!
        ];

        let result = replay_chain(&blocks, &state, 1);
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(2));
        assert!(result.mismatch.is_some());
    }

    #[test]
    fn test_replay_and_verify_with_external_roots() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
        ];

        let mut expected = std::collections::BTreeMap::new();
        expected.insert(1, root.clone());
        expected.insert(2, root.clone());

        let result = replay_and_verify(&blocks, &state, 1, &expected);
        assert!(result.success);
    }

    #[test]
    fn test_replay_and_verify_external_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
        ];

        let mut expected = std::collections::BTreeMap::new();
        expected.insert(1, Hash32([0xAA; 32])); // wrong external root

        let result = replay_and_verify(&blocks, &state, 1, &expected);
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(1));
    }

    #[test]
    fn test_replay_result_fields() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(42, root.clone());

        let (result, _) = replay_block(&block, &state, 1);
        assert_eq!(result.height, 42);
        assert!(result.receipts.is_empty());
    }
}
