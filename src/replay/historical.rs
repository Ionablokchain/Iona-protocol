//! Replaying historical blocks.
//!
//! Re‑executes a chain of blocks from a known starting state, verifying
//! that each state transition produces the expected state root. This is
//! the primary tool for:
//!
//! - Validating that a new binary produces identical results on old blocks
//! - Auditing the chain after a suspected bug or divergence
//! - Regression testing after code changes
//! - Performance benchmarking of execution
//!
//! # Example
//!
//! ```ignore
//! use iona::replay::{replay_chain, ReplayConfig, ReplayProgress};
//!
//! let config = ReplayConfig::default();
//! let progress = |h, total| println!("Replaying block {}/{}", h, total);
//! let result = replay_chain(&blocks, &genesis_state, 1, Some(&config), Some(progress))?;
//! if result.success {
//!     println!("All {} blocks replayed successfully", result.total_blocks);
//! } else {
//!     println!("Failed at height {}", result.failed_at.unwrap());
//! }
//! ```
//!
//! # Features
//!
//! - Optional verification of transaction root, receipts root, and gas used.
//! - Progress reporting via callback.
//! - Serialisation of results to JSON for offline analysis.
//! - Parallel replay (chunk‑based) for performance (requires `parallel` feature).
//! - Detailed metrics: total time, blocks/second, gas/second.

use crate::execution::{execute_block, KvState};
use crate::types::{Block, Hash32, Height, Receipt};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::time::{Duration, Instant};
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
    /// Transaction root mismatch.
    #[error("transaction root mismatch at height {height}: expected {expected}, got {actual}")]
    TransactionRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },
    /// Receipts root mismatch.
    #[error("receipts root mismatch at height {height}: expected {expected}, got {actual}")]
    ReceiptsRootMismatch {
        height: Height,
        expected: String,
        actual: String,
    },
    /// Gas used mismatch.
    #[error("gas used mismatch at height {height}: expected {expected}, got {actual}")]
    GasMismatch {
        height: Height,
        expected: u64,
        actual: u64,
    },
    /// Blocks must be sorted by height in ascending order.
    #[error("blocks must be sorted by height in ascending order (found height {prev} followed by {current})")]
    UnsortedBlocks { prev: Height, current: Height },
    /// Empty block list provided.
    #[error("empty block list provided")]
    EmptyBlockList,
    /// I/O error.
    #[error("I/O error: {0}")]
    Io(String),
    /// Serialisation error.
    #[error("serialisation error: {0}")]
    Serialization(String),
    /// Block decode error.
    #[error("block decode error: {0}")]
    BlockDecode(String),
    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for replay.
#[derive(Debug, Clone)]
pub struct ReplayConfig {
    /// Stop replay on first error (default: true).
    pub stop_on_first_error: bool,
    /// Verify transaction root (default: true).
    pub verify_tx_root: bool,
    /// Verify receipts root (default: true).
    pub verify_receipts_root: bool,
    /// Verify gas used (default: true).
    pub verify_gas_used: bool,
    /// Verify intrinsic gas used (default: true).
    pub verify_intrinsic_gas: bool,
    /// Number of blocks to process in parallel (0 = sequential, default: 0).
    pub parallel_chunk_size: usize,
    /// Log progress every N blocks (0 = no progress logging, default: 1000).
    pub progress_log_interval: usize,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            stop_on_first_error: true,
            verify_tx_root: true,
            verify_receipts_root: true,
            verify_gas_used: true,
            verify_intrinsic_gas: true,
            parallel_chunk_size: 0,
            progress_log_interval: 1000,
        }
    }
}

impl ReplayConfig {
    /// Create a config that skips all verifications (fast replay).
    #[must_use]
    pub fn fast() -> Self {
        Self {
            verify_tx_root: false,
            verify_receipts_root: false,
            verify_gas_used: false,
            verify_intrinsic_gas: false,
            ..Default::default()
        }
    }

    /// Create a config for strict verification (all checks enabled).
    #[must_use]
    pub fn strict() -> Self {
        Self {
            stop_on_first_error: true,
            verify_tx_root: true,
            verify_receipts_root: true,
            verify_gas_used: true,
            verify_intrinsic_gas: true,
            parallel_chunk_size: 0,
            progress_log_interval: 0,
        }
    }

    /// Enable parallel replay with given chunk size.
    #[must_use]
    pub fn with_parallel(mut self, chunk_size: usize) -> Self {
        self.parallel_chunk_size = chunk_size;
        self
    }
}

// -----------------------------------------------------------------------------
// Progress reporting
// -----------------------------------------------------------------------------

/// Progress status during replay.
#[derive(Debug, Clone)]
pub enum ReplayProgress {
    /// Initialisation started with total blocks.
    Started { total_blocks: usize },
    /// A block is about to be replayed (height, index, total).
    BlockStart { height: Height, index: usize, total: usize },
    /// A block was replayed successfully (height, gas used, cumulative gas).
    BlockComplete { height: Height, gas_used: u64, cumulative_gas: u64 },
    /// An error occurred on a block (height, error).
    BlockError { height: Height, error: String },
    /// Replay completed (success or failure).
    Finished { success: bool, total_blocks: usize, total_gas: u64, duration_ms: u64 },
}

/// Type alias for progress callback.
pub type ProgressCallback = dyn Fn(ReplayProgress) + Send + Sync;

// -----------------------------------------------------------------------------
// Result types (Serializable)
// -----------------------------------------------------------------------------

/// Result of replaying a single block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockReplayResult {
    pub height: Height,
    pub state_root: Hash32,
    pub expected_root: Hash32,
    pub match_ok: bool,
    pub receipts: Vec<Receipt>,
    pub gas_used: u64,
    pub intrinsic_gas_used: u64,
    pub exec_gas_used: u64,
    pub vm_gas_used: u64,
    pub evm_gas_used: u64,
    pub tx_root_match: bool,
    pub receipts_root_match: bool,
    pub gas_match: bool,
    pub intrinsic_gas_match: bool,
    pub replay_time_ms: u64,
}

impl BlockReplayResult {
    #[must_use]
    pub fn new(
        height: Height,
        state_root: Hash32,
        expected_root: Hash32,
        receipts: Vec<Receipt>,
        gas_used: u64,
        intrinsic_gas_used: u64,
        exec_gas_used: u64,
        vm_gas_used: u64,
        evm_gas_used: u64,
        tx_root_match: bool,
        receipts_root_match: bool,
        gas_match: bool,
        intrinsic_gas_match: bool,
        replay_time_ms: u64,
    ) -> Self {
        Self {
            height,
            state_root,
            expected_root,
            match_ok: state_root == expected_root && tx_root_match && receipts_root_match && gas_match,
            receipts,
            gas_used,
            intrinsic_gas_used,
            exec_gas_used,
            vm_gas_used,
            evm_gas_used,
            tx_root_match,
            receipts_root_match,
            gas_match,
            intrinsic_gas_match,
            replay_time_ms,
        }
    }
}

/// Result of replaying an entire chain segment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainReplayResult {
    pub success: bool,
    pub failed_at: Option<Height>,
    pub blocks: Vec<BlockReplayResult>,
    pub total_blocks: usize,
    pub total_gas: u64,
    pub mismatch: Option<String>,
    pub total_time_ms: u64,
    pub blocks_per_second: f64,
    pub gas_per_second: f64,
}

impl ChainReplayResult {
    #[must_use]
    pub fn success(blocks: Vec<BlockReplayResult>, total_gas: u64, duration_ms: u64) -> Self {
        let total_blocks = blocks.len();
        let blocks_per_second = if duration_ms > 0 {
            (total_blocks as f64) / (duration_ms as f64 / 1000.0)
        } else { 0.0 };
        let gas_per_second = if duration_ms > 0 {
            (total_gas as f64) / (duration_ms as f64 / 1000.0)
        } else { 0.0 };
        Self {
            success: true,
            failed_at: None,
            blocks,
            total_blocks,
            total_gas,
            mismatch: None,
            total_time_ms: duration_ms,
            blocks_per_second,
            gas_per_second,
        }
    }

    #[must_use]
    pub fn failure(
        failed_at: Height,
        blocks: Vec<BlockReplayResult>,
        total_gas: u64,
        mismatch: String,
        duration_ms: u64,
    ) -> Self {
        let total_blocks = blocks.len();
        let blocks_per_second = if duration_ms > 0 {
            (total_blocks as f64) / (duration_ms as f64 / 1000.0)
        } else { 0.0 };
        let gas_per_second = if duration_ms > 0 {
            (total_gas as f64) / (duration_ms as f64 / 1000.0)
        } else { 0.0 };
        Self {
            success: false,
            failed_at: Some(failed_at),
            blocks,
            total_blocks,
            total_gas,
            mismatch: Some(mismatch),
            total_time_ms: duration_ms,
            blocks_per_second,
            gas_per_second,
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics (internal)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Default)]
struct ReplayMetrics {
    total_blocks: usize,
    total_gas: u64,
    start_time: Instant,
}

impl ReplayMetrics {
    fn new() -> Self {
        Self {
            total_blocks: 0,
            total_gas: 0,
            start_time: Instant::now(),
        }
    }

    fn add_block(&mut self, gas_used: u64) {
        self.total_blocks += 1;
        self.total_gas += gas_used;
    }
}

// -----------------------------------------------------------------------------
// Core replay functions
// -----------------------------------------------------------------------------

/// Replay a single block from a given state.
///
/// Returns the replay result and the new state after execution.
/// This function does not return a `Result` – mismatches are recorded in the
/// `BlockReplayResult` fields.
#[must_use]
pub fn replay_block(
    block: &Block,
    state: &KvState,
    base_fee_per_gas: u64,
    config: &ReplayConfig,
) -> (BlockReplayResult, KvState) {
    let start = Instant::now();
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

    // Compute transaction root
    let tx_root_match = if config.verify_tx_root {
        let computed_tx_root = crate::merkle::merkle_root(&block.txs);
        computed_tx_root == block.header.tx_root
    } else {
        true
    };

    // Compute receipts root
    let receipts_root_match = if config.verify_receipts_root {
        let computed_receipts_root = crate::merkle::receipts_root(&receipts);
        computed_receipts_root == block.header.receipts_root
    } else {
        true
    };

    // Gas match
    let gas_match = if config.verify_gas_used {
        gas_used == block.header.gas_used
    } else {
        true
    };

    let intrinsic_gas_match = if config.verify_intrinsic_gas {
        gas_used == block.header.intrinsic_gas_used + block.header.exec_gas_used + block.header.vm_gas_used + block.header.evm_gas_used
    } else {
        true
    };

    let replay_time_ms = start.elapsed().as_millis() as u64;

    let result = BlockReplayResult::new(
        block.header.height,
        state_root,
        expected_root,
        receipts,
        gas_used,
        block.header.intrinsic_gas_used,
        block.header.exec_gas_used,
        block.header.vm_gas_used,
        block.header.evm_gas_used,
        tx_root_match,
        receipts_root_match,
        gas_match,
        intrinsic_gas_match,
        replay_time_ms,
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
    config: Option<&ReplayConfig>,
    progress_callback: Option<&ProgressCallback>,
) -> ReplayResult<ChainReplayResult> {
    if blocks.is_empty() {
        return Err(ReplayError::EmptyBlockList);
    }

    let config = config.unwrap_or(&ReplayConfig::default());

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

    let start_time = Instant::now();
    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;
    let mut metrics = ReplayMetrics::new();

    if let Some(cb) = progress_callback {
        cb(ReplayProgress::Started { total_blocks: blocks.len() });
    }

    info!(total_blocks = blocks.len(), "starting chain replay");

    for (idx, block) in blocks.iter().enumerate() {
        if let Some(cb) = progress_callback {
            cb(ReplayProgress::BlockStart {
                height: block.header.height,
                index: idx,
                total: blocks.len(),
            });
        }

        let (result, new_state) = replay_block(block, &state, base_fee_per_gas, &config);
        total_gas += result.gas_used;
        metrics.add_block(result.gas_used);

        if let Some(cb) = progress_callback {
            cb(ReplayProgress::BlockComplete {
                height: result.height,
                gas_used: result.gas_used,
                cumulative_gas: total_gas,
            });
        }

        // Check if we should stop on first error.
        let has_error = !result.match_ok ||
            (config.verify_tx_root && !result.tx_root_match) ||
            (config.verify_receipts_root && !result.receipts_root_match) ||
            (config.verify_gas_used && !result.gas_match) ||
            (config.verify_intrinsic_gas && !result.intrinsic_gas_match);

        results.push(result);

        if has_error && config.stop_on_first_error {
            let mismatch = format!(
                "mismatch at height {}: state_root={}, tx_root_match={}, receipts_root_match={}, gas_match={}",
                blocks[idx].header.height,
                state.root() == blocks[idx].header.state_root,
                config.verify_tx_root,
                config.verify_receipts_root,
                config.verify_gas_used,
            );
            if let Some(cb) = progress_callback {
                cb(ReplayProgress::BlockError {
                    height: blocks[idx].header.height,
                    error: mismatch.clone(),
                });
            }
            let duration_ms = start_time.elapsed().as_millis() as u64;
            return Ok(ChainReplayResult::failure(
                blocks[idx].header.height,
                results,
                total_gas,
                mismatch,
                duration_ms,
            ));
        }

        state = new_state;

        // Log progress periodically
        if config.progress_log_interval > 0 && idx % config.progress_log_interval == 0 {
            info!(
                height = block.header.height,
                gas = total_gas,
                "replayed {} blocks", idx + 1
            );
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    if let Some(cb) = progress_callback {
        cb(ReplayProgress::Finished {
            success: true,
            total_blocks: blocks.len(),
            total_gas,
            duration_ms,
        });
    }

    info!(total_blocks = results.len(), total_gas, "chain replay completed successfully");
    Ok(ChainReplayResult::success(results, total_gas, duration_ms))
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
    config: Option<&ReplayConfig>,
    progress_callback: Option<&ProgressCallback>,
) -> ReplayResult<ChainReplayResult> {
    if blocks.is_empty() {
        return Err(ReplayError::EmptyBlockList);
    }

    let config = config.unwrap_or(&ReplayConfig::default());

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

    let start_time = Instant::now();
    let mut state = initial_state.clone();
    let mut results = Vec::with_capacity(blocks.len());
    let mut total_gas = 0u64;
    let mut metrics = ReplayMetrics::new();

    if let Some(cb) = progress_callback {
        cb(ReplayProgress::Started { total_blocks: blocks.len() });
    }

    info!(total_blocks = blocks.len(), "starting replay with external verification");

    for (idx, block) in blocks.iter().enumerate() {
        if let Some(cb) = progress_callback {
            cb(ReplayProgress::BlockStart {
                height: block.header.height,
                index: idx,
                total: blocks.len(),
            });
        }

        let (result, new_state) = replay_block(block, &state, base_fee_per_gas, &config);
        total_gas += result.gas_used;
        metrics.add_block(result.gas_used);

        if let Some(cb) = progress_callback {
            cb(ReplayProgress::BlockComplete {
                height: result.height,
                gas_used: result.gas_used,
                cumulative_gas: total_gas,
            });
        }

        // Check external expected root if provided.
        if let Some(ext_root) = expected_roots.get(&block.header.height) {
            if result.state_root != *ext_root {
                let mismatch = format!(
                    "external root mismatch at height {}: expected {}, got {}",
                    result.height,
                    hex::encode(ext_root.0),
                    hex::encode(result.state_root.0),
                );
                if let Some(cb) = progress_callback {
                    cb(ReplayProgress::BlockError {
                        height: result.height,
                        error: mismatch.clone(),
                    });
                }
                results.push(result);
                let duration_ms = start_time.elapsed().as_millis() as u64;
                return Ok(ChainReplayResult::failure(
                    result.height,
                    results,
                    total_gas,
                    mismatch,
                    duration_ms,
                ));
            }
        }

        // Check internal block header root and other verifications.
        let has_error = !result.match_ok ||
            (config.verify_tx_root && !result.tx_root_match) ||
            (config.verify_receipts_root && !result.receipts_root_match) ||
            (config.verify_gas_used && !result.gas_match) ||
            (config.verify_intrinsic_gas && !result.intrinsic_gas_match);

        results.push(result);

        if has_error && config.stop_on_first_error {
            let mismatch = format!(
                "mismatch at height {}: state_root={}, tx_root_match={}, receipts_root_match={}, gas_match={}",
                block.header.height,
                state.root() == block.header.state_root,
                config.verify_tx_root,
                config.verify_receipts_root,
                config.verify_gas_used,
            );
            if let Some(cb) = progress_callback {
                cb(ReplayProgress::BlockError {
                    height: block.header.height,
                    error: mismatch.clone(),
                });
            }
            let duration_ms = start_time.elapsed().as_millis() as u64;
            return Ok(ChainReplayResult::failure(
                block.header.height,
                results,
                total_gas,
                mismatch,
                duration_ms,
            ));
        }

        state = new_state;
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    if let Some(cb) = progress_callback {
        cb(ReplayProgress::Finished {
            success: true,
            total_blocks: blocks.len(),
            total_gas,
            duration_ms,
        });
    }

    info!(total_blocks = results.len(), total_gas, "replay with external verification completed successfully");
    Ok(ChainReplayResult::success(results, total_gas, duration_ms))
}

// -----------------------------------------------------------------------------
// File I/O helpers
// -----------------------------------------------------------------------------

/// Load blocks from a JSON Lines file (one block per line).
pub fn load_blocks_from_file(path: &Path) -> ReplayResult<Vec<Block>> {
    let file = File::open(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line.map_err(|e| ReplayError::Io(e.to_string()))?;
        let block: Block = serde_json::from_str(&line)
            .map_err(|e| ReplayError::Serialization(e.to_string()))?;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Save replay result to a JSON file (pretty).
pub fn save_replay_result_to_file(result: &ChainReplayResult, path: &Path) -> ReplayResult<()> {
    let file = File::create(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(())
}

/// Load replay result from a JSON file.
pub fn load_replay_result_from_file(path: &Path) -> ReplayResult<ChainReplayResult> {
    let file = File::open(path).map_err(|e| ReplayError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let result: ChainReplayResult = serde_json::from_reader(reader)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(result)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader};
    use crate::merkle::merkle_root;

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

    fn with_tx_root(block: Block, tx_root: Hash32) -> Block {
        let mut b = block;
        b.header.tx_root = tx_root;
        b
    }

    #[test]
    fn test_replay_empty_block() -> ReplayResult<()> {
        let state = KvState::default();
        let expected_root = state.root();
        let block = empty_block(1, expected_root);
        let config = ReplayConfig::default();

        let (result, new_state) = replay_block(&block, &state, 1, &config);
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

        let result = replay_chain(&blocks, &state, 1, None, None)?;
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

        let result = replay_chain(&blocks, &state, 1, None, None)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(2));
        assert!(result.mismatch.is_some());
        Ok(())
    }

    #[test]
    fn test_replay_chain_tx_root_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let mut block = empty_block(1, root);
        block.header.tx_root = Hash32([0xAA; 32]); // mismatch (actual root is zero)
        let blocks = vec![block];

        let config = ReplayConfig::default();
        let result = replay_chain(&blocks, &state, 1, Some(&config), None)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(1));
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
        let err = replay_chain(&blocks, &state, 1, None, None).unwrap_err();
        assert!(matches!(
            err,
            ReplayError::UnsortedBlocks { prev: 2, current: 1 }
        ));
    }

    #[test]
    fn test_empty_block_list_error() {
        let state = KvState::default();
        let blocks = vec![];
        let err = replay_chain(&blocks, &state, 1, None, None).unwrap_err();
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

        let result = replay_and_verify(&blocks, &state, 1, &expected, None, None)?;
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

        let result = replay_and_verify(&blocks, &state, 1, &expected, None, None)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(1));
        Ok(())
    }

    #[test]
    fn test_progress_callback() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
        ];

        let mut events = Vec::new();
        let progress = |ev: ReplayProgress| {
            events.push(ev);
        };

        let result = replay_chain(&blocks, &state, 1, None, Some(&progress))?;
        assert!(result.success);
        assert!(events.len() >= 2);
        assert!(matches!(events[0], ReplayProgress::Started { .. }));
        assert!(matches!(events.last(), Some(ReplayProgress::Finished { .. })));
        Ok(())
    }

    #[test]
    fn test_file_io_roundtrip() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
        ];
        let result = replay_chain(&blocks, &state, 1, None, None)?;

        let dir = tempfile::tempdir().map_err(|e| ReplayError::Io(e.to_string()))?;
        let path = dir.path().join("replay_result.json");
        save_replay_result_to_file(&result, &path)?;
        let loaded = load_replay_result_from_file(&path)?;
        assert_eq!(loaded.total_blocks, result.total_blocks);
        assert_eq!(loaded.total_gas, result.total_gas);
        assert_eq!(loaded.success, result.success);
        Ok(())
    }

    #[test]
    fn test_load_blocks_from_file() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
        ];

        let dir = tempfile::tempdir().map_err(|e| ReplayError::Io(e.to_string()))?;
        let path = dir.path().join("blocks.jsonl");
        let file = File::create(&path).map_err(|e| ReplayError::Io(e.to_string()))?;
        let writer = BufWriter::new(file);
        for block in &blocks {
            serde_json::to_writer(&writer, block)
                .map_err(|e| ReplayError::Serialization(e.to_string()))?;
            writeln!(&writer).map_err(|e| ReplayError::Io(e.to_string()))?;
        }
        drop(writer);

        let loaded = load_blocks_from_file(&path)?;
        assert_eq!(loaded.len(), blocks.len());
        assert_eq!(loaded[0].header.height, blocks[0].header.height);
        Ok(())
    }
}
