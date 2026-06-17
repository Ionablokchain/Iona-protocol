//! Replay and determinism verification subsystem.
//!
//! Provides tools for:
//! - **Replaying historical blocks** to verify state transitions
//! - **Verifying state root reproducibility** across rebuilds
//! - **Detecting divergence** across environments (platforms, compilers)
//! - **Logging nondeterministic inputs** for audit and debugging
//!
//! # Architecture
//!
//! ```text
//!   ReplayConfig → replay_chain()
//!       │
//!       ├── historical::replay_chain()
//!       │       │
//!       │       └── BlockReplayResult
//!       │
//!       ├── state_root_verify::verify_roots()
//!       │
//!       ├── divergence::detect_divergence_range()
//!       │
//!       └── nondeterminism::NdLogger::log()
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::replay::{replay_chain, ReplayConfig, ReplayProgress};
//!
//! let config = ReplayConfig::default();
//! let progress = |ev| println!("{:?}", ev);
//! let result = replay_chain(&blocks, &genesis, 1, Some(&config), Some(&progress))?;
//! if result.success {
//!     println!("All {} blocks replayed", result.total_blocks);
//! }
//! ```

pub mod divergence;
pub mod historical;
pub mod nondeterminism;
pub mod replay_tool;
pub mod state_root_verify;

use crate::execution::KvState;
use crate::types::{Block, Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter};
use std::path::Path;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Re-exports of core types from submodules
// -----------------------------------------------------------------------------

pub use divergence::{
    compare_snapshots, detect_divergence, detect_divergence_range, Divergence, DivergenceDetail,
    DivergenceReport, NodeSnapshot,
};
pub use historical::{replay_chain as replay_chain_historical, ChainReplayResult, HistoricalError};
pub use nondeterminism::{NdLogger, NondeterminismSource};
pub use replay_tool::{replay_and_verify, replay_block};
pub use state_root_verify::{verify_roots, VerifyError, VerifyResult};

// -----------------------------------------------------------------------------
// Unified errors
// -----------------------------------------------------------------------------

/// Errors that can occur during replay or verification operations.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Error from the historical replay subsystem.
    #[error("historical replay error: {0}")]
    Historical(#[from] HistoricalError),

    /// Error from state root verification.
    #[error("state root verification error: {0}")]
    StateRootVerify(#[from] VerifyError),

    /// Error from divergence detection.
    #[error("divergence detection error: {0}")]
    Divergence(#[from] divergence::DivergenceError),

    /// Error from nondeterminism logging.
    #[error("nondeterminism logging error: {0}")]
    Nondeterminism(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialisation error.
    #[error("serialisation error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),
}

pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// Unified configuration
// -----------------------------------------------------------------------------

/// Configuration for replay and verification operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Whether to persist intermediate results to disk.
    pub persist_intermediate: bool,
    /// Directory to persist intermediate results.
    pub persist_dir: Option<String>,
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
            persist_intermediate: false,
            persist_dir: None,
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
            persist_intermediate: false,
            persist_dir: None,
        }
    }

    /// Enable parallel replay with given chunk size.
    #[must_use]
    pub fn with_parallel(mut self, chunk_size: usize) -> Self {
        self.parallel_chunk_size = chunk_size;
        self
    }

    /// Enable persistence of intermediate results.
    #[must_use]
    pub fn with_persistence(mut self, dir: impl Into<String>) -> Self {
        self.persist_intermediate = true;
        self.persist_dir = Some(dir.into());
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
// High‑level convenience functions
// -----------------------------------------------------------------------------

/// Replay a chain of blocks with full configuration and progress reporting.
///
/// This is the main entry point for block replay. It wraps
/// [`historical::replay_chain`] and integrates with configuration and progress.
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state (e.g., genesis state).
/// * `base_fee_per_gas` – Base fee to use for all blocks.
/// * `config` – Optional replay configuration (uses default if None).
/// * `progress` – Optional progress callback.
///
/// # Returns
/// A `ChainReplayResult` indicating success or failure.
pub fn replay_chain(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    config: Option<&ReplayConfig>,
    progress: Option<&ProgressCallback>,
) -> ReplayResult<ChainReplayResult> {
    let config = config.unwrap_or(&ReplayConfig::default());
    let result = historical::replay_chain(
        blocks,
        initial_state,
        base_fee_per_gas,
        Some(config),
        progress,
    )?;
    Ok(result)
}

/// Verify state roots against an external map of expected roots.
///
/// Wraps [`state_root_verify::verify_roots`] with configuration.
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state.
/// * `base_fee_per_gas` – Base fee for all blocks.
/// * `expected_roots` – Map from height to expected state root.
/// * `config` – Optional replay configuration.
/// * `progress` – Optional progress callback.
///
/// # Returns
/// A `VerifyResult` indicating pass/fail and mismatch details.
pub fn verify_state_roots(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    expected_roots: &BTreeMap<Height, Hash32>,
    config: Option<&ReplayConfig>,
    progress: Option<&ProgressCallback>,
) -> ReplayResult<VerifyResult> {
    let config = config.unwrap_or(&ReplayConfig::default());
    let result = state_root_verify::verify_roots(
        blocks,
        initial_state,
        base_fee_per_gas,
        expected_roots,
        Some(config),
        progress,
    )?;
    Ok(result)
}

/// Compare two or more sets of node snapshots and return a divergence report.
///
/// Wraps [`divergence::detect_divergence_range`] and returns a `DivergenceReport`.
///
/// # Arguments
/// * `node_snapshots` – A map from node identifier to a vector of snapshots.
///
/// # Returns
/// A `DivergenceReport` detailing any divergence between nodes.
pub fn compare_environments(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
) -> ReplayResult<DivergenceReport> {
    Ok(divergence::detect_divergence_range(node_snapshots)?)
}

/// Create a new nondeterminism logger that writes to the given file.
///
/// # Arguments
/// * `path` – File path for the log output.
///
/// # Returns
/// An `NdLogger` instance.
pub fn create_nd_logger(path: impl AsRef<Path>) -> ReplayResult<NdLogger> {
    NdLogger::new(path).map_err(|e| ReplayError::Nondeterminism(e.to_string()))
}

// -----------------------------------------------------------------------------
// File I/O helpers
// -----------------------------------------------------------------------------

/// Load blocks from a JSON Lines file (one block per line).
pub fn load_blocks_from_file(path: &Path) -> ReplayResult<Vec<Block>> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();
    for line in std::io::BufRead::lines(reader) {
        let line = line?;
        let block: Block = serde_json::from_str(&line)
            .map_err(|e| ReplayError::Serialization(e.to_string()))?;
        blocks.push(block);
    }
    Ok(blocks)
}

/// Save replay result to a JSON file (pretty).
pub fn save_replay_result(result: &ChainReplayResult, path: &Path) -> ReplayResult<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(())
}

/// Load replay result from a JSON file.
pub fn load_replay_result(path: &Path) -> ReplayResult<ChainReplayResult> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let result: ChainReplayResult = serde_json::from_reader(reader)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(result)
}

/// Save divergence report to a JSON file.
pub fn save_divergence_report(report: &DivergenceReport, path: &Path) -> ReplayResult<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, report)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(())
}

/// Load divergence report from a JSON file.
pub fn load_divergence_report(path: &Path) -> ReplayResult<DivergenceReport> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let report: DivergenceReport = serde_json::from_reader(reader)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(report)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;
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
    fn test_replay_chain_success() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
        ];
        let result = replay_chain(&blocks, &state, 1, None, None)?;
        assert!(result.success);
        Ok(())
    }

    #[test]
    fn test_replay_chain_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let bad_root = Hash32([0xFF; 32]);
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, bad_root),
        ];
        let result = replay_chain(&blocks, &state, 1, None, None)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(2));
        Ok(())
    }

    #[test]
    fn test_verify_state_roots_external() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
        ];
        let mut expected = BTreeMap::new();
        expected.insert(1, root.clone());
        expected.insert(2, root.clone());
        let result = verify_state_roots(&blocks, &state, 1, &expected, None, None)?;
        assert!(result.passed);
        Ok(())
    }

    #[test]
    fn test_verify_state_roots_external_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone())];
        let mut expected = BTreeMap::new();
        expected.insert(1, Hash32([0xAA; 32]));
        let result = verify_state_roots(&blocks, &state, 1, &expected, None, None)?;
        assert!(!result.passed);
        assert!(result.mismatches.len() == 1);
        Ok(())
    }

    #[test]
    fn test_file_io_roundtrip() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
        ];
        let result = replay_chain(&blocks, &state, 1, None, None)?;
        let dir = tempfile::tempdir()?;
        let path = dir.path().join("result.json");
        save_replay_result(&result, &path)?;
        let loaded = load_replay_result(&path)?;
        assert_eq!(loaded.total_blocks, result.total_blocks);
        assert_eq!(loaded.total_gas, result.total_gas);
        Ok(())
    }

    #[test]
    fn test_compare_environments() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let mut snaps = BTreeMap::new();
        snaps.insert(
            "node-1".into(),
            vec![
                NodeSnapshot {
                    node_id: "node-1".into(),
                    height: 1,
                    state_root: root,
                    balances: None,
                    nonces: None,
                    kv: None,
                    code_hashes: None,
                    storage: None,
                    receipts: None,
                    logs: None,
                    snapshot_time: None,
                    node_version: None,
                },
            ],
        );
        let bad_root = Hash32([0xAA; 32]);
        snaps.insert(
            "node-2".into(),
            vec![
                NodeSnapshot {
                    node_id: "node-2".into(),
                    height: 1,
                    state_root: bad_root,
                    balances: None,
                    nonces: None,
                    kv: None,
                    code_hashes: None,
                    storage: None,
                    receipts: None,
                    logs: None,
                    snapshot_time: None,
                    node_version: None,
                },
            ],
        );
        let report = compare_environments(&snaps)?;
        assert!(!report.all_agree);
        assert_eq!(report.divergences.len(), 1);
        Ok(())
    }
}
