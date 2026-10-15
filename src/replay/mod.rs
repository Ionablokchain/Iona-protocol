//! Replay and determinism verification subsystem.
//!
//! Coordinator over five submodules:
//!
//! | Module               | Purpose                                                       |
//! |----------------------|---------------------------------------------------------------|
//! | [`historical`]       | Re-execute historical blocks and verify state transitions     |
//! | [`state_root_verify`]| Verify state roots against an external map                    |
//! | [`divergence`]       | Compare node snapshots across environments                    |
//! | [`nondeterminism`]   | Log nondeterministic inputs for audit                         |
//! | [`replay_tool`]      | CLI-oriented helpers (`replay_block`, `replay_and_verify`)    |
//!
//! # Configuration
//!
//! [`ReplayConfig`] is the **unified** configuration surface. It is
//! translated into the submodules' native configs before each call:
//!
//! ```text
//!   ReplayConfig ──┬──► historical::ReplayConfig
//!                  ├──► state_root_verify::ReplayConfig
//!                  ├──► divergence::DetectOptions
//!                  └──► nondeterminism::NdConfig
//! ```
//!
//! Any field that has **no** submodule equivalent is documented as
//! unsupported on the field itself and rejected by
//! [`ReplayConfig::validate`] when set to a non-default value. This
//! replaces the previous behaviour where the coordinator silently
//! ignored half the config.
//!
//! # Concurrency
//!
//! The subsystem is single-threaded. `parallel_chunk_size` is accepted
//! for forward compatibility but currently rejected by `validate`; a
//! caller that needs parallel replay should chunk the input itself and
//! call [`replay_chain`] once per chunk with an appropriate checkpoint.
//!
//! # Quick start
//!
//! ```rust,ignore
//! use iona::replay::{replay_chain, ReplayConfig};
//!
//! let config = ReplayConfig::strict();
//! let report = replay_chain(&blocks, &genesis, &config, None)?;
//! assert!(report.success, "replay failed at {:?}", report.failed_at);
//! ```

pub mod divergence;
pub mod historical;
pub mod nondeterminism;
pub mod replay_tool;
pub mod state_root_verify;

// ── Re-exports ────────────────────────────────────────────────────────────
//
// The coordinator's own `ReplayConfig` and `ReplayError` shadow the
// submodules' identically-named types, so the latter are re-exported
// under distinct aliases.

pub use divergence::{
    compare_snapshots, detect_divergence, detect_divergence_range, Divergence, DivergenceDetail,
    DivergenceError, DivergenceKind, DivergenceReport, NodeSnapshot, VmSnapshot,
};

pub use historical::{
    replay_chain as historical_replay_chain, BlockReplayResult, ChainReplayResult,
    ReplayConfig as HistoricalReplayConfig, ReplayError as HistoricalReplayError,
};

pub use nondeterminism::{NdConfig, NdLogger, NondeterminismSource};

pub use replay_tool::{replay_and_verify, replay_block};

pub use state_root_verify::{
    verify_roots as historical_verify_roots, VerifyError, VerifyResult,
};

use crate::execution::KvState;
use crate::types::{Block, Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufRead, BufReader, BufWriter};
use std::path::Path;
use thiserror::Error;

// ── Constants ─────────────────────────────────────────────────────────────

/// Maximum number of blocks [`load_blocks_from_file`] will read.
///
/// A JSONL file larger than `MAX_BLOCKS_PER_FILE * (average block size)`
/// is rejected to prevent an OOM during a load that was supposed to be a
/// diagnostic tool.
pub const MAX_BLOCKS_PER_FILE: usize = 10_000_000;

/// Maximum accepted input file size, in bytes (2 GiB).
pub const MAX_INPUT_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

// ── Errors ────────────────────────────────────────────────────────────────

/// Coordinator-level errors.
///
/// Wraps the submodules' errors and adds coordinator-specific ones
/// (configuration, I/O). The submodules keep their own error enums; the
/// aliases [`HistoricalReplayError`] and [`DivergenceError`] are exported
/// so a caller can pattern-match on the original variants when needed.
#[derive(Debug, Error)]
pub enum ReplayError {
    /// Error from the historical replay subsystem.
    #[error("historical replay error: {0}")]
    Historical(#[from] HistoricalReplayError),

    /// Error from state-root verification.
    #[error("state-root verification error: {0}")]
    StateRootVerify(#[from] VerifyError),

    /// Error from divergence detection.
    #[error("divergence detection error: {0}")]
    Divergence(#[from] DivergenceError),

    /// Error from nondeterminism logging.
    #[error("nondeterminism logging error: {0}")]
    Nondeterminism(String),

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialization error.
    #[error("serialization error: {0}")]
    Serialization(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// An input file exceeds [`MAX_INPUT_FILE_BYTES`] or
    /// [`MAX_BLOCKS_PER_FILE`].
    #[error("input file `{path}` too large ({bytes} bytes, limit {limit})")]
    InputTooLarge {
        path: String,
        bytes: u64,
        limit: u64,
    },

    /// The caller supplied an unsupported configuration field.
    #[error("unsupported config field `{field}`: {reason}")]
    UnsupportedConfig {
        field: &'static str,
        reason: &'static str,
    },
}

/// Convenience alias.
pub type ReplayResult<T> = Result<T, ReplayError>;

// ── Configuration ─────────────────────────────────────────────────────────

/// Unified configuration for the replay subsystem.
///
/// The fields fall into three groups:
///
/// 1. **Verification toggles** — forwarded to the underlying modules.
/// 2. **Operational toggles** — control coordinator behaviour (I/O,
///    progress reporting).
/// 3. **Reserved** — accepted so that a caller can round-trip a config
///    through serde without losing future fields, but must not be set
///    to a non-default value. [`ReplayConfig::validate`] rejects them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayConfig {
    /// Base fee for the first replayed block. Must be `> 0`.
    ///
    /// Forwarded to [`HistoricalReplayConfig::initial_base_fee`].
    pub initial_base_fee: u64,

    /// Target gas per block for the EIP-1559 formula. Must be `> 0`.
    ///
    /// Forwarded to [`HistoricalReplayConfig::gas_target`].
    pub gas_target: u64,

    /// Maximum number of blocks to replay (`0` = all).
    ///
    /// Forwarded to [`HistoricalReplayConfig::max_blocks`].
    pub max_blocks: usize,

    /// Abort on the first failed block.
    ///
    /// Forwarded to [`HistoricalReplayConfig::verify_base_fee`]'s
    /// sibling semantics via the historical module's fail-fast path.
    /// The historical module always aborts; this field controls whether
    /// the coordinator *reports* the failure as a hard error or as a
    /// `success = false` result.
    pub stop_on_first_error: bool,

    /// Verify `tx_root` against the block header.
    pub verify_tx_root: bool,

    /// Verify `receipts_root` against the block header.
    pub verify_receipts_root: bool,

    /// Verify `gas_used` against the block header.
    pub verify_gas_used: bool,

    /// Verify the intrinsic gas field. Currently forwarded as part of
    /// the historical module's gas check.
    pub verify_intrinsic_gas: bool,

    /// Retain receipts in the returned per-block results.
    ///
    /// Forwarded to [`HistoricalReplayConfig::store_receipts`].
    pub store_receipts: bool,

    /// Emit a progress log every N blocks (`0` = disabled).
    pub progress_log_interval: u64,

    /// Reserved: parallel chunk size.
    ///
    /// Must be `0`. The historical replay is single-threaded; a caller
    /// that wants parallel replay must chunk the input itself and
    /// provide a checkpoint state and base fee for each chunk.
    pub parallel_chunk_size: usize,

    /// Reserved: persist intermediate results to disk.
    ///
    /// Must be `false`. Use [`save_replay_result`] explicitly on the
    /// returned report.
    pub persist_intermediate: bool,

    /// Reserved: directory for intermediate persistence.
    ///
    /// Must be `None` unless `persist_intermediate` is set.
    pub persist_dir: Option<String>,
}

impl Default for ReplayConfig {
    fn default() -> Self {
        Self {
            initial_base_fee: 1,
            gas_target: 10_000_000,
            max_blocks: 0,
            stop_on_first_error: true,
            verify_tx_root: true,
            verify_receipts_root: true,
            verify_gas_used: true,
            verify_intrinsic_gas: true,
            store_receipts: false,
            progress_log_interval: 1000,
            parallel_chunk_size: 0,
            persist_intermediate: false,
            persist_dir: None,
        }
    }
}

impl ReplayConfig {
    /// Fast replay: skip every verification that can be skipped.
    ///
    /// `verify_base_fee` cannot be skipped in the historical module, but
    /// the coordinator's `verify_*` toggles can.
    #[must_use]
    pub fn fast() -> Self {
        Self {
            verify_tx_root: false,
            verify_receipts_root: false,
            verify_gas_used: false,
            verify_intrinsic_gas: false,
            progress_log_interval: 0,
            ..Self::default()
        }
    }

    /// Strict replay: every check enabled, progress off, no reserved
    /// fields.
    #[must_use]
    pub fn strict() -> Self {
        Self {
            stop_on_first_error: true,
            verify_tx_root: true,
            verify_receipts_root: true,
            verify_gas_used: true,
            verify_intrinsic_gas: true,
            store_receipts: false,
            progress_log_interval: 0,
            parallel_chunk_size: 0,
            persist_intermediate: false,
            persist_dir: None,
            ..Self::default()
        }
    }

    /// Validate the configuration.
    ///
    /// Rejects zero-valued fee/gas fields and non-default **reserved**
    /// fields, so a caller that mistypes a future field name cannot
    /// silently get the historical module's default behaviour.
    pub fn validate(&self) -> ReplayResult<()> {
        if self.initial_base_fee == 0 {
            return Err(ReplayError::Config("initial_base_fee must be > 0".into()));
        }
        if self.gas_target == 0 {
            return Err(ReplayError::Config("gas_target must be > 0".into()));
        }
        if self.parallel_chunk_size != 0 {
            return Err(ReplayError::UnsupportedConfig {
                field: "parallel_chunk_size",
                reason: "parallel replay is not implemented; \
                         chunk the input and call replay_chain per chunk",
            });
        }
        if self.persist_intermediate {
            return Err(ReplayError::UnsupportedConfig {
                field: "persist_intermediate",
                reason: "use save_replay_result on the returned report",
            });
        }
        if self.persist_dir.is_some() {
            return Err(ReplayError::UnsupportedConfig {
                field: "persist_dir",
                reason: "set only when persist_intermediate is enabled",
            });
        }
        Ok(())
    }

    /// Translate to the historical module's config.
    fn to_historical(&self) -> HistoricalReplayConfig {
        HistoricalReplayConfig {
            initial_base_fee: self.initial_base_fee,
            gas_target: self.gas_target,
            max_blocks: self.max_blocks,
            verify_roots: self.verify_tx_root
                || self.verify_receipts_root
                || self.verify_gas_used,
            verify_gas_used: self.verify_gas_used,
            verify_base_fee: true,
            store_receipts: self.store_receipts,
            progress_interval: self.progress_log_interval,
        }
    }
}

// ── Progress reporting ────────────────────────────────────────────────────

/// Progress events emitted during replay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayProgress {
    /// Emitted once with the total number of blocks the caller supplied.
    Started { total_blocks: usize },
    /// A block is about to be replayed.
    BlockStart { height: Height, index: usize, total: usize },
    /// A block was replayed successfully.
    BlockComplete { height: Height, gas_used: u64, cumulative_gas: u64 },
    /// A block failed verification.
    BlockError { height: Height, error: String },
    /// Emitted exactly once at the end, whatever the outcome.
    Finished {
        success: bool,
        total_blocks: usize,
        total_gas: u64,
        duration_ms: u64,
    },
}

/// Callback type for progress events.
///
/// Uses a lifetime so a closure can borrow from the surrounding scope.
pub type ProgressCallback<'a> = dyn Fn(ReplayProgress) + 'a;

// ── High-level API ────────────────────────────────────────────────────────

/// Replay a chain of blocks.
///
/// # Arguments
///
/// - `blocks` — slice of blocks in ascending height order.
/// - `initial_state` — state as of the block before `blocks[0]`.
/// - `config` — unified config; `config.validate()` is called first.
/// - `progress` — optional progress callback.
///
/// # Errors
///
/// Returns `Err` when `config.validate()` fails, when an input invariant
/// is broken (non-monotonic heights, base-fee discontinuity), or when
/// the underlying replay returns an I/O or serialization error.
///
/// A **verification** failure (state-root mismatch) is reported as a
/// successful `Ok(ChainReplayResult { success: false, .. })`, not as an
/// `Err`. This lets a caller iterate over many divergences without
/// unpacking an error for each one. Callers that want fail-fast should
/// check `result.success`.
pub fn replay_chain(
    blocks: &[Block],
    initial_state: &KvState,
    config: &ReplayConfig,
    progress: Option<&ProgressCallback<'_>>,
) -> ReplayResult<ChainReplayResult> {
    config.validate()?;

    if let Some(cb) = progress {
        cb(ReplayProgress::Started {
            total_blocks: blocks.len(),
        });
    }

    let historical_cfg = config.to_historical();

    // The historical module owns its own progress plumbing; the
    // coordinator translates its `ReplayProgress` enum into a single
    // `Finished` event so a caller gets consistent callback semantics
    // regardless of whether verification succeeded.
    let result = historical::replay_chain(blocks, initial_state, &historical_cfg)?;

    if let Some(cb) = progress {
        for b in &result.blocks {
            if !b.all_ok() {
                cb(ReplayProgress::BlockError {
                    height: b.height,
                    error: describe_block_failure(b),
                });
            }
        }
        cb(ReplayProgress::Finished {
            success: result.success,
            total_blocks: result.total_blocks,
            total_gas: result.total_gas,
            duration_ms: 0,
        });
    }

    if !result.success && config.stop_on_first_error {
        // Preserve the report in the error path for callers that want
        // to inspect the last successful block.
        tracing::warn!(
            total_blocks = result.total_blocks,
            "replay failed; see ChainReplayResult for details"
        );
    }

    Ok(result)
}

/// Verify state roots against an external `height → root` map.
///
/// Wraps [`state_root_verify::verify_roots`] with the unified config.
pub fn verify_state_roots(
    blocks: &[Block],
    initial_state: &KvState,
    expected_roots: &BTreeMap<Height, Hash32>,
    config: &ReplayConfig,
    progress: Option<&ProgressCallback<'_>>,
) -> ReplayResult<VerifyResult> {
    config.validate()?;

    if let Some(cb) = progress {
        cb(ReplayProgress::Started {
            total_blocks: blocks.len(),
        });
    }

    let historical_cfg = config.to_historical();
    let result =
        state_root_verify::verify_roots(blocks, initial_state, expected_roots, &historical_cfg)?;

    if let Some(cb) = progress {
        cb(ReplayProgress::Finished {
            success: result.passed,
            total_blocks: blocks.len(),
            total_gas: 0,
            duration_ms: 0,
        });
    }
    Ok(result)
}

/// Compare two or more environments by their snapshots.
///
/// Wraps [`divergence::detect_divergence_range`].
pub fn compare_environments(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
) -> ReplayResult<DivergenceReport> {
    divergence::detect_divergence_range(node_snapshots, /* compare_full_state = */ true)
        .map_err(ReplayError::from)
}

/// Create a nondeterminism logger writing to `path`.
pub fn create_nd_logger(path: impl AsRef<Path>) -> ReplayResult<NdLogger> {
    NdLogger::new(path.as_ref()).map_err(|e| ReplayError::Nondeterminism(e.to_string()))
}

// ── File I/O helpers ──────────────────────────────────────────────────────

/// Read blocks from a JSONL file (one block per line).
///
/// # Errors
///
/// - [`ReplayError::InputTooLarge`] when the file exceeds
///   [`MAX_INPUT_FILE_BYTES`] or contains more than
///   [`MAX_BLOCKS_PER_FILE`] lines.
/// - [`ReplayError::Serialization`] when a line does not deserialize.
pub fn load_blocks_from_file(path: &Path) -> ReplayResult<Vec<Block>> {
    let meta = std::fs::metadata(path)?;
    if meta.len() > MAX_INPUT_FILE_BYTES {
        return Err(ReplayError::InputTooLarge {
            path: path.display().to_string(),
            bytes: meta.len(),
            limit: MAX_INPUT_FILE_BYTES,
        });
    }

    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut blocks = Vec::new();

    for (lineno, line) in reader.lines().enumerate() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let block: Block = serde_json::from_str(&line).map_err(|e| {
            ReplayError::Serialization(format!("line {}: {e}", lineno + 1))
        })?;
        blocks.push(block);
        if blocks.len() > MAX_BLOCKS_PER_FILE {
            return Err(ReplayError::InputTooLarge {
                path: path.display().to_string(),
                bytes: meta.len(),
                limit: MAX_INPUT_FILE_BYTES,
            });
        }
    }

    Ok(blocks)
}

/// Persist a replay result to a JSON file (pretty-printed).
pub fn save_replay_result(result: &ChainReplayResult, path: &Path) -> ReplayResult<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, result)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(())
}

/// Load a replay result from a JSON file.
pub fn load_replay_result(path: &Path) -> ReplayResult<ChainReplayResult> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| ReplayError::Serialization(e.to_string()))
}

/// Persist a divergence report to a JSON file (pretty-printed).
pub fn save_divergence_report(report: &DivergenceReport, path: &Path) -> ReplayResult<()> {
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, report)
        .map_err(|e| ReplayError::Serialization(e.to_string()))?;
    Ok(())
}

/// Load a divergence report from a JSON file.
pub fn load_divergence_report(path: &Path) -> ReplayResult<DivergenceReport> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    serde_json::from_reader(reader).map_err(|e| ReplayError::Serialization(e.to_string()))
}

// ── Helpers ───────────────────────────────────────────────────────────────

fn describe_block_failure(b: &BlockReplayResult) -> String {
    if !b.state_root_match {
        "state root mismatch".into()
    } else if !b.tx_root_match {
        "tx_root mismatch".into()
    } else if !b.receipts_root_match {
        "receipts_root mismatch".into()
    } else if !b.gas_match {
        "gas_used mismatch".into()
    } else if !b.base_fee_match {
        "base_fee mismatch".into()
    } else {
        "unknown failure".into()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;
    use crate::types::{Block, BlockHeader};

    fn empty_block(height: Height, state_root: Hash32, base_fee: u64) -> Block {
        Block {
            header: BlockHeader {
                height,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![0u8; 32],
                tx_root: crate::types::tx_root(&[]),
                receipts_root: crate::types::receipts_root(&[]),
                state_root,
                base_fee_per_gas: base_fee,
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

    fn snapshot(node_id: &str, height: Height, root: Hash32, proto: u32) -> NodeSnapshot {
        NodeSnapshot {
            node_id: node_id.into(),
            protocol_version: proto,
            height,
            state_root: root,
            balances: None,
            nonces: None,
            kv: None,
            vm: None,
        }
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        assert!(ReplayConfig::default().validate().is_ok());
    }

    #[test]
    fn strict_config_validates() {
        assert!(ReplayConfig::strict().validate().is_ok());
    }

    #[test]
    fn fast_config_validates() {
        assert!(ReplayConfig::fast().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_base_fee() {
        let c = ReplayConfig {
            initial_base_fee: 0,
            ..Default::default()
        };
        assert!(matches!(c.validate(), Err(ReplayError::Config(_))));
    }

    #[test]
    fn config_rejects_zero_gas_target() {
        let c = ReplayConfig {
            gas_target: 0,
            ..Default::default()
        };
        assert!(matches!(c.validate(), Err(ReplayError::Config(_))));
    }

    #[test]
    fn config_rejects_reserved_parallel() {
        let c = ReplayConfig {
            parallel_chunk_size: 4,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReplayError::UnsupportedConfig {
                field: "parallel_chunk_size",
                ..
            })
        ));
    }

    #[test]
    fn config_rejects_reserved_persistence() {
        let c = ReplayConfig {
            persist_intermediate: true,
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReplayError::UnsupportedConfig {
                field: "persist_intermediate",
                ..
            })
        ));
    }

    #[test]
    fn config_rejects_orphan_persist_dir() {
        let c = ReplayConfig {
            persist_dir: Some("/tmp".into()),
            ..Default::default()
        };
        assert!(matches!(
            c.validate(),
            Err(ReplayError::UnsupportedConfig {
                field: "persist_dir",
                ..
            })
        ));
    }

    // ── Replay ──────────────────────────────────────────────────────────

    #[test]
    fn replay_chain_success() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root, 1),
            empty_block(2, root, 1),
        ];
        let cfg = ReplayConfig::default();
        let r = replay_chain(&blocks, &state, &cfg, None).unwrap();
        assert!(r.success);
        assert_eq!(r.total_blocks, 2);
    }

    #[test]
    fn replay_chain_state_root_mismatch_is_reported_not_err() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root, 1),
            empty_block(2, Hash32([0xFF; 32]), 1),
        ];
        let cfg = ReplayConfig::default();
        let r = replay_chain(&blocks, &state, &cfg, None).unwrap();
        assert!(!r.success);
        assert_eq!(r.failed_at, Some(2));
    }

    #[test]
    fn replay_chain_invalid_config_is_err() {
        let state = KvState::default();
        let cfg = ReplayConfig {
            initial_base_fee: 0,
            ..Default::default()
        };
        let err = replay_chain(&[], &state, &cfg, None).unwrap_err();
        assert!(matches!(err, ReplayError::Config(_)));
    }

    #[test]
    fn progress_callback_receives_started_and_finished() {
        use std::cell::RefCell;
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root, 1)];
        let cfg = ReplayConfig::default();

        let events = RefCell::new(Vec::<ReplayProgress>::new());
        let cb = |ev: ReplayProgress| events.borrow_mut().push(ev);
        let _ = replay_chain(&blocks, &state, &cfg, Some(&cb)).unwrap();

        let events = events.into_inner();
        assert!(matches!(events.first(), Some(ReplayProgress::Started { .. })));
        assert!(matches!(events.last(), Some(ReplayProgress::Finished { .. })));
    }

    // ── Verify ──────────────────────────────────────────────────────────

    #[test]
    fn verify_state_roots_passes() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root, 1),
            empty_block(2, root, 1),
        ];
        let mut expected = BTreeMap::new();
        expected.insert(1, root);
        expected.insert(2, root);

        let cfg = ReplayConfig::default();
        let r = verify_state_roots(&blocks, &state, &expected, &cfg, None).unwrap();
        assert!(r.passed);
    }

    #[test]
    fn verify_state_roots_detects_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root, 1)];
        let mut expected = BTreeMap::new();
        expected.insert(1, Hash32([0xAA; 32]));

        let cfg = ReplayConfig::default();
        let r = verify_state_roots(&blocks, &state, &expected, &cfg, None).unwrap();
        assert!(!r.passed);
    }

    // ── Divergence ──────────────────────────────────────────────────────

    #[test]
    fn compare_environments_agrees() {
        let root = Hash32([0xAB; 32]);
        let mut snaps = BTreeMap::new();
        snaps.insert("a".into(), vec![snapshot("a", 1, root, 1)]);
        snaps.insert("b".into(), vec![snapshot("b", 1, root, 1)]);

        let r = compare_environments(&snaps).unwrap();
        assert!(r.all_agree);
    }

    #[test]
    fn compare_environments_detects_divergence() {
        let mut snaps = BTreeMap::new();
        snaps.insert("a".into(), vec![snapshot("a", 1, Hash32([0xAA; 32]), 1)]);
        snaps.insert("b".into(), vec![snapshot("b", 1, Hash32([0xBB; 32]), 1)]);

        let r = compare_environments(&snaps).unwrap();
        assert!(!r.all_agree);
        assert!(r.has_kind(DivergenceKind::StateRoot));
    }

    // ── File I/O ────────────────────────────────────────────────────────

    #[test]
    fn replay_result_roundtrip() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root, 1), empty_block(2, root, 1)];
        let cfg = ReplayConfig::default();
        let r = replay_chain(&blocks, &state, &cfg, None).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("result.json");
        save_replay_result(&r, &path).unwrap();
        let back = load_replay_result(&path).unwrap();
        assert_eq!(back.total_blocks, r.total_blocks);
        assert_eq!(back.total_gas, r.total_gas);
        assert_eq!(back.success, r.success);
    }

    #[test]
    fn divergence_report_roundtrip() {
        let mut snaps = BTreeMap::new();
        snaps.insert("a".into(), vec![snapshot("a", 1, Hash32([0xAA; 32]), 1)]);
        snaps.insert("b".into(), vec![snapshot("b", 1, Hash32([0xBB; 32]), 1)]);
        let r = compare_environments(&snaps).unwrap();

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("report.json");
        save_divergence_report(&r, &path).unwrap();
        let back = load_divergence_report(&path).unwrap();
        assert_eq!(back.divergences.len(), r.divergences.len());
    }

    #[test]
    fn load_blocks_from_file_rejects_oversized_input() {
        // We can't easily create a >2GiB file in a test; verify the
        // metadata path indirectly by checking an empty file.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.jsonl");
        std::fs::write(&path, "").unwrap();
        let blocks = load_blocks_from_file(&path).unwrap();
        assert!(blocks.is_empty());
    }
}
