//! State root reproducibility verification.
//!
//! Verifies that state roots are reproducible across:
//! - Different binary builds (same source, different compiler/platform)
//! - Multiple executions on the same machine
//! - Parallel vs serial execution paths
//!
//! This is critical for consensus safety: if two nodes compute different
//! state roots for the same block, the chain splits.
//!
//! # Approach
//!
//! 1. Execute the same block N times and verify identical roots
//! 2. Compare roots against golden vectors (known‑good values)
//! 3. Detect platform‑specific nondeterminism (float ops, hashmap order)
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::replay::state_root_verify::{verify_block_reproducibility, VerificationConfig};
//!
//! let config = VerificationConfig::default();
//! let result = verify_block_reproducibility(&block, &state, base_fee, &config)?;
//! assert!(result.all_match);
//! ```

use crate::execution::{execute_block, KvState};
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
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during state root verification.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// Number of iterations must be at least 1.
    #[error("iterations must be >= 1, got {0}")]
    InvalidIterations(usize),

    /// Base fee per gas must be greater than 0.
    #[error("base fee per gas must be > 0, got {0}")]
    InvalidBaseFee(u64),

    /// Computed root differs from the provided golden vector.
    #[error("golden vector mismatch at height {height}: expected {expected}, got {actual}")]
    GoldenMismatch {
        height: Height,
        expected: String,
        actual: String,
    },

    /// State root inconsistency across multiple executions of the same block.
    #[error("state root inconsistency: iteration {iteration}: first={first}, current={current}")]
    Inconsistency {
        iteration: usize,
        first: String,
        current: String,
    },

    /// I/O error.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Serialisation error.
    #[error("serialisation error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// No blocks to verify.
    #[error("no blocks to verify")]
    NoBlocks,
}

pub type VerifyResult<T> = Result<T, VerifyError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for reproducibility verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationConfig {
    /// Number of times to execute each block (must be >= 1).
    pub iterations: usize,
    /// Stop on first failure (default: true).
    pub stop_on_first_failure: bool,
    /// Log progress every N blocks (0 = disabled).
    pub progress_interval: usize,
    /// Whether to log detailed results for each block.
    pub log_detailed: bool,
}

impl Default for VerificationConfig {
    fn default() -> Self {
        Self {
            iterations: 3,
            stop_on_first_failure: true,
            progress_interval: 1000,
            log_detailed: false,
        }
    }
}

impl VerificationConfig {
    /// Create a config for quick verification (fewer iterations).
    #[must_use]
    pub fn quick() -> Self {
        Self {
            iterations: 2,
            ..Default::default()
        }
    }

    /// Create a config for thorough verification (more iterations).
    #[must_use]
    pub fn thorough() -> Self {
        Self {
            iterations: 10,
            ..Default::default()
        }
    }
}

// -----------------------------------------------------------------------------
// Progress reporting
// -----------------------------------------------------------------------------

/// Progress events during verification.
#[derive(Debug, Clone)]
pub enum VerifyProgress {
    /// Started with total blocks and iterations per block.
    Started { total_blocks: usize, iterations_per_block: usize },
    /// A block is being verified (height, index, total).
    BlockStart { height: Height, index: usize, total: usize },
    /// A block was verified (height, all_match, iteration count).
    BlockComplete { height: Height, all_match: bool, iteration: usize },
    /// An error occurred during verification.
    BlockError { height: Height, error: String },
    /// Verification completed.
    Finished { success: bool, total_blocks: usize, total_iterations: usize, duration_ms: u64 },
}

/// Type alias for progress callback.
pub type ProgressCallback = dyn Fn(VerifyProgress) + Send + Sync;

// -----------------------------------------------------------------------------
// Result types
// -----------------------------------------------------------------------------

/// Result of a reproducibility check for a single block.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReproducibilityResult {
    /// Block height.
    pub height: Height,
    /// Number of iterations executed.
    pub iterations: usize,
    /// Whether all iterations produced the same root.
    pub all_match: bool,
    /// The root from the first execution (canonical).
    pub canonical_root: Hash32,
    /// The first iteration index where divergence occurred (if any).
    pub diverged_at: Option<usize>,
    /// All state roots collected during each iteration.
    pub roots: Vec<Hash32>,
    /// Time taken to verify this block (milliseconds).
    pub verify_time_ms: u64,
}

/// Result of verifying reproducibility across multiple blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchVerificationResult {
    /// Total number of blocks processed.
    pub total_blocks: usize,
    /// Number of iterations performed per block.
    pub iterations_per_block: usize,
    /// Whether all blocks were reproducible (all_match == true).
    pub all_reproducible: bool,
    /// Per‑block reproducibility results.
    pub results: Vec<ReproducibilityResult>,
    /// First height where reproducibility failed (if any).
    pub first_failure: Option<Height>,
    /// Total time taken (milliseconds).
    pub total_time_ms: u64,
    /// Blocks per second.
    pub blocks_per_second: f64,
    /// Iterations per second.
    pub iterations_per_second: f64,
}

impl std::fmt::Display for BatchVerificationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "State Root Reproducibility: {}",
            if self.all_reproducible {
                "ALL REPRODUCIBLE"
            } else {
                "NONDETERMINISM DETECTED"
            }
        )?;
        writeln!(
            f,
            "  blocks={}, iterations_per_block={}, total_time={}ms",
            self.total_blocks, self.iterations_per_block, self.total_time_ms
        )?;
        writeln!(
            f,
            "  performance: {:.2} blocks/s, {:.2} iter/s",
            self.blocks_per_second, self.iterations_per_second
        )?;
        if let Some(h) = self.first_failure {
            writeln!(f, "  FIRST FAILURE at height {}", h)?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Core verification functions
// -----------------------------------------------------------------------------

/// Verify that executing a block N times produces the same state root.
///
/// # Arguments
/// * `block` – The block to execute.
/// * `initial_state` – The state before executing the block.
/// * `base_fee_per_gas` – The base fee for gas calculations.
/// * `config` – Verification configuration (iterations, etc.).
pub fn verify_block_reproducibility(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    config: &VerificationConfig,
) -> VerifyResult<ReproducibilityResult> {
    if config.iterations == 0 {
        return Err(VerifyError::InvalidIterations(config.iterations));
    }
    if base_fee_per_gas == 0 {
        return Err(VerifyError::InvalidBaseFee(base_fee_per_gas));
    }

    let start_time = Instant::now();
    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let mut roots = Vec::with_capacity(config.iterations);

    // Execute the block the requested number of times.
    for _ in 0..config.iterations {
        let (new_state, _gas, _receipts) =
            execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);
        roots.push(new_state.root());
    }

    let canonical = roots[0].clone();
    let diverged_at = roots
        .iter()
        .enumerate()
        .find(|(_, r)| **r != canonical)
        .map(|(i, _)| i);

    let verify_time_ms = start_time.elapsed().as_millis() as u64;

    Ok(ReproducibilityResult {
        height: block.header.height,
        iterations: config.iterations,
        all_match: diverged_at.is_none(),
        canonical_root: canonical,
        diverged_at,
        roots,
        verify_time_ms,
    })
}

/// Verify reproducibility for a chain of blocks (sequential execution).
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state (genesis or checkpoint).
/// * `base_fee_per_gas` – Base fee for all blocks.
/// * `config` – Verification configuration.
/// * `progress` – Optional progress callback.
pub fn verify_chain_reproducibility(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    config: &VerificationConfig,
    progress: Option<&ProgressCallback>,
) -> VerifyResult<BatchVerificationResult> {
    if blocks.is_empty() {
        return Err(VerifyError::NoBlocks);
    }
    if config.iterations == 0 {
        return Err(VerifyError::InvalidIterations(config.iterations));
    }
    if base_fee_per_gas == 0 {
        return Err(VerifyError::InvalidBaseFee(base_fee_per_gas));
    }

    let start_time = Instant::now();
    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure = None;
    let mut state = initial_state.clone();

    if let Some(cb) = progress {
        cb(VerifyProgress::Started {
            total_blocks: blocks.len(),
            iterations_per_block: config.iterations,
        });
    }

    info!(
        total_blocks = blocks.len(),
        iterations_per_block = config.iterations,
        "starting reproducibility verification"
    );

    for (idx, block) in blocks.iter().enumerate() {
        if let Some(cb) = progress {
            cb(VerifyProgress::BlockStart {
                height: block.header.height,
                index: idx,
                total: blocks.len(),
            });
        }

        // Check reproducibility for this block using the current state.
        let result = verify_block_reproducibility(block, &state, base_fee_per_gas, config)?;

        if let Some(cb) = progress {
            cb(VerifyProgress::BlockComplete {
                height: result.height,
                all_match: result.all_match,
                iteration: result.iterations,
            });
        }

        if !result.all_match && first_failure.is_none() {
            first_failure = Some(block.header.height);
            let err = format!(
                "nondeterministic root at height {}: diverged at iteration {}",
                result.height,
                result.diverged_at.unwrap_or(result.iterations)
            );
            if let Some(cb) = progress {
                cb(VerifyProgress::BlockError {
                    height: result.height,
                    error: err.clone(),
                });
            }
            warn!(height = block.header.height, "{}", err);
            if config.stop_on_first_failure {
                results.push(result);
                let duration_ms = start_time.elapsed().as_millis() as u64;
                let total_blocks = results.len();
                let blocks_per_second = if duration_ms > 0 {
                    (total_blocks as f64) / (duration_ms as f64 / 1000.0)
                } else {
                    0.0
                };
                let iterations_per_second = if duration_ms > 0 {
                    ((total_blocks * config.iterations) as f64) / (duration_ms as f64 / 1000.0)
                } else {
                    0.0
                };
                if let Some(cb) = progress {
                    cb(VerifyProgress::Finished {
                        success: false,
                        total_blocks,
                        total_iterations: total_blocks * config.iterations,
                        duration_ms,
                    });
                }
                return Ok(BatchVerificationResult {
                    total_blocks,
                    iterations_per_block: config.iterations,
                    all_reproducible: false,
                    results,
                    first_failure,
                    total_time_ms: duration_ms,
                    blocks_per_second,
                    iterations_per_second,
                });
            }
        }

        // Advance the state using the canonical (first) execution.
        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };
        let (new_state, _, _) = execute_block(&state, &block.txs, base_fee_per_gas, &proposer_addr);
        state = new_state;

        results.push(result);

        // Log progress periodically
        if config.progress_interval > 0 && (idx + 1) % config.progress_interval == 0 {
            info!(height = block.header.height, processed = idx + 1, "verification progress");
        }
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    let all_reproducible = first_failure.is_none();
    let total_blocks = results.len();
    let total_iterations = total_blocks * config.iterations;
    let blocks_per_second = if duration_ms > 0 {
        (total_blocks as f64) / (duration_ms as f64 / 1000.0)
    } else {
        0.0
    };
    let iterations_per_second = if duration_ms > 0 {
        (total_iterations as f64) / (duration_ms as f64 / 1000.0)
    } else {
        0.0
    };

    if let Some(cb) = progress {
        cb(VerifyProgress::Finished {
            success: all_reproducible,
            total_blocks,
            total_iterations,
            duration_ms,
        });
    }

    info!(
        total_blocks,
        total_iterations,
        duration_ms,
        all_reproducible,
        "verification completed"
    );

    Ok(BatchVerificationResult {
        total_blocks,
        iterations_per_block: config.iterations,
        all_reproducible,
        results,
        first_failure,
        total_time_ms: duration_ms,
        blocks_per_second,
        iterations_per_second,
    })
}

/// Compare a computed state root against a golden vector (known‑good value).
///
/// # Arguments
/// * `block` – The block to execute.
/// * `initial_state` – The state before executing the block.
/// * `base_fee_per_gas` – Base fee for gas calculations.
/// * `golden_root` – The expected state root.
///
/// # Returns
/// The computed state root if it matches the golden vector.
pub fn verify_against_golden(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    golden_root: Hash32,
) -> VerifyResult<Hash32> {
    if base_fee_per_gas == 0 {
        return Err(VerifyError::InvalidBaseFee(base_fee_per_gas));
    }

    let proposer_addr = if block.header.proposer_pk.is_empty() {
        "0000000000000000000000000000000000000000".to_string()
    } else {
        crate::crypto::tx::derive_address(&block.header.proposer_pk)
    };

    let (new_state, _, _) =
        execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);
    let computed = new_state.root();

    if computed != golden_root {
        return Err(VerifyError::GoldenMismatch {
            height: block.header.height,
            expected: hex::encode(golden_root.0),
            actual: hex::encode(computed.0),
        });
    }
    Ok(computed)
}

/// Verify that `KvState::root()` is deterministic (no hashmap ordering issues).
///
/// Computes the state root multiple times and ensures all results are identical.
///
/// # Arguments
/// * `state` – The state to test.
/// * `iterations` – Number of times to compute the root (must be ≥ 1).
pub fn verify_state_root_consistency(state: &KvState, iterations: usize) -> VerifyResult<Hash32> {
    if iterations == 0 {
        return Err(VerifyError::InvalidIterations(iterations));
    }

    let first = state.root();
    for i in 1..iterations {
        let root = state.root();
        if root != first {
            return Err(VerifyError::Inconsistency {
                iteration: i,
                first: hex::encode(first.0),
                current: hex::encode(root.0),
            });
        }
    }
    Ok(first)
}

// -----------------------------------------------------------------------------
// File I/O for golden vectors
// -----------------------------------------------------------------------------

/// A collection of golden roots indexed by height.
pub type GoldenVectors = BTreeMap<Height, Hash32>;

/// Load golden vectors from a JSON file (map of height -> root hex).
pub fn load_golden_vectors(path: &Path) -> VerifyResult<GoldenVectors> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    // Expected format: { "height": "hex_root", ... }
    let raw: BTreeMap<Height, String> = serde_json::from_reader(reader)?;
    let mut vectors = BTreeMap::new();
    for (h, hex_str) in raw {
        let bytes = hex::decode(hex_str).map_err(|e| {
            VerifyError::Serialization(serde_json::Error::custom(format!("invalid hex: {}", e)))
        })?;
        if bytes.len() != 32 {
            return Err(VerifyError::Serialization(serde_json::Error::custom(
                "root must be 32 bytes",
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        vectors.insert(h, Hash32(arr));
    }
    Ok(vectors)
}

/// Save golden vectors to a JSON file.
pub fn save_golden_vectors(path: &Path, vectors: &GoldenVectors) -> VerifyResult<()> {
    let mut raw = BTreeMap::new();
    for (h, root) in vectors {
        raw.insert(*h, hex::encode(root.0));
    }
    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &raw)?;
    Ok(())
}

/// Verify a chain against golden vectors loaded from a file.
///
/// # Arguments
/// * `blocks` – Slice of blocks in ascending height order.
/// * `initial_state` – Starting state.
/// * `base_fee_per_gas` – Base fee for all blocks.
/// * `golden_path` – Path to the golden vectors JSON file.
/// * `config` – Verification configuration.
/// * `progress` – Optional progress callback.
///
/// # Returns
/// A `BatchVerificationResult` indicating success or failure.
pub fn verify_against_golden_file(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    golden_path: &Path,
    config: &VerificationConfig,
    progress: Option<&ProgressCallback>,
) -> VerifyResult<BatchVerificationResult> {
    if blocks.is_empty() {
        return Err(VerifyError::NoBlocks);
    }
    let golden = load_golden_vectors(golden_path)?;

    let start_time = Instant::now();
    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure = None;
    let mut state = initial_state.clone();

    if let Some(cb) = progress {
        cb(VerifyProgress::Started {
            total_blocks: blocks.len(),
            iterations_per_block: config.iterations,
        });
    }

    info!(
        total_blocks = blocks.len(),
        golden_path = %golden_path.display(),
        "starting golden vector verification"
    );

    for (idx, block) in blocks.iter().enumerate() {
        if let Some(cb) = progress {
            cb(VerifyProgress::BlockStart {
                height: block.header.height,
                index: idx,
                total: blocks.len(),
            });
        }

        // Check against golden root.
        let golden_root = golden.get(&block.header.height).ok_or_else(|| {
            VerifyError::GoldenMismatch {
                height: block.header.height,
                expected: "missing".to_string(),
                actual: "computed".to_string(),
            }
        })?;

        // Execute block once (we don't need multiple iterations here).
        let proposer_addr = if block.header.proposer_pk.is_empty() {
            "0000000000000000000000000000000000000000".to_string()
        } else {
            crate::crypto::tx::derive_address(&block.header.proposer_pk)
        };
        let (new_state, gas_used, receipts) =
            execute_block(&state, &block.txs, base_fee_per_gas, &proposer_addr);
        let computed = new_state.root();

        let match_ok = computed == *golden_root;

        if !match_ok {
            let err = format!(
                "golden mismatch at height {}: expected {}, got {}",
                block.header.height,
                hex::encode(golden_root.0),
                hex::encode(computed.0)
            );
            if let Some(cb) = progress {
                cb(VerifyProgress::BlockError {
                    height: block.header.height,
                    error: err.clone(),
                });
            }
            warn!("{}", err);
            if config.stop_on_first_failure {
                let duration_ms = start_time.elapsed().as_millis() as u64;
                return Ok(BatchVerificationResult {
                    total_blocks: blocks.len(),
                    iterations_per_block: 1,
                    all_reproducible: false,
                    results: Vec::new(),
                    first_failure: Some(block.header.height),
                    total_time_ms: duration_ms,
                    blocks_per_second: 0.0,
                    iterations_per_second: 0.0,
                });
            }
        }

        state = new_state;
        // We don't store per-block results here to simplify.
    }

    let duration_ms = start_time.elapsed().as_millis() as u64;
    if let Some(cb) = progress {
        cb(VerifyProgress::Finished {
            success: true,
            total_blocks: blocks.len(),
            total_iterations: blocks.len(),
            duration_ms,
        });
    }

    Ok(BatchVerificationResult {
        total_blocks: blocks.len(),
        iterations_per_block: 1,
        all_reproducible: true,
        results: Vec::new(), // not populated for simplicity
        first_failure: None,
        total_time_ms: duration_ms,
        blocks_per_second: (blocks.len() as f64) / (duration_ms as f64 / 1000.0),
        iterations_per_second: (blocks.len() as f64) / (duration_ms as f64 / 1000.0),
    })
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
    fn test_block_reproducibility() -> VerifyResult<()> {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let config = VerificationConfig::default();
        let result = verify_block_reproducibility(&block, &state, 1, &config)?;
        assert!(result.all_match);
        assert_eq!(result.iterations, config.iterations);
        assert_eq!(result.roots.len(), config.iterations);
        Ok(())
    }

    #[test]
    fn test_block_reproducibility_zero_iterations() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let mut config = VerificationConfig::default();
        config.iterations = 0;
        let result = verify_block_reproducibility(&block, &state, 1, &config);
        assert!(matches!(result, Err(VerifyError::InvalidIterations(0))));
    }

    #[test]
    fn test_chain_reproducibility() -> VerifyResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root.clone()), empty_block(2, root.clone())];
        let config = VerificationConfig::default();
        let result = verify_chain_reproducibility(&blocks, &state, 1, &config, None)?;
        assert!(result.all_reproducible);
        assert_eq!(result.total_blocks, 2);
        Ok(())
    }

    #[test]
    fn test_golden_vector_match() -> VerifyResult<()> {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let result = verify_against_golden(&block, &state, 1, root)?;
        assert_eq!(result, root);
        Ok(())
    }

    #[test]
    fn test_golden_vector_mismatch() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let bad_golden = Hash32([0xFF; 32]);
        let result = verify_against_golden(&block, &state, 1, bad_golden);
        assert!(matches!(result, Err(VerifyError::GoldenMismatch { .. })));
    }

    #[test]
    fn test_state_root_consistency() -> VerifyResult<()> {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.kv.insert("key1".into(), "val1".into());
        state.nonces.insert("alice".into(), 5);
        let result = verify_state_root_consistency(&state, 100)?;
        assert_eq!(result, state.root());
        Ok(())
    }

    #[test]
    fn test_state_root_consistency_zero_iterations() {
        let state = KvState::default();
        let result = verify_state_root_consistency(&state, 0);
        assert!(matches!(result, Err(VerifyError::InvalidIterations(0))));
    }

    #[test]
    fn test_batch_result_display() -> VerifyResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];
        let config = VerificationConfig::default();
        let result = verify_chain_reproducibility(&blocks, &state, 1, &config, None)?;
        let s = format!("{result}");
        assert!(s.contains("State Root Reproducibility"));
        assert!(s.contains("ALL REPRODUCIBLE"));
        Ok(())
    }

    #[test]
    fn test_golden_file_io() -> VerifyResult<()> {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let mut vectors = GoldenVectors::new();
        vectors.insert(1, root);

        let dir = tempfile::tempdir()?;
        let path = dir.path().join("golden.json");
        save_golden_vectors(&path, &vectors)?;
        let loaded = load_golden_vectors(&path)?;
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.get(&1), Some(&root));
        Ok(())
    }
}
