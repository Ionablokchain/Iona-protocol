//! State root reproducibility verification.
//!
//! Verifies that state roots are reproducible across:
//!
//! - Different binary builds (same source, different compiler/platform).
//! - Multiple executions on the same machine.
//! - Parallel vs serial execution paths.
//!
//! This is critical for consensus safety: if two nodes compute different
//! state roots for the same block, the chain splits.
//!
//! # Approach
//!
//! 1. Execute each block `N` times from the **same** pre-block state and
//!    verify that all executions produce identical roots.
//! 2. Compare roots against golden vectors (known-good values) when
//!    supplied.
//! 3. Optionally capture a [`NdLogger`] report describing any
//!    nondeterminism observed during verification.
//!
//! # Bounds
//!
//! [`ReproducibilityConfig::iterations_per_block`] is capped at
//! [`MAX_ITERATIONS_PER_BLOCK`]. The cost of verification is
//! `blocks × iterations_per_block` block executions; without a cap a
//! caller could pass `usize::MAX` and hang the tool.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::replay::state_root_verify::{ReproducibilityConfig, verify_chain_reproducibility};
//!
//! let config = ReproducibilityConfig::default();
//! let result = verify_chain_reproducibility(&blocks, &state, &config)?;
//! assert!(result.all_reproducible);
//! ```

use crate::execution::{execute_block, KvState};
use crate::replay::nondeterminism::{NdLogger, NdSeverity, NdSource};
use crate::types::{Block, Hash32, Height};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

// ── Limits ────────────────────────────────────────────────────────────────

/// Upper bound on [`ReproducibilityConfig::iterations_per_block`].
///
/// A single verification pass re-executes each block
/// `iterations_per_block` times. At 1 000 the total work is
/// `blocks × 1 000`; combined with a large block slice this already takes
/// hours. Values above the cap are rejected.
pub const MAX_ITERATIONS_PER_BLOCK: usize = 1_000;

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors returned by the reproducibility verifiers.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ReproducibilityError {
    /// `iterations_per_block == 0` would make the check a no-op and
    /// `roots[0]` would panic.
    #[error("iterations_per_block must be > 0")]
    ZeroIterations,

    /// `iterations_per_block > MAX_ITERATIONS_PER_BLOCK`.
    #[error("iterations_per_block ({0}) exceeds MAX_ITERATIONS_PER_BLOCK ({MAX_ITERATIONS_PER_BLOCK})")]
    TooManyIterations(usize),

    /// A block's proposer public key could not be converted into an
    /// address.
    #[error("invalid proposer pubkey at height {height}: {reason}")]
    InvalidProposer { height: Height, reason: String },

    /// The initial state failed `KvState::root()` consistency check.
    #[error("state root not consistent: {0}")]
    StateRootInconsistent(String),
}

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for reproducibility verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityConfig {
    /// Number of times to execute each block. Must be in
    /// `[1, MAX_ITERATIONS_PER_BLOCK]`.
    pub iterations_per_block: usize,
    /// Stop at the first block whose iterations produce different roots.
    pub stop_on_first_failure: bool,
    /// Record nondeterminism events into an [`NdLogger`] alongside the
    /// verification.
    pub enable_nondeterminism_logging: bool,
    /// Base fee used for every block execution.
    ///
    /// The real chain derives this from EIP-1559; the verifier does not
    /// attempt to reproduce the EIP-1559 schedule, it only checks that
    /// execution is a pure function of `(state, block, base_fee)`.
    pub base_fee_per_gas: u64,
}

impl Default for ReproducibilityConfig {
    fn default() -> Self {
        Self {
            iterations_per_block: 3,
            stop_on_first_failure: true,
            enable_nondeterminism_logging: false,
            base_fee_per_gas: 1,
        }
    }
}

impl ReproducibilityConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ReproducibilityError> {
        if self.iterations_per_block == 0 {
            return Err(ReproducibilityError::ZeroIterations);
        }
        if self.iterations_per_block > MAX_ITERATIONS_PER_BLOCK {
            return Err(ReproducibilityError::TooManyIterations(
                self.iterations_per_block,
            ));
        }
        if self.base_fee_per_gas == 0 {
            // Not a hard error — the caller may legitimately want to
            // exercise zero-fee execution. Documented, not enforced.
        }
        Ok(())
    }
}

// ── Result types ──────────────────────────────────────────────────────────

/// Result of a reproducibility check for a single block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReproducibilityResult {
    pub height: Height,
    pub iterations: usize,
    pub all_match: bool,
    /// The canonical root (from the first execution).
    pub canonical_root: Hash32,
    /// The pre-block state root, for cross-referencing divergence reports.
    pub input_root: Hash32,
    /// If any mismatch, the 0-based iteration at which divergence was
    /// detected.
    pub diverged_at: Option<usize>,
    /// All computed roots, in execution order.
    pub roots: Vec<Hash32>,
    /// Human-readable description of the divergence, when present.
    pub diff_description: Option<String>,
}

/// Result of verifying reproducibility across multiple blocks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchReproducibilityResult {
    /// Number of blocks actually verified. When `stop_on_first_failure`
    /// is set, this can be less than the input length.
    pub total_blocks: usize,
    /// Total number of block executions performed
    /// (`sum(results[i].iterations)`).
    pub total_iterations: usize,
    pub all_reproducible: bool,
    pub results: Vec<ReproducibilityResult>,
    /// First block whose iterations produced different roots.
    pub first_failure: Option<Height>,
    /// `Display` of the [`NdLogger::report`] when
    /// `enable_nondeterminism_logging` is set.
    pub nondeterminism_report: Option<String>,
}

impl BatchReproducibilityResult {
    /// Blocks that were not reproducible.
    #[must_use]
    pub fn failures(&self) -> Vec<&ReproducibilityResult> {
        self.results.iter().filter(|r| !r.all_match).collect()
    }
}

impl std::fmt::Display for BatchReproducibilityResult {
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
            "  blocks={}, total_iterations={}",
            self.total_blocks, self.total_iterations
        )?;
        if let Some(h) = self.first_failure {
            writeln!(f, "  FIRST FAILURE at height {h}")?;
        }
        if let Some(report) = &self.nondeterminism_report {
            writeln!(f, "\n{report}")?;
        }
        Ok(())
    }
}

// ── Verification ──────────────────────────────────────────────────────────

/// Verify that executing `block` `N` times produces the same state root.
///
/// Also returns the **post-block state** from the first (canonical)
/// execution so a chain verifier does not need to execute the block a
/// second time to advance.
///
/// # Errors
///
/// - [`ReproducibilityError::ZeroIterations`] when the config is
///   invalid.
/// - [`ReproducibilityError::InvalidProposer`] when the block's proposer
///   public key cannot be turned into an address.
pub fn verify_block_reproducibility(
    block: &Block,
    initial_state: &KvState,
    config: &ReproducibilityConfig,
    logger: Option<&NdLogger>,
) -> Result<(ReproducibilityResult, KvState), ReproducibilityError> {
    config.validate()?;
    let proposer_addr = resolve_proposer(block)?;
    let height = block.header.height;
    let input_root = initial_state.root();

    let mut roots: Vec<Hash32> = Vec::with_capacity(config.iterations_per_block);
    let mut canonical_state: Option<KvState> = None;

    for i in 0..config.iterations_per_block {
        let (new_state, _gas, _receipts) = execute_block(
            initial_state,
            &block.txs,
            config.base_fee_per_gas,
            &proposer_addr,
        );
        let root = new_state.root();

        if i == 0 {
            canonical_state = Some(new_state);
        }
        roots.push(root);
    }

    // The first execution established the canonical state.
    let canonical_state = canonical_state.expect("iterations_per_block > 0 guaranteed above");
    let canonical_root = roots[0];

    let diverged_at = roots
        .iter()
        .enumerate()
        .skip(1)
        .find(|(_, r)| **r != canonical_root)
        .map(|(i, _)| i);

    // Log only on actual divergence. Logging every iteration would drown
    // the audit trail.
    if let Some(l) = logger {
        if config.enable_nondeterminism_logging {
            if let Some(idx) = diverged_at {
                l.set_height(height);
                l.log(
                    NdSource::Other("state_root_divergence".into()),
                    NdSeverity::Critical,
                    &format!(
                        "iteration {idx} produced a different state root \
                         (input_root={}, canonical={}, divergent={})",
                        short_hex(&input_root),
                        short_hex(&canonical_root),
                        short_hex(&roots[idx]),
                    ),
                    &short_hex(&roots[idx]),
                    Some("check KvState::root and any HashMap/HashSet usage"),
                );
            } else {
                debug!(height, iterations = config.iterations_per_block, "block reproducible");
            }
        }
    }

    let diff_description = diverged_at.map(|idx| {
        format!(
            "iteration {idx} diverged: root=0x{}, canonical=0x{}",
            hex::encode(roots[idx].0),
            hex::encode(canonical_root.0),
        )
    });

    let result = ReproducibilityResult {
        height,
        iterations: config.iterations_per_block,
        all_match: diverged_at.is_none(),
        canonical_root,
        input_root,
        diverged_at,
        roots,
        diff_description,
    };

    Ok((result, canonical_state))
}

/// Verify reproducibility for a chain of blocks.
///
/// # Errors
///
/// Same as [`verify_block_reproducibility`]. A failed verification is
/// **not** an error: it is reported through
/// [`BatchReproducibilityResult::all_reproducible`].
pub fn verify_chain_reproducibility(
    blocks: &[Block],
    initial_state: &KvState,
    config: &ReproducibilityConfig,
) -> Result<BatchReproducibilityResult, ReproducibilityError> {
    config.validate()?;

    // Sanity: the initial state must have a stable root.
    let _ = verify_state_root_consistency(initial_state, 3)?;

    let logger = if config.enable_nondeterminism_logging {
        Some(NdLogger::new(true))
    } else {
        None
    };

    let mut results = Vec::with_capacity(blocks.len());
    let mut first_failure: Option<Height> = None;
    let mut state = initial_state.clone();
    let mut total_iterations: usize = 0;

    for (idx, block) in blocks.iter().enumerate() {
        debug!(
            height = block.header.height,
            index = idx,
            "verifying block reproducibility"
        );

        let (result, canonical_state) =
            verify_block_reproducibility(block, &state, config, logger.as_ref())?;

        total_iterations = total_iterations.saturating_add(result.iterations);

        let failed = !result.all_match;
        if failed && first_failure.is_none() {
            first_failure = Some(block.header.height);
            warn!(
                height = block.header.height,
                diverged_at = ?result.diverged_at,
                "nondeterminism detected"
            );
        }

        // Advance the working state using the canonical execution's
        // post-state.
        state = canonical_state;
        results.push(result);

        info!(
            height = block.header.height,
            idx = idx + 1,
            total = blocks.len(),
            "verified"
        );

        if failed && config.stop_on_first_failure {
            break;
        }
    }

    let nondeterminism_report = logger.as_ref().map(|l| l.report().to_string());

    let all_reproducible = first_failure.is_none();
    Ok(BatchReproducibilityResult {
        total_blocks: results.len(),
        total_iterations,
        all_reproducible,
        results,
        first_failure,
        nondeterminism_report,
    })
}

// ── Golden-vector verification ────────────────────────────────────────────

/// Compare the computed state root against a golden value.
///
/// # Errors
///
/// - [`ReproducibilityError::InvalidProposer`] on a malformed proposer
///   key.
/// - A string error describing the mismatch when the root differs from
///   the golden value.
pub fn verify_against_golden(
    block: &Block,
    initial_state: &KvState,
    base_fee_per_gas: u64,
    golden_root: Hash32,
) -> Result<Hash32, String> {
    let proposer_addr = resolve_proposer(block).map_err(|e| e.to_string())?;

    let (new_state, _gas, _receipts) =
        execute_block(initial_state, &block.txs, base_fee_per_gas, &proposer_addr);

    let computed = new_state.root();
    if computed != golden_root {
        return Err(format!(
            "golden vector mismatch at height {}: expected 0x{}, got 0x{}",
            block.header.height,
            hex::encode(golden_root.0),
            hex::encode(computed.0),
        ));
    }
    Ok(computed)
}

// ── Root consistency ──────────────────────────────────────────────────────

/// Verify that `KvState::root()` is itself deterministic.
///
/// `KvState::root()` is a pure function of the state. If the state uses
/// a `HashMap` internally, `root()` may iterate in an
/// iteration-order-dependent way and produce different values across
/// calls. This check catches that class of bug directly.
pub fn verify_state_root_consistency(
    state: &KvState,
    iterations: usize,
) -> Result<Hash32, ReproducibilityError> {
    // `iterations == 0` is treated as `1` — the caller gets the root
    // with no consistency check performed, which is what a zero-count
    // means in practice.
    let iterations = iterations.max(1);
    let first = state.root();
    for i in 1..iterations {
        let root = state.root();
        if root != first {
            return Err(ReproducibilityError::StateRootInconsistent(format!(
                "iteration {i}: first=0x{}, current=0x{}",
                hex::encode(first.0),
                hex::encode(root.0),
            )));
        }
    }
    Ok(first)
}

// ── State diff ────────────────────────────────────────────────────────────

/// Compare two states field-by-field and return a human-readable list of
/// differences.
///
/// Intended for post-mortem debugging: a caller that finds a divergent
/// root can print this list to see which account or KV entry moved.
#[must_use]
pub fn compare_states(a: &KvState, b: &KvState) -> Vec<String> {
    let mut diffs = Vec::new();
    compare_map(&mut diffs, "balance", &a.balances, &b.balances);
    compare_map(&mut diffs, "nonce", &a.nonces, &b.nonces);
    compare_map(&mut diffs, "kv", &a.kv, &b.kv);
    diffs
}

fn compare_map<V>(
    diffs: &mut Vec<String>,
    label: &str,
    a: &std::collections::BTreeMap<String, V>,
    b: &std::collections::BTreeMap<String, V>,
) where
    V: std::fmt::Debug + PartialEq,
{
    for (k, va) in a {
        match b.get(k) {
            Some(vb) if va != vb => {
                diffs.push(format!("{label} {k}: {va:?} vs {vb:?}"));
            }
            None => {
                diffs.push(format!("{label} {k} only in A: {va:?}"));
            }
            _ => {}
        }
    }
    for (k, vb) in b {
        if !a.contains_key(k) {
            diffs.push(format!("{label} {k} only in B: {vb:?}"));
        }
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Resolve the proposer address from a block header, or a hard error.
fn resolve_proposer(block: &Block) -> Result<String, ReproducibilityError> {
    let pk = &block.header.proposer_pk;
    let height = block.header.height;

    if pk.is_empty() {
        return Ok("0000000000000000000000000000000000000000".to_string());
    }

    let addr = crate::crypto::tx::derive_address(pk);
    if addr.is_empty() {
        return Err(ReproducibilityError::InvalidProposer {
            height,
            reason: "derive_address returned an empty string".into(),
        });
    }
    Ok(addr.to_string())
}

/// First eight hex characters of a 32-byte hash, prefixed with `0x`.
fn short_hex(h: &Hash32) -> String {
    format!("0x{}", hex::encode(&h.0[..8]))
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

    fn config(iterations: usize) -> ReproducibilityConfig {
        ReproducibilityConfig {
            iterations_per_block: iterations,
            ..Default::default()
        }
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn default_config_validates() {
        assert_eq!(ReproducibilityConfig::default().validate(), Ok(()));
    }

    #[test]
    fn config_rejects_zero_iterations() {
        let c = config(0);
        assert_eq!(c.validate(), Err(ReproducibilityError::ZeroIterations));
    }

    #[test]
    fn config_rejects_excessive_iterations() {
        let c = config(MAX_ITERATIONS_PER_BLOCK + 1);
        assert!(matches!(
            c.validate(),
            Err(ReproducibilityError::TooManyIterations(_))
        ));
    }

    // ── Single-block verification ───────────────────────────────────────

    #[test]
    fn block_reproducibility_succeeds() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let c = config(3);

        let (result, new_state) =
            verify_block_reproducibility(&block, &state, &c, None).unwrap();

        assert!(result.all_match, "not reproducible at {:?}", result.diverged_at);
        assert_eq!(result.iterations, 3);
        assert_eq!(result.roots.len(), 3);
        assert_eq!(result.canonical_root, root);
        assert_eq!(result.input_root, root);
        assert_eq!(new_state.root(), root);
    }

    #[test]
    fn block_reproducibility_rejects_zero_iterations() {
        let state = KvState::default();
        let block = empty_block(1, state.root());
        let c = config(0);
        assert!(matches!(
            verify_block_reproducibility(&block, &state, &c, None),
            Err(ReproducibilityError::ZeroIterations)
        ));
    }

    // ── Chain verification ──────────────────────────────────────────────

    #[test]
    fn chain_reproducibility_succeeds() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
        ];
        let c = config(3);

        let r = verify_chain_reproducibility(&blocks, &state, &c).unwrap();
        assert!(r.all_reproducible, "result: {r}");
        assert_eq!(r.total_blocks, 2);
        // 2 blocks × 3 iterations = 6 total executions.
        assert_eq!(r.total_iterations, 6);
        assert!(r.failures().is_empty());
    }

    #[test]
    fn chain_reproducibility_total_iterations_reflects_actual_work() {
        // This is the regression for a bug where `total_iterations` was
        // set to `config.iterations_per_block` instead of the sum over
        // all verified blocks.
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root),
            empty_block(2, root),
            empty_block(3, root),
        ];
        let c = config(4);

        let r = verify_chain_reproducibility(&blocks, &state, &c).unwrap();
        assert_eq!(r.total_blocks, 3);
        assert_eq!(r.total_iterations, 12);
    }

    #[test]
    fn chain_reproducibility_empty_blocks_is_ok() {
        let state = KvState::default();
        let r = verify_chain_reproducibility(&[], &state, &config(3)).unwrap();
        assert!(r.all_reproducible);
        assert_eq!(r.total_blocks, 0);
        assert_eq!(r.total_iterations, 0);
    }

    // ── Golden vector ───────────────────────────────────────────────────

    #[test]
    fn golden_vector_matches() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        assert_eq!(verify_against_golden(&block, &state, 1, root), Ok(root));
    }

    #[test]
    fn golden_vector_mismatch_is_reported() {
        let state = KvState::default();
        let root = state.root();
        let block = empty_block(1, root);
        let bad = Hash32([0xFF; 32]);
        let err = verify_against_golden(&block, &state, 1, bad).unwrap_err();
        assert!(err.contains("golden vector mismatch"));
    }

    // ── State root consistency ──────────────────────────────────────────

    #[test]
    fn state_root_is_consistent() {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.balances.insert("bob".into(), 500);
        state.kv.insert("k".into(), "v".into());
        state.nonces.insert("alice".into(), 5);

        assert!(verify_state_root_consistency(&state, 100).is_ok());
    }

    #[test]
    fn state_root_consistency_zero_iterations_returns_root() {
        let state = KvState::default();
        // `iterations == 0` is treated as `1`; no panic.
        let root = verify_state_root_consistency(&state, 0).unwrap();
        assert_eq!(root, state.root());
    }

    // ── State diff ──────────────────────────────────────────────────────

    #[test]
    fn compare_states_reports_all_differences() {
        let mut a = KvState::default();
        let mut b = KvState::default();

        a.balances.insert("alice".into(), 100);
        b.balances.insert("alice".into(), 200); // differs
        b.balances.insert("bob".into(), 50);    // only in B
        a.nonces.insert("alice".into(), 1);
        a.nonces.insert("carol".into(), 7);     // only in A
        a.kv.insert("k1".into(), "v1".into());
        b.kv.insert("k1".into(), "v2".into());  // differs

        let diffs = compare_states(&a, &b);
        assert!(diffs.iter().any(|d| d.contains("balance alice") && d.contains("100 vs 200")));
        assert!(diffs.iter().any(|d| d.contains("balance bob") && d.contains("only in B")));
        assert!(diffs.iter().any(|d| d.contains("nonce carol") && d.contains("only in A")));
        assert!(diffs.iter().any(|d| d.contains("kv k1")));
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn batch_result_display_reports_success() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];
        let r = verify_chain_reproducibility(&blocks, &state, &config(2)).unwrap();
        let s = r.to_string();
        assert!(s.contains("ALL REPRODUCIBLE"));
        assert!(s.contains("blocks=1"));
        assert!(s.contains("total_iterations=2"));
    }

    // ── Nondeterminism logging ──────────────────────────────────────────

    #[test]
    fn nondeterminism_logger_is_attached_when_enabled() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];
        let c = ReproducibilityConfig {
            enable_nondeterminism_logging: true,
            ..config(2)
        };
        let r = verify_chain_reproducibility(&blocks, &state, &c).unwrap();
        assert!(r.all_reproducible);
        assert!(r.nondeterminism_report.is_some());
    }

    #[test]
    fn nondeterminism_logger_not_attached_when_disabled() {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![empty_block(1, root)];
        let c = config(2);
        let r = verify_chain_reproducibility(&blocks, &state, &c).unwrap();
        assert!(r.nondeterminism_report.is_none());
    }

    // ── Helpers ─────────────────────────────────────────────────────────

    #[test]
    fn short_hex_is_eight_bytes() {
        let h = Hash32([0xAB; 32]);
        let s = short_hex(&h);
        assert_eq!(s.len(), 2 + 16); // "0x" + 8 bytes
        assert!(s.starts_with("0x"));
    }
}
