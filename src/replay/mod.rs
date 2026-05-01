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
//!   historical::replay_chain(blocks, state)
//!       │
//!       ├── state_root_verify::verify_roots(blocks, expected_roots)
//!       │
//!       ├── divergence::compare_results(local, remote)
//!       │
//!       └── nondeterminism::NdLogger::log(source, value)
//! ```
//!
//! # Quick Start
//!
//! ```rust,ignore
//! use iona::replay::{replay_chain, ReplayError};
//!
//! fn main() -> Result<(), ReplayError> {
//!     let result = replay_chain(&blocks, &genesis_state, base_fee)?;
//!     if !result.success {
//!         eprintln!("Replay failed at height {:?}", result.failed_at);
//!     }
//!     Ok(())
//! }
//! ```

pub mod divergence;
pub mod historical;
pub mod nondeterminism;
pub mod replay_tool;
pub mod state_root_verify;

use crate::execution::KvState;
use crate::types::{Block, Hash32, Height};
use std::collections::BTreeMap;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Re-export core types from submodules
// -----------------------------------------------------------------------------

pub use divergence::{
    compare_snapshots, detect_divergence, detect_divergence_range, Divergence, DivergenceDetail,
    DivergenceReport, NodeSnapshot,
};
pub use historical::{replay_chain, replay_chain_simple, ChainReplayResult};
pub use nondeterminism::{NdLogger, NondeterminismSource};
pub use replay_tool::{replay_and_verify, replay_block};
pub use state_root_verify::{verify_roots, VerifyResult};

// -----------------------------------------------------------------------------
// Unified errors
// -----------------------------------------------------------------------------

/// Errors that can occur during replay or verification operations.
#[derive(Debug, Error)]
pub enum ReplayError {
    #[error("historical replay error: {0}")]
    Historical(#[from] historical::HistoricalError),

    #[error("state root verification error: {0}")]
    StateRootVerify(#[from] state_root_verify::VerifyError),

    #[error("divergence detection error: {0}")]
    Divergence(#[from] divergence::DivergenceError),

    #[error("nondeterminism logging error: {0}")]
    Nondeterminism(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Alias for `Result<T, ReplayError>`.
pub type ReplayResult<T> = Result<T, ReplayError>;

// -----------------------------------------------------------------------------
// High-level convenience API
// -----------------------------------------------------------------------------

/// Replay a chain of blocks and verify state roots against block headers.
///
/// This is the main entry point for block replay. It wraps
/// [`historical::replay_chain`] and returns a [`ChainReplayResult`].
pub fn verify_chain(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
) -> ReplayResult<historical::ChainReplayResult> {
    Ok(historical::replay_chain(blocks, initial_state, base_fee_per_gas)?)
}

/// Verify state roots against an external map of expected roots.
///
/// Wraps [`state_root_verify::verify_roots`].
pub fn verify_state_roots(
    blocks: &[Block],
    initial_state: &KvState,
    base_fee_per_gas: u64,
    expected_roots: &BTreeMap<Height, Hash32>,
) -> ReplayResult<state_root_verify::VerifyResult> {
    Ok(state_root_verify::verify_roots(blocks, initial_state, base_fee_per_gas, expected_roots)?)
}

/// Compare two sets of node snapshots and return a divergence report.
///
/// Wraps [`divergence::detect_divergence_range`].
pub fn compare_environments(
    node_snapshots: &BTreeMap<String, Vec<NodeSnapshot>>,
) -> ReplayResult<DivergenceReport> {
    Ok(divergence::detect_divergence_range(node_snapshots)?)
}

/// Create a new nondeterminism logger that writes to the given file.
pub fn create_nd_logger(path: impl AsRef<std::path::Path>) -> ReplayResult<NdLogger> {
    NdLogger::new(path).map_err(|e| ReplayError::Nondeterminism(e.to_string()))
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader};
    use crate::execution::KvState;

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
    fn test_verify_chain_success() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, root.clone()),
        ];
        let result = verify_chain(&blocks, &state, 1)?;
        assert!(result.success);
        Ok(())
    }

    #[test]
    fn test_verify_chain_mismatch() -> ReplayResult<()> {
        let state = KvState::default();
        let root = state.root();
        let bad_root = Hash32([0xFF; 32]);
        let blocks = vec![
            empty_block(1, root.clone()),
            empty_block(2, bad_root),
        ];
        let result = verify_chain(&blocks, &state, 1)?;
        assert!(!result.success);
        assert_eq!(result.failed_at, Some(2));
        Ok(())
    }
}
