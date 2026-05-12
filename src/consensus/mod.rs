//! IONA consensus engine and supporting modules.
//!
//! This module implements a Tendermint‑style BFT consensus engine with:
//! - Round‑robin proposer selection
//! - Prevote / Precommit voting
//! - Double‑sign protection (persistent guard)
//! - Fast finality (optimistic single‑round commit)
//! - Quorum calculators and diagnostics
//! - Validator set management
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::consensus::{Engine, Config, ValidatorSet};
//!
//! let config = Config::default();
//! let vset = ValidatorSet::default();
//! let engine = Engine::new(config, vset, 1, Hash32::zero(), …);
//! ```

pub mod block_producer;
pub mod debug_trace;
pub mod diagnostic;
pub mod double_sign;
pub mod engine;
pub mod fast_finality;
pub mod genesis;
pub mod messages;
pub mod quorum;
pub mod quorum_diag;
pub mod validator_set;

// -----------------------------------------------------------------------------
// Re‑exports – core consensus types
// -----------------------------------------------------------------------------

pub use block_producer::*;
pub use diagnostic::*;
pub use double_sign::*;
pub use engine::*;
pub use fast_finality::*;
pub use messages::*;
pub use quorum::*;
pub use validator_set::*;

// -----------------------------------------------------------------------------
// Prelude – convenient import of common consensus items
// -----------------------------------------------------------------------------

/// Prelude for the consensus module.
pub mod prelude {
    pub use super::{
        Config, ConsensusMsg, Engine, Proposal, QuorumCalculator, Validator, ValidatorSet, Vote,
        VoteType,
    };
    pub use super::diagnostic::{diagnose, ConsensusDiagnostic, StallReason};
    pub use super::double_sign::{vote_guard_key, DoubleSignGuard};
    pub use super::fast_finality::{FinalityStats, FinalityTracker, PipelineState};
}
