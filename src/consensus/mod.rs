//! IONA consensus engine — Tendermint‑style BFT with sub‑second finality.
//!
//! This module implements a Byzantine Fault Tolerant (BFT) consensus protocol
//! that ensures safety and liveness under up to 1/3 of faulty validators.
//! It is heavily inspired by Tendermint, with optimisations for high throughput
//! and low latency.
//!
//! # Submodules
//!
//! - `messages` – core consensus message types (Proposal, Vote) and deterministic signing.
//! - `validator_set` – validator set management (active validators, proposer selection).
//! - `quorum` – vote tallying and quorum calculation.
//! - `engine` – the main consensus state machine (Engine).
//! - `double_sign` – double‑signature detection and prevention.
//! - `block_producer` – simple round‑robin block production.
//! - `fast_finality` – sub‑second finality with adaptive timeouts and pipelining.
//! - `genesis` – genesis configuration and validator set initialisation.
//! - `quorum_diag` – diagnostic tools for quorum analysis.
//! - `diagnostic` – additional consensus diagnostics.
//! - `debug_trace` – structured tracing of consensus events.
//!
//! # Key Components
//!
//! - **Engine**: The central state machine that processes messages, advances rounds,
//!   and produces commits. It uses the `fast_quorum` flag to commit as soon as
//!   2/3+ votes are received, bypassing timeouts.
//! - **Fast finality**: Integrated via `fast_finality::FinalityTracker` and
//!   `fast_finality::PipelineState` to measure commit times, adapt timeouts,
//!   and pipeline the next block’s transaction selection.
//! - **Double‑sign protection**: The `DoubleSignGuard` persists signed messages
//!   to disk to prevent equivocation across restarts.
//!
//! # Usage
//!
//! The main entry point is `Engine::new(...)`. After construction, call
//! `engine.tick()` periodically to advance the state machine, and
//! `engine.on_message()` to process incoming consensus messages from the network.
//! When a block is committed, `Outbox::on_commit()` is called with the
//! `CommitCertificate` and the new state.
//!
//! For detailed documentation, see the respective submodules.

pub mod messages;
pub mod validator_set;
pub mod quorum;
pub mod engine;
pub mod double_sign;
pub mod block_producer;
pub mod fast_finality;
pub mod genesis;
pub mod quorum_diag;
pub mod diagnostic;
pub mod debug_trace;

// Re‑export core types for convenience.
pub use messages::*;
pub use validator_set::*;
pub use quorum::*;
pub use engine::*;
pub use double_sign::*;
pub use block_producer::*;
pub use fast_finality::*;
pub use genesis::GenesisConfig; // explicitly re‑export the genesis config
