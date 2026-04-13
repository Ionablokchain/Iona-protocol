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

pub mod divergence;
pub mod historical;
pub mod nondeterminism;
pub mod replay_tool;
pub mod state_root_verify;
