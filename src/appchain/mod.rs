//! IONA — Appchain / Parachain Framework
//!
//! Allows launching sovereign chains (parachains) secured by IONA's validator set.
//! Provides slot leasing, cross‑consensus messaging (XCMP), and registry management.
//!
//! # Architecture
//! - **Slot**: Auction-based mechanism to allocate block production slots to parachains.
//! - **Sovereign**: State management for each parachain (head, validation code).
//! - **XCMP**: Cross-chain message passing with nonce and timeout.
//! - **Registry**: Central registry of all registered parachains.

pub mod slot;
pub mod sovereign;
pub mod xcmp;
pub mod registry;

// -----------------------------------------------------------------------------
// Re-exports for convenience
// -----------------------------------------------------------------------------
pub use slot::{SlotManager, Slot, SlotLease, SlotStatus};
pub use sovereign::{SovereignChain, SovereigntyStatus};
pub use xcmp::{XcmpMessage, XcmpChannel, XcmpError};
pub use registry::{ParachainRegistry, ParachainInfo, ParachainStatus};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Core error type for the parachain framework.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParachainError {
    #[error("parachain with id {0} already exists")]
    AlreadyExists(u32),
    #[error("parachain with id {0} not found")]
    NotFound(u32),
    #[error("invalid slot duration: {0}")]
    InvalidSlotDuration(u64),
    #[error("insufficient funds for slot lease: need {need}, have {have}")]
    InsufficientFunds { need: u64, have: u64 },
    #[error("slot {0} is not available")]
    SlotNotAvailable(u64),
    #[error("XCMP error: {0}")]
    Xcmp(String),
    #[error("sovereign chain error: {0}")]
    Sovereign(String),
    #[error("registry error: {0}")]
    Registry(String),
    #[error("timeout while waiting for XCMP response")]
    XcmpTimeout,
    #[error("invalid proof for message")]
    InvalidProof,
}

pub type ParachainResult<T> = Result<T, ParachainError>;
