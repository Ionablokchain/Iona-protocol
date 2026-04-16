//! Mempool module for IONA.
//!
//! This module provides two transaction pool implementations:
//! - `pool::StandardMempool`: a basic FIFO mempool with nonce ordering,
//!   replace‑by‑fee (RBF), TTL, and eviction.
//! - `mev_resistant::MevMempool`: a MEV‑resistant mempool with commit‑reveal,
//!   threshold encryption, fair ordering, and backrun protection.
//!
//! Both pools implement the `Mempool` trait, allowing the node to switch
//! between them seamlessly.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::mempool::{StandardMempool, MevMempool, MevConfig};
//!
//! // Standard mempool
//! let mut pool = StandardMempool::new(200_000);
//! pool.push(tx)?;
//!
//! // MEV‑resistant mempool
//! let config = MevConfig::default();
//! let mut mev_pool = MevMempool::new(config);
//! mev_pool.submit_tx(tx)?;
//! ```

pub mod mev_resistant;
pub mod pool;

// Re‑export core types from the standard mempool.
pub use pool::{
    Mempool, MempoolError, MempoolMetrics, StandardMempool,
};

// Re‑export MEV‑resistant mempool types.
pub use mev_resistant::{
    compute_commit_hash, decrypt_tx_envelope, derive_epoch_secret, encrypt_tx_envelope,
    CommitStatus, EncryptedEnvelope, MevConfig, MevMempool, MevMempoolMetrics, TxCommit, TxReveal,
};
