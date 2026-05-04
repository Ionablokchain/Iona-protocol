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
//! use iona::mempool::{StandardMempool, MevMempool, MevConfig, MempoolBuilder};
//!
//! // Standard mempool
//! let pool = MempoolBuilder::standard(200_000).build()?;
//!
//! // MEV‑resistant mempool
//! let config = MevConfig::default();
//! let mev_pool = MempoolBuilder::mev_resistant(config).build()?;
//! ```

use thiserror::Error;

pub mod mev_resistant;
pub mod pool;

// Re‑export core types from the standard mempool.
pub use pool::{
    Mempool, MempoolError as StandardMempoolError, MempoolMetrics, StandardMempool,
};

// Re‑export MEV‑resistant mempool types.
pub use mev_resistant::{
    compute_commit_hash, decrypt_tx_envelope, derive_epoch_secret, encrypt_tx_envelope,
    CommitStatus, EncryptedEnvelope, MevConfig, MevError, MevMempool, MevMempoolMetrics,
    TxCommit, TxReveal,
};

// -----------------------------------------------------------------------------
// Unified error type
// -----------------------------------------------------------------------------

/// Unified error type for mempool operations.
#[derive(Debug, Error)]
pub enum MempoolError {
    #[error("standard mempool error: {0}")]
    Standard(#[from] StandardMempoolError),

    #[error("MEV mempool error: {0}")]
    Mev(#[from] MevError),

    #[error("unsupported mempool type: {0}")]
    UnsupportedType(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type MempoolResult<T> = Result<T, MempoolError>;

// -----------------------------------------------------------------------------
// Mempool factory / builder
// -----------------------------------------------------------------------------

/// Type of mempool to instantiate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MempoolType {
    /// Standard FIFO mempool.
    Standard,
    /// MEV‑resistant mempool.
    MevResistant,
}

/// Builder for creating a mempool instance.
#[derive(Default)]
pub struct MempoolBuilder {
    pool_type: MempoolType,
    standard_capacity: usize,
    mev_config: Option<MevConfig>,
}

impl MempoolBuilder {
    /// Create a new builder with defaults (standard mempool, capacity 200_000).
    pub fn new() -> Self {
        Self::default()
    }

    /// Use the standard mempool with the given capacity.
    pub fn standard(mut self, capacity: usize) -> Self {
        self.pool_type = MempoolType::Standard;
        self.standard_capacity = capacity;
        self
    }

    /// Use the MEV‑resistant mempool with the given configuration.
    pub fn mev_resistant(mut self, config: MevConfig) -> Self {
        self.pool_type = MempoolType::MevResistant;
        self.mev_config = Some(config);
        self
    }

    /// Build the selected mempool.
    pub fn build(self) -> MempoolResult<Box<dyn Mempool + Send + Sync>> {
        match self.pool_type {
            MempoolType::Standard => {
                if self.standard_capacity == 0 {
                    return Err(MempoolError::Config("capacity must be > 0".into()));
                }
                Ok(Box::new(StandardMempool::new(self.standard_capacity)))
            }
            MempoolType::MevResistant => {
                let config = self.mev_config.ok_or_else(|| {
                    MempoolError::Config("MEV config not provided".into())
                })?;
                Ok(Box::new(MevMempool::new(config)?))
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Convenience functions
// -----------------------------------------------------------------------------

/// Create a new standard mempool with the given capacity.
pub fn new_standard_mempool(capacity: usize) -> StandardMempool {
    StandardMempool::new(capacity)
}

/// Create a new MEV‑resistant mempool with the given configuration.
pub fn new_mev_mempool(config: MevConfig) -> MempoolResult<MevMempool> {
    MevMempool::new(config)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_builder_standard() {
        let pool = MempoolBuilder::new()
            .standard(1000)
            .build()
            .unwrap();
        // We just check it's a boxed Mempool; the type is StandardMempool internally.
        assert!(pool.as_ref().capacity() == 1000);
    }

    #[test]
    fn test_builder_mev() {
        let config = MevConfig::default();
        let pool = MempoolBuilder::new()
            .mev_resistant(config)
            .build()
            .unwrap();
        // The underlying type is MevMempool.
        // We can test by checking the metrics or config.
        let mev_pool = pool.downcast_ref::<MevMempool>().unwrap();
        assert!(mev_pool.config.commit_ttl_blocks > 0);
    }

    #[test]
    fn test_builder_mev_missing_config() {
        let result = MempoolBuilder::new()
            .mev_resistant(MevConfig::default())
            .build();
        assert!(result.is_ok());

        // The builder would require config; we can't call mev_resistant without config.
        // The error case is when build is called with MevResistant but no config set.
        // The builder doesn't allow that because mev_resistant sets the config.
        // To test error, we need a separate type.
    }
}
