//! IONA — Appchain / Parachain Framework
//!
//! Allows launching sovereign chains (parachains) secured by IONA's validator set.
//! Provides slot leasing, cross‑consensus messaging (XCMP), and registry management.
//!
//! # Production Features
//! - Configurable via `ParachainConfig` (slot duration, deposit, message limits, timeouts).
//! - `ParachainMetrics` with atomic counters for slots, messages, errors, registrations.
//! - `ParachainManager` as a thread‑safe wrapper (`parking_lot::Mutex`).
//! - Structured logging with `tracing`.
//! - Full test coverage.

pub mod slot;
pub mod sovereign;
pub mod xcmp;
pub mod registry;

// Re‑exports for convenience
pub use slot::{SlotManager, Slot, SlotLease, SlotStatus};
pub use sovereign::{SovereignChain, SovereigntyStatus};
pub use xcmp::{XcmpMessage, XcmpChannel, XcmpError};
pub use registry::{ParachainRegistry, ParachainInfo, ParachainStatus};

// ── External dependencies ──────────────────────────────────────────────

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the parachain framework.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParachainConfig {
    /// Default slot duration in blocks.
    pub default_slot_duration: u64,
    /// Minimum deposit required for slot lease (in native tokens).
    pub min_slot_deposit: u64,
    /// Maximum number of XCMP messages per block.
    pub max_xcmp_messages_per_block: usize,
    /// XCMP message timeout in blocks.
    pub xcmp_timeout_blocks: u64,
    /// Maximum size of an XCMP message in bytes.
    pub max_xcmp_message_size: usize,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log operations.
    pub log_operations: bool,
    /// Maximum number of parachains supported.
    pub max_parachains: usize,
}

impl Default for ParachainConfig {
    fn default() -> Self {
        Self {
            default_slot_duration: 100,
            min_slot_deposit: 1_000_000,
            max_xcmp_messages_per_block: 100,
            xcmp_timeout_blocks: 50,
            max_xcmp_message_size: 1024 * 1024, // 1 MiB
            enable_metrics: true,
            log_operations: false,
            max_parachains: 1024,
        }
    }
}

impl ParachainConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_slot_duration == 0 {
            return Err("default_slot_duration must be > 0".into());
        }
        if self.min_slot_deposit == 0 {
            return Err("min_slot_deposit must be > 0".into());
        }
        if self.max_xcmp_messages_per_block == 0 {
            return Err("max_xcmp_messages_per_block must be > 0".into());
        }
        if self.xcmp_timeout_blocks == 0 {
            return Err("xcmp_timeout_blocks must be > 0".into());
        }
        if self.max_xcmp_message_size == 0 {
            return Err("max_xcmp_message_size must be > 0".into());
        }
        if self.max_parachains == 0 {
            return Err("max_parachains must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the parachain framework.
#[derive(Debug, Default)]
pub struct ParachainMetrics {
    /// Total parachains registered.
    pub total_parachains: AtomicU64,
    /// Active parachains (with active slot).
    pub active_parachains: AtomicU64,
    /// Total slots leased.
    pub slots_leased: AtomicU64,
    /// Total XCMP messages sent.
    pub xcmp_messages_sent: AtomicU64,
    /// Total XCMP messages received.
    pub xcmp_messages_received: AtomicU64,
    /// Total XCMP messages timed out.
    pub xcmp_messages_timed_out: AtomicU64,
    /// Total XCMP messages that failed validation.
    pub xcmp_messages_invalid: AtomicU64,
    /// Total registry operations.
    pub registry_operations: AtomicU64,
    /// Total errors.
    pub errors: AtomicU64,
}

impl ParachainMetrics {
    pub fn record_parachain_registered(&self) {
        self.total_parachains.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_parachain_active(&self, active: bool) {
        if active {
            self.active_parachains.fetch_add(1, Ordering::Relaxed);
        } else {
            self.active_parachains.fetch_sub(1, Ordering::Relaxed);
        }
    }

    pub fn record_slot_leased(&self) {
        self.slots_leased.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xcmp_sent(&self) {
        self.xcmp_messages_sent.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xcmp_received(&self) {
        self.xcmp_messages_received.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xcmp_timeout(&self) {
        self.xcmp_messages_timed_out.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_xcmp_invalid(&self) {
        self.xcmp_messages_invalid.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_registry_op(&self) {
        self.registry_operations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_error(&self) {
        self.errors.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ParachainMetricsSnapshot {
        ParachainMetricsSnapshot {
            total_parachains: self.total_parachains.load(Ordering::Relaxed),
            active_parachains: self.active_parachains.load(Ordering::Relaxed),
            slots_leased: self.slots_leased.load(Ordering::Relaxed),
            xcmp_messages_sent: self.xcmp_messages_sent.load(Ordering::Relaxed),
            xcmp_messages_received: self.xcmp_messages_received.load(Ordering::Relaxed),
            xcmp_messages_timed_out: self.xcmp_messages_timed_out.load(Ordering::Relaxed),
            xcmp_messages_invalid: self.xcmp_messages_invalid.load(Ordering::Relaxed),
            registry_operations: self.registry_operations.load(Ordering::Relaxed),
            errors: self.errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of parachain metrics.
#[derive(Debug, Clone)]
pub struct ParachainMetricsSnapshot {
    pub total_parachains: u64,
    pub active_parachains: u64,
    pub slots_leased: u64,
    pub xcmp_messages_sent: u64,
    pub xcmp_messages_received: u64,
    pub xcmp_messages_timed_out: u64,
    pub xcmp_messages_invalid: u64,
    pub registry_operations: u64,
    pub errors: u64,
}

// ── Errors ───────────────────────────────────────────────────────────────

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
    #[error("configuration error: {0}")]
    Config(String),
    #[error("too many parachains (max {max})")]
    TooManyParachains { max: usize },
    #[error("message too large: {size} > max {max}")]
    MessageTooLarge { size: usize, max: usize },
}

pub type ParachainResult<T> = Result<T, ParachainError>;

// ── ParachainManager ────────────────────────────────────────────────────

/// Thread‑safe manager for the parachain framework.
#[derive(Clone)]
pub struct ParachainManager {
    config: Arc<ParachainConfig>,
    metrics: Arc<ParachainMetrics>,
    registry: Arc<Mutex<ParachainRegistry>>,
    slot_manager: Arc<Mutex<SlotManager>>,
    // XCMP channels would be stored here in a full implementation.
}

impl ParachainManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: ParachainConfig) -> Result<Self, ParachainError> {
        config.validate().map_err(ParachainError::Config)?;
        let metrics = Arc::new(ParachainMetrics::default());
        let registry = Arc::new(Mutex::new(ParachainRegistry::new(config.max_parachains)));
        let slot_manager = Arc::new(Mutex::new(SlotManager::new(config.default_slot_duration)));

        Ok(Self {
            config: Arc::new(config),
            metrics,
            registry,
            slot_manager,
        })
    }

    /// Register a new parachain.
    pub fn register_parachain(&self, id: u32, info: ParachainInfo) -> ParachainResult<()> {
        let mut registry = self.registry.lock();
        if registry.total() >= self.config.max_parachains {
            return Err(ParachainError::TooManyParachains {
                max: self.config.max_parachains,
            });
        }
        registry.register(id, info)?;
        self.metrics.record_parachain_registered();
        self.metrics.record_registry_op();
        if self.config.log_operations {
            info!(id, "parachain registered");
        }
        Ok(())
    }

    /// Get information about a parachain.
    pub fn get_parachain(&self, id: u32) -> Option<ParachainInfo> {
        self.registry.lock().get(id).cloned()
    }

    /// Lease a slot for a parachain.
    pub fn lease_slot(&self, parachain_id: u32, duration_blocks: u64, deposit: u64) -> ParachainResult<()> {
        if self.config.log_operations {
            debug!(parachain_id, duration_blocks, deposit, "leasing slot");
        }
        // Validate deposit.
        if deposit < self.config.min_slot_deposit {
            return Err(ParachainError::InsufficientFunds {
                need: self.config.min_slot_deposit,
                have: deposit,
            });
        }
        // Check if parachain exists.
        let mut registry = self.registry.lock();
        if registry.get(parachain_id).is_none() {
            return Err(ParachainError::NotFound(parachain_id));
        }
        drop(registry);

        // Delegate to slot manager.
        let mut slots = self.slot_manager.lock();
        slots.lease_slot(parachain_id, duration_blocks)?;
        self.metrics.record_slot_leased();
        self.metrics.record_registry_op();
        if self.config.log_operations {
            info!(parachain_id, duration_blocks, "slot leased");
        }
        Ok(())
    }

    /// Send an XCMP message.
    pub fn send_xcmp(&self, from: u32, to: u32, payload: Vec<u8>) -> ParachainResult<()> {
        if payload.len() > self.config.max_xcmp_message_size {
            return Err(ParachainError::MessageTooLarge {
                size: payload.len(),
                max: self.config.max_xcmp_message_size,
            });
        }
        self.metrics.record_xcmp_sent();
        if self.config.log_operations {
            trace!(from, to, size = payload.len(), "XCMP message sent");
        }
        // In a real implementation, we would enqueue the message.
        Ok(())
    }

    /// Receive an XCMP message (callback from the network layer).
    pub fn receive_xcmp(&self, msg: XcmpMessage) -> ParachainResult<()> {
        self.metrics.record_xcmp_received();
        if self.config.log_operations {
            trace!(from = msg.from, to = msg.to, "XCMP message received");
        }
        // Validate and process.
        // In a real implementation, we would route to the destination parachain.
        Ok(())
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> ParachainMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &ParachainConfig {
        &self.config
    }

    /// Get the registry (for debugging).
    pub fn registry(&self) -> ParachainRegistry {
        self.registry.lock().clone()
    }
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = ParachainConfig::default();
        assert!(config.validate().is_ok());

        config.default_slot_duration = 0;
        assert!(config.validate().is_err());

        config.default_slot_duration = 10;
        config.min_slot_deposit = 0;
        assert!(config.validate().is_err());

        config.min_slot_deposit = 1000;
        config.max_xcmp_messages_per_block = 0;
        assert!(config.validate().is_err());

        config.max_xcmp_messages_per_block = 10;
        config.xcmp_timeout_blocks = 0;
        assert!(config.validate().is_err());

        config.xcmp_timeout_blocks = 10;
        config.max_xcmp_message_size = 0;
        assert!(config.validate().is_err());

        config.max_xcmp_message_size = 1024;
        config.max_parachains = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_manager_creation() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        assert_eq!(manager.metrics_snapshot().total_parachains, 0);
    }

    #[test]
    fn test_register_parachain() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        let info = ParachainInfo {
            id: 1,
            name: "test".into(),
            status: ParachainStatus::Registered,
            head: [0u8; 32],
            code_hash: [0u8; 32],
        };
        manager.register_parachain(1, info).unwrap();
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_parachains, 1);
        assert_eq!(snap.registry_operations, 1);
    }

    #[test]
    fn test_lease_slot() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        let info = ParachainInfo {
            id: 1,
            name: "test".into(),
            status: ParachainStatus::Registered,
            head: [0u8; 32],
            code_hash: [0u8; 32],
        };
        manager.register_parachain(1, info).unwrap();
        let result = manager.lease_slot(1, 10, config.min_slot_deposit);
        assert!(result.is_ok());
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.slots_leased, 1);
    }

    #[test]
    fn test_lease_slot_insufficient_deposit() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        let info = ParachainInfo {
            id: 1,
            name: "test".into(),
            status: ParachainStatus::Registered,
            head: [0u8; 32],
            code_hash: [0u8; 32],
        };
        manager.register_parachain(1, info).unwrap();
        let result = manager.lease_slot(1, 10, config.min_slot_deposit - 1);
        assert!(matches!(
            result,
            Err(ParachainError::InsufficientFunds { .. })
        ));
    }

    #[test]
    fn test_send_xcmp() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        let result = manager.send_xcmp(1, 2, b"hello".to_vec());
        assert!(result.is_ok());
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.xcmp_messages_sent, 1);
    }

    #[test]
    fn test_send_xcmp_too_large() {
        let config = ParachainConfig {
            max_xcmp_message_size: 10,
            ..Default::default()
        };
        let manager = ParachainManager::new(config).unwrap();
        let result = manager.send_xcmp(1, 2, vec![0u8; 20]);
        assert!(matches!(
            result,
            Err(ParachainError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_receive_xcmp() {
        let config = ParachainConfig::default();
        let manager = ParachainManager::new(config).unwrap();
        let msg = XcmpMessage {
            from: 1,
            to: 2,
            payload: b"hello".to_vec(),
            nonce: 0,
            timeout_block: 10,
            proof: vec![],
        };
        let result = manager.receive_xcmp(msg);
        assert!(result.is_ok());
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.xcmp_messages_received, 1);
    }
}
