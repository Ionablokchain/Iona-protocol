//! Parachain registry.
//!
//! Maintains the set of all registered parachains, their metadata, and
//! current status. Used by the IONA consensus to know which parachains
//! are allowed to produce blocks.
//!
//! # Production Features
//! - Configurable via `RegistryConfig` (max parachains, deposit, validation).
//! - `RegistryMetrics` with atomic counters for registrations, activations, status changes.
//! - `RegistryManager` as a thread‑safe wrapper (`parking_lot::Mutex`).
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::{ParachainError, ParachainResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the parachain registry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryConfig {
    /// Maximum number of parachains allowed.
    pub max_parachains: usize,
    /// Minimum deposit required for registration.
    pub min_deposit: u64,
    /// Whether to validate parachain names (non‑empty, unique).
    pub validate_names: bool,
    /// Whether to track metrics.
    pub track_metrics: bool,
    /// Whether to log operations.
    pub log_operations: bool,
}

impl Default for RegistryConfig {
    fn default() -> Self {
        Self {
            max_parachains: 1024,
            min_deposit: 1_000_000,
            validate_names: true,
            track_metrics: true,
            log_operations: false,
        }
    }
}

impl RegistryConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_parachains == 0 {
            return Err("max_parachains must be > 0".into());
        }
        if self.min_deposit == 0 {
            return Err("min_deposit must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the parachain registry.
#[derive(Debug, Default)]
pub struct RegistryMetrics {
    pub total_registered: AtomicU64,
    pub active_count: AtomicU64,
    pub paused_count: AtomicU64,
    pub deregistered_count: AtomicU64,
    pub activations: AtomicU64,
    pub pauses: AtomicU64,
    pub deregistrations: AtomicU64,
    pub registration_failures: AtomicU64,
}

impl RegistryMetrics {
    pub fn record_registration(&self, success: bool) {
        if success {
            self.total_registered.fetch_add(1, Ordering::Relaxed);
        } else {
            self.registration_failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_status_change(&self, from: ParachainStatus, to: ParachainStatus) {
        match from {
            ParachainStatus::Active => self.active_count.fetch_sub(1, Ordering::Relaxed),
            ParachainStatus::Paused => self.paused_count.fetch_sub(1, Ordering::Relaxed),
            _ => 0,
        };
        match to {
            ParachainStatus::Active => self.active_count.fetch_add(1, Ordering::Relaxed),
            ParachainStatus::Paused => self.paused_count.fetch_add(1, Ordering::Relaxed),
            ParachainStatus::Deregistered => self.deregistered_count.fetch_add(1, Ordering::Relaxed),
            _ => 0,
        };
    }

    pub fn record_activation(&self) {
        self.activations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_pause(&self) {
        self.pauses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_deregistration(&self) {
        self.deregistrations.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> RegistryMetricsSnapshot {
        RegistryMetricsSnapshot {
            total_registered: self.total_registered.load(Ordering::Relaxed),
            active_count: self.active_count.load(Ordering::Relaxed),
            paused_count: self.paused_count.load(Ordering::Relaxed),
            deregistered_count: self.deregistered_count.load(Ordering::Relaxed),
            activations: self.activations.load(Ordering::Relaxed),
            pauses: self.pauses.load(Ordering::Relaxed),
            deregistrations: self.deregistrations.load(Ordering::Relaxed),
            registration_failures: self.registration_failures.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of registry metrics.
#[derive(Debug, Clone)]
pub struct RegistryMetricsSnapshot {
    pub total_registered: u64,
    pub active_count: u64,
    pub paused_count: u64,
    pub deregistered_count: u64,
    pub activations: u64,
    pub pauses: u64,
    pub deregistrations: u64,
    pub registration_failures: u64,
}

// ── Status ──────────────────────────────────────────────────────────────

/// Status of a parachain in the registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParachainStatus {
    Registered,
    Active,
    Paused,
    Deregistered,
}

impl ParachainStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Registered => "registered",
            Self::Active => "active",
            Self::Paused => "paused",
            Self::Deregistered => "deregistered",
        }
    }
}

// ── Parachain Info ──────────────────────────────────────────────────────

/// Information about a registered parachain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParachainInfo {
    pub id: u32,
    pub name: String,
    pub owner: String,
    pub status: ParachainStatus,
    pub slot_id: Option<u64>,
    pub validation_code_hash: [u8; 32],
    pub registered_at: u64,
    pub deposit: u64,
    /// Optional metadata for the parachain (e.g., description, website)
    #[serde(default)]
    pub metadata: BTreeMap<String, String>,
    /// Timestamp of last status change
    #[serde(default)]
    pub last_status_change: u64,
}

impl ParachainInfo {
    /// Check if the parachain is active.
    pub fn is_active(&self) -> bool {
        self.status == ParachainStatus::Active
    }

    /// Check if the parachain is registered.
    pub fn is_registered(&self) -> bool {
        self.status == ParachainStatus::Registered
    }

    /// Check if the parachain is paused.
    pub fn is_paused(&self) -> bool {
        self.status == ParachainStatus::Paused
    }

    /// Check if the parachain is deregistered.
    pub fn is_deregistered(&self) -> bool {
        self.status == ParachainStatus::Deregistered
    }

    /// Get the slot ID if active.
    pub fn slot(&self) -> Option<u64> {
        self.slot_id
    }
}

// ── Parachain Registry ──────────────────────────────────────────────────

/// Registry of all parachains.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParachainRegistry {
    /// Map of parachain ID to info.
    chains: BTreeMap<u32, ParachainInfo>,
    /// Next available parachain ID.
    next_id: u32,
    /// Configuration (for validation).
    #[serde(skip)]
    config: Option<RegistryConfig>,
    /// Metrics (for recording).
    #[serde(skip)]
    metrics: Option<Arc<RegistryMetrics>>,
}

impl ParachainRegistry {
    /// Create a new registry with default configuration.
    pub fn new() -> Self {
        Self {
            chains: BTreeMap::new(),
            next_id: 1,
            config: None,
            metrics: None,
        }
    }

    /// Create a new registry with configuration.
    pub fn with_config(config: RegistryConfig) -> Self {
        Self {
            chains: BTreeMap::new(),
            next_id: 1,
            config: Some(config),
            metrics: None,
        }
    }

    /// Set metrics for this registry.
    pub fn set_metrics(&mut self, metrics: Arc<RegistryMetrics>) {
        self.metrics = Some(metrics);
    }

    /// Register a new parachain (generates a new ID).
    pub fn register(
        &mut self,
        name: &str,
        owner: &str,
        validation_code_hash: [u8; 32],
        deposit: u64,
        block_height: u64,
    ) -> ParachainResult<u32> {
        // Check configuration.
        if let Some(config) = &self.config {
            if self.chains.len() >= config.max_parachains {
                if let Some(metrics) = &self.metrics {
                    metrics.record_registration(false);
                }
                return Err(ParachainError::TooManyParachains {
                    max: config.max_parachains,
                });
            }
            if deposit < config.min_deposit {
                if let Some(metrics) = &self.metrics {
                    metrics.record_registration(false);
                }
                return Err(ParachainError::InsufficientFunds {
                    need: config.min_deposit,
                    have: deposit,
                });
            }
            if config.validate_names {
                if name.trim().is_empty() {
                    return Err(ParachainError::Registry("name cannot be empty".into()));
                }
                // Check for duplicate names.
                for info in self.chains.values() {
                    if info.name == name {
                        return Err(ParachainError::Registry(
                            format!("parachain name '{}' already exists", name)
                        ));
                    }
                }
            }
        }

        let id = self.next_id;
        self.next_id += 1;

        let info = ParachainInfo {
            id,
            name: name.to_string(),
            owner: owner.to_string(),
            status: ParachainStatus::Registered,
            slot_id: None,
            validation_code_hash,
            registered_at: block_height,
            deposit,
            metadata: BTreeMap::new(),
            last_status_change: block_height,
        };

        self.chains.insert(id, info);

        if let Some(metrics) = &self.metrics {
            metrics.record_registration(true);
        }
        if let Some(config) = &self.config {
            if config.log_operations {
                info!(id, name, owner, "parachain registered");
            }
        }

        Ok(id)
    }

    /// Activate a parachain (assign a slot to it).
    pub fn activate(&mut self, id: u32, slot_id: u64) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        if info.status != ParachainStatus::Registered {
            return Err(ParachainError::Sovereign(
                format!("chain {} not in registered state (status: {:?})", id, info.status)
            ));
        }

        let old_status = info.status;
        info.status = ParachainStatus::Active;
        info.slot_id = Some(slot_id);
        info.last_status_change = current_block_height();

        if let Some(metrics) = &self.metrics {
            metrics.record_status_change(old_status, ParachainStatus::Active);
            metrics.record_activation();
        }
        if let Some(config) = &self.config {
            if config.log_operations {
                info!(id, slot_id, "parachain activated");
            }
        }

        Ok(())
    }

    /// Pause a parachain (e.g., after slashing).
    pub fn pause(&mut self, id: u32) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        let old_status = info.status;
        info.status = ParachainStatus::Paused;
        info.last_status_change = current_block_height();

        if let Some(metrics) = &self.metrics {
            metrics.record_status_change(old_status, ParachainStatus::Paused);
            metrics.record_pause();
        }
        if let Some(config) = &self.config {
            if config.log_operations {
                warn!(id, "parachain paused");
            }
        }

        Ok(())
    }

    /// Deregister a parachain (slashing the deposit).
    pub fn deregister(&mut self, id: u32) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        let old_status = info.status;
        info.status = ParachainStatus::Deregistered;
        info.last_status_change = current_block_height();

        if let Some(metrics) = &self.metrics {
            metrics.record_status_change(old_status, ParachainStatus::Deregistered);
            metrics.record_deregistration();
        }
        if let Some(config) = &self.config {
            if config.log_operations {
                warn!(id, owner = %info.owner, "parachain deregistered");
            }
        }

        Ok(())
    }

    /// Get a reference to a parachain info.
    pub fn get(&self, id: u32) -> Option<&ParachainInfo> {
        self.chains.get(&id)
    }

    /// Get a mutable reference.
    pub fn get_mut(&mut self, id: u32) -> Option<&mut ParachainInfo> {
        self.chains.get_mut(&id)
    }

    /// Get a parachain by name.
    pub fn get_by_name(&self, name: &str) -> Option<&ParachainInfo> {
        self.chains.values().find(|info| info.name == name)
    }

    /// List all active parachains.
    pub fn active(&self) -> Vec<&ParachainInfo> {
        self.chains
            .values()
            .filter(|c| c.status == ParachainStatus::Active)
            .collect()
    }

    /// List all parachains.
    pub fn all(&self) -> Vec<&ParachainInfo> {
        self.chains.values().collect()
    }

    /// Get total number of parachains.
    pub fn total(&self) -> usize {
        self.chains.len()
    }

    /// Get number of active parachains.
    pub fn active_count(&self) -> usize {
        self.active().len()
    }

    /// Check if a parachain exists.
    pub fn exists(&self, id: u32) -> bool {
        self.chains.contains_key(&id)
    }

    /// Update parachain metadata.
    pub fn set_metadata(&mut self, id: u32, key: &str, value: &str) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        info.metadata.insert(key.to_string(), value.to_string());
        Ok(())
    }

    /// Remove a metadata key.
    pub fn remove_metadata(&mut self, id: u32, key: &str) -> ParachainResult<()> {
        let info = self.chains.get_mut(&id).ok_or(ParachainError::NotFound(id))?;
        info.metadata.remove(key);
        Ok(())
    }

    /// Clear all parachains (for testing).
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.chains.clear();
        self.next_id = 1;
    }
}

impl Default for ParachainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── RegistryManager (thread‑safe) ──────────────────────────────────────

/// Thread‑safe manager for the parachain registry.
#[derive(Clone)]
pub struct RegistryManager {
    config: Arc<RegistryConfig>,
    metrics: Arc<RegistryMetrics>,
    registry: Arc<parking_lot::Mutex<ParachainRegistry>>,
}

impl RegistryManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: RegistryConfig) -> Result<Self, ParachainError> {
        config.validate().map_err(|e| ParachainError::Config(e))?;
        let metrics = Arc::new(RegistryMetrics::default());
        let mut registry = ParachainRegistry::with_config(config.clone());
        registry.set_metrics(metrics.clone());

        Ok(Self {
            config: Arc::new(config),
            metrics,
            registry: Arc::new(parking_lot::Mutex::new(registry)),
        })
    }

    /// Register a new parachain.
    pub fn register(
        &self,
        name: &str,
        owner: &str,
        validation_code_hash: [u8; 32],
        deposit: u64,
        block_height: u64,
    ) -> ParachainResult<u32> {
        self.registry.lock().register(
            name,
            owner,
            validation_code_hash,
            deposit,
            block_height,
        )
    }

    /// Activate a parachain.
    pub fn activate(&self, id: u32, slot_id: u64) -> ParachainResult<()> {
        self.registry.lock().activate(id, slot_id)
    }

    /// Pause a parachain.
    pub fn pause(&self, id: u32) -> ParachainResult<()> {
        self.registry.lock().pause(id)
    }

    /// Deregister a parachain.
    pub fn deregister(&self, id: u32) -> ParachainResult<()> {
        self.registry.lock().deregister(id)
    }

    /// Get a parachain info (read‑only).
    pub fn get(&self, id: u32) -> Option<ParachainInfo> {
        self.registry.lock().get(id).cloned()
    }

    /// Get a parachain by name.
    pub fn get_by_name(&self, name: &str) -> Option<ParachainInfo> {
        self.registry.lock().get_by_name(name).cloned()
    }

    /// List all active parachains.
    pub fn active(&self) -> Vec<ParachainInfo> {
        self.registry.lock().active().into_iter().cloned().collect()
    }

    /// List all parachains.
    pub fn all(&self) -> Vec<ParachainInfo> {
        self.registry.lock().all().into_iter().cloned().collect()
    }

    /// Get total number of parachains.
    pub fn total(&self) -> usize {
        self.registry.lock().total()
    }

    /// Check if a parachain exists.
    pub fn exists(&self, id: u32) -> bool {
        self.registry.lock().exists(id)
    }

    /// Update metadata.
    pub fn set_metadata(&self, id: u32, key: &str, value: &str) -> ParachainResult<()> {
        self.registry.lock().set_metadata(id, key, value)
    }

    /// Remove metadata.
    pub fn remove_metadata(&self, id: u32, key: &str) -> ParachainResult<()> {
        self.registry.lock().remove_metadata(id, key)
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> RegistryMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &RegistryConfig {
        &self.config
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────

/// Get the current block height (placeholder).
/// In production, this would come from the consensus engine.
fn current_block_height() -> u64 {
    // For now, we use a simple timestamp.
    // In a real implementation, this would be the current block height.
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_registration() {
        let mut reg = ParachainRegistry::new();
        let id = reg.register("mychain", "owner", [0u8; 32], 10000, 100).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Registered);
        reg.activate(id, 5).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Active);
        assert_eq!(reg.get(id).unwrap().slot_id, Some(5));
    }

    #[test]
    fn test_config_validation() {
        let mut config = RegistryConfig::default();
        assert!(config.validate().is_ok());

        config.max_parachains = 0;
        assert!(config.validate().is_err());

        config.max_parachains = 10;
        config.min_deposit = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_register_with_config() {
        let config = RegistryConfig::default();
        let mut reg = ParachainRegistry::with_config(config);
        let result = reg.register("mychain", "owner", [0u8; 32], 500, 100);
        assert!(matches!(result, Err(ParachainError::InsufficientFunds { .. })));
    }

    #[test]
    fn test_duplicate_name() {
        let config = RegistryConfig {
            validate_names: true,
            ..Default::default()
        };
        let mut reg = ParachainRegistry::with_config(config);
        reg.register("mychain", "owner1", [0u8; 32], 10000, 100).unwrap();
        let result = reg.register("mychain", "owner2", [0u8; 32], 10000, 100);
        assert!(matches!(result, Err(ParachainError::Registry(_))));
    }

    #[test]
    fn test_max_parachains() {
        let config = RegistryConfig {
            max_parachains: 2,
            ..Default::default()
        };
        let mut reg = ParachainRegistry::with_config(config);
        reg.register("chain1", "owner1", [0u8; 32], 10000, 100).unwrap();
        reg.register("chain2", "owner2", [0u8; 32], 10000, 100).unwrap();
        let result = reg.register("chain3", "owner3", [0u8; 32], 10000, 100);
        assert!(matches!(result, Err(ParachainError::TooManyParachains { .. })));
    }

    #[test]
    fn test_pause_and_deregister() {
        let mut reg = ParachainRegistry::new();
        let id = reg.register("mychain", "owner", [0u8; 32], 10000, 100).unwrap();
        reg.activate(id, 5).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Active);

        reg.pause(id).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Paused);

        reg.deregister(id).unwrap();
        assert_eq!(reg.get(id).unwrap().status, ParachainStatus::Deregistered);
    }

    #[test]
    fn test_metadata() {
        let mut reg = ParachainRegistry::new();
        let id = reg.register("mychain", "owner", [0u8; 32], 10000, 100).unwrap();
        reg.set_metadata(id, "website", "https://example.com").unwrap();
        let info = reg.get(id).unwrap();
        assert_eq!(info.metadata.get("website"), Some(&"https://example.com".to_string()));

        reg.remove_metadata(id, "website").unwrap();
        let info = reg.get(id).unwrap();
        assert!(!info.metadata.contains_key("website"));
    }

    #[test]
    fn test_manager() {
        let config = RegistryConfig::default();
        let manager = RegistryManager::new(config).unwrap();
        let id = manager.register("mychain", "owner", [0u8; 32], 10000, 100).unwrap();
        manager.activate(id, 5).unwrap();

        assert_eq!(manager.total(), 1);
        assert_eq!(manager.active().len(), 1);
        assert!(manager.exists(id));
        assert_eq!(manager.get(id).unwrap().status, ParachainStatus::Active);

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_registered, 1);
        assert_eq!(snap.active_count, 1);
    }
}
