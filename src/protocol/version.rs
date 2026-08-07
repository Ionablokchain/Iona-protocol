//! Protocol versioning for IONA.
//!
//! Every block header carries a `protocol_version` field. Nodes use this to:
//!   - Decide which validation / execution rules to apply.
//!   - Reject blocks produced under an unsupported protocol.
//!   - Coordinate hard‑fork upgrades via an **activation height**.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                        Protocol Version Module                         │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │  activation   │        schedule          │
//! │ (VersionCfg)│ (VersionError)│ (Activation)  │ (validation, queries)    │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │                 manager (VersionManager)                               │
//! │              (centralised state + operations)                         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::version::{VersionManager, VersionConfig};
//!
//! let config = VersionConfig::default();
//! let manager = VersionManager::new(config).unwrap();
//! let pv = manager.version_for_height(1000);
//! assert_eq!(pv, 1);
//! manager.validate_block_version(1, 1000).unwrap();
//! ```

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for protocol versioning.
    use serde::{Deserialize, Serialize};
    use super::error::VersionResult;

    /// Constants (defaults)
    pub const DEFAULT_PROTOCOL_VERSION: u32 = 1;
    pub const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[1];
    pub const DEFAULT_GRACE_BLOCKS: u64 = 1000;

    /// Configuration for protocol versioning.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct VersionConfig {
        /// The protocol version this binary produces.
        pub current_version: u32,
        /// All protocol versions this binary can validate/execute.
        pub supported_versions: Vec<u32>,
        /// Minimum version accepted for new blocks (after grace).
        pub min_version: u32,
        /// Default grace blocks.
        pub default_grace_blocks: u64,
    }

    impl Default for VersionConfig {
        fn default() -> Self {
            Self {
                current_version: DEFAULT_PROTOCOL_VERSION,
                supported_versions: DEFAULT_SUPPORTED_VERSIONS.to_vec(),
                min_version: DEFAULT_PROTOCOL_VERSION,
                default_grace_blocks: DEFAULT_GRACE_BLOCKS,
            }
        }
    }

    impl VersionConfig {
        /// Create a config for testing with a custom current version.
        pub fn with_current(mut self, version: u32) -> Self {
            self.current_version = version;
            self
        }

        /// Create a config with extra supported versions.
        pub fn with_supported(mut self, versions: &[u32]) -> Self {
            self.supported_versions = versions.to_vec();
            self
        }

        /// Validate the configuration.
        pub fn validate(&self) -> VersionResult<()> {
            if self.current_version == 0 {
                return Err(super::error::VersionError::Config("current_version must be > 0".into()));
            }
            if self.supported_versions.is_empty() {
                return Err(super::error::VersionError::Config("supported_versions cannot be empty".into()));
            }
            if !self.supported_versions.contains(&self.current_version) {
                return Err(super::error::VersionError::Config(format!(
                    "current_version {} not in supported_versions: {:?}",
                    self.current_version, self.supported_versions
                )));
            }
            if self.min_version == 0 {
                return Err(super::error::VersionError::Config("min_version must be > 0".into()));
            }
            if self.default_grace_blocks == 0 {
                return Err(super::error::VersionError::Config("default_grace_blocks must be > 0".into()));
            }
            Ok(())
        }

        /// Get the default activation schedule based on this config.
        pub fn default_activations(&self) -> Vec<super::activation::ProtocolActivation> {
            vec![super::activation::ProtocolActivation {
                protocol_version: self.min_version,
                activation_height: None,
                grace_blocks: 0,
            }]
        }
    }
}

pub mod error {
    //! Error types for version validation.
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum VersionError {
        #[error("unsupported protocol version {version}; supported: {supported:?}")]
        Unsupported { version: u32, supported: Vec<u32> },

        #[error("protocol version {version} is too old at height {height}; expected >= {expected} (grace window expired)")]
        TooOld { version: u32, height: u64, expected: u32 },

        #[error("activation schedule invalid: {detail}")]
        InvalidSchedule { detail: String },

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type VersionResult<T> = Result<T, VersionError>;
}

pub mod activation {
    //! Activation configuration and defaults.
    use serde::{Deserialize, Serialize};
    use super::error::{VersionResult, VersionError};

    /// Per‑version activation rule.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ProtocolActivation {
        pub protocol_version: u32,
        pub activation_height: Option<u64>,
        #[serde(default = "default_grace_blocks")]
        pub grace_blocks: u64,
    }

    fn default_grace_blocks() -> u64 {
        1000
    }

    impl ProtocolActivation {
        pub fn validate(&self) -> VersionResult<()> {
            if self.protocol_version == 0 {
                return Err(VersionError::InvalidSchedule {
                    detail: "protocol_version must be > 0".into(),
                });
            }
            if let Some(h) = self.activation_height {
                if h == 0 {
                    return Err(VersionError::InvalidSchedule {
                        detail: "activation_height cannot be 0 (use None for genesis)".into(),
                    });
                }
            }
            Ok(())
        }
    }

    /// Returns the default activation schedule: protocol version 1 active from genesis.
    #[must_use]
    pub fn default_activations() -> Vec<ProtocolActivation> {
        vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }]
    }

    /// Get a summary of the activation schedule (for debugging / RPC).
    #[must_use]
    pub fn activation_summary(activations: &[ProtocolActivation]) -> Vec<String> {
        activations
            .iter()
            .map(|a| {
                format!(
                    "PV {} -> height {:?}, grace {}",
                    a.protocol_version, a.activation_height, a.grace_blocks
                )
            })
            .collect()
    }
}

pub mod schedule {
    //! Schedule validation and queries.
    use super::{
        config::VersionConfig,
        error::{VersionResult, VersionError},
        activation::ProtocolActivation,
    };
    use std::collections::BTreeSet;
    use tracing::{debug, warn};

    /// Validate an activation schedule for consistency.
    pub fn validate_activation_schedule(
        activations: &[ProtocolActivation],
        config: &VersionConfig,
    ) -> VersionResult<()> {
        if activations.is_empty() {
            return Err(VersionError::InvalidSchedule {
                detail: "schedule cannot be empty".into(),
            });
        }

        let mut prev_pv = 0;
        let mut prev_height: Option<u64> = None;
        let mut seen_pvs = BTreeSet::new();

        for a in activations {
            a.validate()?;

            if a.protocol_version <= prev_pv {
                return Err(VersionError::InvalidSchedule {
                    detail: format!(
                        "protocol versions must be strictly increasing: {} <= {}",
                        a.protocol_version, prev_pv
                    ),
                });
            }
            if !config.supported_versions.contains(&a.protocol_version) {
                return Err(VersionError::InvalidSchedule {
                    detail: format!(
                        "protocol version {} not in supported versions {:?}",
                        a.protocol_version, config.supported_versions
                    ),
                });
            }
            if seen_pvs.contains(&a.protocol_version) {
                return Err(VersionError::InvalidSchedule {
                    detail: format!("duplicate protocol version {}", a.protocol_version),
                });
            }
            seen_pvs.insert(a.protocol_version);

            if let Some(h) = a.activation_height {
                if let Some(prev) = prev_height {
                    if h <= prev {
                        return Err(VersionError::InvalidSchedule {
                            detail: format!(
                                "activation heights must be strictly increasing: {} <= {}",
                                h, prev
                            ),
                        });
                    }
                }
                prev_height = Some(h);
            }
            prev_pv = a.protocol_version;
        }

        if activations[0].protocol_version < config.min_version {
            return Err(VersionError::InvalidSchedule {
                detail: format!(
                    "first protocol version {} is below min_version {}",
                    activations[0].protocol_version, config.min_version
                ),
            });
        }

        Ok(())
    }

    /// Returns the protocol version that should be used when producing a block
    /// at the given `height`, based on the activation schedule.
    #[must_use]
    pub fn version_for_height(height: u64, activations: &[ProtocolActivation]) -> u32 {
        let mut active_version = 1u32;
        for activation in activations {
            match activation.activation_height {
                None => {
                    active_version = active_version.max(activation.protocol_version);
                }
                Some(h) if height >= h => {
                    active_version = active_version.max(activation.protocol_version);
                }
                _ => {}
            }
        }
        debug!(height, active_version, "computed PV for height");
        active_version
    }

    /// Check whether a given `protocol_version` is acceptable for a block at
    /// `height`. Returns `Ok(())` or a `VersionError`.
    pub fn validate_block_version(
        block_version: u32,
        height: u64,
        activations: &[ProtocolActivation],
        config: &VersionConfig,
    ) -> VersionResult<()> {
        if !config.supported_versions.contains(&block_version) {
            let err = VersionError::Unsupported {
                version: block_version,
                supported: config.supported_versions.clone(),
            };
            warn!("{}", err);
            return Err(err);
        }

        let expected = version_for_height(height, activations);
        if block_version < expected {
            let in_grace = activations.iter().any(|activation| {
                activation.protocol_version == expected
                    && activation
                        .activation_height
                        .map(|ah| height < ah + activation.grace_blocks)
                        .unwrap_or(false)
            });
            if !in_grace {
                let err = VersionError::TooOld {
                    version: block_version,
                    height,
                    expected,
                };
                warn!("{}", err);
                return Err(err);
            }
        }

        debug!(
            height,
            block_version,
            expected_version = expected,
            "block version validation passed"
        );
        Ok(())
    }
}

pub mod metrics {
    //! Metrics for version checks.
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct VersionMetrics {
        pub total_checks: AtomicU64,
        pub passed_checks: AtomicU64,
        pub failed_checks: AtomicU64,
        pub total_duration_ms: AtomicU64,
    }

    impl VersionMetrics {
        pub fn record_check(&self, passed: bool, duration_ms: u64) {
            self.total_checks.fetch_add(1, Ordering::Relaxed);
            if passed {
                self.passed_checks.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_checks.fetch_add(1, Ordering::Relaxed);
            }
            self.total_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> VersionMetricsSnapshot {
            VersionMetricsSnapshot {
                total_checks: self.total_checks.load(Ordering::Relaxed),
                passed_checks: self.passed_checks.load(Ordering::Relaxed),
                failed_checks: self.failed_checks.load(Ordering::Relaxed),
                total_duration_ms: self.total_duration_ms.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct VersionMetricsSnapshot {
        pub total_checks: u64,
        pub passed_checks: u64,
        pub failed_checks: u64,
        pub total_duration_ms: u64,
    }
}

pub mod manager {
    //! Centralised version manager.
    use super::{
        config::VersionConfig,
        error::{VersionResult, VersionError},
        activation::ProtocolActivation,
        schedule::{validate_activation_schedule, version_for_height, validate_block_version},
        metrics::VersionMetrics,
    };
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info, warn};

    /// Centralised manager for protocol versioning.
    #[derive(Debug)]
    pub struct VersionManager {
        config: VersionConfig,
        activations: Vec<ProtocolActivation>,
        metrics: Arc<VersionMetrics>,
    }

    impl VersionManager {
        /// Create a new manager with default configuration and activations.
        pub fn new(config: VersionConfig) -> VersionResult<Self> {
            config.validate()?;
            let activations = config.default_activations();
            validate_activation_schedule(&activations, &config)?;
            info!(
                current_version = config.current_version,
                supported = ?config.supported_versions,
                "version manager created"
            );
            Ok(Self {
                config,
                activations,
                metrics: Arc::new(VersionMetrics::default()),
            })
        }

        /// Create a manager with a custom activation schedule.
        pub fn with_activations(
            config: VersionConfig,
            activations: Vec<ProtocolActivation>,
        ) -> VersionResult<Self> {
            config.validate()?;
            validate_activation_schedule(&activations, &config)?;
            info!(
                current_version = config.current_version,
                activations_len = activations.len(),
                "version manager created with custom schedule"
            );
            Ok(Self {
                config,
                activations,
                metrics: Arc::new(VersionMetrics::default()),
            })
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &VersionMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &VersionConfig {
            &self.config
        }

        /// Get the activation schedule.
        pub fn activations(&self) -> &[ProtocolActivation] {
            &self.activations
        }

        /// Update configuration at runtime (re‑validates schedule).
        pub fn set_config(&mut self, config: VersionConfig) -> VersionResult<()> {
            config.validate()?;
            validate_activation_schedule(&self.activations, &config)?;
            self.config = config;
            Ok(())
        }

        /// Replace the activation schedule (re‑validates).
        pub fn set_activations(&mut self, activations: Vec<ProtocolActivation>) -> VersionResult<()> {
            validate_activation_schedule(&activations, &self.config)?;
            self.activations = activations;
            Ok(())
        }

        /// Returns the protocol version for a given height.
        pub fn version_for_height(&self, height: u64) -> u32 {
            version_for_height(height, &self.activations)
        }

        /// Validate a block's protocol version.
        pub fn validate_block_version(&self, block_version: u32, height: u64) -> VersionResult<()> {
            let start = Instant::now();
            let result = validate_block_version(block_version, height, &self.activations, &self.config);
            let dur = start.elapsed().as_millis() as u64;
            let passed = result.is_ok();
            self.metrics.record_check(passed, dur);
            if !passed {
                warn!(
                    block_version,
                    height,
                    error = ?result.err(),
                    "block version validation failed"
                );
            } else {
                debug!(block_version, height, "block version validation passed");
            }
            result
        }

        /// Check if a protocol version is supported by this binary.
        pub fn is_supported(&self, version: u32) -> bool {
            self.config.supported_versions.contains(&version)
        }

        /// Returns the highest supported version.
        pub fn max_supported(&self) -> u32 {
            *self.config.supported_versions.iter().max().unwrap_or(&1)
        }

        /// Returns the lowest supported version.
        pub fn min_supported(&self) -> u32 {
            *self.config.supported_versions.iter().min().unwrap_or(&1)
        }

        /// Get the current (produced) version.
        pub fn current_version(&self) -> u32 {
            self.config.current_version
        }

        /// Get a summary of the activation schedule.
        pub fn activation_summary(&self) -> Vec<String> {
            super::activation::activation_summary(&self.activations)
        }

        /// Human‑readable version string.
        pub fn version_string(&self) -> String {
            format!(
                "iona-node v{} (protocol v{}, schema v{})",
                env!("CARGO_PKG_VERSION"),
                self.config.current_version,
                crate::storage::CURRENT_SCHEMA_VERSION,
            )
        }

        /// Validate the entire schedule (consistency check).
        pub fn validate_schedule(&self) -> VersionResult<()> {
            validate_activation_schedule(&self.activations, &self.config)
        }
    }

    // Convenience: default manager with default config and activations.
    impl Default for VersionManager {
        fn default() -> Self {
            Self::new(VersionConfig::default()).expect("default version manager")
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::VersionConfig;
pub use error::{VersionError, VersionResult};
pub use activation::{ProtocolActivation, default_activations, activation_summary};
pub use schedule::{validate_activation_schedule, version_for_height, validate_block_version};
pub use manager::VersionManager;
pub use metrics::{VersionMetrics, VersionMetricsSnapshot};

// -----------------------------------------------------------------------------
// Legacy standalone functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Returns the default activation schedule: protocol version 1 active from genesis.
#[deprecated(since = "1.0.0", note = "use VersionManager::activations() or default_activations()")]
pub fn default_activations() -> Vec<ProtocolActivation> {
    activation::default_activations()
}

/// Validate an activation schedule (legacy).
#[deprecated(since = "1.0.0", note = "use VersionManager::validate_schedule() or schedule::validate_activation_schedule")]
pub fn validate_activation_schedule_legacy(
    activations: &[ProtocolActivation],
    config: &VersionConfig,
) -> VersionResult<()> {
    schedule::validate_activation_schedule(activations, config)
}

/// Returns the protocol version for a given height (legacy).
#[deprecated(since = "1.0.0", note = "use VersionManager::version_for_height()")]
pub fn version_for_height_legacy(height: u64, activations: &[ProtocolActivation]) -> u32 {
    schedule::version_for_height(height, activations)
}

/// Validate a block's protocol version (legacy).
#[deprecated(since = "1.0.0", note = "use VersionManager::validate_block_version()")]
pub fn validate_block_version_legacy(
    block_version: u32,
    height: u64,
    activations: &[ProtocolActivation],
) -> VersionResult<()> {
    let config = VersionConfig::default();
    schedule::validate_block_version(block_version, height, activations, &config)
}

/// Returns `true` if this binary supports the given protocol version.
#[must_use]
pub fn is_supported(version: u32) -> bool {
    let manager = VersionManager::default();
    manager.is_supported(version)
}

/// Returns the highest (latest) protocol version supported by this binary.
#[must_use]
pub fn max_supported_pv() -> u32 {
    let manager = VersionManager::default();
    manager.max_supported()
}

/// Returns the lowest (earliest) protocol version supported by this binary.
#[must_use]
pub fn min_supported_pv() -> u32 {
    let manager = VersionManager::default();
    manager.min_supported()
}

/// Human‑readable version string for logs / RPC.
#[must_use]
pub fn version_string() -> String {
    let manager = VersionManager::default();
    manager.version_string()
}

// Re‑export constants for backward compatibility.
pub use config::{DEFAULT_PROTOCOL_VERSION, DEFAULT_SUPPORTED_VERSIONS, DEFAULT_GRACE_BLOCKS};

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_config_default() {
        let config = VersionConfig::default();
        assert_eq!(config.current_version, 1);
        assert_eq!(config.supported_versions, vec![1]);
    }

    #[test]
    fn test_version_config_validate_ok() {
        let config = VersionConfig::default();
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_version_config_validate_fail_empty_supported() {
        let mut config = VersionConfig::default();
        config.supported_versions = vec![];
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_version_config_validate_fail_current_not_supported() {
        let mut config = VersionConfig::default();
        config.current_version = 2;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_default_activations() {
        let a = default_activations();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].protocol_version, 1);
        assert!(a[0].activation_height.is_none());
    }

    #[test]
    fn test_validate_activation_schedule_ok() {
        let config = VersionConfig::default();
        let a = default_activations();
        assert!(validate_activation_schedule(&a, &config).is_ok());
    }

    #[test]
    fn test_validate_activation_schedule_with_upgrade_ok() {
        let config = VersionConfig::with_current(VersionConfig::default(), 2)
            .with_supported(&[1, 2]);
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ];
        assert!(validate_activation_schedule(&activations, &config).is_ok());
    }

    #[test]
    fn test_validate_activation_schedule_duplicate_pv() {
        let config = VersionConfig::default().with_supported(&[1, 2]);
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ];
        assert!(validate_activation_schedule(&activations, &config).is_err());
    }

    #[test]
    fn test_validate_activation_schedule_unsupported() {
        let config = VersionConfig::default();
        let activations = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        }];
        assert!(validate_activation_schedule(&activations, &config).is_err());
    }

    #[test]
    fn test_version_for_height_genesis() {
        let activations = default_activations();
        assert_eq!(version_for_height(0, &activations), 1);
        assert_eq!(version_for_height(999_999, &activations), 1);
    }

    #[test]
    fn test_version_for_height_with_upgrade() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(100_000),
                grace_blocks: 500,
            },
        ];
        assert_eq!(version_for_height(99_999, &activations), 1);
        assert_eq!(version_for_height(100_000, &activations), 2);
        assert_eq!(version_for_height(200_000, &activations), 2);
    }

    #[test]
    fn test_validate_block_version_ok() {
        let config = VersionConfig::default();
        let activations = default_activations();
        assert!(validate_block_version(1, 0, &activations, &config).is_ok());
        assert!(validate_block_version(1, 1_000_000, &activations, &config).is_ok());
    }

    #[test]
    fn test_validate_block_version_unsupported() {
        let config = VersionConfig::default();
        let activations = default_activations();
        let err = validate_block_version(99, 0, &activations, &config).unwrap_err();
        assert!(matches!(err, VersionError::Unsupported { version: 99, .. }));
    }

    #[test]
    fn test_validate_block_version_too_old() {
        let config = VersionConfig::default().with_supported(&[1, 2]);
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 10,
            },
        ];
        let err = validate_block_version(1, 2000, &activations, &config).unwrap_err();
        assert!(matches!(err, VersionError::TooOld { version: 1, height: 2000, expected: 2 }));
    }

    #[test]
    fn test_manager_new() {
        let manager = VersionManager::new(VersionConfig::default()).unwrap();
        assert_eq!(manager.current_version(), 1);
        assert!(manager.is_supported(1));
        assert!(!manager.is_supported(2));
    }

    #[test]
    fn test_manager_version_for_height() {
        let manager = VersionManager::new(VersionConfig::default()).unwrap();
        assert_eq!(manager.version_for_height(0), 1);
    }

    #[test]
    fn test_manager_validate_block_version() {
        let manager = VersionManager::new(VersionConfig::default()).unwrap();
        assert!(manager.validate_block_version(1, 0).is_ok());
    }

    #[test]
    fn test_manager_metrics() {
        let manager = VersionManager::default();
        let _ = manager.validate_block_version(1, 0);
        let metrics = manager.metrics().snapshot();
        assert_eq!(metrics.total_checks, 1);
        assert_eq!(metrics.passed_checks, 1);
    }

    #[test]
    fn test_manager_set_config() {
        let mut manager = VersionManager::default();
        let new_config = VersionConfig::with_current(VersionConfig::default(), 2)
            .with_supported(&[1, 2]);
        manager.set_config(new_config).unwrap();
        assert_eq!(manager.current_version(), 2);
    }

    #[test]
    fn test_manager_set_activations() {
        let mut manager = VersionManager::default();
        let new_activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ];
        manager.set_activations(new_activations).unwrap();
        assert_eq!(manager.activations().len(), 2);
    }

    #[test]
    fn test_manager_version_string() {
        let manager = VersionManager::default();
        let s = manager.version_string();
        assert!(s.contains("iona-node v"));
        assert!(s.contains("protocol v1"));
    }

    #[test]
    fn test_standalone_is_supported() {
        assert!(is_supported(1));
        assert!(!is_supported(99));
    }

    #[test]
    fn test_standalone_max_min_supported() {
        assert_eq!(max_supported_pv(), 1);
        assert_eq!(min_supported_pv(), 1);
    }

    #[test]
    fn test_activation_summary() {
        let activations = default_activations();
        let summary = activation_summary(&activations);
        assert_eq!(summary.len(), 1);
        assert!(summary[0].contains("PV 1"));
    }

    #[test]
    fn test_protocol_activation_validate_ok() {
        let a = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        assert!(a.validate().is_ok());
    }

    #[test]
    fn test_protocol_activation_validate_zero_pv() {
        let a = ProtocolActivation {
            protocol_version: 0,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        assert!(a.validate().is_err());
    }

    #[test]
    fn test_protocol_activation_validate_zero_height() {
        let a = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(0),
            grace_blocks: 100,
        };
        assert!(a.validate().is_err());
    }
}
