//! Protocol versioning for IONA.
//!
//! Every block header carries a `protocol_version` field. Nodes use this to:
//!   - Decide which validation / execution rules to apply.
//!   - Reject blocks produced under an unsupported protocol.
//!   - Coordinate hard‑fork upgrades via an **activation height**.
//!
//! # Upgrade flow
//!
//! 1. **Minor (rolling):** `protocol_version` stays the same; only storage
//!    schema or RPC fields change. Nodes upgrade one‑by‑one with no halt.
//!
//! 2. **Major (coordinated):** A new `protocol_version` is introduced.
//!    - Pre‑activation: nodes support *both* old and new versions.
//!    - At `activation_height`: nodes start producing new‑version blocks.
//!    - After a grace window: old‑version blocks are rejected.
//!
//! # Example
//!
//! ```
//! use iona::protocol::version::{VersionConfig, version_for_height, validate_block_version};
//!
//! let config = VersionConfig::default();
//! let activations = config.activations();
//! let pv = version_for_height(1000, &activations);
//! assert_eq!(pv, 1);
//! validate_block_version(1, 1000, &activations).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Constants (defaults)
// -----------------------------------------------------------------------------

/// Default protocol version this binary produces.
pub const DEFAULT_PROTOCOL_VERSION: u32 = 1;

/// Default supported versions.
pub const DEFAULT_SUPPORTED_VERSIONS: &[u32] = &[1];

/// Default grace blocks when not specified.
pub const DEFAULT_GRACE_BLOCKS: u64 = 1000;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during version validation.
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

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

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
            return Err(VersionError::Config("current_version must be > 0".into()));
        }
        if self.supported_versions.is_empty() {
            return Err(VersionError::Config("supported_versions cannot be empty".into()));
        }
        if !self.supported_versions.contains(&self.current_version) {
            return Err(VersionError::Config(format!(
                "current_version {} not in supported_versions: {:?}",
                self.current_version, self.supported_versions
            )));
        }
        if self.min_version == 0 {
            return Err(VersionError::Config("min_version must be > 0".into()));
        }
        if self.default_grace_blocks == 0 {
            return Err(VersionError::Config("default_grace_blocks must be > 0".into()));
        }
        Ok(())
    }

    /// Get the default activation schedule based on this config.
    pub fn default_activations(&self) -> Vec<ProtocolActivation> {
        vec![ProtocolActivation {
            protocol_version: self.min_version,
            activation_height: None,
            grace_blocks: 0,
        }]
    }
}

// -----------------------------------------------------------------------------
// Activation configuration
// -----------------------------------------------------------------------------

/// Per‑version activation rule.
///
/// When the chain reaches `activation_height`, the node switches to producing
/// blocks with `protocol_version`. Before that height, it continues to
/// produce blocks with the previous version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolActivation {
    /// The protocol version to activate.
    pub protocol_version: u32,
    /// Block height at which this version becomes mandatory.
    /// `None` means "already active from genesis".
    pub activation_height: Option<u64>,
    /// Number of blocks after `activation_height` during which the *previous*
    /// version is still accepted (grace window for stragglers).
    /// After `activation_height + grace_blocks`, only this version is accepted.
    #[serde(default = "default_grace_blocks")]
    pub grace_blocks: u64,
}

/// Default grace blocks value (1000 blocks).
fn default_grace_blocks() -> u64 {
    1000
}

impl ProtocolActivation {
    /// Validate a single activation entry.
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

// -----------------------------------------------------------------------------
// Schedule validation
// -----------------------------------------------------------------------------

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

    // Check each entry.
    for a in activations {
        a.validate()?;
    }

    // Check that protocol versions are strictly increasing and all supported.
    let mut prev_pv = 0;
    let mut prev_height: Option<u64> = None;
    let mut seen_pvs = BTreeSet::new();

    for a in activations {
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

    // Ensure the first activation is for version >= min_version.
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

// -----------------------------------------------------------------------------
// Core queries
// -----------------------------------------------------------------------------

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
) -> VersionResult<()> {
    // Use the default config for supported versions.
    let config = VersionConfig::default();
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

/// Returns `true` if this binary supports the given protocol version.
#[must_use]
pub fn is_supported(version: u32) -> bool {
    VersionConfig::default().supported_versions.contains(&version)
}

// -----------------------------------------------------------------------------
// Convenience helpers
// -----------------------------------------------------------------------------

/// Human‑readable version string for logs / RPC.
#[must_use]
pub fn version_string() -> String {
    let config = VersionConfig::default();
    format!(
        "iona-node v{} (protocol v{}, schema v{})",
        env!("CARGO_PKG_VERSION"),
        config.current_version,
        crate::storage::CURRENT_SCHEMA_VERSION,
    )
}

/// Returns the highest (latest) protocol version supported by this binary.
#[must_use]
pub fn max_supported_pv() -> u32 {
    let config = VersionConfig::default();
    *config.supported_versions.iter().max().unwrap_or(&1)
}

/// Returns the lowest (earliest) protocol version supported by this binary.
#[must_use]
pub fn min_supported_pv() -> u32 {
    let config = VersionConfig::default();
    *config.supported_versions.iter().min().unwrap_or(&1)
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
        let activations = default_activations();
        assert!(validate_block_version(1, 0, &activations).is_ok());
        assert!(validate_block_version(1, 1_000_000, &activations).is_ok());
    }

    #[test]
    fn test_validate_block_version_unsupported() {
        let activations = default_activations();
        let err = validate_block_version(99, 0, &activations).unwrap_err();
        assert!(matches!(err, VersionError::Unsupported { version: 99, .. }));
    }

    #[test]
    fn test_validate_block_version_grace_window() {
        let activations = vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: Some(1000),
            grace_blocks: 100,
        }];
        assert!(validate_block_version(1, 999, &activations).is_ok());
        assert!(validate_block_version(1, 1000, &activations).is_ok());
        assert!(validate_block_version(1, 1100, &activations).is_ok());
        let err = validate_block_version(99, 1000, &activations).unwrap_err();
        assert!(matches!(err, VersionError::Unsupported { .. }));
    }

    #[test]
    fn test_validate_block_version_too_old() {
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
        // At height 2000, PV=1 should be rejected (grace expired).
        let err = validate_block_version(1, 2000, &activations).unwrap_err();
        assert!(matches!(err, VersionError::TooOld { version: 1, height: 2000, expected: 2 }));
    }

    #[test]
    fn test_is_supported() {
        assert!(is_supported(1));
        assert!(!is_supported(0));
        assert!(!is_supported(99));
    }

    #[test]
    fn test_max_supported_pv() {
        assert_eq!(max_supported_pv(), 1);
    }

    #[test]
    fn test_min_supported_pv() {
        assert_eq!(min_supported_pv(), 1);
    }

    #[test]
    fn test_version_string() {
        let s = version_string();
        assert!(s.contains("iona-node v"));
        assert!(s.contains("protocol v1"));
        assert!(s.contains("schema v"));
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
