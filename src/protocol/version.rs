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
//! use iona::protocol::version::{version_for_height, validate_block_version, default_activations};
//!
//! let activations = default_activations();
//! let pv = version_for_height(1000, &activations);
//! assert_eq!(pv, 1);
//! validate_block_version(1, 1000, &activations).unwrap();
//! ```

use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// The protocol version this binary produces when creating new blocks.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// All protocol versions this binary can validate / execute.
/// Older versions are kept here to allow syncing historical blocks.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1];

/// Minimum protocol version accepted for *new* blocks after a grace window.
/// Set equal to `CURRENT_PROTOCOL_VERSION` once a hard fork is fully activated.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

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
/// `height`. Returns `Ok(())` or an error string.
#[must_use]
pub fn validate_block_version(
    block_version: u32,
    height: u64,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&block_version) {
        let err = format!(
            "unsupported protocol version {block_version}; supported: {SUPPORTED_PROTOCOL_VERSIONS:?}"
        );
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
            let err = format!(
                "protocol version {block_version} is too old at height {height}; \
                 expected >= {expected}"
            );
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
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

// -----------------------------------------------------------------------------
// Convenience helpers
// -----------------------------------------------------------------------------

/// Human‑readable version string for logs / RPC.
#[must_use]
pub fn version_string() -> String {
    format!(
        "iona-node v{} (protocol v{}, schema v{})",
        env!("CARGO_PKG_VERSION"),
        CURRENT_PROTOCOL_VERSION,
        crate::storage::CURRENT_SCHEMA_VERSION,
    )
}

/// Returns the highest (latest) protocol version supported by this binary.
#[must_use]
pub fn max_supported_pv() -> u32 {
    *SUPPORTED_PROTOCOL_VERSIONS.iter().max().unwrap_or(&1)
}

/// Returns the lowest (earliest) protocol version supported by this binary.
#[must_use]
pub fn min_supported_pv() -> u32 {
    *SUPPORTED_PROTOCOL_VERSIONS.iter().min().unwrap_or(&1)
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
        assert!(validate_block_version(99, 0, &activations).is_err());
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
        assert!(validate_block_version(99, 1000, &activations).is_err());
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
}
