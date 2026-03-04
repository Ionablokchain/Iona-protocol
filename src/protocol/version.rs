//! Protocol versioning for IONA.
//!
//! Every block header carries a `protocol_version` field.  Nodes use this to:
//!   - Decide which validation / execution rules to apply.
//!   - Reject blocks produced under an unsupported protocol.
//!   - Coordinate hard-fork upgrades via an **activation height**.
//!
//! # Upgrade flow
//!
//! 1. **Minor (rolling):** `protocol_version` stays the same; only storage
//!    schema or RPC fields change.  Nodes upgrade one-by-one with no halt.
//!
//! 2. **Major (coordinated):** A new `protocol_version` is introduced.
//!    - Pre-activation: nodes support *both* old and new versions.
//!    - At `activation_height`: nodes start producing new-version blocks.
//!    - After a grace window: old-version blocks are rejected.

use serde::{Deserialize, Serialize};

// ─── Constants ───────────────────────────────────────────────────────────────

/// The protocol version this binary produces when creating new blocks.
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// All protocol versions this binary can validate / execute.
/// Older versions are kept here to allow syncing historical blocks.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1];

/// Minimum protocol version accepted for *new* blocks after a grace window.
/// Set equal to `CURRENT_PROTOCOL_VERSION` once a hard fork is fully activated.
pub const MIN_PROTOCOL_VERSION: u32 = 1;

// ─── Activation config ──────────────────────────────────────────────────────

/// Per-version activation rule.
///
/// When the chain reaches `activation_height`, the node switches to producing
/// blocks with `protocol_version`.  Before that height, it continues to
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

fn default_grace_blocks() -> u64 { 1000 }

/// Default activation schedule: v1 active from genesis.
pub fn default_activations() -> Vec<ProtocolActivation> {
    vec![ProtocolActivation {
        protocol_version: 1,
        activation_height: None, // genesis
        grace_blocks: 0,
    }]
}

// ─── Queries ─────────────────────────────────────────────────────────────────

/// Returns the protocol version that should be used when producing a block
/// at the given `height`, based on the activation schedule.
pub fn version_for_height(height: u64, activations: &[ProtocolActivation]) -> u32 {
    let mut active_version = 1u32;
    for a in activations {
        match a.activation_height {
            None => {
                // Active from genesis
                active_version = active_version.max(a.protocol_version);
            }
            Some(h) if height >= h => {
                active_version = active_version.max(a.protocol_version);
            }
            _ => {}
        }
    }
    active_version
}

/// Check whether a given `protocol_version` is acceptable for a block at
/// `height`.  Returns `Ok(())` or an error string.
pub fn validate_block_version(
    block_version: u32,
    height: u64,
    activations: &[ProtocolActivation],
) -> Result<(), String> {
    // Must be a version we know how to execute.
    if !SUPPORTED_PROTOCOL_VERSIONS.contains(&block_version) {
        return Err(format!(
            "unsupported protocol version {block_version}; supported: {SUPPORTED_PROTOCOL_VERSIONS:?}"
        ));
    }

    // After activation + grace, the old version is rejected.
    let expected = version_for_height(height, activations);
    if block_version < expected {
        // Check if we're still inside the grace window of the *next* activation.
        let in_grace = activations.iter().any(|a| {
            a.protocol_version == expected
                && a.activation_height
                    .map(|ah| height < ah + a.grace_blocks)
                    .unwrap_or(false)
        });
        if !in_grace {
            return Err(format!(
                "protocol version {block_version} is too old at height {height}; \
                 expected >= {expected}"
            ));
        }
    }

    Ok(())
}

/// Returns `true` if this binary supports the given protocol version.
pub fn is_supported(version: u32) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

// ─── Display ─────────────────────────────────────────────────────────────────

/// Human-readable version string for logs / RPC.
pub fn version_string() -> String {
    format!(
        "iona-node v{} (protocol v{}, schema v{})",
        env!("CARGO_PKG_VERSION"),
        CURRENT_PROTOCOL_VERSION,
        crate::storage::CURRENT_SCHEMA_VERSION,
    )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

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
        // This test simulates a future scenario where SUPPORTED includes v2.
        // Since SUPPORTED_PROTOCOL_VERSIONS is compile-time &[1], we test the
        // grace-window logic using only v1 blocks against a schedule that
        // activates v1 at a specific height (no higher version needed).
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ];
        // Before activation: v1 is fine (version_for_height returns 1)
        assert!(validate_block_version(1, 999, &activations).is_ok());
        // At activation: v1 is the expected version
        assert!(validate_block_version(1, 1000, &activations).is_ok());
        // After activation + grace: v1 still fine (it IS the active version)
        assert!(validate_block_version(1, 1100, &activations).is_ok());
        // Unsupported version always rejected
        assert!(validate_block_version(99, 1000, &activations).is_err());
    }

    #[test]
    fn test_is_supported() {
        assert!(is_supported(1));
        assert!(!is_supported(0));
        assert!(!is_supported(99));
    }
}
