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

/// The protocol version that this binary **produces** when creating new blocks
/// on the chain described by `default_activations()` (i.e., the current active version).
pub const CURRENT_PROTOCOL_VERSION: u32 = 1;

/// The highest protocol version this binary can validate / execute.
/// Older versions are kept here to allow syncing historical blocks.
pub const HIGHEST_SUPPORTED_PROTOCOL_VERSION: u32 = 3;

/// All protocol versions this binary can validate / execute.
pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[1, 2, 3];

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

/// Validate that an activation schedule is well‑formed.
///
/// # Rules
/// - First activation must have `activation_height = None` and `protocol_version = 1`.
/// - Subsequent activations must have strictly increasing `protocol_version`.
/// - Subsequent activations must have strictly increasing `activation_height` (if `Some`).
/// - No duplicate `protocol_version`.
pub fn validate_activation_schedule(activations: &[ProtocolActivation]) -> Result<(), String> {
    if activations.is_empty() {
        return Err("activation schedule cannot be empty".into());
    }

    let first = &activations[0];
    if first.protocol_version != 1 {
        return Err(format!(
            "first activation must have protocol_version = 1, got {}",
            first.protocol_version
        ));
    }
    if first.activation_height.is_some() {
        return Err("first activation must have activation_height = None".into());
    }

    let mut prev_pv = first.protocol_version;
    let mut prev_height: Option<u64> = None;

    for act in activations.iter().skip(1) {
        // PV strictly increasing
        if act.protocol_version <= prev_pv {
            return Err(format!(
                "protocol versions must be strictly increasing: {} <= {}",
                act.protocol_version, prev_pv
            ));
        }

        // Must have an activation height
        let Some(ah) = act.activation_height else {
            return Err(format!(
                "activation for PV={} must specify activation_height",
                act.protocol_version
            ));
        };

        // Height strictly increasing
        if let Some(prev) = prev_height {
            if ah <= prev {
                return Err(format!(
                    "activation heights must be strictly increasing: {} <= {}",
                    ah, prev
                ));
            }
        }

        prev_pv = act.protocol_version;
        prev_height = Some(ah);
    }

    Ok(())
}

// ─── Queries ─────────────────────────────────────────────────────────────────

/// Returns the protocol version that should be used when producing a block
/// at the given `height`, based on the activation schedule.
///
/// The schedule is assumed to be well‑formed (see `validate_activation_schedule`).
/// If not sorted, this function will still work because it iterates all activations.
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

/// Check whether a given `protocol_version` is acceptable for a block at `height`.
///
/// Returns `Ok(())` or an error string.
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

    let expected = version_for_height(height, activations);

    if block_version == expected {
        return Ok(());
    }

    if block_version < expected {
        if is_in_grace_window(block_version, height, activations) {
            return Ok(());
        }
        return Err(format!(
            "protocol version {block_version} is too old at height {height}; expected {expected}"
        ));
    }

    // block_version > expected
    Err(format!(
        "protocol version {block_version} is too new at height {height}; expected {expected}"
    ))
}

/// Returns `true` if the given block version is still accepted during a grace window.
/// The grace window only accepts the version immediately preceding the current expected version.
pub fn is_in_grace_window(
    block_version: u32,
    height: u64,
    activations: &[ProtocolActivation],
) -> bool {
    let expected = version_for_height(height, activations);

    // Find the activation that made `expected` mandatory.
    let current_activation = match activations.iter().find(|a| a.protocol_version == expected) {
        Some(a) => a,
        None => return false,
    };

    let activation_height = match current_activation.activation_height {
        Some(h) => h,
        None => return false,
    };

    // We must be strictly inside the grace window.
    if height < activation_height || height >= activation_height.saturating_add(current_activation.grace_blocks) {
        return false;
    }

    // Find the maximum protocol version strictly less than `expected`.
    let previous_version = activations
        .iter()
        .filter(|a| a.protocol_version < expected)
        .map(|a| a.protocol_version)
        .max();

    matches!(previous_version, Some(prev) if block_version == prev)
}

/// Returns `true` if this binary supports the given protocol version.
pub fn is_supported(version: u32) -> bool {
    SUPPORTED_PROTOCOL_VERSIONS.contains(&version)
}

/// Returns the next activation after the given height (if any).
pub fn next_activation(height: u64, activations: &[ProtocolActivation]) -> Option<&ProtocolActivation> {
    activations
        .iter()
        .filter(|a| a.activation_height.map(|ah| ah > height).unwrap_or(false))
        .min_by(|a, b| a.activation_height.cmp(&b.activation_height))
}

// ─── Display ─────────────────────────────────────────────────────────────────

/// Human-readable version string for logs / RPC.
pub fn version_string() -> String {
    format!(
        "iona-node v{} (current protocol v{}, highest supported v{}, schema v{})",
        env!("CARGO_PKG_VERSION"),
        CURRENT_PROTOCOL_VERSION,
        HIGHEST_SUPPORTED_PROTOCOL_VERSION,
        crate::storage::CURRENT_SCHEMA_VERSION,
    )
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_activations() -> Vec<ProtocolActivation> {
        vec![
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
            ProtocolActivation {
                protocol_version: 3,
                activation_height: Some(200_000),
                grace_blocks: 1000,
            },
        ]
    }

    #[test]
    fn test_highest_supported_matches_list() {
        assert_eq!(
            SUPPORTED_PROTOCOL_VERSIONS.last().copied(),
            Some(HIGHEST_SUPPORTED_PROTOCOL_VERSION)
        );
    }

    #[test]
    fn test_validate_activation_schedule_ok() {
        assert!(validate_activation_schedule(&valid_activations()).is_ok());
    }

    #[test]
    fn test_validate_activation_schedule_invalid_first() {
        let acts = vec![ProtocolActivation {
            protocol_version: 2,
            activation_height: None,
            grace_blocks: 0,
        }];
        assert!(validate_activation_schedule(&acts).is_err());
    }

    #[test]
    fn test_validate_activation_schedule_non_increasing_pv() {
        let acts = vec![
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
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(200_000),
                grace_blocks: 1000,
            },
        ];
        assert!(validate_activation_schedule(&acts).is_err());
    }

    #[test]
    fn test_validate_activation_schedule_non_increasing_height() {
        let acts = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(200_000),
                grace_blocks: 500,
            },
            ProtocolActivation {
                protocol_version: 3,
                activation_height: Some(100_000),
                grace_blocks: 1000,
            },
        ];
        assert!(validate_activation_schedule(&acts).is_err());
    }

    #[test]
    fn test_version_for_height_genesis() {
        let activations = default_activations();
        assert_eq!(version_for_height(0, &activations), 1);
        assert_eq!(version_for_height(999_999, &activations), 1);
    }

    #[test]
    fn test_version_for_height_with_upgrade() {
        let activations = valid_activations();
        assert_eq!(version_for_height(0, &activations), 1);
        assert_eq!(version_for_height(99_999, &activations), 1);
        assert_eq!(version_for_height(100_000, &activations), 2);
        assert_eq!(version_for_height(199_999, &activations), 2);
        assert_eq!(version_for_height(200_000, &activations), 3);
    }

    #[test]
    fn test_validate_block_version_ok() {
        let activations = valid_activations();
        assert!(validate_block_version(1, 99_999, &activations).is_ok());
        assert!(validate_block_version(2, 100_000, &activations).is_ok());
        assert!(validate_block_version(2, 150_000, &activations).is_ok());
        assert!(validate_block_version(3, 200_000, &activations).is_ok());
    }

    #[test]
    fn test_validate_block_version_unsupported() {
        let activations = valid_activations();
        assert!(validate_block_version(99, 0, &activations).is_err());
    }

    #[test]
    fn test_validate_block_version_grace_window() {
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
        // During grace (height 1050), v1 is still accepted
        assert!(validate_block_version(1, 1050, &activations).is_ok());
        // After grace (height 1101), v1 is rejected
        assert!(validate_block_version(1, 1101, &activations).is_err());
        // v2 is always fine
        assert!(validate_block_version(2, 1050, &activations).is_ok());
    }

    #[test]
    fn test_grace_window_boundaries() {
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

        // At activation height: v1 still allowed (grace starts at activation)
        assert!(validate_block_version(1, 1000, &activations).is_ok());
        assert!(validate_block_version(2, 1000, &activations).is_ok());

        // Last height of grace window
        assert!(validate_block_version(1, 1099, &activations).is_ok());

        // First height after grace window: v1 rejected
        assert!(validate_block_version(1, 1100, &activations).is_err());
        assert!(validate_block_version(2, 1100, &activations).is_ok());
    }

    #[test]
    fn test_validate_block_version_future() {
        let activations = valid_activations();
        // v3 at height 150_000 (before its activation) is too new and must be rejected
        assert!(validate_block_version(3, 150_000, &activations).is_err());
        // v2 at height 50_000 is too new and must be rejected (since expected = 1)
        assert!(validate_block_version(2, 50_000, &activations).is_err());
    }

    #[test]
    fn test_is_in_grace_window() {
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
        // During grace (height 1050), v1 is accepted
        assert!(is_in_grace_window(1, 1050, &activations));
        // After grace (height 1101), v1 not accepted
        assert!(!is_in_grace_window(1, 1101, &activations));
        // v2 always false
        assert!(!is_in_grace_window(2, 1050, &activations));
        // v0 (unsupported) false
        assert!(!is_in_grace_window(0, 1050, &activations));
    }

    #[test]
    fn test_next_activation() {
        let activations = valid_activations();
        let next = next_activation(50_000, &activations);
        assert_eq!(next.map(|a| a.protocol_version), Some(2));
        let next = next_activation(150_000, &activations);
        assert_eq!(next.map(|a| a.protocol_version), Some(3));
        let next = next_activation(300_000, &activations);
        assert_eq!(next, None);
    }

    #[test]
    fn test_version_string() {
        let s = version_string();
        assert!(s.contains("iona-node"));
        assert!(s.contains("current protocol v1"));
        assert!(s.contains("highest supported v3"));
    }
}
