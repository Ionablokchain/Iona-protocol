//! P2P wire compatibility and capability negotiation.
//!
//! Defines the `Hello` handshake message exchanged when two nodes connect,
//! and the rules for determining whether two nodes are compatible.
//!
//! # Wire Compatibility Rules
//!
//! 1. New fields in messages use `#[serde(default)]` for backward compat.
//! 2. Unknown message `type_id` values are silently ignored (forward compat).
//! 3. Two nodes connect iff `intersection(supported_pv) != {}`.
//! 4. Session PV = `min(max(local.supported_pv), max(remote.supported_pv))`.

use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use super::version::{CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
use crate::storage::CURRENT_SCHEMA_VERSION;
use crate::types::Hash32;

/// Bitmask for optional capabilities (for future extensions).
pub type CapabilityFlags = u64;

/// Capability flags (example).
pub mod capabilities {
    pub const SNAPSHOT_SYNC: u64 = 1 << 0;
    pub const ZSTD_COMPRESSION: u64 = 1 << 1;
    pub const LIGHT_CLIENT: u64 = 1 << 2;
    // ... etc.
}

// ─── Hello handshake ────────────────────────────────────────────────────────

/// Handshake message exchanged when two nodes first connect.
///
/// Both sides send a `Hello`; if the compatibility check fails the
/// connection is dropped with a descriptive error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol versions this node can validate / execute.
    /// Must be non‑empty and usually sorted.
    pub supported_pv: Vec<u32>,
    /// Schema versions this node can read (informational; not used for gating).
    pub supported_sv: Vec<u32>,
    /// Semver of the binary (informational, not protocol-significant).
    pub software_version: String,
    /// Chain identifier — must match for connection.
    pub chain_id: u64,
    /// Hash of the genesis block — must match for connection.
    pub genesis_hash: Hash32,
    /// Height of the local chain tip (informational).
    pub head_height: u64,
    /// Protocol version of the local chain tip.
    pub head_pv: u32,
    /// Optional capabilities bitmap (for feature negotiation).
    #[serde(default)]
    pub capabilities: CapabilityFlags,
    /// Optional peer ID (for logging / debugging).
    #[serde(default)]
    pub peer_id: Option<String>,
}

impl Hello {
    /// Build a `Hello` for the local node.
    pub fn local(
        chain_id: u64,
        genesis_hash: Hash32,
        head_height: u64,
        capabilities: CapabilityFlags,
        peer_id: Option<String>,
    ) -> Self {
        debug_assert!(!SUPPORTED_PROTOCOL_VERSIONS.is_empty(), "supported PV list cannot be empty");
        Self {
            supported_pv: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            supported_sv: (0..=CURRENT_SCHEMA_VERSION).collect(),
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            chain_id,
            genesis_hash,
            head_height,
            head_pv: CURRENT_PROTOCOL_VERSION,
            capabilities,
            peer_id,
        }
    }
}

// ─── Compatibility check ────────────────────────────────────────────────────

/// Result of comparing two `Hello` messages.
#[derive(Debug, Clone)]
pub struct CompatResult {
    /// Whether the two nodes are compatible (can peer).
    pub compatible: bool,
    /// Negotiated session PV (only valid if `compatible == true`).
    pub session_pv: u32,
    /// Intersection of capabilities (bitwise AND).
    pub common_capabilities: CapabilityFlags,
    /// Human-readable reason for incompatibility (empty if compatible).
    pub reason: String,
}

/// Check whether a remote `Hello` is compatible with our local node.
///
/// # Rules (from UPGRADE_SPEC.md section 4.3)
///
/// ```text
/// Connect(local, remote) =
///     local.chain_id == remote.chain_id
///     AND local.genesis_hash == remote.genesis_hash
///     AND intersection(local.supported_pv, remote.supported_pv) != {}
/// ```
pub fn check_hello_compat(local: &Hello, remote: &Hello) -> CompatResult {
    // Chain ID must match.
    if local.chain_id != remote.chain_id {
        return CompatResult {
            compatible: false,
            session_pv: 0,
            common_capabilities: 0,
            reason: format!(
                "chain_id mismatch: local={}, remote={}",
                local.chain_id, remote.chain_id
            ),
        };
    }

    // Genesis hash must match.
    if local.genesis_hash != remote.genesis_hash {
        return CompatResult {
            compatible: false,
            session_pv: 0,
            common_capabilities: 0,
            reason: "genesis_hash mismatch".into(),
        };
    }

    // Ensure lists are sorted for deterministic behavior (optional, but good practice).
    let local_pv = ensure_sorted(&local.supported_pv);
    let remote_pv = ensure_sorted(&remote.supported_pv);

    // PV intersection must be non-empty.
    let intersection: Vec<u32> = local_pv
        .iter()
        .copied()
        .filter(|pv| remote_pv.contains(pv))
        .collect();

    if intersection.is_empty() {
        return CompatResult {
            compatible: false,
            session_pv: 0,
            common_capabilities: 0,
            reason: format!(
                "no common protocol version: local={:?}, remote={:?}",
                local_pv, remote_pv
            ),
        };
    }

    // Session PV = min(max(local), max(remote)).
    let local_max = local_pv.iter().copied().max().unwrap_or(1);
    let remote_max = remote_pv.iter().copied().max().unwrap_or(1);
    let session_pv = local_max.min(remote_max);

    // Common capabilities = bitwise AND.
    let common_capabilities = local.capabilities & remote.capabilities;

    CompatResult {
        compatible: true,
        session_pv,
        common_capabilities,
        reason: String::new(),
    }
}

/// Helper to ensure a slice is sorted (returns a sorted Vec).
fn ensure_sorted(v: &[u32]) -> Vec<u32> {
    let mut sorted = v.to_vec();
    sorted.sort_unstable();
    sorted.dedup();
    sorted
}

// ─── Message type IDs ───────────────────────────────────────────────────────

/// Well-known P2P message type IDs.
///
/// Unknown IDs are silently ignored by receivers (forward compatibility).
pub mod msg_type {
    pub const PROPOSAL: u8 = 0;
    pub const VOTE: u8 = 1;
    pub const EVIDENCE: u8 = 2;
    pub const BLOCK_REQUEST: u8 = 3;
    pub const BLOCK_RESPONSE: u8 = 4;
    pub const HELLO: u8 = 5;
    pub const STATUS: u8 = 6;
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hello(chain_id: u64, pvs: Vec<u32>, caps: u64) -> Hello {
        Hello {
            supported_pv: pvs,
            supported_sv: vec![0, 1, 2, 3, 4],
            software_version: "27.1.0".into(),
            chain_id,
            genesis_hash: Hash32::zero(),
            head_height: 100,
            head_pv: 1,
            capabilities: caps,
            peer_id: None,
        }
    }

    #[test]
    fn test_compat_same_pv() {
        let a = make_hello(1, vec![1], 0);
        let b = make_hello(1, vec![1], 0);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1);
        assert_eq!(r.common_capabilities, 0);
    }

    #[test]
    fn test_compat_overlapping_pv() {
        let a = make_hello(1, vec![1], 0);
        let b = make_hello(1, vec![1, 2], 0);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1); // min(max(1), max(2)) = 1
    }

    #[test]
    fn test_compat_both_upgraded() {
        let a = make_hello(1, vec![1, 2], 0);
        let b = make_hello(1, vec![1, 2], 0);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 2);
    }

    #[test]
    fn test_compat_unsorted() {
        let a = make_hello(1, vec![2, 1], 0); // unsorted
        let b = make_hello(1, vec![1, 2], 0);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 2);
    }

    #[test]
    fn test_incompat_no_overlap() {
        let a = make_hello(1, vec![1], 0);
        let b = make_hello(1, vec![2], 0);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("no common protocol version"));
    }

    #[test]
    fn test_incompat_chain_id() {
        let a = make_hello(1, vec![1], 0);
        let b = make_hello(2, vec![1], 0);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("chain_id mismatch"));
    }

    #[test]
    fn test_incompat_genesis() {
        let mut a = make_hello(1, vec![1], 0);
        let b = make_hello(1, vec![1], 0);
        a.genesis_hash = Hash32([1u8; 32]);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("genesis_hash mismatch"));
    }

    #[test]
    fn test_capabilities_and() {
        let a = make_hello(1, vec![1], capabilities::SNAPSHOT_SYNC | capabilities::ZSTD_COMPRESSION);
        let b = make_hello(1, vec![1], capabilities::ZSTD_COMPRESSION | capabilities::LIGHT_CLIENT);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.common_capabilities, capabilities::ZSTD_COMPRESSION);
    }

    #[test]
    fn test_local_hello() {
        let caps = capabilities::SNAPSHOT_SYNC;
        let peer_id = Some("Qm...".into());
        let h = Hello::local(6126151, Hash32::zero(), 42, caps, peer_id);
        assert_eq!(h.chain_id, 6126151);
        assert_eq!(h.head_height, 42);
        assert_eq!(h.capabilities, caps);
        assert_eq!(h.peer_id, Some("Qm...".into()));
        assert!(h.supported_pv.contains(&CURRENT_PROTOCOL_VERSION));
    }

    #[test]
    fn test_session_pv_formula() {
        // Test min(max(local), max(remote)) with various combos.
        let cases = vec![
            (vec![1], vec![1], 1),
            (vec![1], vec![1, 2], 1),
            (vec![1, 2], vec![1], 1),
            (vec![1, 2], vec![1, 2], 2),
            (vec![1, 2, 3], vec![2, 3], 3),
            (vec![2, 3], vec![1, 2, 3], 3),
            (vec![3], vec![1, 2], 2), // intersection exists (2) but session PV = min(3,2) = 2
        ];
        for (local_pv, remote_pv, expected) in cases {
            let local = make_hello(1, local_pv, 0);
            let remote = make_hello(1, remote_pv, 0);
            let r = check_hello_compat(&local, &remote);
            assert!(r.compatible);
            assert_eq!(r.session_pv, expected);
        }
    }
}
