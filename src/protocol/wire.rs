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
//!
//! # Example
//!
//! ```rust,ignore
//! let local = Hello::local(chain_id, genesis_hash, head_height);
//! let remote = Hello::local(chain_id, genesis_hash, other_height);
//! let result = check_hello_compat(&local, &remote);
//! if result.compatible {
//!     let session_pv = result.session_pv;
//! } else {
//!     eprintln!("Incompatible: {}", result.reason);
//! }
//! ```

use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

use super::version::{CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
use crate::storage::CURRENT_SCHEMA_VERSION;
use crate::types::Hash32;

// -----------------------------------------------------------------------------
// Hello handshake
// -----------------------------------------------------------------------------

/// Handshake message exchanged when two nodes first connect.
///
/// Both sides send a `Hello`; if the compatibility check fails the
/// connection is dropped with a descriptive error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Hello {
    /// Protocol versions this node can validate / execute.
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
}

impl Hello {
    /// Build a `Hello` for the local node.
    #[must_use]
    pub fn local(chain_id: u64, genesis_hash: Hash32, head_height: u64) -> Self {
        debug!(
            chain_id,
            head_height,
            supported_pv = ?SUPPORTED_PROTOCOL_VERSIONS,
            "creating local Hello handshake"
        );
        Self {
            supported_pv: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
            supported_sv: (0..=CURRENT_SCHEMA_VERSION).collect(),
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            chain_id,
            genesis_hash,
            head_height,
            head_pv: CURRENT_PROTOCOL_VERSION,
        }
    }
}

// -----------------------------------------------------------------------------
// Compatibility result
// -----------------------------------------------------------------------------

/// Result of comparing two `Hello` messages.
#[derive(Debug, Clone)]
pub struct CompatResult {
    /// Whether the two nodes are compatible (can peer).
    pub compatible: bool,
    /// Negotiated session PV (only valid if `compatible == true`).
    pub session_pv: u32,
    /// Human‑readable reason for incompatibility (empty if compatible).
    pub reason: String,
}

impl CompatResult {
    /// Returns `true` if compatible, `false` otherwise.
    #[must_use]
    pub fn is_compatible(&self) -> bool {
        self.compatible
    }

    /// Returns the reason as a string (empty if compatible).
    #[must_use]
    pub fn reason(&self) -> &str {
        &self.reason
    }
}

// -----------------------------------------------------------------------------
// Compatibility check
// -----------------------------------------------------------------------------

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
#[must_use]
pub fn check_hello_compat(local: &Hello, remote: &Hello) -> CompatResult {
    // Chain ID must match.
    if local.chain_id != remote.chain_id {
        let reason = format!(
            "chain_id mismatch: local={}, remote={}",
            local.chain_id, remote.chain_id
        );
        warn!("{}", reason);
        return CompatResult {
            compatible: false,
            session_pv: 0,
            reason,
        };
    }

    // Genesis hash must match.
    if local.genesis_hash != remote.genesis_hash {
        let reason = "genesis_hash mismatch".into();
        warn!("{}", reason);
        return CompatResult {
            compatible: false,
            session_pv: 0,
            reason,
        };
    }

    // PV intersection must be non‑empty.
    let intersection: Vec<u32> = local
        .supported_pv
        .iter()
        .copied()
        .filter(|pv| remote.supported_pv.contains(pv))
        .collect();

    if intersection.is_empty() {
        let reason = format!(
            "no common protocol version: local={:?}, remote={:?}",
            local.supported_pv, remote.supported_pv
        );
        warn!("{}", reason);
        return CompatResult {
            compatible: false,
            session_pv: 0,
            reason,
        };
    }

    // Session PV = min(max(local), max(remote)).
    let local_max = local.supported_pv.iter().copied().max().unwrap_or(1);
    let remote_max = remote.supported_pv.iter().copied().max().unwrap_or(1);
    let session_pv = local_max.min(remote_max);

    debug!(
        local_max,
        remote_max,
        session_pv,
        intersection_len = intersection.len(),
        "handshake compatibility succeeded"
    );

    CompatResult {
        compatible: true,
        session_pv,
        reason: String::new(),
    }
}

// -----------------------------------------------------------------------------
// Message type IDs
// -----------------------------------------------------------------------------

/// Well‑known P2P message type IDs.
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_hello(chain_id: u64, pvs: Vec<u32>) -> Hello {
        Hello {
            supported_pv: pvs,
            supported_sv: vec![0, 1, 2, 3, 4],
            software_version: "27.1.0".into(),
            chain_id,
            genesis_hash: Hash32::zero(),
            head_height: 100,
            head_pv: 1,
        }
    }

    #[test]
    fn test_compat_same_pv() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1]);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1);
        assert!(r.is_compatible());
        assert_eq!(r.reason(), "");
    }

    #[test]
    fn test_compat_overlapping_pv() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1, 2]);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1);
    }

    #[test]
    fn test_compat_both_upgraded() {
        let a = make_hello(1, vec![1, 2]);
        let b = make_hello(1, vec![1, 2]);
        let r = check_hello_compat(&a, &b);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 2);
    }

    #[test]
    fn test_incompat_no_overlap() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![2]);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("no common protocol version"));
        assert!(!r.is_compatible());
    }

    #[test]
    fn test_incompat_chain_id() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(2, vec![1]);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("chain_id mismatch"));
    }

    #[test]
    fn test_incompat_genesis() {
        let mut a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1]);
        a.genesis_hash = Hash32([1u8; 32]);
        let r = check_hello_compat(&a, &b);
        assert!(!r.compatible);
        assert!(r.reason.contains("genesis_hash mismatch"));
    }

    #[test]
    fn test_local_hello() {
        let h = Hello::local(6126151, Hash32::zero(), 42);
        assert_eq!(h.chain_id, 6126151);
        assert_eq!(h.head_height, 42);
        assert!(h.supported_pv.contains(&CURRENT_PROTOCOL_VERSION));
    }
}
