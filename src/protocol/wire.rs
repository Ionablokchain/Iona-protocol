//! P2P wire compatibility and capability negotiation.
//!
//! This module defines the `Hello` handshake message exchanged when two nodes connect,
//! and the rules for determining whether two nodes are compatible to peer.
//!
//! # Wire Compatibility Rules
//!
//! 1. New fields in messages must use `#[serde(default)]` for backward compatibility.
//! 2. Unknown message `type_id` values are silently ignored (forward compatibility).
//! 3. Two nodes connect iff `intersection(supported_pv) != {}`.
//! 4. Session PV = `min(max(local.supported_pv), max(remote.supported_pv))`.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Wire Module                                   │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     hello     │        compat            │
//! │ (WireConfig)│ (WireError)  │ (Hello, Builder)│ (compatibility checks)  │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   metrics   │    manager   │    msg_type   │                          │
//! │ (metrics)   │ (WireManager)│ (constants)   │                          │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::protocol::wire::{WireManager, WireConfig, HelloBuilder};
//!
//! let config = WireConfig::default();
//! let manager = WireManager::new(config).unwrap();
//! let local = HelloBuilder::new(chain_id, genesis_hash, head_height).build();
//! let remote = HelloBuilder::new(chain_id, genesis_hash, other_height).build();
//! let result = manager.check_compat(&local, &remote);
//! if result.compatible {
//!     let session_pv = result.session_pv;
//! } else {
//!     eprintln!("Incompatible: {}", result.reason);
//! }
//! ```

#![allow(dead_code)]

use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for wire compatibility.
    use serde::{Deserialize, Serialize};
    use super::error::{WireResult, WireError};
    use super::compat::NegotiationMode;
    use crate::protocol::version::SUPPORTED_PROTOCOL_VERSIONS;

    /// Configuration for wire compatibility checks.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct WireConfig {
        /// Whether to enforce chain ID match (default: true).
        pub enforce_chain_id: bool,
        /// Whether to enforce genesis hash match (default: true).
        pub enforce_genesis_hash: bool,
        /// Whether to enforce at least one common PV (default: true).
        pub enforce_common_pv: bool,
        /// Supported protocol versions for the local node.
        pub local_supported_pv: Vec<u32>,
        /// Session PV negotiation mode: "min_max" or "intersection_max".
        pub negotiation_mode: NegotiationMode,
        /// Whether to log compatibility failures (default: true).
        pub log_failures: bool,
        /// Whether to collect timing metrics.
        pub collect_timing: bool,
    }

    impl Default for WireConfig {
        fn default() -> Self {
            Self {
                enforce_chain_id: true,
                enforce_genesis_hash: true,
                enforce_common_pv: true,
                local_supported_pv: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
                negotiation_mode: NegotiationMode::MinMax,
                log_failures: true,
                collect_timing: true,
            }
        }
    }

    impl WireConfig {
        /// Create a config with strict enforcement (all checks enabled).
        pub fn strict() -> Self {
            Self {
                enforce_chain_id: true,
                enforce_genesis_hash: true,
                enforce_common_pv: true,
                local_supported_pv: SUPPORTED_PROTOCOL_VERSIONS.to_vec(),
                negotiation_mode: NegotiationMode::MinMax,
                log_failures: true,
                collect_timing: true,
            }
        }

        /// Create a config for testing (all checks disabled).
        pub fn test() -> Self {
            Self {
                enforce_chain_id: false,
                enforce_genesis_hash: false,
                enforce_common_pv: false,
                local_supported_pv: vec![1],
                negotiation_mode: NegotiationMode::MinMax,
                log_failures: false,
                collect_timing: false,
            }
        }

        /// Set custom local supported PV list.
        pub fn with_local_pv(mut self, pvs: &[u32]) -> Self {
            self.local_supported_pv = pvs.to_vec();
            self
        }

        /// Validate the configuration.
        pub fn validate(&self) -> WireResult<()> {
            if self.local_supported_pv.is_empty() {
                return Err(WireError::Config("local_supported_pv cannot be empty".into()));
            }
            Ok(())
        }
    }
}

pub mod error {
    //! Error types for wire compatibility.
    use super::compat::NegotiationMode;
    use thiserror::Error;

    #[derive(Debug, Error, Clone, PartialEq, Eq)]
    pub enum WireError {
        #[error("chain ID mismatch: local={local}, remote={remote}")]
        ChainIdMismatch { local: u64, remote: u64 },

        #[error("genesis hash mismatch: local={local}, remote={remote}")]
        GenesisHashMismatch { local: String, remote: String },

        #[error("no common protocol version: local={local:?}, remote={remote:?}")]
        NoCommonPv { local: Vec<u32>, remote: Vec<u32> },

        #[error("local supported PV list is empty")]
        LocalEmptyPv,

        #[error("remote supported PV list is empty")]
        RemoteEmptyPv,

        #[error("invalid chain ID: {0}")]
        InvalidChainId(u64),

        #[error("configuration error: {0}")]
        Config(String),
    }

    pub type WireResult<T> = Result<T, WireError>;
}

pub mod hello {
    //! Hello handshake message and builder.
    use serde::{Deserialize, Serialize};
    use super::compat::NegotiationMode;
    use super::error::{WireResult, WireError};
    use crate::protocol::version::{CURRENT_PROTOCOL_VERSION, SUPPORTED_PROTOCOL_VERSIONS};
    use crate::storage::CURRENT_SCHEMA_VERSION;
    use crate::types::Hash32;
    use std::collections::HashSet;
    use tracing::debug;

    /// Default chain ID for IONA testnet.
    pub const DEFAULT_CHAIN_ID: u64 = 6126151;

    /// Default genesis hash (zero for testnet).
    pub const DEFAULT_GENESIS_HASH: Hash32 = Hash32::zero();

    /// Handshake message exchanged when two nodes first connect.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct Hello {
        pub supported_pv: Vec<u32>,
        pub supported_sv: Vec<u32>,
        pub software_version: String,
        pub chain_id: u64,
        pub genesis_hash: Hash32,
        pub head_height: u64,
        pub head_pv: u32,
    }

    impl Hello {
        /// Build a `Hello` handshake message for the local node.
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

        /// Validate the `Hello` message.
        pub fn validate(&self) -> WireResult<()> {
            if self.supported_pv.is_empty() {
                return Err(WireError::LocalEmptyPv);
            }
            if self.chain_id == 0 {
                return Err(WireError::InvalidChainId(self.chain_id));
            }
            Ok(())
        }

        /// Get the maximum supported protocol version.
        #[must_use]
        pub fn max_pv(&self) -> u32 {
            self.supported_pv.iter().copied().max().unwrap_or(1)
        }

        /// Get the minimum supported protocol version.
        #[must_use]
        pub fn min_pv(&self) -> u32 {
            self.supported_pv.iter().copied().min().unwrap_or(1)
        }

        /// Check if this `Hello` supports a specific PV.
        #[must_use]
        pub fn supports(&self, pv: u32) -> bool {
            self.supported_pv.contains(&pv)
        }

        /// Get the intersection of supported PVs with another `Hello`.
        #[must_use]
        pub fn intersection(&self, other: &Hello) -> Vec<u32> {
            let set: HashSet<u32> = self.supported_pv.iter().copied().collect();
            other
                .supported_pv
                .iter()
                .copied()
                .filter(|pv| set.contains(pv))
                .collect()
        }

        /// Check if there is any common PV with another `Hello`.
        #[must_use]
        pub fn has_common_pv(&self, other: &Hello) -> bool {
            !self.intersection(other).is_empty()
        }

        /// Negotiate the session PV with another `Hello` using a given mode.
        #[must_use]
        pub fn negotiate_session_pv(&self, other: &Hello, mode: NegotiationMode) -> u32 {
            match mode {
                NegotiationMode::MinMax => {
                    let local_max = self.max_pv();
                    let remote_max = other.max_pv();
                    local_max.min(remote_max)
                }
                NegotiationMode::IntersectionMax => {
                    let inter = self.intersection(other);
                    inter.into_iter().max().unwrap_or(1)
                }
            }
        }
    }

    /// Builder for constructing `Hello` messages.
    #[derive(Debug, Clone)]
    pub struct HelloBuilder {
        chain_id: u64,
        genesis_hash: Hash32,
        head_height: u64,
        supported_pv: Option<Vec<u32>>,
        supported_sv: Option<Vec<u32>>,
        software_version: Option<String>,
        head_pv: Option<u32>,
    }

    impl HelloBuilder {
        pub fn new(chain_id: u64, genesis_hash: Hash32, head_height: u64) -> Self {
            Self {
                chain_id,
                genesis_hash,
                head_height,
                supported_pv: None,
                supported_sv: None,
                software_version: None,
                head_pv: None,
            }
        }

        pub fn supported_pv(mut self, pvs: &[u32]) -> Self {
            self.supported_pv = Some(pvs.to_vec());
            self
        }

        pub fn supported_sv(mut self, svs: &[u32]) -> Self {
            self.supported_sv = Some(svs.to_vec());
            self
        }

        pub fn software_version(mut self, version: &str) -> Self {
            self.software_version = Some(version.to_string());
            self
        }

        pub fn head_pv(mut self, pv: u32) -> Self {
            self.head_pv = Some(pv);
            self
        }

        pub fn build(self) -> Hello {
            Hello {
                supported_pv: self
                    .supported_pv
                    .unwrap_or_else(|| SUPPORTED_PROTOCOL_VERSIONS.to_vec()),
                supported_sv: self
                    .supported_sv
                    .unwrap_or_else(|| (0..=CURRENT_SCHEMA_VERSION).collect()),
                software_version: self
                    .software_version
                    .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string()),
                chain_id: self.chain_id,
                genesis_hash: self.genesis_hash,
                head_height: self.head_height,
                head_pv: self.head_pv.unwrap_or(CURRENT_PROTOCOL_VERSION),
            }
        }
    }
}

pub mod compat {
    //! Compatibility checks and negotiation.
    use serde::{Deserialize, Serialize};
    use super::{
        config::WireConfig,
        error::{WireResult, WireError},
        hello::Hello,
    };
    use tracing::{debug, warn};

    /// Session PV negotiation mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum NegotiationMode {
        MinMax,
        IntersectionMax,
    }

    /// Result of comparing two `Hello` messages.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct CompatResult {
        pub compatible: bool,
        pub session_pv: u32,
        pub reason: String,
        pub error_code: Option<String>,
    }

    impl CompatResult {
        pub fn success(session_pv: u32) -> Self {
            Self {
                compatible: true,
                session_pv,
                reason: String::new(),
                error_code: None,
            }
        }

        pub fn failure(reason: impl Into<String>, error_code: impl Into<String>) -> Self {
            Self {
                compatible: false,
                session_pv: 0,
                reason: reason.into(),
                error_code: Some(error_code.into()),
            }
        }

        pub fn is_compatible(&self) -> bool {
            self.compatible
        }

        pub fn reason(&self) -> &str {
            &self.reason
        }

        pub fn into_result(self) -> WireResult<u32> {
            if self.compatible {
                Ok(self.session_pv)
            } else {
                Err(WireError::NoCommonPv {
                    local: vec![],
                    remote: vec![],
                })
            }
        }
    }

    /// Check whether a remote `Hello` is compatible with our local node.
    #[must_use]
    pub fn check_hello_compat(local: &Hello, remote: &Hello, config: &WireConfig) -> CompatResult {
        if let Err(e) = local.validate() {
            if config.log_failures {
                warn!("local Hello invalid: {}", e);
            }
            return CompatResult::failure(format!("local Hello invalid: {}", e), "LOCAL_INVALID");
        }
        if let Err(e) = remote.validate() {
            if config.log_failures {
                warn!("remote Hello invalid: {}", e);
            }
            return CompatResult::failure(format!("remote Hello invalid: {}", e), "REMOTE_INVALID");
        }

        if config.enforce_chain_id && local.chain_id != remote.chain_id {
            let reason = format!(
                "chain_id mismatch: local={}, remote={}",
                local.chain_id, remote.chain_id
            );
            if config.log_failures {
                warn!("{}", reason);
            }
            return CompatResult::failure(reason, "CHAIN_ID_MISMATCH");
        }

        if config.enforce_genesis_hash && local.genesis_hash != remote.genesis_hash {
            let reason = "genesis_hash mismatch".into();
            if config.log_failures {
                warn!("{}", reason);
            }
            return CompatResult::failure(reason, "GENESIS_HASH_MISMATCH");
        }

        if config.enforce_common_pv && !local.has_common_pv(remote) {
            let reason = format!(
                "no common protocol version: local={:?}, remote={:?}",
                local.supported_pv, remote.supported_pv
            );
            if config.log_failures {
                warn!("{}", reason);
            }
            return CompatResult::failure(reason, "NO_COMMON_PV");
        }

        let session_pv = local.negotiate_session_pv(remote, config.negotiation_mode);
        debug!(
            session_pv,
            local_max = local.max_pv(),
            remote_max = remote.max_pv(),
            "handshake compatibility succeeded"
        );
        CompatResult::success(session_pv)
    }

    /// Simplified compatibility check using default config.
    #[must_use]
    pub fn check_hello_compat_default(local: &Hello, remote: &Hello) -> CompatResult {
        check_hello_compat(local, remote, &WireConfig::default())
    }

    /// Negotiate session PV between two supported lists (standalone helper).
    #[must_use]
    pub fn negotiate_session_pv(local_pv: &[u32], remote_pv: &[u32], mode: NegotiationMode) -> u32 {
        let local_hello = Hello {
            supported_pv: local_pv.to_vec(),
            supported_sv: vec![],
            software_version: "".into(),
            chain_id: 0,
            genesis_hash: crate::types::Hash32::zero(),
            head_height: 0,
            head_pv: 0,
        };
        let remote_hello = Hello {
            supported_pv: remote_pv.to_vec(),
            supported_sv: vec![],
            software_version: "".into(),
            chain_id: 0,
            genesis_hash: crate::types::Hash32::zero(),
            head_height: 0,
            head_pv: 0,
        };
        local_hello.negotiate_session_pv(&remote_hello, mode)
    }
}

pub mod metrics {
    //! Metrics for wire compatibility checks.
    use std::sync::atomic::{AtomicU64, Ordering};

    #[derive(Debug, Default)]
    pub struct WireMetrics {
        pub total_checks: AtomicU64,
        pub passed_checks: AtomicU64,
        pub failed_checks: AtomicU64,
        pub total_duration_ms: AtomicU64,
        pub incompat_chain_id: AtomicU64,
        pub incompat_genesis: AtomicU64,
        pub incompat_no_pv: AtomicU64,
    }

    impl WireMetrics {
        pub fn record_check(&self, passed: bool, duration_ms: u64) {
            self.total_checks.fetch_add(1, Ordering::Relaxed);
            if passed {
                self.passed_checks.fetch_add(1, Ordering::Relaxed);
            } else {
                self.failed_checks.fetch_add(1, Ordering::Relaxed);
            }
            self.total_duration_ms.fetch_add(duration_ms, Ordering::Relaxed);
        }

        pub fn record_incompat(&self, error_code: &str) {
            match error_code {
                "CHAIN_ID_MISMATCH" => self.incompat_chain_id.fetch_add(1, Ordering::Relaxed),
                "GENESIS_HASH_MISMATCH" => self.incompat_genesis.fetch_add(1, Ordering::Relaxed),
                "NO_COMMON_PV" => self.incompat_no_pv.fetch_add(1, Ordering::Relaxed),
                _ => 0,
            };
        }

        pub fn snapshot(&self) -> WireMetricsSnapshot {
            WireMetricsSnapshot {
                total_checks: self.total_checks.load(Ordering::Relaxed),
                passed_checks: self.passed_checks.load(Ordering::Relaxed),
                failed_checks: self.failed_checks.load(Ordering::Relaxed),
                total_duration_ms: self.total_duration_ms.load(Ordering::Relaxed),
                incompat_chain_id: self.incompat_chain_id.load(Ordering::Relaxed),
                incompat_genesis: self.incompat_genesis.load(Ordering::Relaxed),
                incompat_no_pv: self.incompat_no_pv.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone)]
    pub struct WireMetricsSnapshot {
        pub total_checks: u64,
        pub passed_checks: u64,
        pub failed_checks: u64,
        pub total_duration_ms: u64,
        pub incompat_chain_id: u64,
        pub incompat_genesis: u64,
        pub incompat_no_pv: u64,
    }
}

pub mod manager {
    //! Centralised wire manager.
    use super::{
        config::WireConfig,
        error::{WireResult, WireError},
        hello::Hello,
        compat::{CompatResult, check_hello_compat},
        metrics::WireMetrics,
    };
    use crate::types::Hash32;
    use std::sync::Arc;
    use std::time::Instant;
    use tracing::{debug, info, warn};

    /// Centralised manager for wire compatibility.
    #[derive(Debug)]
    pub struct WireManager {
        config: WireConfig,
        metrics: Arc<WireMetrics>,
    }

    impl WireManager {
        /// Create a new wire manager with the given configuration.
        pub fn new(config: WireConfig) -> WireResult<Self> {
            config.validate()?;
            info!(
                enforce_chain_id = config.enforce_chain_id,
                enforce_genesis_hash = config.enforce_genesis_hash,
                negotiation_mode = ?config.negotiation_mode,
                "wire manager created"
            );
            Ok(Self {
                config,
                metrics: Arc::new(WireMetrics::default()),
            })
        }

        /// Create a wire manager with default configuration.
        pub fn default() -> Self {
            Self::new(WireConfig::default()).expect("default wire manager")
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &WireMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &WireConfig {
            &self.config
        }

        /// Update the configuration at runtime.
        pub fn set_config(&mut self, config: WireConfig) -> WireResult<()> {
            config.validate()?;
            self.config = config;
            Ok(())
        }

        /// Check compatibility between two Hello messages.
        pub fn check_compat(&self, local: &Hello, remote: &Hello) -> CompatResult {
            let start = Instant::now();
            let result = check_hello_compat(local, remote, &self.config);
            let dur = start.elapsed().as_millis() as u64;
            self.metrics.record_check(result.compatible, dur);
            if !result.compatible {
                if let Some(code) = &result.error_code {
                    self.metrics.record_incompat(code);
                }
                warn!(
                    compatible = false,
                    reason = %result.reason,
                    duration_ms = dur,
                    "wire compatibility check failed"
                );
            } else {
                debug!(
                    compatible = true,
                    session_pv = result.session_pv,
                    duration_ms = dur,
                    "wire compatibility check passed"
                );
            }
            result
        }

        /// Create a local Hello message.
        pub fn local_hello(&self, chain_id: u64, genesis_hash: Hash32, head_height: u64) -> Hello {
            Hello::local(chain_id, genesis_hash, head_height)
        }

        /// Create a Hello with the configured local supported PVs.
        pub fn local_hello_with_config(&self, chain_id: u64, genesis_hash: Hash32, head_height: u64) -> Hello {
            Hello {
                supported_pv: self.config.local_supported_pv.clone(),
                supported_sv: (0..=crate::storage::CURRENT_SCHEMA_VERSION).collect(),
                software_version: env!("CARGO_PKG_VERSION").to_string(),
                chain_id,
                genesis_hash,
                head_height,
                head_pv: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
            }
        }

        /// Negotiate session PV between two supported lists.
        pub fn negotiate_session_pv(&self, local_pv: &[u32], remote_pv: &[u32]) -> u32 {
            super::compat::negotiate_session_pv(local_pv, remote_pv, self.config.negotiation_mode)
        }
    }
}

pub mod msg_type {
    //! Well‑known P2P message type IDs.
    pub const PROPOSAL: u8 = 0;
    pub const VOTE: u8 = 1;
    pub const EVIDENCE: u8 = 2;
    pub const BLOCK_REQUEST: u8 = 3;
    pub const BLOCK_RESPONSE: u8 = 4;
    pub const HELLO: u8 = 5;
    pub const STATUS: u8 = 6;
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::WireConfig;
pub use error::{WireError, WireResult};
pub use hello::{Hello, HelloBuilder, DEFAULT_CHAIN_ID, DEFAULT_GENESIS_HASH};
pub use compat::{CompatResult, NegotiationMode, check_hello_compat, check_hello_compat_default, negotiate_session_pv};
pub use metrics::{WireMetrics, WireMetricsSnapshot};
pub use manager::WireManager;
pub use msg_type as message_types;

// -----------------------------------------------------------------------------
// Legacy standalone functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Check compatibility between two Hello messages (legacy).
#[deprecated(since = "1.0.0", note = "use WireManager::check_compat() or check_hello_compat()")]
pub fn check_hello_compat_legacy(local: &Hello, remote: &Hello) -> CompatResult {
    check_hello_compat(local, remote, &WireConfig::default())
}

/// Negotiate session PV (legacy).
#[deprecated(since = "1.0.0", note = "use WireManager::negotiate_session_pv() or negotiate_session_pv()")]
pub fn negotiate_session_pv_legacy(local_pv: &[u32], remote_pv: &[u32]) -> u32 {
    negotiate_session_pv(local_pv, remote_pv, NegotiationMode::MinMax)
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
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1);
        assert!(r.is_compatible());
        assert_eq!(r.reason(), "");
    }

    #[test]
    fn test_compat_overlapping_pv() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1, 2]);
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 1);
    }

    #[test]
    fn test_compat_both_upgraded() {
        let a = make_hello(1, vec![1, 2]);
        let b = make_hello(1, vec![1, 2]);
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(r.compatible);
        assert_eq!(r.session_pv, 2);
    }

    #[test]
    fn test_incompat_no_overlap() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![2]);
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(!r.compatible);
        assert!(r.reason.contains("no common protocol version"));
        assert!(!r.is_compatible());
    }

    #[test]
    fn test_incompat_chain_id() {
        let a = make_hello(1, vec![1]);
        let b = make_hello(2, vec![1]);
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(!r.compatible);
        assert!(r.reason.contains("chain_id mismatch"));
    }

    #[test]
    fn test_incompat_genesis() {
        let mut a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1]);
        a.genesis_hash = Hash32([1u8; 32]);
        let config = WireConfig::default();
        let r = check_hello_compat(&a, &b, &config);
        assert!(!r.compatible);
        assert!(r.reason.contains("genesis_hash mismatch"));
    }

    #[test]
    fn test_local_hello() {
        let h = Hello::local(6126151, Hash32::zero(), 42);
        assert_eq!(h.chain_id, 6126151);
        assert_eq!(h.head_height, 42);
        assert!(h.supported_pv.contains(&crate::protocol::version::CURRENT_PROTOCOL_VERSION));
    }

    #[test]
    fn test_msg_type_constants() {
        assert_eq!(msg_type::PROPOSAL, 0);
        assert_eq!(msg_type::VOTE, 1);
        assert_eq!(msg_type::EVIDENCE, 2);
        assert_eq!(msg_type::BLOCK_REQUEST, 3);
        assert_eq!(msg_type::BLOCK_RESPONSE, 4);
        assert_eq!(msg_type::HELLO, 5);
        assert_eq!(msg_type::STATUS, 6);
    }

    #[test]
    fn test_hello_validate() {
        let h = Hello::local(6126151, Hash32::zero(), 42);
        assert!(h.validate().is_ok());

        let mut bad = h.clone();
        bad.supported_pv = vec![];
        assert!(bad.validate().is_err());

        let mut bad2 = h;
        bad2.chain_id = 0;
        assert!(bad2.validate().is_err());
    }

    #[test]
    fn test_hello_intersection() {
        let a = make_hello(1, vec![1, 2, 3]);
        let b = make_hello(1, vec![2, 3, 4]);
        let inter = a.intersection(&b);
        assert_eq!(inter, vec![2, 3]);
    }

    #[test]
    fn test_hello_has_common_pv() {
        let a = make_hello(1, vec![1, 2]);
        let b = make_hello(1, vec![2, 3]);
        assert!(a.has_common_pv(&b));
        let c = make_hello(1, vec![4, 5]);
        assert!(!a.has_common_pv(&c));
    }

    #[test]
    fn test_hello_max_pv() {
        let h = make_hello(1, vec![1, 2, 3]);
        assert_eq!(h.max_pv(), 3);
        assert_eq!(h.min_pv(), 1);
    }

    #[test]
    fn test_hello_supports() {
        let h = make_hello(1, vec![1, 2, 3]);
        assert!(h.supports(2));
        assert!(!h.supports(4));
    }

    #[test]
    fn test_negotiate_session_pv_minmax() {
        let a = make_hello(1, vec![1, 2]);
        let b = make_hello(1, vec![1, 2, 3]);
        let mode = NegotiationMode::MinMax;
        let session = a.negotiate_session_pv(&b, mode);
        assert_eq!(session, 2);

        let c = make_hello(1, vec![1]);
        let session2 = a.negotiate_session_pv(&c, mode);
        assert_eq!(session2, 1);
    }

    #[test]
    fn test_negotiate_session_pv_intersection_max() {
        let a = make_hello(1, vec![1, 2, 4]);
        let b = make_hello(1, vec![2, 3, 4]);
        let mode = NegotiationMode::IntersectionMax;
        let session = a.negotiate_session_pv(&b, mode);
        assert_eq!(session, 4);
    }

    #[test]
    fn test_hello_builder() {
        let h = HelloBuilder::new(6126151, Hash32::zero(), 100)
            .supported_pv(&[1, 2])
            .software_version("test")
            .head_pv(2)
            .build();
        assert_eq!(h.chain_id, 6126151);
        assert_eq!(h.head_height, 100);
        assert_eq!(h.supported_pv, vec![1, 2]);
        assert_eq!(h.software_version, "test");
        assert_eq!(h.head_pv, 2);
    }

    #[test]
    fn test_compat_result_into_result() {
        let r = CompatResult::success(2);
        let res: WireResult<u32> = r.into_result();
        assert_eq!(res.unwrap(), 2);

        let r2 = CompatResult::failure("error", "ERR");
        let res2: WireResult<u32> = r2.into_result();
        assert!(res2.is_err());
    }

    #[test]
    fn test_wire_config_validation() {
        let config = WireConfig::default();
        assert!(config.validate().is_ok());

        let mut bad = WireConfig::default();
        bad.local_supported_pv = vec![];
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_negotiate_session_pv_standalone() {
        let pv1 = vec![1, 2];
        let pv2 = vec![1, 2, 3];
        let session = negotiate_session_pv(&pv1, &pv2, NegotiationMode::MinMax);
        assert_eq!(session, 2);
    }

    #[test]
    fn test_wire_manager() {
        let manager = WireManager::default();
        let a = make_hello(1, vec![1]);
        let b = make_hello(1, vec![1]);
        let result = manager.check_compat(&a, &b);
        assert!(result.compatible);
        let metrics = manager.metrics().snapshot();
        assert_eq!(metrics.total_checks, 1);
        assert_eq!(metrics.passed_checks, 1);
    }

    #[test]
    fn test_wire_manager_local_hello_with_config() {
        let manager = WireManager::default();
        let h = manager.local_hello_with_config(6126151, Hash32::zero(), 100);
        assert_eq!(h.chain_id, 6126151);
        assert_eq!(h.head_height, 100);
        assert!(!h.supported_pv.is_empty());
    }

    #[test]
    fn test_wire_manager_set_config() {
        let mut manager = WireManager::default();
        let new_config = WireConfig {
            enforce_chain_id: false,
            ..Default::default()
        };
        manager.set_config(new_config).unwrap();
        assert!(!manager.config().enforce_chain_id);
    }
}
