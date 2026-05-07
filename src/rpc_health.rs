//! Health, status, and metrics RPC endpoints for IONA v28.
//!
//! Provides JSON responses for:
//! - `GET /health`  → overall node health (ok/degraded/error)
//! - `GET /status`  → detailed node status (consensus, peers, validator set)
//! - `GET /metrics` → Prometheus metrics (handled separately)
//!
//! # Example
//!
//! ```rust
//! use iona::rpc_health::{HealthResponse, StatusBuilder, StatusResponse};
//!
//! let health = HealthResponse::ok(100, 5, true);
//! assert_eq!(health.status, "ok");
//! ```

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Health status constant for fully operational node.
pub const HEALTH_OK: &str = "ok";

/// Health status constant for degraded but still serving.
pub const HEALTH_DEGRADED: &str = "degraded";

/// Health status constant for non‑operational node.
pub const HEALTH_ERROR: &str = "error";

/// Default health degradation reason: no quorum.
pub const REASON_NO_QUORUM: &str = "no_quorum";

/// Default health degradation reason: syncing in progress.
pub const REASON_SYNCING: &str = "syncing";

/// Default health degradation reason: no connected peers.
pub const REASON_NO_PEERS: &str = "no_peers";

/// Version string (from Cargo.toml).
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when building health or status responses (currently infallible).
#[derive(Debug, Error)]
pub enum RpcHealthError {
    #[error("invalid health status: {0}")]
    InvalidStatus(String),
}

pub type RpcHealthResult<T> = Result<T, RpcHealthError>;

// -----------------------------------------------------------------------------
// HealthResponse
// -----------------------------------------------------------------------------

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// `"ok"`, `"degraded"` or `"error"`.
    pub status: String,
    /// Optional reason (e.g., `"no_quorum"`, `"syncing"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Current block height.
    pub height: u64,
    /// Number of connected peers.
    pub peers: usize,
    /// Whether this node is producing blocks.
    pub producing: bool,
    /// Node version string.
    pub version: String,
}

impl HealthResponse {
    /// Create a healthy response.
    pub fn ok(height: u64, peers: usize, producing: bool) -> Self {
        Self {
            status: HEALTH_OK.to_string(),
            reason: None,
            height,
            peers,
            producing,
            version: NODE_VERSION.to_string(),
        }
    }

    /// Create a degraded response with a human‑readable reason.
    pub fn degraded(reason: &str, height: u64, peers: usize, producing: bool) -> Self {
        Self {
            status: HEALTH_DEGRADED.to_string(),
            reason: Some(reason.to_string()),
            height,
            peers,
            producing,
            version: NODE_VERSION.to_string(),
        }
    }

    /// Create an error response (node cannot serve).
    pub fn error(reason: &str) -> Self {
        Self {
            status: HEALTH_ERROR.to_string(),
            reason: Some(reason.to_string()),
            height: 0,
            peers: 0,
            producing: false,
            version: NODE_VERSION.to_string(),
        }
    }

    /// Validate the response status.
    pub fn validate(&self) -> RpcHealthResult<()> {
        match self.status.as_str() {
            HEALTH_OK | HEALTH_DEGRADED | HEALTH_ERROR => Ok(()),
            other => Err(RpcHealthError::InvalidStatus(other.to_string())),
        }
    }
}

// -----------------------------------------------------------------------------
// StatusResponse
// -----------------------------------------------------------------------------

/// Detailed node status response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    pub node_version: String,
    pub protocol_version: u32,
    pub chain_id: u64,
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub peers: usize,
    pub peer_ids: Vec<String>,
    pub validators: ValidatorSetInfo,
    pub is_validator: bool,
    pub is_producing: bool,
    pub last_commit_time: u64,
    pub blocks_per_minute: f64,
    pub mempool_size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

/// Validator set summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetInfo {
    pub total: usize,
    pub total_power: u64,
    pub quorum_threshold: u64,
    pub validators: Vec<ValidatorInfo>,
}

/// Single validator information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey_short: String,
    pub power: u64,
    pub connected: bool,
}

// -----------------------------------------------------------------------------
// StatusBuilder
// -----------------------------------------------------------------------------

/// Builder for constructing a `StatusResponse` from node state.
#[derive(Debug, Default)]
pub struct StatusBuilder {
    pub protocol_version: u32,
    pub chain_id: u64,
    pub height: u64,
    pub round: u32,
    pub step: String,
    pub peers: usize,
    pub peer_ids: Vec<String>,
    pub is_validator: bool,
    pub is_producing: bool,
    pub last_commit_time: u64,
    pub blocks_per_minute: f64,
    pub mempool_size: usize,
    pub diagnostic: Option<String>,
    pub validator_infos: Vec<ValidatorInfo>,
    pub total_power: u64,
    pub quorum_threshold: u64,
}

impl StatusBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the final `StatusResponse`.
    pub fn build(self) -> StatusResponse {
        StatusResponse {
            node_version: NODE_VERSION.to_string(),
            protocol_version: self.protocol_version,
            chain_id: self.chain_id,
            height: self.height,
            round: self.round,
            step: self.step,
            peers: self.peers,
            peer_ids: self.peer_ids,
            validators: ValidatorSetInfo {
                total: self.validator_infos.len(),
                total_power: self.total_power,
                quorum_threshold: self.quorum_threshold,
                validators: self.validator_infos,
            },
            is_validator: self.is_validator,
            is_producing: self.is_producing,
            last_commit_time: self.last_commit_time,
            blocks_per_minute: self.blocks_per_minute,
            mempool_size: self.mempool_size,
            diagnostic: self.diagnostic,
        }
    }
}

impl Default for StatusBuilder {
    fn default() -> Self {
        Self {
            protocol_version: 0,
            chain_id: 0,
            height: 0,
            round: 0,
            step: String::new(),
            peers: 0,
            peer_ids: Vec::new(),
            is_validator: false,
            is_producing: false,
            last_commit_time: 0,
            blocks_per_minute: 0.0,
            mempool_size: 0,
            diagnostic: None,
            validator_infos: Vec::new(),
            total_power: 0,
            quorum_threshold: 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ok() {
        let h = HealthResponse::ok(100, 5, true);
        assert_eq!(h.status, HEALTH_OK);
        assert!(h.reason.is_none());
        assert_eq!(h.height, 100);
        assert_eq!(h.version, NODE_VERSION);
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_degraded() {
        let h = HealthResponse::degraded(REASON_NO_QUORUM, 50, 2, false);
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason.as_deref(), Some(REASON_NO_QUORUM));
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_error() {
        let h = HealthResponse::error("startup_failed");
        assert_eq!(h.status, HEALTH_ERROR);
        assert_eq!(h.height, 0);
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_validate_invalid() {
        let h = HealthResponse {
            status: "unknown".to_string(),
            reason: None,
            height: 0,
            peers: 0,
            producing: false,
            version: NODE_VERSION.to_string(),
        };
        assert!(h.validate().is_err());
    }

    #[test]
    fn test_status_builder() {
        let status = StatusBuilder::new()
            .build();
        assert_eq!(status.node_version, NODE_VERSION);
        assert_eq!(status.height, 0);
        assert_eq!(status.validators.total, 0);
    }

    #[test]
    fn test_status_builder_with_values() {
        let status = StatusBuilder {
            protocol_version: 1,
            chain_id: 6126151,
            height: 42,
            round: 0,
            step: "Propose".into(),
            peers: 3,
            peer_ids: vec!["12D3K..1".into(), "12D3K..2".into(), "12D3K..3".into()],
            is_validator: true,
            is_producing: true,
            last_commit_time: 1234567890,
            blocks_per_minute: 120.0,
            mempool_size: 50,
            diagnostic: None,
            validator_infos: vec![
                ValidatorInfo {
                    pubkey_short: "aabb..".into(),
                    power: 1,
                    connected: true,
                },
                ValidatorInfo {
                    pubkey_short: "ccdd..".into(),
                    power: 1,
                    connected: true,
                },
                ValidatorInfo {
                    pubkey_short: "eeff..".into(),
                    power: 1,
                    connected: false,
                },
            ],
            total_power: 3,
            quorum_threshold: 3,
        }
        .build();

        assert_eq!(status.node_version, NODE_VERSION);
        assert_eq!(status.height, 42);
        assert_eq!(status.validators.total, 3);
        assert_eq!(status.validators.quorum_threshold, 3);
    }

    #[test]
    fn test_health_serialization() {
        let h = HealthResponse::ok(100, 5, true);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("reason"));
    }

    #[test]
    fn test_status_serialization() {
        let status = StatusBuilder::new().build();
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"node_version\""));
        assert!(json.contains("\"height\":0"));
    }
}
