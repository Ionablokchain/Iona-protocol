//! Health, status, and metrics RPC endpoints for IONA v28.
//!
//! GET /health  → ok/fail + reason
//! GET /status  → height, round, peers, validator set, commit info
//! GET /metrics → prometheus-format metrics (optional)

use serde::{Deserialize, Serialize};

/// Health check response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// "ok" or "degraded" or "error".
    pub status: String,
    /// Reason if not ok (e.g. "no_quorum", "syncing", "no_peers").
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
    pub fn ok(height: u64, peers: usize, producing: bool) -> Self {
        Self {
            status: "ok".into(),
            reason: None,
            height,
            peers,
            producing,
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    pub fn degraded(reason: &str, height: u64, peers: usize, producing: bool) -> Self {
        Self {
            status: "degraded".into(),
            reason: Some(reason.into()),
            height,
            peers,
            producing,
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }

    pub fn error(reason: &str) -> Self {
        Self {
            status: "error".into(),
            reason: Some(reason.into()),
            height: 0,
            peers: 0,
            producing: false,
            version: env!("CARGO_PKG_VERSION").into(),
        }
    }
}

/// Status response (detailed node info).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node software version.
    pub node_version: String,
    /// Current protocol version.
    pub protocol_version: u32,
    /// Chain ID.
    pub chain_id: u64,
    /// Current block height.
    pub height: u64,
    /// Current consensus round.
    pub round: u32,
    /// Current consensus step (Propose/Prevote/Precommit/Commit).
    pub step: String,
    /// Number of connected peers.
    pub peers: usize,
    /// Connected peer IDs (truncated).
    pub peer_ids: Vec<String>,
    /// Validator set info.
    pub validators: ValidatorSetInfo,
    /// Whether this node is a validator.
    pub is_validator: bool,
    /// Whether this node is producing blocks.
    pub is_producing: bool,
    /// Last commit timestamp (unix seconds).
    pub last_commit_time: u64,
    /// Blocks since last check (for monitoring).
    pub blocks_per_minute: f64,
    /// Mempool size.
    pub mempool_size: usize,
    /// Consensus diagnostic summary (one-line "why no commit" if stalled).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
}

/// Validator set summary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetInfo {
    pub total: usize,
    pub total_power: u64,
    pub quorum_threshold: u64,
    /// Short hex of each validator's public key.
    pub validators: Vec<ValidatorInfo>,
}

/// Single validator info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub pubkey_short: String,
    pub power: u64,
    pub connected: bool,
}

/// Builder for constructing a StatusResponse from node state.
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
    pub fn build(self) -> StatusResponse {
        StatusResponse {
            node_version: env!("CARGO_PKG_VERSION").into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_health_ok() {
        let h = HealthResponse::ok(100, 5, true);
        assert_eq!(h.status, "ok");
        assert!(h.reason.is_none());
        assert_eq!(h.height, 100);
    }

    #[test]
    fn test_health_degraded() {
        let h = HealthResponse::degraded("no_quorum", 50, 2, false);
        assert_eq!(h.status, "degraded");
        assert_eq!(h.reason.as_deref(), Some("no_quorum"));
    }

    #[test]
    fn test_health_error() {
        let h = HealthResponse::error("startup_failed");
        assert_eq!(h.status, "error");
        assert_eq!(h.height, 0);
    }

    #[test]
    fn test_status_builder() {
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
                ValidatorInfo { pubkey_short: "aabb..".into(), power: 1, connected: true },
                ValidatorInfo { pubkey_short: "ccdd..".into(), power: 1, connected: true },
                ValidatorInfo { pubkey_short: "eeff..".into(), power: 1, connected: false },
            ],
            total_power: 3,
            quorum_threshold: 3,
        }.build();

        assert_eq!(status.node_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(status.height, 42);
        assert_eq!(status.validators.total, 3);
        assert_eq!(status.validators.quorum_threshold, 3);
    }

    #[test]
    fn test_health_serialization() {
        let h = HealthResponse::ok(100, 5, true);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("reason")); // None fields skipped
    }
}
