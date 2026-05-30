//! Quantum health, status, and metrics RPC endpoints for IONA v28.
//!
//! # Quantum Observability Model
//!
//! Health and status endpoints perform projective measurements on the
//! node's quantum state. Each response represents a collapse of the
//! quantum superposition to a classical observable.
//!
//! # Hamiltonian for Health Observables
//!
//! ```text
//! Ĥ_health = Ĥ_vital + Ĥ_consensus + Ĥ_network
//!
//! Ĥ_vital     = E_vital |alive⟩⟨alive|
//! Ĥ_consensus = Σ_h ω_h a†_h a_h
//! Ĥ_network   = Σ_p g_p (σ^+_p σ^-_p)
//! ```
//!
//! # Measurement Operators
//!
//! - `GET /health` → Ô_health = |ok⟩⟨ok| + |degraded⟩⟨degraded| + |error⟩⟨error|
//! - `GET /status` → Ô_status = Σ_i λ_i |status_i⟩⟨status_i|
//! - `GET /metrics` → Ô_metrics = Σ_j μ_j |metric_j⟩⟨metric_j|

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Health status eigenvalue for fully operational node (pure state).
pub const HEALTH_OK: &str = "ok";

/// Health status eigenvalue for degraded but still serving (mixed state).
pub const HEALTH_DEGRADED: &str = "degraded";

/// Health status eigenvalue for non‑operational node (decohered state).
pub const HEALTH_ERROR: &str = "error";

/// Default health degradation reason: no quorum (entanglement broken).
pub const REASON_NO_QUORUM: &str = "no_quorum";

/// Default health degradation reason: syncing in progress (state transfer).
pub const REASON_SYNCING: &str = "syncing";

/// Default health degradation reason: no connected peers (isolation).
pub const REASON_NO_PEERS: &str = "no_peers";

/// Default health degradation reason: decoherence threshold exceeded.
pub const REASON_DECOHERENCE: &str = "decoherence";

/// Version string (from Cargo.toml) — classical observable.
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Minimum coherence threshold for healthy state.
const MIN_COHERENCE: f64 = 0.9;

/// Measurement decoherence per health check.
const HEALTH_CHECK_DECOHERENCE: f64 = 0.0001;

// -----------------------------------------------------------------------------
// Quantum Health Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum health measurements.
#[derive(Debug, Error)]
pub enum RpcHealthError {
    #[error("invalid health status eigenvalue: {0}")]
    InvalidStatus(String),

    #[error("quantum decoherence: coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("measurement incompatibility: cannot observe {a} and {b} simultaneously")]
    IncompatibleMeasurement { a: String, b: String },
}

pub type RpcHealthResult<T> = Result<T, RpcHealthError>;

// -----------------------------------------------------------------------------
// Quantum Health Response
// -----------------------------------------------------------------------------

/// Health check response — projective measurement of Ô_health.
///
/// Collapses the node's quantum state to one of three eigenstates:
/// |ok⟩, |degraded⟩, or |error⟩.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    /// `"ok"`, `"degraded"` or `"error"` — eigenvalue.
    pub status: String,
    /// Optional reason for degradation (e.g., `"no_quorum"`, `"decoherence"`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Current block height — position eigenvalue.
    pub height: u64,
    /// Number of connected peers — entanglement count.
    pub peers: usize,
    /// Whether this node is producing blocks — unitary evolution active.
    pub producing: bool,
    /// Node version string — basis set identifier.
    pub version: String,
    /// Quantum coherence of the node (1.0 = pure state).
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Measurement timestamp (Unix seconds).
    #[serde(default)]
    pub timestamp: u64,
    /// Uptime in seconds since node start.
    #[serde(default)]
    pub uptime_seconds: u64,
}

fn default_coherence() -> f64 {
    1.0
}

impl HealthResponse {
    /// Create a healthy response — eigenvalue |ok⟩.
    pub fn ok(
        height: u64,
        peers: usize,
        producing: bool,
        coherence: f64,
        uptime_seconds: u64,
    ) -> Self {
        Self {
            status: HEALTH_OK.to_string(),
            reason: None,
            height,
            peers,
            producing,
            version: NODE_VERSION.to_string(),
            coherence,
            timestamp: current_timestamp(),
            uptime_seconds,
        }
    }

    /// Create a degraded response — eigenvalue |degraded⟩.
    pub fn degraded(
        reason: &str,
        height: u64,
        peers: usize,
        producing: bool,
        coherence: f64,
        uptime_seconds: u64,
    ) -> Self {
        Self {
            status: HEALTH_DEGRADED.to_string(),
            reason: Some(reason.to_string()),
            height,
            peers,
            producing,
            version: NODE_VERSION.to_string(),
            coherence,
            timestamp: current_timestamp(),
            uptime_seconds,
        }
    }

    /// Create an error response — eigenvalue |error⟩ (complete decoherence).
    pub fn error(reason: &str) -> Self {
        Self {
            status: HEALTH_ERROR.to_string(),
            reason: Some(reason.to_string()),
            height: 0,
            peers: 0,
            producing: false,
            version: NODE_VERSION.to_string(),
            coherence: 0.0,
            timestamp: current_timestamp(),
            uptime_seconds: 0,
        }
    }

    /// Create health response from quantum node state.
    pub fn from_quantum_state(
        height: u64,
        peers: usize,
        producing: bool,
        coherence: f64,
        uptime_seconds: u64,
    ) -> Self {
        if coherence < 0.5 {
            return Self::error(REASON_DECOHERENCE);
        }

        if !producing {
            if peers == 0 {
                return Self::degraded(
                    REASON_NO_PEERS,
                    height,
                    peers,
                    producing,
                    coherence,
                    uptime_seconds,
                );
            }
            return Self::degraded(
                REASON_NO_QUORUM,
                height,
                peers,
                producing,
                coherence,
                uptime_seconds,
            );
        }

        if coherence < MIN_COHERENCE {
            return Self::degraded(
                REASON_DECOHERENCE,
                height,
                peers,
                producing,
                coherence,
                uptime_seconds,
            );
        }

        Self::ok(height, peers, producing, coherence, uptime_seconds)
    }

    /// Validate the response status eigenvalue.
    pub fn validate(&self) -> RpcHealthResult<()> {
        match self.status.as_str() {
            HEALTH_OK | HEALTH_DEGRADED | HEALTH_ERROR => Ok(()),
            other => Err(RpcHealthError::InvalidStatus(other.to_string())),
        }
    }

    /// Check if the node is in a healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.status == HEALTH_OK && self.coherence >= MIN_COHERENCE
    }

    /// Check if the node is degraded but operational.
    pub fn is_degraded(&self) -> bool {
        self.status == HEALTH_DEGRADED && self.coherence >= 0.5
    }

    /// Check if the node is in error state.
    pub fn is_error(&self) -> bool {
        self.status == HEALTH_ERROR || self.coherence < 0.5
    }
}

// -----------------------------------------------------------------------------
// Quantum Status Response
// -----------------------------------------------------------------------------

/// Detailed node status response — complete quantum state tomography.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Node version — basis set identifier.
    pub node_version: String,
    /// Protocol version — quantum number.
    pub protocol_version: u32,
    /// Chain ID — system identifier.
    pub chain_id: u64,
    /// Current block height — position eigenvalue.
    pub height: u64,
    /// Current consensus round — time step.
    pub round: u32,
    /// Current consensus step — phase.
    pub step: String,
    /// Number of connected peers — entanglement count.
    pub peers: usize,
    /// Connected peer identifiers — entangled partners.
    pub peer_ids: Vec<String>,
    /// Validator set information — basis states.
    pub validators: ValidatorSetInfo,
    /// Whether this node is a validator — observable eigenvalue.
    pub is_validator: bool,
    /// Whether this node is producing blocks — unitary evolution active.
    pub is_producing: bool,
    /// Last commit time (Unix seconds) — last collapse.
    pub last_commit_time: u64,
    /// Blocks per minute — evolution rate.
    pub blocks_per_minute: f64,
    /// Current mempool size — occupation number.
    pub mempool_size: usize,
    /// Quantum coherence of the node.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement entropy.
    #[serde(default)]
    pub entanglement_entropy: f64,
    /// Optional diagnostic message.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    /// Measurement timestamp.
    #[serde(default)]
    pub timestamp: u64,
    /// Uptime in seconds.
    #[serde(default)]
    pub uptime_seconds: u64,
}

/// Validator set summary — basis state decomposition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorSetInfo {
    /// Total number of validators.
    pub total: usize,
    /// Total voting power.
    pub total_power: u64,
    /// Quorum threshold (2/3 of total power).
    pub quorum_threshold: u64,
    /// Individual validator information.
    pub validators: Vec<ValidatorInfo>,
}

/// Single validator information — basis state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    /// Short public key representation.
    pub pubkey_short: String,
    /// Voting power.
    pub power: u64,
    /// Whether this validator is connected.
    pub connected: bool,
    /// Validator coherence (1.0 = fully operational).
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Quantum Status Builder
// -----------------------------------------------------------------------------

/// Builder for constructing a quantum `StatusResponse`.
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
    pub coherence: f64,
    pub entanglement_entropy: f64,
    pub uptime_seconds: u64,
}

impl StatusBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Build the final quantum `StatusResponse`.
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
            coherence: self.coherence,
            entanglement_entropy: self.entanglement_entropy,
            diagnostic: self.diagnostic,
            timestamp: current_timestamp(),
            uptime_seconds: self.uptime_seconds,
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Utility Functions
// -----------------------------------------------------------------------------

/// Get current Unix timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Health Response Tests ──────────────────────────────────────────
    #[test]
    fn test_health_ok() {
        let h = HealthResponse::ok(100, 5, true, 0.99, 3600);
        assert_eq!(h.status, HEALTH_OK);
        assert!(h.reason.is_none());
        assert_eq!(h.height, 100);
        assert_eq!(h.version, NODE_VERSION);
        assert!((h.coherence - 0.99).abs() < 1e-10);
        assert!(h.is_healthy());
        assert!(!h.is_degraded());
        assert!(!h.is_error());
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_degraded() {
        let h = HealthResponse::degraded(
            REASON_NO_QUORUM,
            50,
            2,
            false,
            0.75,
            1800,
        );
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason.as_deref(), Some(REASON_NO_QUORUM));
        assert!(!h.is_healthy());
        assert!(h.is_degraded());
        assert!(!h.is_error());
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_error() {
        let h = HealthResponse::error("startup_failed");
        assert_eq!(h.status, HEALTH_ERROR);
        assert_eq!(h.height, 0);
        assert_eq!(h.coherence, 0.0);
        assert!(!h.is_healthy());
        assert!(!h.is_degraded());
        assert!(h.is_error());
        assert!(h.validate().is_ok());
    }

    #[test]
    fn test_health_from_quantum_state_healthy() {
        let h = HealthResponse::from_quantum_state(100, 5, true, 0.95, 3600);
        assert_eq!(h.status, HEALTH_OK);
        assert!(h.is_healthy());
    }

    #[test]
    fn test_health_from_quantum_state_decohered() {
        let h = HealthResponse::from_quantum_state(100, 0, false, 0.3, 3600);
        assert_eq!(h.status, HEALTH_ERROR);
        assert!(h.is_error());
    }

    #[test]
    fn test_health_from_quantum_state_no_peers() {
        let h = HealthResponse::from_quantum_state(100, 0, false, 0.95, 3600);
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason.as_deref(), Some(REASON_NO_PEERS));
    }

    #[test]
    fn test_health_from_quantum_state_low_coherence() {
        let h = HealthResponse::from_quantum_state(100, 5, true, 0.85, 3600);
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason.as_deref(), Some(REASON_DECOHERENCE));
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
            coherence: 1.0,
            timestamp: 0,
            uptime_seconds: 0,
        };
        assert!(h.validate().is_err());
    }

    // ── Status Builder Tests ───────────────────────────────────────────
    #[test]
    fn test_status_builder_default() {
        let status = StatusBuilder::new().build();
        assert_eq!(status.node_version, NODE_VERSION);
        assert_eq!(status.height, 0);
        assert_eq!(status.validators.total, 0);
        assert_eq!(status.coherence, 0.0);
    }

    #[test]
    fn test_status_builder_with_quantum_values() {
        let status = StatusBuilder {
            protocol_version: 1,
            chain_id: 6126151,
            height: 42,
            round: 0,
            step: "Propose".into(),
            peers: 3,
            peer_ids: vec![
                "12D3K..1".into(),
                "12D3K..2".into(),
                "12D3K..3".into(),
            ],
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
                    coherence: 0.99,
                },
                ValidatorInfo {
                    pubkey_short: "ccdd..".into(),
                    power: 1,
                    connected: true,
                    coherence: 0.98,
                },
                ValidatorInfo {
                    pubkey_short: "eeff..".into(),
                    power: 1,
                    connected: false,
                    coherence: 0.0,
                },
            ],
            total_power: 3,
            quorum_threshold: 3,
            coherence: 0.95,
            entanglement_entropy: 0.05,
            uptime_seconds: 7200,
        }
        .build();

        assert_eq!(status.node_version, NODE_VERSION);
        assert_eq!(status.height, 42);
        assert_eq!(status.validators.total, 3);
        assert_eq!(status.validators.quorum_threshold, 3);
        assert!((status.coherence - 0.95).abs() < 1e-10);
        assert!((status.entanglement_entropy - 0.05).abs() < 1e-10);
        assert_eq!(status.uptime_seconds, 7200);
    }

    // ── Serialization Tests ────────────────────────────────────────────
    #[test]
    fn test_health_serialization() {
        let h = HealthResponse::ok(100, 5, true, 0.99, 3600);
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"ok\""));
        assert!(!json.contains("reason"));
        assert!(json.contains("\"coherence\":0.99"));
    }

    #[test]
    fn test_health_degraded_serialization() {
        let h = HealthResponse::degraded(
            REASON_NO_QUORUM,
            50,
            2,
            false,
            0.75,
            1800,
        );
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains("\"status\":\"degraded\""));
        assert!(json.contains("\"reason\":\"no_quorum\""));
    }

    #[test]
    fn test_status_serialization() {
        let status = StatusBuilder::new().build();
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("\"node_version\""));
        assert!(json.contains("\"height\":0"));
        assert!(json.contains("\"coherence\""));
        assert!(json.contains("\"timestamp\""));
    }

    #[test]
    fn test_validator_info_coherence() {
        let v = ValidatorInfo {
            pubkey_short: "test".into(),
            power: 10,
            connected: true,
            coherence: 0.97,
        };
        assert!((v.coherence - 0.97).abs() < 1e-10);
    }
}
