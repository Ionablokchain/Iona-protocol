//! Quantum health, status, and metrics RPC endpoints for IONA v28.
//!
//! # Quantum Observability Model
//!
//! Health and status endpoints perform projective measurements on the
//! node's quantum state. Each response represents a collapse of the
//! quantum superposition to a classical observable.
//!
//! # Production Features
//! - Thread‑safe `HealthManager` with `parking_lot::Mutex`.
//! - Configurable thresholds (coherence, peers, producing).
//! - Persistent statistics with atomic writes and file locking.
//! - Structured logging with `tracing`.
//! - Versioned serialization for forward compatibility.
//! - Comprehensive validation for all responses.
//! - Easy integration with consensus engine and network layer.

use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Health status eigenvalue for fully operational node.
pub const HEALTH_OK: &str = "ok";

/// Health status eigenvalue for degraded but still serving.
pub const HEALTH_DEGRADED: &str = "degraded";

/// Health status eigenvalue for non‑operational node.
pub const HEALTH_ERROR: &str = "error";

/// Default degradation reasons.
pub const REASON_NO_QUORUM: &str = "no_quorum";
pub const REASON_SYNCING: &str = "syncing";
pub const REASON_NO_PEERS: &str = "no_peers";
pub const REASON_DECOHERENCE: &str = "decoherence";
pub const REASON_STARTUP: &str = "startup";

/// Version string (from Cargo.toml).
pub const NODE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default coherence threshold for healthy state.
const DEFAULT_MIN_COHERENCE: f64 = 0.9;

/// Default minimum peers for healthy state.
const DEFAULT_MIN_PEERS: usize = 1;

/// Default decoherence rate per health check.
const DEFAULT_DECOHERENCE_RATE: f64 = 0.0001;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default statistics window size.
const DEFAULT_STATS_WINDOW: usize = 100;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during health and status measurements.
#[derive(Debug, Error)]
pub enum RpcHealthError {
    #[error("invalid health status eigenvalue: {0}")]
    InvalidStatus(String),

    #[error("quantum decoherence: coherence {coherence:.4} below threshold {threshold:.4}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("measurement incompatibility: cannot observe {a} and {b} simultaneously")]
    IncompatibleMeasurement { a: String, b: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("state not initialized")]
    StateNotInitialized,
}

pub type RpcHealthResult<T> = Result<T, RpcHealthError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for health and status endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthConfig {
    /// Minimum coherence for `ok` status (0.0 – 1.0).
    pub min_coherence_ok: f64,
    /// Minimum coherence for `degraded` status (0.0 – 1.0).
    pub min_coherence_degraded: f64,
    /// Minimum number of connected peers for `ok` status.
    pub min_peers_ok: usize,
    /// Whether producing blocks is required for `ok` status.
    pub require_producing_for_ok: bool,
    /// Decoherence rate per measurement (0.0 – 1.0).
    pub decoherence_rate: f64,
    /// Whether to persist statistics to disk.
    pub persist_stats: bool,
    /// Statistics window size.
    pub stats_window_size: usize,
}

impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            min_coherence_ok: DEFAULT_MIN_COHERENCE,
            min_coherence_degraded: 0.5,
            min_peers_ok: DEFAULT_MIN_PEERS,
            require_producing_for_ok: true,
            decoherence_rate: DEFAULT_DECOHERENCE_RATE,
            persist_stats: true,
            stats_window_size: DEFAULT_STATS_WINDOW,
        }
    }
}

impl HealthConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.min_coherence_ok) {
            return Err("min_coherence_ok must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_coherence_degraded) {
            return Err("min_coherence_degraded must be between 0.0 and 1.0".into());
        }
        if self.min_coherence_ok < self.min_coherence_degraded {
            return Err("min_coherence_ok must be >= min_coherence_degraded".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if self.stats_window_size == 0 {
            return Err("stats_window_size must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Persistent Statistics
// -----------------------------------------------------------------------------

/// Persistent statistics state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatsStateV1 {
    version: u32,
    health_checks: u64,
    ok_count: u64,
    degraded_count: u64,
    error_count: u64,
    last_status: String,
    last_reason: Option<String>,
    avg_coherence: f64,
    avg_peers: f64,
    last_modified: u64,
}

impl StatsStateV1 {
    fn from_stats(stats: &HealthStats) -> Self {
        Self {
            version: CURRENT_VERSION,
            health_checks: stats.health_checks,
            ok_count: stats.ok_count,
            degraded_count: stats.degraded_count,
            error_count: stats.error_count,
            last_status: stats.last_status.clone(),
            last_reason: stats.last_reason.clone(),
            avg_coherence: stats.avg_coherence,
            avg_peers: stats.avg_peers,
            last_modified: current_timestamp(),
        }
    }

    fn into_stats(self) -> HealthStats {
        HealthStats {
            health_checks: self.health_checks,
            ok_count: self.ok_count,
            degraded_count: self.degraded_count,
            error_count: self.error_count,
            last_status: self.last_status,
            last_reason: self.last_reason,
            avg_coherence: self.avg_coherence,
            avg_peers: self.avg_peers,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── File I/O ─────────────────────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, RpcHealthError> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| RpcHealthError::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let start = SystemTime::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed().unwrap_or_default() > timeout {
                    return Err(RpcHealthError::LockFailed(format!(
                        "timeout after {}s",
                        LOCK_TIMEOUT_SECS
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), RpcHealthError> {
    file.unlock().map_err(|e| RpcHealthError::LockFailed(e.to_string()))
}

fn load_stats(path: &Path) -> Result<HealthStats, RpcHealthError> {
    if !path.exists() {
        return Ok(HealthStats::default());
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(RpcHealthError::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: StatsStateV1 = serde_json::from_value(raw)?;
        Ok(st.into_stats())
    } else {
        // Legacy format: try to parse as stats directly.
        match serde_json::from_value::<HealthStats>(raw) {
            Ok(stats) => Ok(stats),
            Err(e) => Err(RpcHealthError::Serialization(e)),
        }
    }
}

fn save_stats(path: &Path, stats: &HealthStats) -> Result<(), RpcHealthError> {
    let st = StatsStateV1::from_stats(stats);
    let json = serde_json::to_string_pretty(&st)?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Health Statistics
// -----------------------------------------------------------------------------

/// Statistics for health checks.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthStats {
    pub health_checks: u64,
    pub ok_count: u64,
    pub degraded_count: u64,
    pub error_count: u64,
    pub last_status: String,
    pub last_reason: Option<String>,
    pub avg_coherence: f64,
    pub avg_peers: f64,
}

impl HealthStats {
    /// Record a health measurement.
    pub fn record(&mut self, status: &str, reason: Option<&str>, coherence: f64, peers: usize) {
        self.health_checks = self.health_checks.wrapping_add(1);
        match status {
            HEALTH_OK => self.ok_count = self.ok_count.wrapping_add(1),
            HEALTH_DEGRADED => self.degraded_count = self.degraded_count.wrapping_add(1),
            _ => self.error_count = self.error_count.wrapping_add(1),
        }
        self.last_status = status.to_string();
        self.last_reason = reason.map(|s| s.to_string());
        // Exponential moving average for coherence and peers.
        let n = self.health_checks as f64;
        self.avg_coherence = (self.avg_coherence * (n - 1.0) + coherence) / n;
        self.avg_peers = (self.avg_peers * (n - 1.0) + peers as f64) / n;
    }
}

// -----------------------------------------------------------------------------
// Health Manager
// -----------------------------------------------------------------------------

/// Thread‑safe manager that holds the current node state and produces
/// health/status responses.
#[derive(Clone)]
pub struct HealthManager {
    config: Arc<HealthConfig>,
    state: Arc<Mutex<HealthState>>,
    stats: Arc<Mutex<HealthStats>>,
    stats_path: Option<PathBuf>,
    /// Total health checks performed (atomic counter).
    checks_performed: Arc<AtomicU64>,
}

/// Internal state of the node (observables).
#[derive(Debug, Clone, Default)]
struct HealthState {
    height: u64,
    round: u32,
    step: String,
    peers: usize,
    peer_ids: Vec<String>,
    is_validator: bool,
    is_producing: bool,
    last_commit_time: u64,
    blocks_per_minute: f64,
    mempool_size: usize,
    coherence: f64,
    entanglement_entropy: f64,
    uptime_seconds: u64,
    protocol_version: u32,
    chain_id: u64,
    validator_infos: Vec<ValidatorInfo>,
    total_power: u64,
    quorum_threshold: u64,
    diagnostic: Option<String>,
}

impl HealthManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: HealthConfig) -> Result<Self, String> {
        config.validate().map_err(|e| format!("config validation: {}", e))?;
        Ok(Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(HealthState::default())),
            stats: Arc::new(Mutex::new(HealthStats::default())),
            stats_path: None,
            checks_performed: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a manager with persistence to disk.
    pub fn with_persistence(
        data_dir: &str,
        config: HealthConfig,
    ) -> Result<Self, RpcHealthError> {
        config.validate().map_err(RpcHealthError::Config)?;
        let path = PathBuf::from(data_dir).join("health_stats.json");
        let stats = if path.exists() {
            load_stats(&path)?
        } else {
            HealthStats::default()
        };
        Ok(Self {
            config: Arc::new(config),
            state: Arc::new(Mutex::new(HealthState::default())),
            stats: Arc::new(Mutex::new(stats)),
            stats_path: Some(path),
            checks_performed: Arc::new(AtomicU64::new(0)),
        })
    }

    // ── State updates ────────────────────────────────────────────────────

    /// Update the current block height.
    pub fn update_height(&self, height: u64) {
        let mut state = self.state.lock();
        state.height = height;
        trace!(height, "health state updated");
    }

    /// Update consensus round and step.
    pub fn update_consensus(&self, round: u32, step: &str) {
        let mut state = self.state.lock();
        state.round = round;
        state.step = step.to_string();
        trace!(round, step, "health state updated");
    }

    /// Update peer information.
    pub fn update_peers(&self, peers: usize, peer_ids: Vec<String>) {
        let mut state = self.state.lock();
        state.peers = peers;
        state.peer_ids = peer_ids;
        trace!(peers, "health state updated");
    }

    /// Update validator status.
    pub fn update_validator_status(&self, is_validator: bool) {
        let mut state = self.state.lock();
        state.is_validator = is_validator;
        trace!(is_validator, "health state updated");
    }

    /// Update block production status.
    pub fn update_producing(&self, is_producing: bool) {
        let mut state = self.state.lock();
        state.is_producing = is_producing;
        trace!(is_producing, "health state updated");
    }

    /// Update last commit time.
    pub fn update_last_commit(&self, time: u64) {
        let mut state = self.state.lock();
        state.last_commit_time = time;
        trace!(time, "health state updated");
    }

    /// Update blocks per minute.
    pub fn update_blocks_per_minute(&self, bpm: f64) {
        let mut state = self.state.lock();
        state.blocks_per_minute = bpm;
        trace!(bpm, "health state updated");
    }

    /// Update mempool size.
    pub fn update_mempool_size(&self, size: usize) {
        let mut state = self.state.lock();
        state.mempool_size = size;
        trace!(size, "health state updated");
    }

    /// Update quantum coherence and entropy.
    pub fn update_quantum(&self, coherence: f64, entropy: f64) {
        let mut state = self.state.lock();
        state.coherence = coherence.clamp(0.0, 1.0);
        state.entanglement_entropy = entropy.max(0.0);
        trace!(coherence, entropy, "health state updated");
    }

    /// Update uptime.
    pub fn update_uptime(&self, uptime: u64) {
        let mut state = self.state.lock();
        state.uptime_seconds = uptime;
        trace!(uptime, "health state updated");
    }

    /// Update protocol and chain identifiers.
    pub fn update_identifiers(&self, protocol_version: u32, chain_id: u64) {
        let mut state = self.state.lock();
        state.protocol_version = protocol_version;
        state.chain_id = chain_id;
        trace!(protocol_version, chain_id, "health state updated");
    }

    /// Update validator set information.
    pub fn update_validator_set(
        &self,
        validators: Vec<ValidatorInfo>,
        total_power: u64,
        quorum_threshold: u64,
    ) {
        let mut state = self.state.lock();
        state.validator_infos = validators;
        state.total_power = total_power;
        state.quorum_threshold = quorum_threshold;
        trace!(count = state.validator_infos.len(), total_power, "health state updated");
    }

    /// Update diagnostic message.
    pub fn update_diagnostic(&self, diag: Option<String>) {
        let mut state = self.state.lock();
        state.diagnostic = diag;
        trace!("health diagnostic updated");
    }

    // ── Response generation ──────────────────────────────────────────────

    /// Measure the current health status — projective measurement.
    pub fn health(&self) -> HealthResponse {
        let state = self.state.lock();
        let config = &self.config;

        // Apply measurement decoherence.
        let coherence = (state.coherence * (-config.decoherence_rate).exp()).clamp(0.0, 1.0);

        // Determine status.
        let (status, reason) = if coherence < config.min_coherence_degraded {
            (HEALTH_ERROR, Some(REASON_DECOHERENCE))
        } else if state.peers < config.min_peers_ok {
            (HEALTH_DEGRADED, Some(REASON_NO_PEERS))
        } else if config.require_producing_for_ok && !state.is_producing {
            (HEALTH_DEGRADED, Some(REASON_NO_QUORUM))
        } else if coherence < config.min_coherence_ok {
            (HEALTH_DEGRADED, Some(REASON_DECOHERENCE))
        } else {
            (HEALTH_OK, None)
        };

        let response = HealthResponse {
            status: status.to_string(),
            reason: reason.map(|s| s.to_string()),
            height: state.height,
            peers: state.peers,
            producing: state.is_producing,
            version: NODE_VERSION.to_string(),
            coherence,
            timestamp: current_timestamp(),
            uptime_seconds: state.uptime_seconds,
        };

        // Record statistics.
        let mut stats = self.stats.lock();
        stats.record(status, reason, coherence, state.peers);
        self.checks_performed.fetch_add(1, Ordering::Relaxed);

        // Persist if enabled.
        if config.persist_stats {
            if let Some(path) = &self.stats_path {
                if let Err(e) = save_stats(path, &stats) {
                    warn!(error = %e, "failed to save health stats");
                }
            }
        }

        trace!(status, height = state.height, "health measurement performed");
        response
    }

    /// Generate a detailed status response — quantum state tomography.
    pub fn status(&self) -> StatusResponse {
        let state = self.state.lock();
        let config = &self.config;

        // Apply measurement decoherence to status as well.
        let coherence = (state.coherence * (-config.decoherence_rate).exp()).clamp(0.0, 1.0);

        StatusResponse {
            node_version: NODE_VERSION.to_string(),
            protocol_version: state.protocol_version,
            chain_id: state.chain_id,
            height: state.height,
            round: state.round,
            step: state.step.clone(),
            peers: state.peers,
            peer_ids: state.peer_ids.clone(),
            validators: ValidatorSetInfo {
                total: state.validator_infos.len(),
                total_power: state.total_power,
                quorum_threshold: state.quorum_threshold,
                validators: state.validator_infos.clone(),
            },
            is_validator: state.is_validator,
            is_producing: state.is_producing,
            last_commit_time: state.last_commit_time,
            blocks_per_minute: state.blocks_per_minute,
            mempool_size: state.mempool_size,
            coherence,
            entanglement_entropy: state.entanglement_entropy,
            diagnostic: state.diagnostic.clone(),
            timestamp: current_timestamp(),
            uptime_seconds: state.uptime_seconds,
        }
    }

    /// Flush statistics to disk.
    pub fn flush_stats(&self) -> Result<(), RpcHealthError> {
        if let Some(path) = &self.stats_path {
            let stats = self.stats.lock().clone();
            save_stats(path, &stats)?;
        }
        Ok(())
    }

    /// Get statistics snapshot.
    pub fn stats(&self) -> HealthStats {
        self.stats.lock().clone()
    }

    /// Get current coherence.
    pub fn coherence(&self) -> f64 {
        self.state.lock().coherence
    }

    /// Get current height.
    pub fn height(&self) -> u64 {
        self.state.lock().height
    }

    /// Get current peers count.
    pub fn peers(&self) -> usize {
        self.state.lock().peers
    }

    /// Get current producing status.
    pub fn is_producing(&self) -> bool {
        self.state.lock().is_producing
    }

    /// Get configuration reference.
    pub fn config(&self) -> &HealthConfig {
        &self.config
    }
}

// -----------------------------------------------------------------------------
// Quantum Health Response
// -----------------------------------------------------------------------------

/// Health check response — projective measurement of Ô_health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    pub height: u64,
    pub peers: usize,
    pub producing: bool,
    pub version: String,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub uptime_seconds: u64,
}

fn default_coherence() -> f64 {
    1.0
}

impl HealthResponse {
    /// Validate the response status eigenvalue.
    pub fn validate(&self) -> RpcHealthResult<()> {
        match self.status.as_str() {
            HEALTH_OK | HEALTH_DEGRADED | HEALTH_ERROR => Ok(()),
            other => Err(RpcHealthError::InvalidStatus(other.to_string())),
        }
    }

    /// Check if the node is in a healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.status == HEALTH_OK && self.coherence >= DEFAULT_MIN_COHERENCE
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
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    #[serde(default)]
    pub entanglement_entropy: f64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diagnostic: Option<String>,
    #[serde(default)]
    pub timestamp: u64,
    #[serde(default)]
    pub uptime_seconds: u64,
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
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> HealthConfig {
        let mut cfg = HealthConfig::default();
        cfg.min_coherence_ok = 0.9;
        cfg.min_coherence_degraded = 0.5;
        cfg.min_peers_ok = 1;
        cfg.require_producing_for_ok = true;
        cfg.decoherence_rate = 0.001;
        cfg.persist_stats = true;
        cfg
    }

    #[test]
    fn test_health_manager_initial() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();
        let h = mgr.health();
        assert_eq!(h.status, HEALTH_ERROR);
        assert_eq!(h.reason, Some(REASON_DECOHERENCE.to_string()));
        assert_eq!(h.height, 0);
        assert_eq!(h.coherence, 0.0);
        assert_eq!(h.peers, 0);
        assert!(!h.producing);
        assert!(h.is_error());
    }

    #[test]
    fn test_health_manager_update_and_check() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();

        mgr.update_height(42);
        mgr.update_peers(3, vec!["peer1".into(), "peer2".into(), "peer3".into()]);
        mgr.update_producing(true);
        mgr.update_quantum(0.95, 0.05);
        mgr.update_uptime(3600);

        let h = mgr.health();
        assert_eq!(h.status, HEALTH_OK);
        assert!(h.reason.is_none());
        assert_eq!(h.height, 42);
        assert_eq!(h.peers, 3);
        assert!(h.producing);
        assert!((h.coherence - 0.949).abs() < 0.001); // decoherence applied
        assert_eq!(h.uptime_seconds, 3600);
        assert!(h.is_healthy());
    }

    #[test]
    fn test_health_manager_low_coherence() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();
        mgr.update_height(10);
        mgr.update_peers(2, vec![]);
        mgr.update_producing(true);
        mgr.update_quantum(0.8, 0.2);

        let h = mgr.health();
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason, Some(REASON_DECOHERENCE.to_string()));
        assert!(!h.is_healthy());
        assert!(h.is_degraded());
    }

    #[test]
    fn test_health_manager_no_peers() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();
        mgr.update_height(10);
        mgr.update_peers(0, vec![]);
        mgr.update_producing(true);
        mgr.update_quantum(0.95, 0.05);

        let h = mgr.health();
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason, Some(REASON_NO_PEERS.to_string()));
    }

    #[test]
    fn test_health_manager_not_producing() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();
        mgr.update_height(10);
        mgr.update_peers(3, vec![]);
        mgr.update_producing(false);
        mgr.update_quantum(0.95, 0.05);

        let h = mgr.health();
        assert_eq!(h.status, HEALTH_DEGRADED);
        assert_eq!(h.reason, Some(REASON_NO_QUORUM.to_string()));
    }

    #[test]
    fn test_status_response() {
        let config = test_config();
        let mgr = HealthManager::new(config).unwrap();
        mgr.update_height(100);
        mgr.update_peers(5, vec!["a".into(), "b".into()]);
        mgr.update_producing(true);
        mgr.update_quantum(0.97, 0.03);
        mgr.update_uptime(7200);
        mgr.update_identifiers(1, 6126151);
        mgr.update_consensus(0, "Propose");
        mgr.update_validator_status(true);

        let status = mgr.status();
        assert_eq!(status.height, 100);
        assert_eq!(status.peers, 5);
        assert_eq!(status.peer_ids.len(), 2);
        assert!(status.is_producing);
        assert!(status.is_validator);
        assert!((status.coherence - 0.969).abs() < 0.001);
        assert_eq!(status.uptime_seconds, 7200);
        assert_eq!(status.protocol_version, 1);
        assert_eq!(status.chain_id, 6126151);
        assert_eq!(status.step, "Propose");
        assert_eq!(status.node_version, NODE_VERSION);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let config = test_config();

        // Create manager and record some stats.
        let mgr = HealthManager::with_persistence(path, config.clone()).unwrap();
        mgr.update_height(1);
        mgr.update_peers(2, vec![]);
        mgr.update_producing(true);
        mgr.update_quantum(0.99, 0.01);
        mgr.health(); // triggers a measurement
        mgr.flush_stats().unwrap();

        // Create a new manager that loads the stats.
        let mgr2 = HealthManager::with_persistence(path, config).unwrap();
        let stats = mgr2.stats();
        assert!(stats.health_checks >= 1);
        assert_eq!(stats.last_status, HEALTH_OK);
        assert!((stats.avg_coherence - 0.989).abs() < 0.001);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = HealthConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.min_coherence_ok = 1.5;
        assert!(cfg.validate().is_err());

        cfg.min_coherence_ok = 0.9;
        cfg.min_coherence_degraded = 0.95;
        assert!(cfg.validate().is_err());

        cfg.min_coherence_degraded = 0.5;
        cfg.decoherence_rate = 1.5;
        assert!(cfg.validate().is_err());

        cfg.decoherence_rate = 0.001;
        cfg.stats_window_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_health_response_validation() {
        let h = HealthResponse {
            status: HEALTH_OK.to_string(),
            reason: None,
            height: 0,
            peers: 0,
            producing: false,
            version: NODE_VERSION.to_string(),
            coherence: 1.0,
            timestamp: 0,
            uptime_seconds: 0,
        };
        assert!(h.validate().is_ok());

        let bad = HealthResponse {
            status: "unknown".to_string(),
            ..h
        };
        assert!(bad.validate().is_err());
    }

    #[test]
    fn test_stats_record() {
        let mut stats = HealthStats::default();
        stats.record(HEALTH_OK, None, 0.99, 5);
        assert_eq!(stats.health_checks, 1);
        assert_eq!(stats.ok_count, 1);
        assert_eq!(stats.degraded_count, 0);
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.last_status, HEALTH_OK);
        assert!((stats.avg_coherence - 0.99).abs() < 1e-10);
        assert!((stats.avg_peers - 5.0).abs() < 1e-10);

        stats.record(HEALTH_DEGRADED, Some(REASON_NO_PEERS), 0.8, 2);
        assert_eq!(stats.health_checks, 2);
        assert_eq!(stats.ok_count, 1);
        assert_eq!(stats.degraded_count, 1);
        assert_eq!(stats.error_count, 0);
        assert_eq!(stats.last_status, HEALTH_DEGRADED);
        assert!((stats.avg_coherence - 0.895).abs() < 1e-10);
        assert!((stats.avg_peers - 3.5).abs() < 1e-10);
    }

    #[test]
    fn test_validator_info_default_coherence() {
        let v = ValidatorInfo {
            pubkey_short: "test".into(),
            power: 10,
            connected: true,
            coherence: 0.97,
        };
        assert!((v.coherence - 0.97).abs() < 1e-10);
    }

    #[test]
    fn test_health_response_is_healthy() {
        let h = HealthResponse {
            status: HEALTH_OK.to_string(),
            reason: None,
            height: 100,
            peers: 5,
            producing: true,
            version: NODE_VERSION.to_string(),
            coherence: 0.95,
            timestamp: 0,
            uptime_seconds: 0,
        };
        assert!(h.is_healthy());

        let degraded = HealthResponse {
            status: HEALTH_DEGRADED.to_string(),
            reason: Some(REASON_NO_PEERS.to_string()),
            ..h.clone()
        };
        assert!(!degraded.is_healthy());
        assert!(degraded.is_degraded());

        let error = HealthResponse {
            status: HEALTH_ERROR.to_string(),
            coherence: 0.3,
            ..h.clone()
        };
        assert!(error.is_error());
        assert!(!error.is_degraded());
    }
}
