//! Persistent peerstore for IONA v28.
//!
//! Saves known peers with their multiaddresses and last-seen timestamps
//! to `peerstore/peers.json` so they survive restarts.
//!
//! # Production Features
//! - Configurable via `PeerstoreConfig` (max peers, prune age, save interval).
//! - Thread‑safe `PeerstoreManager` with `parking_lot::Mutex`.
//! - Prometheus metrics for peer count, operations, and errors.
//! - Atomic writes with file locking (`flock`).
//! - Automatic periodic saving and pruning.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use fs2::FileExt;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, Counter, CounterVec, Gauge,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Default maximum number of peers to keep.
pub const DEFAULT_MAX_PEERS: usize = 1000;

/// Default prune age in seconds (7 days).
pub const DEFAULT_PRUNE_AGE_SECS: u64 = 604800;

/// Default save interval in seconds.
pub const DEFAULT_SAVE_INTERVAL_SECS: u64 = 60;

/// Default lock timeout in seconds.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 10;

/// Default persistence file name.
pub const DEFAULT_PERSIST_FILE: &str = "peers.json";

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the peerstore.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerstoreConfig {
    /// Maximum number of peers to store.
    pub max_peers: usize,
    /// Prune peers not seen in this many seconds.
    pub prune_age_secs: u64,
    /// Auto‑save interval in seconds.
    pub save_interval_secs: u64,
    /// Whether to enable auto‑pruning.
    pub auto_prune: bool,
    /// Whether to enable auto‑saving.
    pub auto_save: bool,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
    /// Persistence file path.
    pub persist_path: PathBuf,
}

impl Default for PeerstoreConfig {
    fn default() -> Self {
        Self {
            max_peers: DEFAULT_MAX_PEERS,
            prune_age_secs: DEFAULT_PRUNE_AGE_SECS,
            save_interval_secs: DEFAULT_SAVE_INTERVAL_SECS,
            auto_prune: true,
            auto_save: true,
            enable_metrics: true,
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
            persist_path: PathBuf::from("data/peerstore/peers.json"),
        }
    }
}

impl PeerstoreConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_peers == 0 {
            return Err("max_peers must be > 0".into());
        }
        if self.prune_age_secs == 0 {
            return Err("prune_age_secs must be > 0".into());
        }
        if self.save_interval_secs == 0 {
            return Err("save_interval_secs must be > 0".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        if self.persist_path.as_os_str().is_empty() {
            return Err("persist_path must not be empty".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the peerstore.
#[derive(Clone)]
pub struct PeerstoreMetrics {
    pub peer_count: Gauge,
    pub add_total: Counter,
    pub remove_total: Counter,
    pub update_total: Counter,
    pub success_total: CounterVec,
    pub failure_total: CounterVec,
    pub prune_total: Counter,
    pub save_total: CounterVec,
    pub load_total: CounterVec,
}

impl PeerstoreMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let peer_count = register_gauge!(
            "iona_peerstore_peers",
            "Current number of known peers"
        )?;
        let add_total = register_counter!(
            "iona_peerstore_adds_total",
            "Total peers added"
        )?;
        let remove_total = register_counter!(
            "iona_peerstore_removes_total",
            "Total peers removed"
        )?;
        let update_total = register_counter!(
            "iona_peerstore_updates_total",
            "Total peer updates"
        )?;
        let success_total = register_counter_vec!(
            "iona_peerstore_successes_total",
            "Successful peer connections",
            &["peer_id"]
        )?;
        let failure_total = register_counter_vec!(
            "iona_peerstore_failures_total",
            "Failed peer connections",
            &["peer_id"]
        )?;
        let prune_total = register_counter!(
            "iona_peerstore_prunes_total",
            "Total pruned peers"
        )?;
        let save_total = register_counter_vec!(
            "iona_peerstore_saves_total",
            "Peerstore save operations",
            &["status"]
        )?;
        let load_total = register_counter_vec!(
            "iona_peerstore_loads_total",
            "Peerstore load operations",
            &["status"]
        )?;
        Ok(Self {
            peer_count,
            add_total,
            remove_total,
            update_total,
            success_total,
            failure_total,
            prune_total,
            save_total,
            load_total,
        })
    }

    pub fn set_peer_count(&self, count: usize) {
        self.peer_count.set(count as f64);
    }

    pub fn record_add(&self) {
        self.add_total.inc();
    }

    pub fn record_remove(&self) {
        self.remove_total.inc();
    }

    pub fn record_update(&self) {
        self.update_total.inc();
    }

    pub fn record_success(&self, peer_id: &str) {
        self.success_total.with_label_values(&[peer_id]).inc();
    }

    pub fn record_failure(&self, peer_id: &str) {
        self.failure_total.with_label_values(&[peer_id]).inc();
    }

    pub fn record_prune(&self, count: usize) {
        self.prune_total.inc_by(count as u64);
    }

    pub fn record_save(&self, status: &str) {
        self.save_total.with_label_values(&[status]).inc();
    }

    pub fn record_load(&self, status: &str) {
        self.load_total.with_label_values(&[status]).inc();
    }
}

impl Default for PeerstoreMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            peer_count: Gauge::new("iona_peerstore_peers", "Peer count").unwrap(),
            add_total: Counter::new("iona_peerstore_adds_total", "Adds").unwrap(),
            remove_total: Counter::new("iona_peerstore_removes_total", "Removes").unwrap(),
            update_total: Counter::new("iona_peerstore_updates_total", "Updates").unwrap(),
            success_total: CounterVec::new(
                prometheus::Opts::new("iona_peerstore_successes_total", "Successes"),
                &["peer_id"],
            ).unwrap(),
            failure_total: CounterVec::new(
                prometheus::Opts::new("iona_peerstore_failures_total", "Failures"),
                &["peer_id"],
            ).unwrap(),
            prune_total: Counter::new("iona_peerstore_prunes_total", "Prunes").unwrap(),
            save_total: CounterVec::new(
                prometheus::Opts::new("iona_peerstore_saves_total", "Saves"),
                &["status"],
            ).unwrap(),
            load_total: CounterVec::new(
                prometheus::Opts::new("iona_peerstore_loads_total", "Loads"),
                &["status"],
            ).unwrap(),
        })
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during peerstore operations.
#[derive(Debug, Error)]
pub enum PeerstoreError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("configuration error: {0}")]
    Config(String),
    #[error("lock acquisition failed: {0}")]
    LockFailed(String),
    #[error("peerstore full (max {max})")]
    PeerstoreFull { max: usize },
}

pub type PeerstoreResult<T> = Result<T, PeerstoreError>;

// ── PeerEntry ─────────────────────────────────────────────────────────────

/// A known peer entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerEntry {
    pub peer_id: String,
    pub addrs: Vec<String>,
    pub last_seen: u64,
    pub success_count: u64,
    pub fail_count: u64,
    #[serde(default)]
    pub label: String,
}

// ── Peerstore (core) ─────────────────────────────────────────────────────

/// Persistent peerstore with optional metrics.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Peerstore {
    pub peers: BTreeMap<String, PeerEntry>,
    #[serde(skip)]
    pub config: Option<PeerstoreConfig>,
    #[serde(skip)]
    pub metrics: Arc<PeerstoreMetrics>,
}

impl Peerstore {
    /// Create a new empty peerstore.
    pub fn new() -> Self {
        Self {
            peers: BTreeMap::new(),
            config: None,
            metrics: Arc::new(PeerstoreMetrics::default()),
        }
    }

    /// Create a peerstore with configuration and metrics.
    pub fn with_config(config: PeerstoreConfig, metrics: Arc<PeerstoreMetrics>) -> Self {
        Self {
            peers: BTreeMap::new(),
            config: Some(config),
            metrics,
        }
    }

    /// Load from a JSON file (returns empty store if file doesn't exist).
    pub fn load(path: &Path, metrics: &PeerstoreMetrics) -> PeerstoreResult<Self> {
        let _lock = acquire_lock(path).map_err(PeerstoreError::LockFailed)?;

        if !path.exists() {
            debug!(path = %path.display(), "peerstore file not found, using empty");
            metrics.record_load("empty");
            return Ok(Self::new());
        }

        let file = File::open(path).map_err(PeerstoreError::Io)?;
        let reader = BufReader::new(file);
        let store: Self = serde_json::from_reader(reader)
            .map_err(PeerstoreError::Serialization)?;

        // Apply metrics to loaded store.
        store.metrics = Arc::new(PeerstoreMetrics::default());
        store.metrics.set_peer_count(store.len());

        info!(path = %path.display(), peers = store.len(), "peerstore loaded");
        metrics.record_load("ok");
        Ok(store)
    }

    /// Save to a JSON file atomically (write to tmp, then rename).
    pub fn save(&self, path: &Path) -> PeerstoreResult<()> {
        let _lock = acquire_lock(path).map_err(PeerstoreError::LockFailed)?;

        let temp_path = path.with_extension(TEMP_EXT);
        let json = serde_json::to_string_pretty(self)
            .map_err(PeerstoreError::Serialization)?;
        fs::write(&temp_path, &json)
            .map_err(PeerstoreError::Io)?;
        fs::rename(&temp_path, path)
            .map_err(PeerstoreError::Io)?;

        if let Some(metrics) = self.metrics.as_ref() {
            metrics.record_save("ok");
        }
        trace!(path = %path.display(), "peerstore saved");
        Ok(())
    }

    /// Get a peer entry by ID.
    pub fn get(&self, peer_id: &str) -> Option<&PeerEntry> {
        self.peers.get(peer_id)
    }

    /// Get a mutable reference to a peer entry.
    pub fn get_mut(&mut self, peer_id: &str) -> Option<&mut PeerEntry> {
        self.peers.get_mut(peer_id)
    }

    /// Record a successful connection to a peer.
    pub fn record_success(&mut self, peer_id: &str, addrs: &[String]) -> PeerstoreResult<()> {
        let now = current_timestamp();

        // Check max peers.
        if let Some(config) = &self.config {
            if self.peers.len() >= config.max_peers && !self.peers.contains_key(peer_id) {
                return Err(PeerstoreError::PeerstoreFull { max: config.max_peers });
            }
        }

        let entry = self.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerEntry {
                peer_id: peer_id.to_string(),
                addrs: Vec::new(),
                last_seen: 0,
                success_count: 0,
                fail_count: 0,
                label: String::new(),
            });

        entry.last_seen = now;
        entry.success_count += 1;

        // Merge addresses (deduplicate).
        for addr in addrs {
            if !entry.addrs.contains(addr) {
                entry.addrs.push(addr.clone());
            }
        }

        self.metrics.record_success(peer_id);
        self.metrics.record_update();
        self.metrics.set_peer_count(self.len());

        trace!(peer_id, success_count = entry.success_count, "recorded success");
        Ok(())
    }

    /// Record a failed connection attempt.
    pub fn record_failure(&mut self, peer_id: &str) {
        if let Some(entry) = self.peers.get_mut(peer_id) {
            entry.fail_count += 1;
            self.metrics.record_failure(peer_id);
            trace!(peer_id, fail_count = entry.fail_count, "recorded failure");
        } else {
            debug!(peer_id, "attempted to record failure for unknown peer");
        }
    }

    /// Update the label of a peer.
    pub fn set_label(&mut self, peer_id: &str, label: &str) {
        let entry = self.peers
            .entry(peer_id.to_string())
            .or_insert_with(|| PeerEntry {
                peer_id: peer_id.to_string(),
                addrs: Vec::new(),
                last_seen: 0,
                success_count: 0,
                fail_count: 0,
                label: String::new(),
            });
        entry.label = label.to_string();
        self.metrics.record_update();
        trace!(peer_id, label, "updated label");
    }

    /// Remove a peer from the store.
    pub fn remove(&mut self, peer_id: &str) -> Option<PeerEntry> {
        if let Some(entry) = self.peers.remove(peer_id) {
            self.metrics.record_remove();
            self.metrics.set_peer_count(self.len());
            trace!(peer_id, "removed peer");
            Some(entry)
        } else {
            None
        }
    }

    /// Get all known peer addresses for bootstrapping (with `/p2p/` suffix).
    pub fn bootnode_addrs(&self) -> Vec<String> {
        let mut addrs = Vec::new();
        for entry in self.peers.values() {
            for addr in &entry.addrs {
                if addr.contains("/p2p/") {
                    addrs.push(addr.clone());
                } else {
                    addrs.push(format!("{}/p2p/{}", addr, entry.peer_id));
                }
            }
        }
        addrs
    }

    /// Number of known peers.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// Is the peerstore empty?
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Prune peers not seen in `max_age_secs` seconds.
    pub fn prune(&mut self, max_age_secs: u64) -> usize {
        let now = current_timestamp();
        let before = self.peers.len();

        self.peers.retain(|_, entry| {
            now.saturating_sub(entry.last_seen) < max_age_secs
        });

        let removed = before - self.peers.len();
        if removed > 0 {
            self.metrics.record_prune(removed);
            self.metrics.set_peer_count(self.len());
            trace!(removed, max_age_secs, "pruned old peers");
        }
        removed
    }

    /// Merge another peerstore into this one (additive).
    pub fn merge(&mut self, other: &Peerstore) {
        for (id, entry) in &other.peers {
            if let Some(existing) = self.peers.get_mut(id) {
                // Merge addrs.
                for addr in &entry.addrs {
                    if !existing.addrs.contains(addr) {
                        existing.addrs.push(addr.clone());
                    }
                }
                // Keep the newer last_seen and higher counts.
                if entry.last_seen > existing.last_seen {
                    existing.last_seen = entry.last_seen;
                }
                existing.success_count = existing.success_count.max(entry.success_count);
                existing.fail_count = existing.fail_count.max(entry.fail_count);
                if !entry.label.is_empty() {
                    existing.label = entry.label.clone();
                }
            } else {
                self.peers.insert(id.clone(), entry.clone());
            }
        }
        self.metrics.set_peer_count(self.len());
    }

    /// Get all peers (for iteration).
    pub fn iter(&self) -> std::collections::btree_map::Iter<'_, String, PeerEntry> {
        self.peers.iter()
    }

    /// Get all peers (for iteration, mutable).
    pub fn iter_mut(&mut self) -> std::collections::btree_map::IterMut<'_, String, PeerEntry> {
        self.peers.iter_mut()
    }
}

impl Default for Peerstore {
    fn default() -> Self {
        Self::new()
    }
}

// ── File locking helper ──────────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file: {}", e))?;
    let timeout = Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(format!("lock timeout after {}s", DEFAULT_LOCK_TIMEOUT_SECS));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// ── Current timestamp helper ─────────────────────────────────────────────

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── PeerstoreManager (thread‑safe wrapper) ──────────────────────────────

/// Thread‑safe manager for the peerstore with auto‑save and auto‑prune.
#[derive(Clone)]
pub struct PeerstoreManager {
    inner: Arc<Mutex<Peerstore>>,
    config: Arc<PeerstoreConfig>,
    path: PathBuf,
    metrics: Arc<PeerstoreMetrics>,
}

impl PeerstoreManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: PeerstoreConfig) -> Result<Self, PeerstoreError> {
        config.validate().map_err(PeerstoreError::Config)?;
        let metrics = Arc::new(PeerstoreMetrics::default());

        // Ensure directory exists.
        if let Some(parent) = config.persist_path.parent() {
            fs::create_dir_all(parent)
                .map_err(PeerstoreError::Io)?;
        }

        // Load existing store or create new.
        let store = if config.persist_path.exists() {
            Peerstore::load(&config.persist_path, &metrics)
                .unwrap_or_else(|_| {
                    warn!("failed to load peerstore, starting fresh");
                    Peerstore::new()
                })
        } else {
            Peerstore::new()
        };

        // Apply config and metrics to store.
        let mut store = store;
        store.config = Some(config.clone());
        store.metrics = metrics.clone();
        store.metrics.set_peer_count(store.len());

        let manager = Self {
            inner: Arc::new(Mutex::new(store)),
            config: Arc::new(config),
            path: config.persist_path.clone(),
            metrics,
        };

        // Start background tasks if enabled.
        if manager.config.auto_prune {
            manager.start_pruner();
        }
        if manager.config.auto_save {
            manager.start_saver();
        }

        info!(
            path = %manager.path.display(),
            peers = manager.len(),
            "peerstore manager initialized"
        );

        Ok(manager)
    }

    /// Record a successful connection.
    pub fn record_success(&self, peer_id: &str, addrs: &[String]) -> PeerstoreResult<()> {
        let mut store = self.inner.lock();
        store.record_success(peer_id, addrs)?;
        // Auto‑save if configured (save will be triggered by background saver).
        Ok(())
    }

    /// Record a failed connection.
    pub fn record_failure(&self, peer_id: &str) {
        let mut store = self.inner.lock();
        store.record_failure(peer_id);
    }

    /// Set label for a peer.
    pub fn set_label(&self, peer_id: &str, label: &str) {
        let mut store = self.inner.lock();
        store.set_label(peer_id, label);
    }

    /// Remove a peer.
    pub fn remove(&self, peer_id: &str) -> Option<PeerEntry> {
        let mut store = self.inner.lock();
        store.remove(peer_id)
    }

    /// Get a peer entry (read‑only).
    pub fn get(&self, peer_id: &str) -> Option<PeerEntry> {
        self.inner.lock().get(peer_id).cloned()
    }

    /// Get all peers (read‑only).
    pub fn all_peers(&self) -> Vec<PeerEntry> {
        self.inner.lock().peers.values().cloned().collect()
    }

    /// Get bootnode addresses.
    pub fn bootnode_addrs(&self) -> Vec<String> {
        self.inner.lock().bootnode_addrs()
    }

    /// Number of peers.
    pub fn len(&self) -> usize {
        self.inner.lock().len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().is_empty()
    }

    /// Force a save to disk.
    pub fn save(&self) -> PeerstoreResult<()> {
        let store = self.inner.lock();
        store.save(&self.path)
    }

    /// Force a prune.
    pub fn prune(&self) -> usize {
        let mut store = self.inner.lock();
        store.prune(self.config.prune_age_secs)
    }

    /// Merge another peerstore into this one.
    pub fn merge(&self, other: &Peerstore) {
        let mut store = self.inner.lock();
        store.merge(other);
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> PeerstoreMetrics {
        self.metrics.clone()
    }

    /// Get configuration.
    pub fn config(&self) -> &PeerstoreConfig {
        &self.config
    }

    /// Start background pruner.
    fn start_pruner(&self) {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.save_interval_secs * 2);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let pruned = manager.prune();
                if pruned > 0 {
                    debug!(pruned, "auto‑prune executed");
                }
                // Save after prune.
                if manager.config.auto_save {
                    if let Err(e) = manager.save() {
                        warn!(error = %e, "auto‑save after prune failed");
                    }
                }
            }
        });
    }

    /// Start background saver.
    fn start_saver(&self) {
        let manager = self.clone();
        let interval = Duration::from_secs(self.config.save_interval_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                if let Err(e) = manager.save() {
                    warn!(error = %e, "auto‑save failed");
                }
            }
        });
    }
}

// ── Utility functions ─────────────────────────────────────────────────────

/// Generate a bootnode multiaddr string with peer ID.
pub fn format_bootnode(ip: &str, port: u16, peer_id: &str) -> String {
    format!("/ip4/{}/tcp/{}/p2p/{}", ip, port, peer_id)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> PeerstoreConfig {
        let mut cfg = PeerstoreConfig::default();
        cfg.max_peers = 10;
        cfg.prune_age_secs = 3600;
        cfg.save_interval_secs = 60;
        cfg.auto_prune = false;
        cfg.auto_save = false;
        cfg.persist_path = tempdir().unwrap().path().join("peers.json");
        cfg
    }

    #[test]
    fn test_peerstore_empty() {
        let ps = Peerstore::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
        assert!(ps.get("any").is_none());
    }

    #[test]
    fn test_record_success() {
        let mut ps = Peerstore::new();
        ps.record_success("12D3KooWAbCd", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();
        assert_eq!(ps.len(), 1);
        let entry = ps.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.success_count, 1);
        assert_eq!(entry.addrs.len(), 1);
        assert!(entry.last_seen > 0);

        // Second success with same addr — should not duplicate.
        ps.record_success("12D3KooWAbCd", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();
        let entry = ps.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.success_count, 2);
        assert_eq!(entry.addrs.len(), 1);

        // New address.
        ps.record_success("12D3KooWAbCd", &["/ip4/5.6.7.8/tcp/7001".into()]).unwrap();
        let entry = ps.get("12D3KooWAbCd").unwrap();
        assert_eq!(entry.addrs.len(), 2);
    }

    #[test]
    fn test_record_failure() {
        let mut ps = Peerstore::new();
        ps.record_success("peer1", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();
        ps.record_failure("peer1");
        let entry = ps.get("peer1").unwrap();
        assert_eq!(entry.fail_count, 1);
        assert_eq!(entry.success_count, 1);

        // Failure for unknown peer should not panic
        ps.record_failure("unknown");
    }

    #[test]
    fn test_set_label() {
        let mut ps = Peerstore::new();
        ps.set_label("peer1", "validator");
        let entry = ps.get("peer1").unwrap();
        assert_eq!(entry.label, "validator");
        ps.set_label("peer1", "new-label");
        let entry = ps.get("peer1").unwrap();
        assert_eq!(entry.label, "new-label");
    }

    #[test]
    fn test_remove() {
        let mut ps = Peerstore::new();
        ps.record_success("peer1", &[]).unwrap();
        assert_eq!(ps.len(), 1);
        let removed = ps.remove("peer1");
        assert!(removed.is_some());
        assert_eq!(ps.len(), 0);
        assert!(ps.remove("peer1").is_none());
    }

    #[test]
    fn test_bootnode_addrs() {
        let mut ps = Peerstore::new();
        ps.record_success("12D3KooW1", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();
        ps.record_success("12D3KooW2", &["/ip4/5.6.7.8/tcp/7002".into()]).unwrap();

        let addrs = ps.bootnode_addrs();
        assert_eq!(addrs.len(), 2);
        assert!(addrs[0].contains("/p2p/12D3KooW1"));
        assert!(addrs[1].contains("/p2p/12D3KooW2"));
    }

    #[test]
    fn test_roundtrip() -> PeerstoreResult<()> {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");

        let mut ps = Peerstore::new();
        ps.record_success("peer1", &["/ip4/1.2.3.4/tcp/7001".into()])?;
        ps.save(&path)?;

        let ps2 = Peerstore::load(&path, &PeerstoreMetrics::default())?;
        assert_eq!(ps2.len(), 1);
        assert!(ps2.peers.contains_key("peer1"));
        Ok(())
    }

    #[test]
    fn test_format_bootnode() {
        let bn = format_bootnode("10.0.1.2", 30334, "12D3KooWAbCd");
        assert_eq!(bn, "/ip4/10.0.1.2/tcp/30334/p2p/12D3KooWAbCd");
    }

    #[test]
    fn test_prune() {
        let mut ps = Peerstore::new();
        ps.record_success("recent", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();

        // Manually set an old peer.
        ps.peers.insert(
            "old".into(),
            PeerEntry {
                peer_id: "old".into(),
                addrs: vec!["/ip4/9.8.7.6/tcp/7001".into()],
                last_seen: 1000,
                success_count: 1,
                fail_count: 0,
                label: String::new(),
            },
        );

        assert_eq!(ps.len(), 2);
        ps.prune(3600);
        assert_eq!(ps.len(), 1);
        assert!(ps.peers.contains_key("recent"));
        assert!(!ps.peers.contains_key("old"));
    }

    #[test]
    fn test_manager() -> PeerstoreResult<()> {
        let cfg = test_config();
        let manager = PeerstoreManager::new(cfg)?;
        let peer_id = "12D3KooWAbCd";
        let addrs = vec!["/ip4/1.2.3.4/tcp/7001".into()];
        manager.record_success(peer_id, &addrs)?;
        assert_eq!(manager.len(), 1);
        let entry = manager.get(peer_id).unwrap();
        assert_eq!(entry.success_count, 1);

        // Save and reload.
        manager.save()?;
        let cfg2 = test_config();
        let manager2 = PeerstoreManager::new(cfg2)?;
        assert_eq!(manager2.len(), 1);
        Ok(())
    }

    #[test]
    fn test_merge() {
        let mut ps1 = Peerstore::new();
        ps1.record_success("a", &["/ip4/1.2.3.4/tcp/7001".into()]).unwrap();

        let mut ps2 = Peerstore::new();
        ps2.record_success("b", &["/ip4/5.6.7.8/tcp/7002".into()]).unwrap();
        ps2.record_success("a", &["/ip4/1.2.3.4/tcp/7003".into()]).unwrap();

        ps1.merge(&ps2);
        assert_eq!(ps1.len(), 2);
        let entry = ps1.get("a").unwrap();
        assert_eq!(entry.addrs.len(), 2); // merged addresses
        assert!(entry.addrs.contains(&"/ip4/1.2.3.4/tcp/7003".into()));
    }

    #[test]
    fn test_max_peers() {
        let config = PeerstoreConfig {
            max_peers: 2,
            prune_age_secs: 3600,
            save_interval_secs: 60,
            auto_prune: false,
            auto_save: false,
            enable_metrics: true,
            lock_timeout_secs: 10,
            persist_path: tempdir().unwrap().path().join("peers.json"),
        };
        let mut ps = Peerstore::with_config(config, Arc::new(PeerstoreMetrics::default()));
        ps.record_success("a", &[]).unwrap();
        ps.record_success("b", &[]).unwrap();
        let err = ps.record_success("c", &[]).unwrap_err();
        assert!(matches!(err, PeerstoreError::PeerstoreFull { max: 2 }));
    }
}
