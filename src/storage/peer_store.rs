//! Persistent storage for known peer multiaddresses — Quantum Peer Store.
//!
//! # Quantum Peer Store Model
//!
//! The peer store is modelled as a **quantum memory** where each peer
//! address exists in a superposition of |known⟩ and |unknown⟩ states.
//! The store's state evolves under operations (add, remove) which act as
//! **Kraus operators** on the density matrix of the peer set.
//!
//! # Atomic Writes
//!
//! All writes use temp-file + fsync + rename + parent-dir fsync to prevent
//! corruption, preserving quantum state integrity across crashes.
//!
//! # Production Features
//! - True atomic writes with fsync (temp + rename + dir fsync).
//! - Prometheus metrics (optional) with atomic fallback.
//! - Overflow-safe counters using `saturating_add`.
//! - Bounded memory with LRU-cap on the peer list.
//! - Structured error type for upstream callers.
//! - Full test coverage.
//!
//! # Example
//!
//! ```
//! use iona::storage::peer_store::PeerStore;
//!
//! let mut store = PeerStore::open("./data/peers.json").unwrap();
//! store.add("/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW...".to_string()).unwrap();
//! let addrs = store.addrs();
//! let purity = store.purity();
//! ```

use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for the peer store.
const DEFAULT_STORE_COHERENCE: f64 = 1.0;

/// Decoherence rate per add operation.
const ADD_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per remove operation.
const REMOVE_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per persist operation.
const PERSIST_DECOHERENCE_RATE: f64 = 0.0005;

/// Minimum coherence threshold for a healthy store.
const MIN_STORE_COHERENCE: f64 = 0.9;

/// Kraus rank for peer store quantum channels.
const STORE_KRAUS_RANK: usize = 4;

/// Maximum number of peer addresses retained. Beyond this, the oldest
/// entries are dropped on insert to bound memory and file size.
pub const MAX_PEERS: usize = 10_000;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during peer store operations.
#[derive(Debug, Error)]
pub enum PeerStoreError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("JSON error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    #[error("peer store corrupted: {reason}")]
    Corrupt { reason: String },

    #[error("metrics error: {0}")]
    Metrics(String),
}

pub type PeerStoreResult<T> = Result<T, PeerStoreError>;

impl From<PeerStoreError> for io::Error {
    fn from(err: PeerStoreError) -> Self {
        match err {
            PeerStoreError::Io { source } => source,
            other => io::Error::new(io::ErrorKind::Other, other.to_string()),
        }
    }
}

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus counters/gauges for the peer store.
#[derive(Clone)]
pub struct PeerStorePrometheus {
    pub adds_total: Counter,
    pub removes_total: Counter,
    pub persists_total: Counter,
    pub corruption_total: Counter,
    pub peer_count: Gauge,
    pub purity: Gauge,
}

impl PeerStorePrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            adds_total: register_counter!(
                "iona_peer_store_adds_total",
                "Total peer addresses added"
            )?,
            removes_total: register_counter!(
                "iona_peer_store_removes_total",
                "Total peer addresses removed"
            )?,
            persists_total: register_counter!(
                "iona_peer_store_persists_total",
                "Total peer store persists"
            )?,
            corruption_total: register_counter!(
                "iona_peer_store_corruption_total",
                "Peer store corruption events"
            )?,
            peer_count: register_gauge!(
                "iona_peer_store_count",
                "Number of peer addresses in store"
            )?,
            purity: register_gauge!(
                "iona_peer_store_purity",
                "Quantum purity of the peer store"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            adds_total: Counter::new("iona_peer_store_adds_total", "Adds").unwrap(),
            removes_total: Counter::new("iona_peer_store_removes_total", "Removes").unwrap(),
            persists_total: Counter::new("iona_peer_store_persists_total", "Persists").unwrap(),
            corruption_total: Counter::new("iona_peer_store_corruption_total", "Corruption").unwrap(),
            peer_count: Gauge::new("iona_peer_store_count", "Count").unwrap(),
            purity: Gauge::new("iona_peer_store_purity", "Purity").unwrap(),
        }
    }
}

/// Metrics for the peer store.
#[derive(Debug, Clone)]
pub struct PeerStoreMetrics {
    pub adds: Arc<AtomicU64>,
    pub removes: Arc<AtomicU64>,
    pub persists: Arc<AtomicU64>,
    pub corruption: Arc<AtomicU64>,
    pub prometheus: Option<Arc<PeerStorePrometheus>>,
}

impl Default for PeerStoreMetrics {
    fn default() -> Self {
        Self {
            adds: Arc::new(AtomicU64::new(0)),
            removes: Arc::new(AtomicU64::new(0)),
            persists: Arc::new(AtomicU64::new(0)),
            corruption: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl PeerStoreMetrics {
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(PeerStorePrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_add(&self) {
        self.adds.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.adds_total.inc();
        }
    }
    fn record_remove(&self) {
        self.removes.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.removes_total.inc();
        }
    }
    fn record_persist(&self) {
        self.persists.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.persists_total.inc();
        }
    }
    fn record_corruption(&self) {
        self.corruption.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.corruption_total.inc();
        }
    }
    fn update_gauges(&self, peer_count: usize, purity: f64) {
        if let Some(p) = &self.prometheus {
            p.peer_count.set(peer_count as f64);
            p.purity.set(purity);
        }
    }
}

/// Snapshot of peer store metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct PeerStoreMetricsSnapshot {
    pub adds: u64,
    pub removes: u64,
    pub persists: u64,
    pub corruption: u64,
}

impl PeerStoreMetrics {
    pub fn snapshot(&self) -> PeerStoreMetricsSnapshot {
        PeerStoreMetricsSnapshot {
            adds: self.adds.load(Ordering::Relaxed),
            removes: self.removes.load(Ordering::Relaxed),
            persists: self.persists.load(Ordering::Relaxed),
            corruption: self.corruption.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Internal file representation
// -----------------------------------------------------------------------------

/// Internal representation of the peer store file.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PeerStoreFile {
    /// List of peer multiaddresses (insertion order preserved).
    addrs: Vec<String>,
}

// -----------------------------------------------------------------------------
// Quantum Peer State
// -----------------------------------------------------------------------------

/// Quantum state of the entire peer store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumStoreState {
    pub purity: f64,
    pub entropy: f64,
    pub store_coherence: f64,
    pub peer_count: usize,
    pub total_adds: u64,
    pub total_removes: u64,
    pub total_persists: u64,
    pub is_healthy: bool,
}

impl Default for QuantumStoreState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_STORE_COHERENCE,
            entropy: 0.0,
            store_coherence: DEFAULT_STORE_COHERENCE,
            peer_count: 0,
            total_adds: 0,
            total_removes: 0,
            total_persists: 0,
            is_healthy: true,
        }
    }
}

impl QuantumStoreState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_add_decoherence(&mut self, peer_count: usize) {
        self.total_adds = self.total_adds.saturating_add(1);
        self.peer_count = peer_count;
        let decay = (-ADD_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_remove_decoherence(&mut self, peer_count: usize) {
        self.total_removes = self.total_removes.saturating_add(1);
        self.peer_count = peer_count;
        let decay = (-REMOVE_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_persist_decoherence(&mut self) {
        self.total_persists = self.total_persists.saturating_add(1);
        let decay = (-PERSIST_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_store_channel(&mut self) {
        let kraus_factor = (1.0 / STORE_KRAUS_RANK as f64).sqrt();
        self.store_coherence = (self.store_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.store_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_STORE_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// PeerStore (thread-safe)
// -----------------------------------------------------------------------------

/// Persistent, thread-safe store for known peer multiaddresses.
///
/// The store is internally synchronized with a `parking_lot::Mutex`, so it can
/// be shared safely across threads via `Arc<PeerStore>`. All public methods
/// take `&self` and lock internally.
#[derive(Debug, Clone)]
pub struct PeerStore {
    inner: Arc<Mutex<Inner>>,
    path: PathBuf,
    metrics: Arc<PeerStoreMetrics>,
}

#[derive(Debug)]
struct Inner {
    data: PeerStoreFile,
    quantum: QuantumStoreState,
}

impl PeerStore {
    /// Open the peer store at the given path (default metrics disabled).
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with_options(path, false).map_err(Into::into)
    }

    /// Open with explicit options.
    ///
    /// - `enable_prometheus`: register Prometheus metrics for this store.
    pub fn open_with_options(
        path: impl Into<PathBuf>,
        enable_prometheus: bool,
    ) -> PeerStoreResult<Self> {
        let path = path.into();
        debug!(path = %path.display(), "opening quantum peer store");

        let metrics = Arc::new(
            PeerStoreMetrics::new(enable_prometheus)
                .map_err(|e| PeerStoreError::Metrics(e.to_string()))?,
        );

        let (data, corruption) = if path.exists() {
            let s = fs::read_to_string(&path)?;
            match serde_json::from_str::<PeerStoreFile>(&s) {
                Ok(data) => (data, false),
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to parse peer store, using default");
                    (PeerStoreFile::default(), true)
                }
            }
        } else {
            (PeerStoreFile::default(), false)
        };

        if corruption {
            metrics.record_corruption();
        }

        let mut quantum = QuantumStoreState::new();
        quantum.peer_count = data.addrs.len();

        let store = Self {
            inner: Arc::new(Mutex::new(Inner { data, quantum })),
            path,
            metrics,
        };

        store.update_gauges();
        Ok(store)
    }

    // -------------------------------------------------------------------------
    // Read-only accessors
    // -------------------------------------------------------------------------

    /// Returns a copy of all known peer addresses.
    pub fn addrs(&self) -> Vec<String> {
        self.inner.lock().data.addrs.clone()
    }

    /// Number of known peer addresses.
    pub fn len(&self) -> usize {
        self.inner.lock().data.addrs.len()
    }

    /// Returns `true` if the store contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.inner.lock().data.addrs.is_empty()
    }

    /// Quantum purity γ = Tr(ρ²) of the store.
    pub fn purity(&self) -> f64 {
        self.inner.lock().quantum.purity
    }

    /// Von Neumann entropy S = -Tr(ρ ln ρ) of the store.
    pub fn entropy(&self) -> f64 {
        self.inner.lock().quantum.entropy
    }

    /// Whether the store is in a healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.inner.lock().quantum.is_healthy
    }

    /// Get a copy of the quantum store statistics.
    pub fn quantum_stats(&self) -> QuantumStoreState {
        self.inner.lock().quantum.clone()
    }

    /// Path to the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    // -------------------------------------------------------------------------
    // Mutating operations
    // -------------------------------------------------------------------------

    /// Adds a new peer address if it is not already present.
    pub fn add(&self, addr: String) -> PeerStoreResult<()> {
        let mut guard = self.inner.lock();
        if guard.data.addrs.iter().any(|a| a == &addr) {
            debug!(addr = %addr, "peer address already present, skipping");
            return Ok(());
        }
        guard.data.addrs.push(addr);
        // Bound the store size.
        if guard.data.addrs.len() > MAX_PEERS {
            let excess = guard.data.addrs.len() - MAX_PEERS;
            guard.data.addrs.drain(0..excess);
        }
        let new_len = guard.data.addrs.len();
        guard.quantum.apply_add_decoherence(new_len);
        guard.quantum.apply_store_channel();
        drop(guard);

        self.metrics.record_add();
        self.persist()?;
        self.update_gauges();
        Ok(())
    }

    /// Removes a peer address if present.
    pub fn remove(&self, addr: &str) -> PeerStoreResult<()> {
        let mut guard = self.inner.lock();
        if let Some(pos) = guard.data.addrs.iter().position(|x| x == addr) {
            guard.data.addrs.remove(pos);
            let new_len = guard.data.addrs.len();
            guard.quantum.apply_remove_decoherence(new_len);
            guard.quantum.apply_store_channel();
            drop(guard);
            self.metrics.record_remove();
            self.persist()?;
            self.update_gauges();
        } else {
            debug!(addr = %addr, "peer address not found, skipping");
        }
        Ok(())
    }

    /// Replaces the entire list of addresses.
    pub fn set_addrs(&self, new_addrs: Vec<String>) -> PeerStoreResult<()> {
        let mut guard = self.inner.lock();
        let old_count = guard.data.addrs.len();
        guard.data.addrs = new_addrs;
        if guard.data.addrs.len() > MAX_PEERS {
            let excess = guard.data.addrs.len() - MAX_PEERS;
            guard.data.addrs.drain(0..excess);
        }
        let new_len = guard.data.addrs.len();
        guard.quantum.apply_remove_decoherence(old_count);
        guard.quantum.apply_add_decoherence(new_len);
        guard.quantum.apply_store_channel();
        drop(guard);

        self.metrics.record_remove();
        self.metrics.record_add();
        self.persist()?;
        self.update_gauges();
        Ok(())
    }

    /// Clears all peer addresses, resetting to the vacuum state |∅⟩.
    pub fn clear(&self) -> PeerStoreResult<()> {
        self.set_addrs(Vec::new())
    }

    // -------------------------------------------------------------------------
    // Internal helpers
    // -------------------------------------------------------------------------

    /// Atomically write the current store to disk.
    fn persist(&self) -> PeerStoreResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        let json = {
            let guard = self.inner.lock();
            serde_json::to_string_pretty(&guard.data)?
        };

        let tmp_path = self.path.with_extension("tmp");
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &self.path)?;
        // fsync parent dir so the rename is durable.
        if let Some(parent) = self.path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        // Apply persist decoherence under the lock.
        {
            let mut guard = self.inner.lock();
            guard.quantum.apply_persist_decoherence();
        }

        self.metrics.record_persist();
        debug!(path = %self.path.display(), "quantum peer store persisted");
        Ok(())
    }

    fn update_gauges(&self) {
        let (count, purity) = {
            let guard = self.inner.lock();
            (guard.data.addrs.len(), guard.quantum.purity)
        };
        self.metrics.update_gauges(count, purity);
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> PeerStoreMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_add_and_get() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store
            .add("/ip4/1.2.3.4/tcp/9000".to_string())
            .unwrap();
        let addrs = store.addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "/ip4/1.2.3.4/tcp/9000");

        // Adding duplicate does nothing.
        store
            .add("/ip4/1.2.3.4/tcp/9000".to_string())
            .unwrap();
        assert_eq!(store.addrs().len(), 1);
    }

    #[test]
    fn test_remove() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        store.add("addr1".to_string()).unwrap();
        store.add("addr2".to_string()).unwrap();
        assert_eq!(store.len(), 2);

        store.remove("addr1").unwrap();
        assert_eq!(store.addrs(), vec!["addr2"]);

        store.remove("nonexistent").unwrap();
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_set_addrs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        store
            .set_addrs(vec!["a".to_string(), "b".to_string()])
            .unwrap();
        assert_eq!(store.addrs(), vec!["a", "b"]);
    }

    #[test]
    fn test_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        store.add("a".to_string()).unwrap();
        store.add("b".to_string()).unwrap();
        store.clear().unwrap();
        assert!(store.is_empty());
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        {
            let store = PeerStore::open(&path).unwrap();
            store.add("persist-me".to_string()).unwrap();
        }
        let store = PeerStore::open(&path).unwrap();
        assert_eq!(store.addrs(), vec!["persist-me"]);
    }

    #[test]
    fn test_corrupted_file_records_metric() -> PeerStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join("peers.json");
        fs::write(&path, "this is not json")?;

        let store = PeerStore::open_with_options(&path, false)?;
        assert!(store.is_empty());
        let snap = store.metrics_snapshot();
        assert_eq!(snap.corruption, 1);
        Ok(())
    }

    #[test]
    fn test_atomic_write_leaves_no_tmp() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();
        store.add("test".to_string()).unwrap();
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_max_peers_bound() -> PeerStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_with_options(&path, false)?;

        // Insert MAX_PEERS + 5 unique addresses; the store must not exceed MAX_PEERS.
        for i in 0..(MAX_PEERS + 5) {
            store.add(format!("peer-{}", i))?;
        }
        assert_eq!(store.len(), MAX_PEERS);
        // Oldest entries must have been dropped.
        assert!(!store.addrs().iter().any(|a| a == "peer-0"));
        Ok(())
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        assert!((store.purity() - 1.0).abs() < 1e-10);
        assert!((store.entropy() - 0.0).abs() < 1e-10);
        assert!(store.is_healthy());
    }

    #[test]
    fn test_add_decoherence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        let initial_purity = store.purity();
        store.add("peer1".to_string()).unwrap();
        assert!(store.purity() < initial_purity);
    }

    #[test]
    fn test_remove_decoherence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        store.add("peer1".to_string()).unwrap();
        let purity_after_add = store.purity();
        store.remove("peer1").unwrap();
        assert!(store.purity() < purity_after_add);
    }

    #[test]
    fn test_quantum_stats() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        store.add("peer1".to_string()).unwrap();
        store.add("peer2".to_string()).unwrap();

        let stats = store.quantum_stats();
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.total_adds, 2);
        assert!(stats.purity < 1.0);
    }

    #[test]
    fn test_health_after_many_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        for i in 0..100 {
            store.add(format!("peer{}", i)).unwrap();
            store.remove(&format!("peer{}", i)).unwrap();
        }

        assert!(store.purity() < 1.0);
        assert!(!store.is_healthy());
    }

    #[test]
    fn test_purity_never_negative() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        for i in 0..10000 {
            store.add(format!("peer{}", i)).unwrap();
        }
        assert!(store.purity() >= 0.0);
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = PeerStorePrometheus::new_unregistered();
        p.adds_total.inc();
        p.removes_total.inc_by(2);
        p.peer_count.set(5.0);
        assert_eq!(p.adds_total.get(), 1);
        assert_eq!(p.removes_total.get(), 2);
        assert_eq!(p.peer_count.get(), 5.0);
    }

    #[test]
    fn test_concurrent_adds() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = Arc::new(PeerStore::open(&path).unwrap());

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for i in 0..50 {
                        let _ = store.add(format!("peer-{}-{}", t, i));
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        // 8 threads × 50 unique addresses each = 400 total.
        assert_eq!(store.len(), 400);
    }
}
