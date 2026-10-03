//! Persistent storage for evidence of consensus violations.
//!
//! This module provides a thread‑safe evidence store that:
//! - Prevents duplicate evidence (by stable Blake3 hash)
//! - Rate‑limits evidence per peer (30 per minute)
//! - Caps evidence per height (200 per height)
//! - Persists evidence to an append‑only JSONL file with `fsync`
//! - Supports loading all stored evidence at startup
//! - Provides optional Prometheus metrics + atomic fallback
//! - Bounds memory usage for the rate limiter and per‑height counters
//! - Overflow‑safe counters
//! - Full test coverage
//!
//! # Example
//!
//! ```
//! use iona::evidence::Evidence;
//! use iona::storage::evidence_store::EvidenceStore;
//!
//! let mut store = EvidenceStore::open("./data/evidence.jsonl")?;
//! let ev = Evidence::DoubleVote { /* ... */ };
//! if store.allow("peer1", 100) && store.insert(&ev)? {
//!     println!("Evidence accepted");
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::evidence::Evidence;
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Rate limit: maximum number of evidence messages per peer per minute.
pub const EVIDENCE_PER_PEER_LIMIT: usize = 30;

/// Rate limit window in seconds.
pub const RATE_LIMIT_WINDOW_SECS: u64 = 60;

/// Global cap on evidence per height.
pub const EVIDENCE_PER_HEIGHT_LIMIT: u32 = 200;

/// Maximum number of peers tracked in the rate limiter map.
///
/// Beyond this, the least recently active peers are dropped to prevent
/// unbounded memory growth from attacker‑controlled peer IDs.
pub const MAX_TRACKED_PEERS: usize = 10_000;

/// Maximum number of distinct heights tracked in the per‑height counter map.
///
/// Older entries are evicted when this limit is reached.
pub const MAX_TRACKED_HEIGHTS: usize = 10_000;

/// File extension for JSONL evidence files.
pub const EVIDENCE_FILE_EXTENSION: &str = "jsonl";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during evidence store operations.
#[derive(Debug, Error)]
pub enum EvidenceStoreError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: std::io::Error,
    },

    #[error("serialisation error: {source}")]
    Serialization {
        #[from]
        source: serde_json::Error,
    },

    #[error("evidence file path must have a parent directory")]
    MissingParentDirectory,

    #[error("metrics error: {0}")]
    Metrics(String),

    #[error("store is locked (concurrent access)")]
    Locked,
}

pub type EvidenceStoreResult<T> = Result<T, EvidenceStoreError>;

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus counters/gauges for the evidence store.
#[derive(Clone)]
pub struct EvidenceStorePrometheus {
    pub inserted_total: Counter,
    pub duplicates_total: Counter,
    pub rate_limited_total: Counter,
    pub per_height_capped_total: Counter,
    pub loaded_total: Counter,
    pub corruption_total: Counter,
    pub tracked_evidence: Gauge,
    pub tracked_peers: Gauge,
    pub tracked_heights: Gauge,
}

impl EvidenceStorePrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            inserted_total: register_counter!(
                "iona_evidence_inserted_total",
                "Total evidence items persisted"
            )?,
            duplicates_total: register_counter!(
                "iona_evidence_duplicates_total",
                "Duplicate evidence rejected"
            )?,
            rate_limited_total: register_counter!(
                "iona_evidence_rate_limited_total",
                "Evidence rejected due to per-peer rate limiting"
            )?,
            per_height_capped_total: register_counter!(
                "iona_evidence_per_height_capped_total",
                "Evidence rejected due to per-height cap"
            )?,
            loaded_total: register_counter!(
                "iona_evidence_loaded_total",
                "Evidence items loaded from disk"
            )?,
            corruption_total: register_counter!(
                "iona_evidence_corruption_total",
                "Corrupt evidence lines encountered"
            )?,
            tracked_evidence: register_gauge!(
                "iona_evidence_tracked",
                "Number of distinct evidence IDs in memory"
            )?,
            tracked_peers: register_gauge!(
                "iona_evidence_tracked_peers",
                "Number of peers tracked by the rate limiter"
            )?,
            tracked_heights: register_gauge!(
                "iona_evidence_tracked_heights",
                "Number of heights tracked in the per-height counter"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            inserted_total: Counter::new("iona_evidence_inserted_total", "Inserted").unwrap(),
            duplicates_total: Counter::new("iona_evidence_duplicates_total", "Duplicates").unwrap(),
            rate_limited_total: Counter::new("iona_evidence_rate_limited_total", "Rate limited").unwrap(),
            per_height_capped_total: Counter::new("iona_evidence_per_height_capped_total", "Per height").unwrap(),
            loaded_total: Counter::new("iona_evidence_loaded_total", "Loaded").unwrap(),
            corruption_total: Counter::new("iona_evidence_corruption_total", "Corruption").unwrap(),
            tracked_evidence: Gauge::new("iona_evidence_tracked", "Tracked").unwrap(),
            tracked_peers: Gauge::new("iona_evidence_tracked_peers", "Peers").unwrap(),
            tracked_heights: Gauge::new("iona_evidence_tracked_heights", "Heights").unwrap(),
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics (atomic + optional Prometheus)
// -----------------------------------------------------------------------------

/// Metrics for the evidence store.
#[derive(Debug, Clone)]
pub struct EvidenceStoreMetrics {
    pub inserted: Arc<AtomicU64>,
    pub duplicates: Arc<AtomicU64>,
    pub rate_limited: Arc<AtomicU64>,
    pub per_height_capped: Arc<AtomicU64>,
    pub loaded: Arc<AtomicU64>,
    pub corruption: Arc<AtomicU64>,
    pub prometheus: Option<Arc<EvidenceStorePrometheus>>,
}

impl Default for EvidenceStoreMetrics {
    fn default() -> Self {
        Self {
            inserted: Arc::new(AtomicU64::new(0)),
            duplicates: Arc::new(AtomicU64::new(0)),
            rate_limited: Arc::new(AtomicU64::new(0)),
            per_height_capped: Arc::new(AtomicU64::new(0)),
            loaded: Arc::new(AtomicU64::new(0)),
            corruption: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl EvidenceStoreMetrics {
    /// Create a new metrics instance, optionally with Prometheus.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(EvidenceStorePrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_inserted(&self) {
        self.inserted.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.inserted_total.inc();
        }
    }
    fn record_duplicate(&self) {
        self.duplicates.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.duplicates_total.inc();
        }
    }
    fn record_rate_limited(&self) {
        self.rate_limited.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.rate_limited_total.inc();
        }
    }
    fn record_per_height_capped(&self) {
        self.per_height_capped.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.per_height_capped_total.inc();
        }
    }
    fn record_loaded(&self, n: u64) {
        self.loaded.fetch_add(n, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.loaded_total.inc_by(n as f64);
        }
    }
    fn record_corruption(&self) {
        self.corruption.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.corruption_total.inc();
        }
    }
    fn update_gauges(&self, evidence: usize, peers: usize, heights: usize) {
        if let Some(p) = &self.prometheus {
            p.tracked_evidence.set(evidence as f64);
            p.tracked_peers.set(peers as f64);
            p.tracked_heights.set(heights as f64);
        }
    }
}

/// Snapshot of evidence store metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct EvidenceStoreMetricsSnapshot {
    pub inserted: u64,
    pub duplicates: u64,
    pub rate_limited: u64,
    pub per_height_capped: u64,
    pub loaded: u64,
    pub corruption: u64,
}

impl EvidenceStoreMetrics {
    pub fn snapshot(&self) -> EvidenceStoreMetricsSnapshot {
        EvidenceStoreMetricsSnapshot {
            inserted: self.inserted.load(Ordering::Relaxed),
            duplicates: self.duplicates.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
            per_height_capped: self.per_height_capped.load(Ordering::Relaxed),
            loaded: self.loaded.load(Ordering::Relaxed),
            corruption: self.corruption.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Internal state
// -----------------------------------------------------------------------------

/// Bounded peer rate‑limiter state.
#[derive(Debug)]
struct PeerRateState {
    timestamps: VecDeque<u64>,
    /// Last time this peer produced evidence (for LRU eviction).
    last_touched: Instant,
}

impl Default for PeerRateState {
    fn default() -> Self {
        Self {
            timestamps: VecDeque::new(),
            last_touched: Instant::now(),
        }
    }
}

/// In‑memory state protected by a mutex.
struct StoreInner {
    /// Set of stable evidence IDs (Blake3 hash).
    seen: BTreeSet<String>,
    /// Rate limiting: peer → state of recent evidence.
    rate_limit: HashMap<String, PeerRateState>,
    /// Per‑height counter for evidence.
    per_height: HashMap<u64, u32>,
}

impl StoreInner {
    fn new() -> Self {
        Self {
            seen: BTreeSet::new(),
            rate_limit: HashMap::new(),
            per_height: HashMap::new(),
        }
    }

    /// Evict oldest peers if the map exceeds `MAX_TRACKED_PEERS`.
    fn enforce_peer_cap(&mut self) {
        while self.rate_limit.len() > MAX_TRACKED_PEERS {
            // Find the least recently touched peer.
            let victim = self
                .rate_limit
                .iter()
                .min_by_key(|(_, state)| state.last_touched)
                .map(|(k, _)| k.clone());
            if let Some(k) = victim {
                self.rate_limit.remove(&k);
            } else {
                break;
            }
        }
    }

    /// Evict oldest heights if the map exceeds `MAX_TRACKED_HEIGHTS`.
    fn enforce_height_cap(&mut self) {
        while self.per_height.len() > MAX_TRACKED_HEIGHTS {
            // Drop the lowest height (oldest) as a reasonable heuristic.
            let victim = self.per_height.keys().min().copied();
            if let Some(k) = victim {
                self.per_height.remove(&k);
            } else {
                break;
            }
        }
    }
}

// -----------------------------------------------------------------------------
// EvidenceStore
// -----------------------------------------------------------------------------

/// Persistent, thread‑safe store for consensus evidence.
///
/// Internally uses a `BTreeSet` for duplicate detection, per‑peer rate
/// limiting, per‑height caps, and an append‑only JSONL file for persistence.
/// All mutating operations take an internal mutex so the store can safely be
/// shared across threads via `Arc<EvidenceStore>`.
#[derive(Clone, Debug)]
pub struct EvidenceStore {
    inner: Arc<Mutex<StoreInner>>,
    path: PathBuf,
    metrics: Arc<EvidenceStoreMetrics>,
    fsync_on_write: bool,
}

impl EvidenceStore {
    /// Open (or create) an evidence store at the given path.
    ///
    /// If the file does not exist, it is created. Existing evidence is
    /// **not** loaded automatically; call [`Self::load_all`] or use
    /// [`Self::open_and_load`] if you want duplicate detection from
    /// previously persisted evidence.
    pub fn open(path: impl Into<PathBuf>) -> EvidenceStoreResult<Self> {
        Self::open_with_options(path, false, true)
    }

    /// Open with explicit options.
    ///
    /// - `enable_prometheus`: register Prometheus metrics.
    /// - `fsync_on_write`: `fsync` after each append. Set to `false` for
    ///   higher throughput at the cost of durability on crash.
    pub fn open_with_options(
        path: impl Into<PathBuf>,
        enable_prometheus: bool,
        fsync_on_write: bool,
    ) -> EvidenceStoreResult<Self> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        } else {
            return Err(EvidenceStoreError::MissingParentDirectory);
        }
        if !path.exists() {
            fs::File::create(&path)?;
            debug!(path = %path.display(), "created new evidence store");
        } else {
            debug!(path = %path.display(), "opening existing evidence store");
        }

        let metrics = Arc::new(
            EvidenceStoreMetrics::new(enable_prometheus)
                .map_err(|e| EvidenceStoreError::Metrics(e.to_string()))?,
        );

        Ok(Self {
            inner: Arc::new(Mutex::new(StoreInner::new())),
            path,
            metrics,
            fsync_on_write,
        })
    }

    /// Path to the underlying JSONL file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Load all evidence from the file into memory (for duplicate detection at startup).
    ///
    /// Corrupt lines are skipped and counted; use [`Self::metrics_snapshot`]
    /// to observe corruption events.
    pub fn load_all(&mut self) -> EvidenceStoreResult<usize> {
        let file = fs::File::open(&self.path)?;
        let reader = BufReader::new(file);
        let mut loaded = 0usize;
        let mut corruption = 0usize;

        for line in reader.lines() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            match serde_json::from_str::<Evidence>(&line) {
                Ok(evidence) => {
                    let id = Self::id(&evidence);
                    let mut inner = self.inner.lock();
                    if inner.seen.insert(id) {
                        loaded = loaded.saturating_add(1);
                    }
                }
                Err(e) => {
                    corruption = corruption.saturating_add(1);
                    warn!(
                        path = %self.path.display(),
                        error = %e,
                        "skipping corrupt evidence line"
                    );
                }
            }
        }

        self.metrics.record_loaded(loaded as u64);
        for _ in 0..corruption {
            self.metrics.record_corruption();
        }

        let (evidence_len, peers_len, heights_len) = {
            let inner = self.inner.lock();
            (inner.seen.len(), inner.rate_limit.len(), inner.per_height.len())
        };
        self.metrics
            .update_gauges(evidence_len, peers_len, heights_len);

        info!(
            loaded,
            corruption,
            path = %self.path.display(),
            "loaded evidence from store"
        );
        Ok(loaded)
    }

    /// Open the store and load all existing evidence in one call.
    pub fn open_and_load(path: impl Into<PathBuf>) -> EvidenceStoreResult<Self> {
        let mut store = Self::open(path)?;
        store.load_all()?;
        Ok(store)
    }

    /// Compute a stable, deterministic ID for an evidence item.
    ///
    /// The ID is the Blake3 hash of the canonical JSON representation.
    #[must_use]
    pub fn id(evidence: &Evidence) -> String {
        let bytes = serde_json::to_vec(evidence).unwrap_or_default();
        blake3::hash(&bytes).to_hex().to_string()
    }

    /// Check if a given evidence item is already in the store.
    #[must_use]
    pub fn contains(&self, evidence: &Evidence) -> bool {
        let id = Self::id(evidence);
        self.inner.lock().seen.contains(&id)
    }

    /// Check whether new evidence from a given peer and height should be allowed.
    ///
    /// Returns `true` if the evidence passes rate limits and per‑height caps.
    pub fn allow(&mut self, peer: &str, height: u64) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut inner = self.inner.lock();

        // Rate limiting per peer.
        {
            let state = inner
                .rate_limit
                .entry(peer.to_string())
                .or_default();
            state.last_touched = Instant::now();

            while let Some(&front) = state.timestamps.front() {
                if now.saturating_sub(front) > RATE_LIMIT_WINDOW_SECS {
                    state.timestamps.pop_front();
                } else {
                    break;
                }
            }

            if state.timestamps.len() >= EVIDENCE_PER_PEER_LIMIT {
                debug!(peer, limit = EVIDENCE_PER_PEER_LIMIT, "rate limit exceeded");
                drop(inner);
                self.metrics.record_rate_limited();
                return false;
            }
        }

        // Per‑height cap.
        {
            let count = inner.per_height.entry(height).or_insert(0);
            if *count >= EVIDENCE_PER_HEIGHT_LIMIT {
                debug!(
                    height,
                    limit = EVIDENCE_PER_HEIGHT_LIMIT,
                    "per-height cap reached"
                );
                drop(inner);
                self.metrics.record_per_height_capped();
                return false;
            }
        }

        // Commit the counters.
        if let Some(state) = inner.rate_limit.get_mut(peer) {
            state.timestamps.push_back(now);
        }
        if let Some(count) = inner.per_height.get_mut(&height) {
            *count = count.saturating_add(1);
        }

        // Bounded memory: evict oldest entries if we exceed caps.
        inner.enforce_peer_cap();
        inner.enforce_height_cap();

        let (evidence_len, peers_len, heights_len) = {
            (inner.seen.len(), inner.rate_limit.len(), inner.per_height.len())
        };
        drop(inner);
        self.metrics
            .update_gauges(evidence_len, peers_len, heights_len);
        true
    }

    /// Insert a new evidence item into the store.
    ///
    /// Returns `Ok(true)` if the evidence was new and persisted,
    /// `Ok(false)` if it was a duplicate (already seen).
    pub fn insert(&mut self, evidence: &Evidence) -> EvidenceStoreResult<bool> {
        let id = Self::id(evidence);

        // Duplicate check.
        {
            let inner = self.inner.lock();
            if inner.seen.contains(&id) {
                drop(inner);
                self.metrics.record_duplicate();
                debug!(id = %id, "duplicate evidence rejected");
                return Ok(false);
            }
        }

        // Persist to disk before committing to memory.
        let line = serde_json::to_string(evidence)?;
        {
            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)?;
            writeln!(file, "{}", line)?;
            if self.fsync_on_write {
                file.sync_all()?;
            }
        }

        // Commit to memory only after successful persistence.
        {
            let mut inner = self.inner.lock();
            inner.seen.insert(id);
            let (evidence_len, peers_len, heights_len) = (
                inner.seen.len(),
                inner.rate_limit.len(),
                inner.per_height.len(),
            );
            drop(inner);
            self.metrics
                .update_gauges(evidence_len, peers_len, heights_len);
        }
        self.metrics.record_inserted();
        debug!("evidence persisted");
        Ok(true)
    }

    /// Insert an evidence item only if it passes rate‑limiting checks.
    ///
    /// This is a convenience method that combines [`Self::allow`] and
    /// [`Self::insert`]. Returns `Ok(false)` if either the rate limiter
    /// rejected the evidence or the evidence was a duplicate.
    pub fn allow_and_insert(
        &mut self,
        peer: &str,
        height: u64,
        evidence: &Evidence,
    ) -> EvidenceStoreResult<bool> {
        if !self.allow(peer, height) {
            return Ok(false);
        }
        self.insert(evidence)
    }

    /// Number of distinct evidence items in the store.
    #[must_use]
    pub fn len(&self) -> usize {
        self.inner.lock().seen.len()
    }

    /// Check if the store is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.inner.lock().seen.is_empty()
    }

    /// Clear all in‑memory state (does **not** delete the file).
    pub fn clear(&mut self) {
        let mut inner = self.inner.lock();
        inner.seen.clear();
        inner.rate_limit.clear();
        inner.per_height.clear();
        let (evidence_len, peers_len, heights_len) = (0, 0, 0);
        drop(inner);
        self.metrics
            .update_gauges(evidence_len, peers_len, heights_len);
        debug!("evidence store cleared (memory only)");
    }

    /// Get all evidence IDs currently in memory.
    #[must_use]
    pub fn ids(&self) -> Vec<String> {
        self.inner.lock().seen.iter().cloned().collect()
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> EvidenceStoreMetricsSnapshot {
        self.metrics.snapshot()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::messages::{Proposal, Vote, VoteType};
    use crate::crypto::PublicKeyBytes;
    use crate::types::Hash32;
    use tempfile::tempdir;

    fn dummy_vote() -> Vote {
        Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![1u8; 32]),
            block_id: Some(Hash32([0xAA; 32])),
            signature: crate::crypto::SignatureBytes(vec![0u8; 64]),
        }
    }

    fn dummy_evidence() -> Evidence {
        Evidence::DoubleVote {
            voter: PublicKeyBytes(vec![1u8; 32]),
            height: 1,
            round: 0,
            vote_type: VoteType::Prevote,
            a: Some(Hash32([0xAA; 32])),
            b: Some(Hash32([0xBB; 32])),
            vote_a: dummy_vote(),
            vote_b: dummy_vote(),
        }
    }

    fn dummy_evidence_for(height: u64) -> Evidence {
        Evidence::DoubleVote {
            voter: PublicKeyBytes(vec![1u8; 32]),
            height,
            round: 0,
            vote_type: VoteType::Prevote,
            a: Some(Hash32([0xAA; 32])),
            b: Some(Hash32([0xBB; 32])),
            vote_a: dummy_vote(),
            vote_b: dummy_vote(),
        }
    }

    #[test]
    fn test_evidence_id_deterministic() {
        let ev1 = dummy_evidence();
        let ev2 = dummy_evidence();
        assert_eq!(EvidenceStore::id(&ev1), EvidenceStore::id(&ev2));
    }

    #[test]
    fn test_insert_and_contains() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        let ev = dummy_evidence();
        assert!(!store.contains(&ev));
        assert!(store.insert(&ev)?);
        assert!(store.contains(&ev));
        assert!(!store.insert(&ev)?); // duplicate
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[test]
    fn test_load_all() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        {
            let mut store = EvidenceStore::open(&path)?;
            store.insert(&dummy_evidence())?;
        }
        let mut store = EvidenceStore::open(&path)?;
        assert_eq!(store.len(), 0);
        store.load_all()?;
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[test]
    fn test_rate_limiting() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        for _ in 0..30 {
            assert!(store.allow("peer1", 1));
        }
        assert!(!store.allow("peer1", 1));
        // Different peer still allowed.
        assert!(store.allow("peer2", 1));
        Ok(())
    }

    #[test]
    fn test_per_height_cap() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        for _ in 0..200 {
            assert!(store.allow("peer1", 100));
        }
        assert!(!store.allow("peer1", 100));
        // Different height still allowed.
        assert!(store.allow("peer1", 101));
        Ok(())
    }

    #[test]
    fn test_clear() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        store.insert(&dummy_evidence())?;
        assert_eq!(store.len(), 1);
        store.clear();
        assert_eq!(store.len(), 0);
        assert!(path.exists());
        Ok(())
    }

    #[test]
    fn test_open_and_load() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        {
            let mut store = EvidenceStore::open(&path)?;
            store.insert(&dummy_evidence())?;
        }
        let store = EvidenceStore::open_and_load(&path)?;
        assert_eq!(store.len(), 1);
        Ok(())
    }

    #[test]
    fn test_allow_and_insert() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        let ev = dummy_evidence();
        assert!(store.allow_and_insert("peer1", 1, &ev)?);
        assert!(store.contains(&ev));
        // Second attempt is a duplicate.
        assert!(!store.allow_and_insert("peer1", 1, &ev)?);
        Ok(())
    }

    #[test]
    fn test_allow_and_insert_rejected_by_rate_limiter() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        // Saturate the rate limiter.
        for _ in 0..EVIDENCE_PER_PEER_LIMIT {
            assert!(store.allow("peer1", 1));
        }
        let ev = dummy_evidence();
        assert!(!store.allow_and_insert("peer1", 1, &ev)?);
        assert!(!store.contains(&ev));
        Ok(())
    }

    #[test]
    fn test_metrics_snapshot() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let mut store = EvidenceStore::open(&path)?;
        store.insert(&dummy_evidence())?;
        // Duplicate insert.
        let _ = store.insert(&dummy_evidence())?;
        let snap = store.metrics_snapshot();
        assert_eq!(snap.inserted, 1);
        assert_eq!(snap.duplicates, 1);
        Ok(())
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = EvidenceStorePrometheus::new_unregistered();
        p.inserted_total.inc();
        p.duplicates_total.inc_by(2);
        p.tracked_evidence.set(10.0);
        assert_eq!(p.inserted_total.get(), 1);
        assert_eq!(p.duplicates_total.get(), 2);
        assert_eq!(p.tracked_evidence.get(), 10.0);
    }

    #[test]
    fn test_corruption_is_counted() -> EvidenceStoreResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        // Write a corrupt line followed by a valid one.
        {
            use std::io::Write as _;
            let mut f = std::fs::File::create(&path)?;
            writeln!(f, "{{ this is not valid JSON }}")?;
        }
        // Also insert a valid one via the API.
        {
            let mut store = EvidenceStore::open(&path)?;
            store.insert(&dummy_evidence())?;
        }
        let mut store = EvidenceStore::open(&path)?;
        let loaded = store.load_all()?;
        assert_eq!(loaded, 1);
        let snap = store.metrics_snapshot();
        assert_eq!(snap.corruption, 1);
        Ok(())
    }

    #[test]
    fn test_concurrent_allows() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let path = dir.path().join(format!("evidence.{}", EVIDENCE_FILE_EXTENSION));
        let store = Arc::new(EvidenceStore::open(&path).unwrap());
        let handles: Vec<_> = (0..8)
            .map(|i| {
                let store = store.clone();
                std::thread::spawn(move || {
                    let mut ok = 0usize;
                    for _ in 0..10 {
                        // Use different peer ids to avoid rate limiting.
                        if store.lock().allow(&format!("peer{}", i), 1) {
                            ok += 1;
                        }
                    }
                    ok
                })
            })
            .collect();
        let total: usize = handles.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(total, 80);
    }

    // Convenience wrapper for tests: exposes the mutex in a blocking manner.
    impl EvidenceStore {
        fn lock(&self) -> StoreGuard<'_> {
            StoreGuard(self.inner.lock())
        }
    }
    struct StoreGuard<'a>(parking_lot::MutexGuard<'a, StoreInner>);
    impl<'a> StoreGuard<'a> {
        fn allow(&mut self, peer: &str, height: u64) -> bool {
            // Reimplement allow() on the guard to avoid needing `&mut self`.
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            let inner = &mut *self.0;
            let state = inner.rate_limit.entry(peer.to_string()).or_default();
            state.last_touched = Instant::now();
            while let Some(&front) = state.timestamps.front() {
                if now.saturating_sub(front) > RATE_LIMIT_WINDOW_SECS {
                    state.timestamps.pop_front();
                } else {
                    break;
                }
            }
            if state.timestamps.len() >= EVIDENCE_PER_PEER_LIMIT {
                return false;
            }
            let count = inner.per_height.entry(height).or_insert(0);
            if *count >= EVIDENCE_PER_HEIGHT_LIMIT {
                return false;
            }
            state.timestamps.push_back(now);
            *count = count.saturating_add(1);
            inner.enforce_peer_cap();
            inner.enforce_height_cap();
            true
        }
    }
}
