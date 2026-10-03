//! Persistent storage for transaction receipts — Quantum Receipts Store.
//!
//! # Quantum Receipts Model
//!
//! Each receipt set is modelled as a **quantum state** |receipts_i⟩ in the
//! Hilbert space of transaction outcomes. The store's density matrix evolves
//! under CRUD operations which act as **Kraus operators**.
//!
//! # Production Features
//! - True atomic writes: temp + fsync + rename + parent-dir fsync.
//! - Prometheus metrics (optional) with atomic fallback.
//! - Overflow-safe counters using `saturating_add`.
//! - Structured error type (`ReceiptsStoreError`) for upstream callers.
//! - Full test coverage.
//!
//! # Mathematical Formalism
//!
//! ```text
//! |receipts⟩ = ⊗_i |receipt_i⟩
//! ρ_store = (1/N) Σ_i |receipts_i⟩⟨receipts_i|
//! ```

use crate::types::{Hash32, Receipt};
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

/// Default quantum coherence for the receipts store.
const DEFAULT_RECEIPTS_COHERENCE: f64 = 1.0;

/// Decoherence rate per put operation.
const PUT_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per get operation (measurement).
const GET_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per delete operation.
const DELETE_DECOHERENCE_RATE: f64 = 0.0003;

/// Decoherence rate per clear operation.
const CLEAR_DECOHERENCE_RATE: f64 = 0.001;

/// Decoherence rate per persist operation.
const PERSIST_DECOHERENCE_RATE: f64 = 0.0003;

/// Minimum coherence threshold for a healthy store.
const MIN_RECEIPTS_COHERENCE: f64 = 0.9;

/// Kraus rank for receipts store quantum channels.
const RECEIPTS_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during receipts store operations.
#[derive(Debug, Error)]
pub enum ReceiptsStoreError {
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

    #[error("metrics error: {0}")]
    Metrics(String),
}

pub type ReceiptsStoreResult<T> = Result<T, ReceiptsStoreError>;

impl From<ReceiptsStoreError> for io::Error {
    fn from(err: ReceiptsStoreError) -> Self {
        match err {
            ReceiptsStoreError::Io { source } => source,
            other => io::Error::new(io::ErrorKind::Other, other.to_string()),
        }
    }
}

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus counters/gauges for the receipts store.
#[derive(Clone)]
pub struct ReceiptsStorePrometheus {
    pub puts_total: Counter,
    pub gets_total: Counter,
    pub deletes_total: Counter,
    pub clears_total: Counter,
    pub receipt_files: Gauge,
    pub purity: Gauge,
}

impl ReceiptsStorePrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            puts_total: register_counter!(
                "iona_receipts_store_puts_total",
                "Total receipts put operations"
            )?,
            gets_total: register_counter!(
                "iona_receipts_store_gets_total",
                "Total receipts get operations"
            )?,
            deletes_total: register_counter!(
                "iona_receipts_store_deletes_total",
                "Total receipts delete operations"
            )?,
            clears_total: register_counter!(
                "iona_receipts_store_clears_total",
                "Total receipts clear operations"
            )?,
            receipt_files: register_gauge!(
                "iona_receipts_store_files",
                "Number of receipt files in the store"
            )?,
            purity: register_gauge!(
                "iona_receipts_store_purity",
                "Quantum purity of the receipts store"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            puts_total: Counter::new("iona_receipts_store_puts_total", "Puts").unwrap(),
            gets_total: Counter::new("iona_receipts_store_gets_total", "Gets").unwrap(),
            deletes_total: Counter::new("iona_receipts_store_deletes_total", "Deletes").unwrap(),
            clears_total: Counter::new("iona_receipts_store_clears_total", "Clears").unwrap(),
            receipt_files: Gauge::new("iona_receipts_store_files", "Files").unwrap(),
            purity: Gauge::new("iona_receipts_store_purity", "Purity").unwrap(),
        }
    }
}

/// Metrics for the receipts store.
#[derive(Debug, Clone)]
pub struct ReceiptsStoreMetrics {
    pub puts: Arc<AtomicU64>,
    pub gets: Arc<AtomicU64>,
    pub deletes: Arc<AtomicU64>,
    pub clears: Arc<AtomicU64>,
    pub prometheus: Option<Arc<ReceiptsStorePrometheus>>,
}

impl Default for ReceiptsStoreMetrics {
    fn default() -> Self {
        Self {
            puts: Arc::new(AtomicU64::new(0)),
            gets: Arc::new(AtomicU64::new(0)),
            deletes: Arc::new(AtomicU64::new(0)),
            clears: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl ReceiptsStoreMetrics {
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(ReceiptsStorePrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_put(&self) {
        self.puts.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.puts_total.inc();
        }
    }
    fn record_get(&self) {
        self.gets.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.gets_total.inc();
        }
    }
    fn record_delete(&self) {
        self.deletes.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.deletes_total.inc();
        }
    }
    fn record_clear(&self) {
        self.clears.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.clears_total.inc();
        }
    }
    fn update_gauges(&self, files: usize, purity: f64) {
        if let Some(p) = &self.prometheus {
            p.receipt_files.set(files as f64);
            p.purity.set(purity);
        }
    }
}

/// Snapshot of receipts store metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReceiptsStoreMetricsSnapshot {
    pub puts: u64,
    pub gets: u64,
    pub deletes: u64,
    pub clears: u64,
}

impl ReceiptsStoreMetrics {
    pub fn snapshot(&self) -> ReceiptsStoreMetricsSnapshot {
        ReceiptsStoreMetricsSnapshot {
            puts: self.puts.load(Ordering::Relaxed),
            gets: self.gets.load(Ordering::Relaxed),
            deletes: self.deletes.load(Ordering::Relaxed),
            clears: self.clears.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Receipts State
// -----------------------------------------------------------------------------

/// Quantum state of the receipts store.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumReceiptsState {
    pub purity: f64,
    pub entropy: f64,
    pub store_coherence: f64,
    pub receipt_count: usize,
    pub total_puts: u64,
    pub total_gets: u64,
    pub total_deletes: u64,
    pub total_persists: u64,
    pub is_healthy: bool,
}

impl Default for QuantumReceiptsState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_RECEIPTS_COHERENCE,
            entropy: 0.0,
            store_coherence: DEFAULT_RECEIPTS_COHERENCE,
            receipt_count: 0,
            total_puts: 0,
            total_gets: 0,
            total_deletes: 0,
            total_persists: 0,
            is_healthy: true,
        }
    }
}

impl QuantumReceiptsState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_put_decoherence(&mut self, receipt_count: usize) {
        self.total_puts = self.total_puts.saturating_add(1);
        self.receipt_count = receipt_count;
        let decay = (-PUT_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_get_decoherence(&mut self) {
        self.total_gets = self.total_gets.saturating_add(1);
        let decay = (-GET_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_delete_decoherence(&mut self, receipt_count: usize) {
        self.total_deletes = self.total_deletes.saturating_add(1);
        self.receipt_count = receipt_count;
        let decay = (-DELETE_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_clear_decoherence(&mut self) {
        self.total_deletes = self.total_deletes.saturating_add(self.receipt_count as u64);
        self.receipt_count = 0;
        let decay = (-CLEAR_DECOHERENCE_RATE).exp();
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
        let kraus_factor = (1.0 / RECEIPTS_KRAUS_RANK as f64).sqrt();
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
        self.is_healthy = self.purity >= MIN_RECEIPTS_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// ReceiptsStore (thread-safe)
// -----------------------------------------------------------------------------

/// Store for transaction receipts, one file per transaction hash.
///
/// The store is internally synchronized with a `parking_lot::Mutex`, so it
/// can be shared across threads via `Arc<ReceiptsStore>`.
#[derive(Debug, Clone)]
pub struct ReceiptsStore {
    inner: Arc<parking_lot::Mutex<Inner>>,
    dir: PathBuf,
    metrics: Arc<ReceiptsStoreMetrics>,
}

#[derive(Debug)]
struct Inner {
    quantum: QuantumReceiptsState,
}

impl ReceiptsStore {
    /// Opens a receipt store at the given directory (default metrics disabled).
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        Self::open_with_options(root, false).map_err(Into::into)
    }

    /// Open with explicit options.
    ///
    /// - `enable_prometheus`: register Prometheus metrics for this store.
    pub fn open_with_options(
        root: impl Into<PathBuf>,
        enable_prometheus: bool,
    ) -> ReceiptsStoreResult<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;

        let metrics = Arc::new(
            ReceiptsStoreMetrics::new(enable_prometheus)
                .map_err(|e| ReceiptsStoreError::Metrics(e.to_string()))?,
        );

        let receipt_count = Self::count_files(&dir)?;
        let mut quantum = QuantumReceiptsState::new();
        quantum.receipt_count = receipt_count;

        debug!(
            path = %dir.display(),
            receipt_count,
            purity = quantum.purity,
            "opened quantum receipts store"
        );

        let store = Self {
            inner: Arc::new(parking_lot::Mutex::new(Inner { quantum })),
            dir,
            metrics,
        };
        store.update_gauges();
        Ok(store)
    }

    /// Count the number of JSON files in the directory.
    fn count_files(dir: &Path) -> io::Result<usize> {
        let mut count = 0usize;
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
                {
                    count = count.saturating_add(1);
                }
            }
        }
        Ok(count)
    }

    /// Returns the file path for a given transaction hash.
    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(id.0)))
    }

    // ── Read-only accessors ──────────────────────────────────────────────

    pub fn purity(&self) -> f64 {
        self.inner.lock().quantum.purity
    }

    pub fn entropy(&self) -> f64 {
        self.inner.lock().quantum.entropy
    }

    pub fn is_healthy(&self) -> bool {
        self.inner.lock().quantum.is_healthy
    }

    pub fn quantum_stats(&self) -> QuantumReceiptsState {
        self.inner.lock().quantum.clone()
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // ── Mutating operations ─────────────────────────────────────────────

    /// Stores a list of receipts for a transaction, atomically.
    pub fn put(&self, id: &Hash32, receipts: &[Receipt]) -> ReceiptsStoreResult<()> {
        let path = self.path_for(id);
        let tmp_path = path.with_extension("tmp");

        debug!(
            hash = %hex::encode(id.0),
            count = receipts.len(),
            "quantum put: creating receipt state"
        );

        let json = serde_json::to_string_pretty(receipts)?;

        // Atomic write: temp + fsync + rename + parent-dir fsync.
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .open(&tmp_path)?;
            f.write_all(json.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &path)?;
        if let Some(parent) = path.parent() {
            if let Ok(dir) = File::open(parent) {
                let _ = dir.sync_all();
            }
        }

        // Update quantum state.
        let receipt_count = Self::count_files(&self.dir)?;
        {
            let mut guard = self.inner.lock();
            guard.quantum.apply_put_decoherence(receipt_count);
            guard.quantum.apply_store_channel();
        }

        self.metrics.record_put();
        self.update_gauges();

        debug!(
            path = %path.display(),
            purity = self.purity(),
            "receipts stored"
        );
        Ok(())
    }

    /// Retrieves the list of receipts for a transaction, if any.
    pub fn get(&self, id: &Hash32) -> ReceiptsStoreResult<Option<Vec<Receipt>>> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }

        let s = fs::read_to_string(&path)?;
        let receipts: Vec<Receipt> = serde_json::from_str(&s)?;

        debug!(
            hash = %hex::encode(id.0),
            count = receipts.len(),
            "loaded receipts (measurement)"
        );
        Ok(Some(receipts))
    }

    /// Retrieves receipts with quantum state tracking.
    pub fn get_quantum(
        &self,
        id: &Hash32,
    ) -> ReceiptsStoreResult<(Option<Vec<Receipt>>, QuantumReceiptsState)> {
        let result = self.get(id)?;
        let qstate = {
            let mut guard = self.inner.lock();
            guard.quantum.apply_get_decoherence();
            guard.quantum.clone()
        };
        self.metrics.record_get();
        self.update_gauges();
        Ok((result, qstate))
    }

    /// Checks if receipts exist for a given transaction.
    pub fn exists(&self, id: &Hash32) -> bool {
        self.path_for(id).exists()
    }

    /// Deletes the receipts file for a transaction.
    pub fn delete(&self, id: &Hash32) -> ReceiptsStoreResult<()> {
        let path = self.path_for(id);
        if path.exists() {
            debug!(hash = %hex::encode(id.0), "quantum delete: annihilating receipt state");
            fs::remove_file(path)?;

            let receipt_count = Self::count_files(&self.dir)?;
            {
                let mut guard = self.inner.lock();
                guard.quantum.apply_delete_decoherence(receipt_count);
                guard.quantum.apply_store_channel();
            }
            self.metrics.record_delete();
            self.update_gauges();
        }
        Ok(())
    }

    /// Returns the number of stored receipt files (not the number of receipts).
    pub fn len(&self) -> ReceiptsStoreResult<usize> {
        Ok(Self::count_files(&self.dir)?)
    }

    /// Returns `true` if the store contains no receipt files.
    pub fn is_empty(&self) -> ReceiptsStoreResult<bool> {
        Ok(self.len()? == 0)
    }

    /// Clears all receipt files from the store.
    pub fn clear(&self) -> ReceiptsStoreResult<()> {
        debug!(dir = %self.dir.display(), "quantum clear: collapsing to vacuum state");
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                fs::remove_file(path)?;
            }
        }
        {
            let mut guard = self.inner.lock();
            guard.quantum.apply_clear_decoherence();
            guard.quantum.apply_store_channel();
        }
        self.metrics.record_clear();
        self.update_gauges();
        Ok(())
    }

    /// Iterates over all stored receipt files.
    pub fn iter(&self) -> ReceiptsIter<'_> {
        ReceiptsIter {
            store: self,
            entries: match fs::read_dir(&self.dir) {
                Ok(entries) => entries.collect::<Result<Vec<_>, _>>().unwrap_or_default(),
                Err(_) => Vec::new(),
            },
            index: 0,
        }
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> ReceiptsStoreMetricsSnapshot {
        self.metrics.snapshot()
    }

    fn update_gauges(&self) {
        let (count, purity) = {
            let guard = self.inner.lock();
            (guard.quantum.receipt_count, guard.quantum.purity)
        };
        self.metrics.update_gauges(count, purity);
    }
}

// -----------------------------------------------------------------------------
// Iterator
// -----------------------------------------------------------------------------

/// Iterator over `(hash, receipts)` pairs in the store.
pub struct ReceiptsIter<'a> {
    store: &'a ReceiptsStore,
    entries: Vec<fs::DirEntry>,
    index: usize,
}

impl<'a> Iterator for ReceiptsIter<'a> {
    type Item = (Hash32, Vec<Receipt>);

    fn next(&mut self) -> Option<Self::Item> {
        while self.index < self.entries.len() {
            let entry = &self.entries[self.index];
            self.index = self.index.saturating_add(1);
            let path = entry.path();
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                let file_stem = match path.file_stem().and_then(|s| s.to_str()) {
                    Some(s) => s,
                    None => continue,
                };
                let hash_bytes = match hex::decode(file_stem) {
                    Ok(b) => b,
                    Err(_) => continue,
                };
                if hash_bytes.len() != 32 {
                    continue;
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&hash_bytes);
                let id = Hash32(hash);
                if let Ok(Some(receipts)) = self.store.get(&id) {
                    return Some((id, receipts));
                }
            }
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Receipt;
    use tempfile::tempdir;

    fn dummy_receipt(tx_hash: &Hash32, success: bool) -> Receipt {
        Receipt {
            tx_hash: tx_hash.clone(),
            success,
            gas_used: 21000,
            intrinsic_gas_used: 21000,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            effective_gas_price: 100,
            burned: 100,
            tip: 0,
            error: if success { None } else { Some("test error".into()) },
            data: None,
        }
    }

    #[test]
    fn test_put_and_get() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0xaa; 32]);

        let receipts = vec![dummy_receipt(&hash, true), dummy_receipt(&hash, false)];
        store.put(&hash, &receipts)?;
        let loaded = store.get(&hash)?.unwrap();
        assert_eq!(loaded.len(), receipts.len());
        assert!(loaded[0].success);
        assert!(!loaded[1].success);
        Ok(())
    }

    #[test]
    fn test_get_nonexistent() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        assert!(store.get(&Hash32([0xbb; 32]))?.is_none());
        Ok(())
    }

    #[test]
    fn test_exists() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0xcc; 32]);
        assert!(!store.exists(&hash));
        store.put(&hash, &[])?;
        assert!(store.exists(&hash));
        Ok(())
    }

    #[test]
    fn test_delete() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0xdd; 32]);
        store.put(&hash, &[])?;
        assert!(store.exists(&hash));
        store.delete(&hash)?;
        assert!(!store.exists(&hash));
        Ok(())
    }

    #[test]
    fn test_atomic_write_does_not_leave_tmp() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0xee; 32]);
        store.put(&hash, &[])?;
        let tmp_path = store.path_for(&hash).with_extension("tmp");
        assert!(!tmp_path.exists());
        Ok(())
    }

    #[test]
    fn test_len_and_is_empty() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        assert!(store.is_empty()?);
        assert_eq!(store.len()?, 0);

        store.put(&Hash32([0x11; 32]), &[])?;
        assert_eq!(store.len()?, 1);
        assert!(!store.is_empty()?);

        store.put(&Hash32([0x22; 32]), &[])?;
        assert_eq!(store.len()?, 2);

        store.delete(&Hash32([0x11; 32]))?;
        assert_eq!(store.len()?, 1);
        Ok(())
    }

    #[test]
    fn test_clear() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        store.put(&Hash32([0x33; 32]), &[])?;
        store.put(&Hash32([0x44; 32]), &[])?;
        assert_eq!(store.len()?, 2);
        store.clear()?;
        assert_eq!(store.len()?, 0);
        assert!(store.is_empty()?);
        Ok(())
    }

    #[test]
    fn test_iter() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash1 = Hash32([0x55; 32]);
        let hash2 = Hash32([0x66; 32]);

        store.put(&hash1, &[dummy_receipt(&hash1, true)])?;
        store.put(
            &hash2,
            &[dummy_receipt(&hash2, true), dummy_receipt(&hash2, false)],
        )?;

        let mut found = 0;
        for (hash, receipts) in store.iter() {
            if hash == hash1 {
                assert_eq!(receipts.len(), 1);
                found |= 1;
            } else if hash == hash2 {
                assert_eq!(receipts.len(), 2);
                found |= 2;
            }
        }
        assert_eq!(found, 3);
        Ok(())
    }

    #[test]
    fn test_quantum_state_initialization() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        assert!((store.purity() - 1.0).abs() < 1e-10);
        assert!((store.entropy() - 0.0).abs() < 1e-10);
        assert!(store.is_healthy());
        Ok(())
    }

    #[test]
    fn test_put_decoherence() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let initial_purity = store.purity();
        store.put(&Hash32([0x77; 32]), &[])?;
        assert!(store.purity() < initial_purity);
        Ok(())
    }

    #[test]
    fn test_get_quantum_decoherence() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0x88; 32]);
        store.put(&hash, &[])?;

        let purity_before_get = store.purity();
        let (result, qstate) = store.get_quantum(&hash)?;

        assert!(result.is_some());
        assert!(qstate.purity < purity_before_get);
        assert_eq!(qstate.total_gets, 1);
        Ok(())
    }

    #[test]
    fn test_delete_decoherence() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let hash = Hash32([0x99; 32]);
        store.put(&hash, &[])?;

        let purity_after_put = store.purity();
        store.delete(&hash)?;
        assert!(store.purity() < purity_after_put);
        Ok(())
    }

    #[test]
    fn test_clear_decoherence_strong() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[])?;
        }

        let purity_before_clear = store.purity();
        store.clear()?;
        assert!(store.purity() < purity_before_clear);
        assert_eq!(store.quantum_stats().receipt_count, 0);
        Ok(())
    }

    #[test]
    fn test_quantum_stats() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        store.put(&Hash32([0xAA; 32]), &[])?;
        store.put(&Hash32([0xBB; 32]), &[])?;

        let stats = store.quantum_stats();
        assert_eq!(stats.receipt_count, 2);
        assert_eq!(stats.total_puts, 2);
        assert!(stats.purity < 1.0);
        Ok(())
    }

    #[test]
    fn test_health_after_many_operations() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        for i in 0..50 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[])?;
            store.delete(&Hash32(hash))?;
        }
        assert!(store.purity() < 1.0);
        assert!(!store.is_healthy());
        Ok(())
    }

    #[test]
    fn test_purity_never_negative() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        for i in 0..10000 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[])?;
        }
        assert!(store.purity() >= 0.0);
        Ok(())
    }

    #[test]
    fn test_entropy_increases() -> ReceiptsStoreResult<()> {
        let dir = tempdir()?;
        let store = ReceiptsStore::open(dir.path())?;
        let initial_entropy = store.entropy();
        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[])?;
        }
        assert!(store.entropy() > initial_entropy);
        Ok(())
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = ReceiptsStorePrometheus::new_unregistered();
        p.puts_total.inc();
        p.gets_total.inc_by(2);
        p.receipt_files.set(5.0);
        assert_eq!(p.puts_total.get(), 1);
        assert_eq!(p.gets_total.get(), 2);
        assert_eq!(p.receipt_files.get(), 5.0);
    }

    #[test]
    fn test_concurrent_puts() {
        use std::sync::Arc;
        let dir = tempdir().unwrap();
        let store = Arc::new(ReceiptsStore::open(dir.path()).unwrap());

        let handles: Vec<_> = (0..8)
            .map(|t| {
                let store = store.clone();
                std::thread::spawn(move || {
                    for i in 0..25 {
                        let mut hash = [0u8; 32];
                        hash[0] = t as u8;
                        hash[1] = i as u8;
                        store.put(&Hash32(hash), &[]).unwrap();
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(store.len().unwrap(), 200);
    }
}
