//! Production block store for IONA.
//!
//! Features:
//! - LRU in‑memory cache for recent blocks
//! - On‑disk block storage (bincode format)
//! - Height index (height → block ID)
//! - Transaction hash index (tx_hash → block location)
//! - True atomic writes via temp file + rename + fsync
//! - fsync on block writes
//! - Pruning of old blocks with retention policy
//! - Prometheus metrics (optional) with atomic fallback
//! - Overflow‑safe counters
//! - Structured errors and logging

use crate::types::{Block, Hash32, Height, Tx};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Number of blocks to keep in the LRU cache.
pub const DEFAULT_CACHE_SIZE: usize = 256;

/// File name for the height index.
const INDEX_FILE: &str = "index.json";

/// File name for the transaction index.
const TX_INDEX_FILE: &str = "tx_index.json";

/// Extension used for temporary files during atomic writes.
const TMP_EXTENSION: &str = "tmp";

/// File extension for block files.
const BLOCK_EXTENSION: &str = "bin";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during block store operations.
#[derive(Debug, Error)]
pub enum BlockStoreError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("serialisation error: {source}")]
    Serialization {
        #[from]
        source: bincode::Error,
    },

    #[error("JSON index error: {source}")]
    Json {
        #[from]
        source: serde_json::Error,
    },

    #[error("block ID mismatch: expected {expected}, got {actual}")]
    IdMismatch { expected: String, actual: String },

    #[error("invalid hex string: {0}")]
    InvalidHex(#[from] hex::FromHexError),

    #[error("invalid hash length: expected 32 bytes, got {0}")]
    InvalidHashLength(usize),

    #[error("block not found: height {height}")]
    BlockNotFound { height: Height },

    #[error("index corrupted: {0}")]
    IndexCorrupt(String),

    #[error("metrics error: {0}")]
    Metrics(String),
}

pub type BlockStoreResult<T> = Result<T, BlockStoreError>;

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for the block store.
#[derive(Clone)]
pub struct BlockStorePrometheus {
    pub blocks_written_total: Counter,
    pub blocks_read_total: Counter,
    pub blocks_removed_total: Counter,
    pub blocks_pruned_total: Counter,
    pub cache_hits_total: Counter,
    pub cache_misses_total: Counter,
    pub best_height: Gauge,
    pub blocks_in_index: Gauge,
}

impl BlockStorePrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            blocks_written_total: register_counter!(
                "iona_blockstore_blocks_written_total",
                "Total blocks written to store"
            )?,
            blocks_read_total: register_counter!(
                "iona_blockstore_blocks_read_total",
                "Total blocks read from store"
            )?,
            blocks_removed_total: register_counter!(
                "iona_blockstore_blocks_removed_total",
                "Total blocks explicitly removed"
            )?,
            blocks_pruned_total: register_counter!(
                "iona_blockstore_blocks_pruned_total",
                "Total blocks pruned"
            )?,
            cache_hits_total: register_counter!(
                "iona_blockstore_cache_hits_total",
                "Block store LRU cache hits"
            )?,
            cache_misses_total: register_counter!(
                "iona_blockstore_cache_misses_total",
                "Block store LRU cache misses"
            )?,
            best_height: register_gauge!(
                "iona_blockstore_best_height",
                "Current best height in the block store"
            )?,
            blocks_in_index: register_gauge!(
                "iona_blockstore_blocks_in_index",
                "Number of blocks in the height index"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            blocks_written_total: Counter::new("iona_blockstore_blocks_written_total", "Written").unwrap(),
            blocks_read_total: Counter::new("iona_blockstore_blocks_read_total", "Read").unwrap(),
            blocks_removed_total: Counter::new("iona_blockstore_blocks_removed_total", "Removed").unwrap(),
            blocks_pruned_total: Counter::new("iona_blockstore_blocks_pruned_total", "Pruned").unwrap(),
            cache_hits_total: Counter::new("iona_blockstore_cache_hits_total", "Hits").unwrap(),
            cache_misses_total: Counter::new("iona_blockstore_cache_misses_total", "Misses").unwrap(),
            best_height: Gauge::new("iona_blockstore_best_height", "Best height").unwrap(),
            blocks_in_index: Gauge::new("iona_blockstore_blocks_in_index", "Blocks").unwrap(),
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics (atomic + optional Prometheus)
// -----------------------------------------------------------------------------

/// Metrics for the block store.
#[derive(Debug, Clone)]
pub struct BlockStoreMetrics {
    pub blocks_written: Arc<AtomicU64>,
    pub blocks_read: Arc<AtomicU64>,
    pub blocks_removed: Arc<AtomicU64>,
    pub blocks_pruned: Arc<AtomicU64>,
    pub cache_hits: Arc<AtomicU64>,
    pub cache_misses: Arc<AtomicU64>,
    pub prometheus: Option<Arc<BlockStorePrometheus>>,
}

impl Default for BlockStoreMetrics {
    fn default() -> Self {
        Self {
            blocks_written: Arc::new(AtomicU64::new(0)),
            blocks_read: Arc::new(AtomicU64::new(0)),
            blocks_removed: Arc::new(AtomicU64::new(0)),
            blocks_pruned: Arc::new(AtomicU64::new(0)),
            cache_hits: Arc::new(AtomicU64::new(0)),
            cache_misses: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl BlockStoreMetrics {
    /// Create a new metrics instance, optionally with Prometheus.
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(BlockStorePrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_write(&self) {
        self.blocks_written.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_written_total.inc();
        }
    }
    fn record_read(&self) {
        self.blocks_read.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_read_total.inc();
        }
    }
    fn record_remove(&self) {
        self.blocks_removed.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_removed_total.inc();
        }
    }
    fn record_prune(&self, count: u64) {
        self.blocks_pruned.fetch_add(count, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.blocks_pruned_total.inc_by(count as f64);
        }
    }
    fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_hits_total.inc();
        }
    }
    fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.cache_misses_total.inc();
        }
    }
    fn update_index_gauges(&self, best_height: Height, index_size: usize) {
        if let Some(p) = &self.prometheus {
            p.best_height.set(best_height as f64);
            p.blocks_in_index.set(index_size as f64);
        }
    }
}

/// Snapshot of block store metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct BlockStoreMetricsSnapshot {
    pub blocks_written: u64,
    pub blocks_read: u64,
    pub blocks_removed: u64,
    pub blocks_pruned: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

impl BlockStoreMetrics {
    pub fn snapshot(&self) -> BlockStoreMetricsSnapshot {
        BlockStoreMetricsSnapshot {
            blocks_written: self.blocks_written.load(Ordering::Relaxed),
            blocks_read: self.blocks_read.load(Ordering::Relaxed),
            blocks_removed: self.blocks_removed.load(Ordering::Relaxed),
            blocks_pruned: self.blocks_pruned.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Index structures
// -----------------------------------------------------------------------------

/// Height → block ID (hex) mapping.
#[derive(Default, Serialize, Deserialize)]
struct IndexFile {
    by_height: HashMap<Height, String>,
    best_height: Height,
}

/// Transaction hash → location mapping.
#[derive(Default, Serialize, Deserialize)]
struct TxIndexFile {
    locs: HashMap<String, TxLocation>,
}

// -----------------------------------------------------------------------------
// Public types
// -----------------------------------------------------------------------------

/// Location of a transaction in the block store.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxLocation {
    pub block_height: Height,
    pub block_id: String, // hex
    pub tx_index: usize,
}

// -----------------------------------------------------------------------------
// FsBlockStore
// -----------------------------------------------------------------------------

/// File‑based block store with LRU cache and transaction indexing.
pub struct FsBlockStore {
    dir: PathBuf,
    idx_path: PathBuf,
    tx_idx_path: PathBuf,
    idx: Mutex<IndexFile>,
    tx_idx: Mutex<TxIndexFile>,
    cache: Mutex<LruCache<Hash32, Block>>,
    metrics: Arc<BlockStoreMetrics>,
    fsync_on_write: bool,
}

impl std::fmt::Debug for FsBlockStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FsBlockStore")
            .field("dir", &self.dir)
            .field("cache_len", &self.cache.lock().len())
            .finish()
    }
}

impl FsBlockStore {
    /// Open or create a block store with default metrics disabled.
    pub fn open(root: impl Into<PathBuf>, cache_size: Option<usize>) -> BlockStoreResult<Self> {
        Self::open_with_options(root, cache_size, false, true)
    }

    /// Open or create a block store with explicit options.
    ///
    /// - `enable_prometheus`: if `true`, register Prometheus metrics.
    /// - `fsync_on_write`: if `true`, `fsync` each block file after writing.
    pub fn open_with_options(
        root: impl Into<PathBuf>,
        cache_size: Option<usize>,
        enable_prometheus: bool,
        fsync_on_write: bool,
    ) -> BlockStoreResult<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;
        debug!(path = %dir.display(), "opening block store");

        let idx_path = dir.join(INDEX_FILE);
        let tx_idx_path = dir.join(TX_INDEX_FILE);

        let idx = if idx_path.exists() {
            let content = fs::read_to_string(&idx_path)?;
            serde_json::from_str(&content).map_err(|e| {
                warn!(path = %idx_path.display(), error = %e, "failed to parse height index");
                BlockStoreError::IndexCorrupt(format!("height index: {}", e))
            })?
        } else {
            IndexFile::default()
        };

        let tx_idx = if tx_idx_path.exists() {
            let content = fs::read_to_string(&tx_idx_path)?;
            serde_json::from_str(&content).map_err(|e| {
                warn!(path = %tx_idx_path.display(), error = %e, "failed to parse tx index");
                BlockStoreError::IndexCorrupt(format!("tx index: {}", e))
            })?
        } else {
            TxIndexFile::default()
        };

        let cache_cap = cache_size.unwrap_or(DEFAULT_CACHE_SIZE).max(1);
        let cap = NonZeroUsize::new(cache_cap)
            .expect("cache_cap is at least 1 after .max(1)");

        let metrics = Arc::new(
            BlockStoreMetrics::new(enable_prometheus)
                .map_err(|e| BlockStoreError::Metrics(e.to_string()))?,
        );

        let store = Self {
            dir,
            idx_path,
            tx_idx_path,
            idx: Mutex::new(idx),
            tx_idx: Mutex::new(tx_idx),
            cache: Mutex::new(LruCache::new(cap)),
            metrics,
            fsync_on_write,
        };

        // Publish initial gauges.
        {
            let idx = store.idx.lock();
            store
                .metrics
                .update_index_gauges(idx.best_height, idx.by_height.len());
        }

        Ok(store)
    }

    /// Return the directory where blocks are stored.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> BlockStoreMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Return the path for a block file.
    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.{}", hex(id), BLOCK_EXTENSION))
    }

    /// Write bytes to `path` atomically: temp file + fsync + rename.
    ///
    /// Correctly preserves the target file until the new content is fully
    /// on disk, avoiding the "empty file on crash" window.
    fn atomic_write(path: &Path, bytes: &[u8], fsync: bool) -> io::Result<()> {
        let tmp_path = path.with_extension(TMP_EXTENSION);
        {
            let mut f = File::create(&tmp_path)?;
            f.write_all(bytes)?;
            if fsync {
                f.sync_all()?;
            }
        }
        // Rename is atomic on POSIX and Windows (when target exists, rename
        // on Windows replaces it since Rust uses MoveFileEx with REPLACE_EXISTING).
        fs::rename(&tmp_path, path)?;
        if fsync {
            // Also fsync the parent directory so the rename is durable.
            if let Some(parent) = path.parent() {
                if let Ok(dir) = File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Write the height index atomically.
    fn persist_index(&self) -> BlockStoreResult<()> {
        let (data, best_height, len) = {
            let idx = self.idx.lock();
            let data = serde_json::to_vec_pretty(&*idx)?;
            (data, idx.best_height, idx.by_height.len())
        };
        Self::atomic_write(&self.idx_path, &data, self.fsync_on_write)?;
        self.metrics.update_index_gauges(best_height, len);
        debug!(path = %self.idx_path.display(), "index persisted");
        Ok(())
    }

    /// Write the transaction index atomically.
    fn persist_tx_index(&self) -> BlockStoreResult<()> {
        let data = {
            let tx_idx = self.tx_idx.lock();
            serde_json::to_vec_pretty(&*tx_idx)?
        };
        Self::atomic_write(&self.tx_idx_path, &data, self.fsync_on_write)?;
        debug!(path = %self.tx_idx_path.display(), "tx index persisted");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Public API
    // -------------------------------------------------------------------------

    /// Return the best (highest) block height.
    pub fn best_height(&self) -> Height {
        self.idx.lock().best_height
    }

    /// Look up the block ID for a given height.
    pub fn block_id_by_height(&self, height: Height) -> Option<Hash32> {
        let idx = self.idx.lock();
        let hex_id = idx.by_height.get(&height)?;
        parse_hash32_hex(hex_id)
    }

    /// Retrieve a block by its hash.
    pub fn get_block(&self, id: &Hash32) -> Option<Block> {
        // 1. Try cache.
        {
            let mut cache = self.cache.lock();
            if let Some(block) = cache.get(id) {
                self.metrics.record_cache_hit();
                debug!(id = %hex(id), "cache hit");
                return Some(block.clone());
            }
            self.metrics.record_cache_miss();
        }

        // 2. Read from disk.
        let path = self.path_for(id);
        let block = match self.read_block_file(&path, id) {
            Ok(block) => block,
            Err(e) => {
                debug!(id = %hex(id), error = %e, "failed to read block");
                return None;
            }
        };
        self.metrics.record_read();

        // 3. Store in cache.
        self.cache.lock().put(*id, block.clone());
        Some(block)
    }

    /// Retrieve a block by its height (canonical chain).
    pub fn get_block_by_height(&self, height: Height) -> Option<Block> {
        let id = self.block_id_by_height(height)?;
        self.get_block(&id)
    }

    /// Store a block. Updates height index, transaction index, and cache.
    /// If a block with the same height already exists, it is overwritten.
    pub fn put_block(&self, block: Block) -> BlockStoreResult<()> {
        let id = block.id();
        let id_hex = hex(&id);
        let path = self.path_for(&id);

        // Serialize and write block atomically.
        let bytes = bincode::serialize(&block)?;
        Self::atomic_write(&path, &bytes, self.fsync_on_write)?;
        self.metrics.record_write();
        debug!(id = %id_hex, height = block.header.height, "block written");

        // Update transaction index.
        {
            let mut tx_idx = self.tx_idx.lock();
            for (i, tx) in block.txs.iter().enumerate() {
                let tx_hash = crate::types::tx_hash(tx);
                let key = hex::encode(tx_hash.0);
                tx_idx.locs.insert(
                    key,
                    TxLocation {
                        block_height: block.header.height,
                        block_id: id_hex.clone(),
                        tx_index: i,
                    },
                );
            }
        }
        self.persist_tx_index()?;

        // Update height index.
        {
            let mut idx = self.idx.lock();
            idx.by_height.insert(block.header.height, id_hex);
            if block.header.height > idx.best_height {
                idx.best_height = block.header.height;
            }
        }
        self.persist_index()?;

        // Update cache.
        self.cache.lock().put(id, block);
        Ok(())
    }

    /// Remove a block by its hash.
    /// Returns `true` if the block existed.
    pub fn remove_block(&self, id: &Hash32) -> BlockStoreResult<bool> {
        let path = self.path_for(id);
        let existed = path.exists();
        if existed {
            fs::remove_file(&path)?;
            self.metrics.record_remove();
            debug!(id = %hex(id), "block removed");
        }

        let id_hex = hex(id);

        // Remove from height index.
        {
            let mut idx = self.idx.lock();
            let height = idx
                .by_height
                .iter()
                .find_map(|(h, hid)| if hid == &id_hex { Some(*h) } else { None });
            if let Some(h) = height {
                idx.by_height.remove(&h);
                if h == idx.best_height {
                    idx.best_height = idx.by_height.keys().max().copied().unwrap_or(0);
                }
            }
        }
        self.persist_index()?;

        // Remove from transaction index.
        {
            let mut tx_idx = self.tx_idx.lock();
            tx_idx.locs.retain(|_, loc| loc.block_id != id_hex);
        }
        self.persist_tx_index()?;

        // Remove from cache.
        self.cache.lock().pop(id);
        Ok(existed)
    }

    /// Check if a block exists.
    pub fn contains_block(&self, id: &Hash32) -> bool {
        self.path_for(id).exists()
    }

    /// Prune old blocks, keeping only the most recent `keep` blocks.
    /// Returns the number of blocks removed.
    pub fn prune(&self, keep: usize) -> BlockStoreResult<usize> {
        // Snapshot and sort the heights once; avoids repeated index locks.
        let mut heights: Vec<Height> = {
            let idx = self.idx.lock();
            idx.by_height.keys().copied().collect()
        };
        if heights.len() <= keep {
            return Ok(0);
        }
        heights.sort_unstable();
        let remove_count = heights.len() - keep;
        let to_remove: Vec<Height> = heights.into_iter().take(remove_count).collect();

        let mut removed = 0usize;
        for h in to_remove {
            if let Some(id) = self.block_id_by_height(h) {
                if self.remove_block(&id)? {
                    removed = removed.saturating_add(1);
                }
            }
        }
        self.metrics.record_prune(removed as u64);
        info!(kept = keep, removed, "pruned old blocks");
        Ok(removed)
    }

    /// Look up which block contains a given transaction hash.
    pub fn tx_location(&self, tx_hash: &Hash32) -> Option<TxLocation> {
        let key = hex::encode(tx_hash.0);
        self.tx_idx.lock().locs.get(&key).cloned()
    }

    /// Read a block file and verify its ID matches the expected one.
    fn read_block_file(&self, path: &Path, expected_id: &Hash32) -> BlockStoreResult<Block> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        let block: Block = bincode::deserialize(&buf)?;
        let actual_id = block.id();
        if &actual_id != expected_id {
            return Err(BlockStoreError::IdMismatch {
                expected: hex(expected_id),
                actual: hex(&actual_id),
            });
        }
        Ok(block)
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Convert a `Hash32` to a hex string.
fn hex(h: &Hash32) -> String {
    hex::encode(h.0)
}

/// Parse a hex string into a `Hash32`.
fn parse_hash32_hex(s: &str) -> Option<Hash32> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash32(arr))
}

// -----------------------------------------------------------------------------
// Implement the `BlockStore` trait for consensus
// -----------------------------------------------------------------------------

impl crate::consensus::BlockStore for FsBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.get_block(id)
    }

    fn put(&self, block: Block) {
        if let Err(e) = self.put_block(block) {
            error!(error = %e, "failed to store block");
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader, Hash32, Tx};
    use tempfile::tempdir;

    fn dummy_block(height: Height, seed: u8) -> Block {
        let header = BlockHeader {
            height,
            round: 0,
            prev: Hash32::zero(),
            proposer_pk: vec![],
            tx_root: Hash32::zero(),
            receipts_root: Hash32::zero(),
            state_root: Hash32([seed; 32]),
            base_fee_per_gas: 1,
            gas_used: 0,
            intrinsic_gas_used: 0,
            exec_gas_used: 0,
            vm_gas_used: 0,
            evm_gas_used: 0,
            chain_id: 1,
            timestamp: 0,
            protocol_version: 1,
        };
        Block { header, txs: vec![] }
    }

    #[test]
    fn test_put_and_get() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let block = dummy_block(1, 0xAA);
        store.put_block(block.clone())?;
        let retrieved = store.get_block(&block.id()).unwrap();
        assert_eq!(retrieved.header.height, block.header.height);
        assert_eq!(retrieved.header.state_root, block.header.state_root);
        Ok(())
    }

    #[test]
    fn test_best_height() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        assert_eq!(store.best_height(), 0);
        let b1 = dummy_block(1, 0x01);
        let b2 = dummy_block(2, 0x02);
        store.put_block(b1)?;
        assert_eq!(store.best_height(), 1);
        store.put_block(b2)?;
        assert_eq!(store.best_height(), 2);
        Ok(())
    }

    #[test]
    fn test_block_id_by_height() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let b1 = dummy_block(5, 0x05);
        let b2 = dummy_block(10, 0x0A);
        store.put_block(b1.clone())?;
        store.put_block(b2.clone())?;
        let id1 = store.block_id_by_height(5).unwrap();
        let id2 = store.block_id_by_height(10).unwrap();
        assert_eq!(id1, b1.id());
        assert_eq!(id2, b2.id());
        assert!(store.block_id_by_height(7).is_none());
        Ok(())
    }

    #[test]
    fn test_tx_location_none() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let tx_hash = Hash32([0x11; 32]);
        assert!(store.tx_location(&tx_hash).is_none());
        Ok(())
    }

    #[test]
    fn test_remove_block() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let block = dummy_block(42, 0x42);
        store.put_block(block.clone())?;
        assert!(store.contains_block(&block.id()));
        let removed = store.remove_block(&block.id())?;
        assert!(removed);
        assert!(!store.contains_block(&block.id()));
        assert!(store.get_block(&block.id()).is_none());
        assert_eq!(store.best_height(), 0);
        Ok(())
    }

    #[test]
    fn test_remove_nonexistent() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let block = dummy_block(1, 0x01);
        let removed = store.remove_block(&block.id())?;
        assert!(!removed);
        Ok(())
    }

    #[test]
    fn test_prune() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        for i in 1..=10 {
            let block = dummy_block(i, i as u8);
            store.put_block(block)?;
        }
        assert_eq!(store.best_height(), 10);
        let removed = store.prune(5)?;
        assert_eq!(removed, 5);
        // best_height stays as the highest retained height (10).
        assert_eq!(store.best_height(), 10);
        for i in 1..=5 {
            assert!(store.block_id_by_height(i).is_none());
        }
        for i in 6..=10 {
            assert!(store.block_id_by_height(i).is_some());
        }
        Ok(())
    }

    #[test]
    fn test_prune_no_op_when_within_limit() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        for i in 1..=3 {
            store.put_block(dummy_block(i, i as u8))?;
        }
        assert_eq!(store.prune(5)?, 0);
        assert_eq!(store.best_height(), 3);
        Ok(())
    }

    #[test]
    fn test_cache_hits_and_misses() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), None)?;
        let block = dummy_block(1, 0xAA);
        store.put_block(block.clone())?;
        // First read: cache hit (put populated the cache).
        let _ = store.get_block(&block.id());
        // Second read: still a cache hit.
        let _ = store.get_block(&block.id());
        let snap = store.metrics_snapshot();
        assert!(snap.cache_hits >= 2);
        Ok(())
    }

    #[test]
    fn test_cache_eviction() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let store = FsBlockStore::open(dir.path(), Some(2))?;
        let b1 = dummy_block(1, 0x01);
        let b2 = dummy_block(2, 0x02);
        let b3 = dummy_block(3, 0x03);
        store.put_block(b1.clone())?;
        store.put_block(b2.clone())?;
        store.put_block(b3.clone())?;
        // b1 should be evicted; reading it triggers a disk read.
        let before = store.metrics_snapshot().cache_misses;
        let _ = store.get_block(&b1.id());
        let after = store.metrics_snapshot().cache_misses;
        assert!(after > before, "expected cache miss for evicted block");
        Ok(())
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = BlockStorePrometheus::new_unregistered();
        p.blocks_written_total.inc();
        p.blocks_written_total.inc_by(2);
        p.cache_hits_total.inc();
        p.best_height.set(42.0);
        assert_eq!(p.blocks_written_total.get(), 3);
        assert_eq!(p.cache_hits_total.get(), 1);
        assert_eq!(p.best_height.get(), 42.0);
    }

    #[test]
    fn test_reopen_preserves_index() -> BlockStoreResult<()> {
        let dir = tempdir().unwrap();
        let b1 = dummy_block(1, 0x01);
        let b2 = dummy_block(2, 0x02);
        {
            let store = FsBlockStore::open(dir.path(), None)?;
            store.put_block(b1.clone())?;
            store.put_block(b2.clone())?;
        }
        let store = FsBlockStore::open(dir.path(), None)?;
        assert_eq!(store.best_height(), 2);
        assert_eq!(store.block_id_by_height(1), Some(b1.id()));
        assert_eq!(store.block_id_by_height(2), Some(b2.id()));
        Ok(())
    }
}
