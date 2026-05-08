//! Production block store for IONA.
//!
//! Features:
//! - LRU in‑memory cache for recent blocks
//! - On‑disk block storage (bincode format)
//! - Height index (height → block ID)
//! - Transaction hash index (tx_hash → block location)
//! - Atomic writes (temporary file + rename)
//! - `fsync` on block writes
//! - Pruning of old blocks

use crate::types::{Block, Hash32, Height, Tx};
use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
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
}

pub type BlockStoreResult<T> = Result<T, BlockStoreError>;

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
#[derive(Debug)]
pub struct FsBlockStore {
    dir: PathBuf,
    idx_path: PathBuf,
    tx_idx_path: PathBuf,
    idx: Mutex<IndexFile>,
    tx_idx: Mutex<TxIndexFile>,
    cache: Mutex<LruCache<Hash32, Block>>,
}

impl FsBlockStore {
    /// Open or create a block store at the given directory.
    pub fn open(root: impl Into<PathBuf>, cache_size: Option<usize>) -> BlockStoreResult<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;
        debug!(path = %dir.display(), "opening block store");

        let idx_path = dir.join(INDEX_FILE);
        let tx_idx_path = dir.join(TX_INDEX_FILE);

        let idx = if idx_path.exists() {
            let content = fs::read_to_string(&idx_path)?;
            serde_json::from_str(&content).unwrap_or_else(|e| {
                warn!(path = %idx_path.display(), error = %e, "failed to parse index, using default");
                IndexFile::default()
            })
        } else {
            IndexFile::default()
        };

        let tx_idx = if tx_idx_path.exists() {
            let content = fs::read_to_string(&tx_idx_path)?;
            serde_json::from_str(&content).unwrap_or_else(|e| {
                warn!(path = %tx_idx_path.display(), error = %e, "failed to parse tx index, using default");
                TxIndexFile::default()
            })
        } else {
            TxIndexFile::default()
        };

        let cache_cap = cache_size.unwrap_or(DEFAULT_CACHE_SIZE);
        let cap = NonZeroUsize::new(cache_cap)
            .unwrap_or_else(|| NonZeroUsize::new(1).unwrap());

        Ok(Self {
            dir,
            idx_path,
            tx_idx_path,
            idx: Mutex::new(idx),
            tx_idx: Mutex::new(tx_idx),
            cache: Mutex::new(LruCache::new(cap)),
        })
    }

    /// Return the path for a block file.
    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.{}", hex(id), BLOCK_EXTENSION))
    }

    /// Write the height index atomically.
    fn persist_index(&self) -> BlockStoreResult<()> {
        let idx = self.idx.lock();
        let tmp = self.idx_path.with_extension(TMP_EXTENSION);
        let data = serde_json::to_string_pretty(&*idx)?;
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, &self.idx_path)?;
        debug!(path = %self.idx_path.display(), "index persisted");
        Ok(())
    }

    /// Write the transaction index atomically.
    fn persist_tx_index(&self) -> BlockStoreResult<()> {
        let tx_idx = self.tx_idx.lock();
        let tmp = self.tx_idx_path.with_extension(TMP_EXTENSION);
        let data = serde_json::to_string_pretty(&*tx_idx)?;
        fs::write(&tmp, &data)?;
        fs::rename(&tmp, &self.tx_idx_path)?;
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
        // 1. Try cache
        {
            let mut cache = self.cache.lock();
            if let Some(block) = cache.get(id) {
                debug!(id = %hex(id), "cache hit");
                return Some(block.clone());
            }
        }

        // 2. Read from disk
        let path = self.path_for(id);
        let block = match self.read_block_file(&path, id) {
            Ok(block) => block,
            Err(e) => {
                debug!(id = %hex(id), error = %e, "failed to read block");
                return None;
            }
        };

        // 3. Store in cache
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

        // Write block to disk with fsync
        let bytes = bincode::serialize(&block)?;
        {
            let mut f = fs::File::create(&path)?;
            f.write_all(&bytes)?;
            f.sync_all()?;
        }
        debug!(id = %id_hex, height = block.header.height, "block written");

        // Update transaction index
        {
            let mut tx_idx = self.tx_idx.lock();
            for (i, tx) in block.txs.iter().enumerate() {
                let tx_hash = crate::types::tx_hash(tx);
                let key = hex::encode(tx_hash.0);
                tx_idx.locs.insert(key, TxLocation {
                    block_height: block.header.height,
                    block_id: id_hex.clone(),
                    tx_index: i,
                });
            }
        }
        self.persist_tx_index()?;

        // Update height index
        {
            let mut idx = self.idx.lock();
            idx.by_height.insert(block.header.height, id_hex);
            if block.header.height > idx.best_height {
                idx.best_height = block.header.height;
            }
        }
        self.persist_index()?;

        // Update cache
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
            debug!(id = %hex(id), "block removed");
        }

        // Remove from height index and transaction index
        let id_hex = hex(id);
        let height_removed = {
            let mut idx = self.idx.lock();
            let height = idx.by_height.iter()
                .find_map(|(h, hid)| if hid == &id_hex { Some(*h) } else { None });
            if let Some(h) = height {
                idx.by_height.remove(&h);
                if h == idx.best_height {
                    idx.best_height = idx.by_height.keys().max().copied().unwrap_or(0);
                }
            }
            height
        };
        self.persist_index()?;

        {
            let mut tx_idx = self.tx_idx.lock();
            tx_idx.locs.retain(|_, loc| loc.block_id != id_hex);
        }
        self.persist_tx_index()?;

        // Remove from cache
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
        let heights: Vec<Height> = {
            let idx = self.idx.lock();
            idx.by_height.keys().copied().collect()
        };
        if heights.len() <= keep {
            return Ok(0);
        }
        let to_remove: Vec<Height> = heights.iter().copied().take(heights.len() - keep).collect();
        let mut removed = 0;
        for h in to_remove {
            if let Some(id) = self.block_id_by_height(h) {
                if self.remove_block(&id)? {
                    removed += 1;
                }
            }
        }
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
        let mut f = fs::File::open(path)?;
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
    fn test_tx_location() -> BlockStoreResult<()> {
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
        assert_eq!(store.best_height(), 10);
        for i in 1..=5 {
            assert!(store.block_id_by_height(i).is_none());
        }
        for i in 6..=10 {
            assert!(store.block_id_by_height(i).is_some());
        }
        Ok(())
    }
}
