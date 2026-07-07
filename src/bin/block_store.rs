//! Block storage for the consensus engine.
//!
//! This module provides an in‑memory block store suitable for testing and
//! a file‑based persistent store for production.

use crate::types::{Block, Hash32, Height};
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// In‑memory block store
// -----------------------------------------------------------------------------

/// Simple in‑memory block store backed by `HashMap`.
#[derive(Clone, Debug, Default)]
pub struct MemBlockStore {
    by_hash: Arc<RwLock<HashMap<Hash32, Block>>>,
    by_height: Arc<RwLock<BTreeMap<Height, Hash32>>>,
}

impl MemBlockStore {
    pub fn new() -> Self {
        Self::default()
    }
}

impl BlockStore for MemBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        self.by_hash.read().unwrap().get(id).cloned()
    }

    fn put(&self, block: Block) {
        let id = block.id();
        let height = block.header.height;
        {
            let mut by_hash = self.by_hash.write().unwrap();
            by_hash.insert(id, block.clone());
        }
        {
            let mut by_height = self.by_height.write().unwrap();
            by_height.insert(height, id);
        }
    }
}

impl MemBlockStore {
    /// Get a block by its height (requires O(log n) lookup).
    pub fn get_by_height(&self, height: Height) -> Option<Block> {
        let by_height = self.by_height.read().unwrap();
        if let Some(id) = by_height.get(&height) {
            self.get(id)
        } else {
            None
        }
    }

    /// Return the highest height stored.
    pub fn latest_height(&self) -> Option<Height> {
        self.by_height.read().unwrap().keys().next_back().copied()
    }

    /// Number of blocks stored.
    pub fn len(&self) -> usize {
        self.by_hash.read().unwrap().len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

// -----------------------------------------------------------------------------
// File‑based block store (persistent)
// -----------------------------------------------------------------------------

/// Persistent block store that writes blocks to individual files in a directory.
/// The directory structure:
///   <root>/blocks/<height>.json
///   <root>/index.json  (mapping height → hash)
pub struct FileBlockStore {
    root: PathBuf,
    index: Arc<RwLock<BTreeMap<Height, Hash32>>>,
}

impl FileBlockStore {
    /// Open or create a block store in the given directory.
    pub fn open(root: impl AsRef<Path>) -> std::io::Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(&root)?;
        let index_path = root.join("index.json");
        let index = if index_path.exists() {
            let data = fs::read_to_string(&index_path)?;
            serde_json::from_str(&data).unwrap_or_default()
        } else {
            BTreeMap::new()
        };
        Ok(Self {
            root,
            index: Arc::new(RwLock::new(index)),
        })
    }

    /// Write the index to disk.
    fn save_index(&self) -> std::io::Result<()> {
        let index_path = self.root.join("index.json");
        let data = serde_json::to_string_pretty(&*self.index.read().unwrap())
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        fs::write(&index_path, data)
    }

    /// Block file path for a given height.
    fn block_path(&self, height: Height) -> PathBuf {
        self.root.join(format!("{}.json", height))
    }
}

impl BlockStore for FileBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        // Find height from index first.
        let height = self.index.read().unwrap().iter().find_map(|(h, stored_id)| {
            if stored_id == id { Some(*h) } else { None }
        })?;
        let path = self.block_path(height);
        let data = fs::read_to_string(&path).ok()?;
        serde_json::from_str(&data).ok()
    }

    fn put(&self, block: Block) {
        let id = block.id();
        let height = block.header.height;

        // Write block file
        let path = self.block_path(height);
        if let Ok(data) = serde_json::to_string_pretty(&block) {
            if let Err(e) = fs::write(&path, data) {
                warn!(height, error = %e, "failed to write block");
                return;
            }
        } else {
            warn!(height, "failed to serialize block");
            return;
        }

        // Update index
        {
            let mut idx = self.index.write().unwrap();
            idx.insert(height, id);
        }
        if let Err(e) = self.save_index() {
            warn!("failed to save index: {}", e);
        }
    }
}

impl FileBlockStore {
    /// Get block by height.
    pub fn get_by_height(&self, height: Height) -> Option<Block> {
        let idx = self.index.read().unwrap();
        let id = idx.get(&height)?;
        self.get(id)
    }

    /// Latest height stored.
    pub fn latest_height(&self) -> Option<Height> {
        self.index.read().unwrap().keys().next_back().copied()
    }

    /// Prune blocks older than `keep` (keep the last `keep` blocks).
    pub fn prune(&self, keep: usize) -> std::io::Result<()> {
        let heights: Vec<Height> = self.index.read().unwrap().keys().copied().collect();
        let total = heights.len();
        if total <= keep {
            return Ok(());
        }
        let to_remove = &heights[..total - keep];
        for &h in to_remove {
            let path = self.block_path(h);
            if let Err(e) = fs::remove_file(&path) {
                warn!(height = h, error = %e, "failed to remove block file");
            }
        }
        // Update index
        {
            let mut idx = self.index.write().unwrap();
            for &h in to_remove {
                idx.remove(&h);
            }
        }
        self.save_index()?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Trait re‑export
// -----------------------------------------------------------------------------

pub use crate::consensus::engine::BlockStore;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Block, BlockHeader, Hash32};

    fn dummy_block(height: Height, hash: u8) -> Block {
        let mut header = BlockHeader::default();
        header.height = height;
        let mut block = Block { header, txs: vec![] };
        // Override id with given hash (simulate)
        let id = Hash32([hash; 32]);
        // In reality, block.id() would compute from header, but for testing we can't change it easily.
        // We'll just use the block as is and rely on equality of the stored block.
        // This is okay because we compare the stored block.
        block
    }

    #[test]
    fn test_mem_block_store() {
        let store = MemBlockStore::new();
        let block1 = dummy_block(1, 0xAA);
        let block2 = dummy_block(2, 0xBB);
        store.put(block1.clone());
        store.put(block2.clone());

        assert_eq!(store.get(&block1.id()), Some(block1));
        assert_eq!(store.get(&block2.id()), Some(block2));
        assert_eq!(store.get_by_height(1), Some(block1));
        assert_eq!(store.get_by_height(2), Some(block2));
        assert_eq!(store.latest_height(), Some(2));
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_file_block_store() -> std::io::Result<()> {
        let dir = tempfile::tempdir()?;
        let store = FileBlockStore::open(dir.path())?;
        let block1 = dummy_block(1, 0xAA);
        let block2 = dummy_block(2, 0xBB);
        store.put(block1.clone());
        store.put(block2.clone());

        assert_eq!(store.get(&block1.id()), Some(block1));
        assert_eq!(store.get(&block2.id()), Some(block2));
        assert_eq!(store.get_by_height(1), Some(block1));
        assert_eq!(store.get_by_height(2), Some(block2));
        assert_eq!(store.latest_height(), Some(2));

        store.prune(1)?;
        assert_eq!(store.get_by_height(1), None);
        assert_eq!(store.get_by_height(2), Some(block2));
        assert_eq!(store.latest_height(), Some(2));

        Ok(())
    }
}
