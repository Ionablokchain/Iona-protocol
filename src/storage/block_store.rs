//! Production block store for IONA.
//!
//! Features:
//! - LRU in-memory cache for recent blocks
//! - Sharded on-disk block storage (first two hex chars as subdir)
//! - Atomic block writes (tmp + rename + fsync)
//! - Single atomic metadata file (`meta.json`) containing:
//!   - canonical height -> block id mapping
//!   - best height
//!   - tx-hash -> (height, block_id, tx_index) index
//! - Rebuild / integrity verification helpers
//! - Reorg-safe overwrite handling at the same height

use crate::types::{Block, Hash32, Height};
use lru::LruCache;
use parking_lot::Mutex;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use tracing::{debug, error, warn};

const CACHE_SIZE: usize = 256;
const META_FILE_NAME: &str = "meta.json";

fn hex_str(h: &Hash32) -> String {
    hex::encode(h.0)
}

fn parse_hash32_hex(s: &str) -> Option<Hash32> {
    let bytes = hex::decode(s).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Some(Hash32(arr))
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> io::Result<()> {
    File::open(path)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> io::Result<()> {
    Ok(())
}

fn json_to_io(err: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn bincode_to_io<E: std::error::Error + Send + Sync + 'static>(err: E) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn read_json_or_default<T>(path: &Path, label: &str) -> io::Result<(T, bool)>
where
    T: DeserializeOwned + Default,
{
    if !path.exists() {
        return Ok((T::default(), false));
    }

    let s = fs::read_to_string(path)?;
    match serde_json::from_str::<T>(&s) {
        Ok(v) => Ok((v, false)),
        Err(e) => {
            warn!("{label} is corrupted, will rebuild: {e}");
            Ok((T::default(), true))
        }
    }
}

/// Per-transaction location index entry.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxLocation {
    pub block_height: Height,
    pub block_id: String, // hex
    pub tx_index: usize,
}

/// Persisted metadata file.
/// Stored atomically as one unit to avoid partial index inconsistencies.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct StoreMeta {
    by_height: HashMap<Height, String>,
    best_height: Height,
    tx_locs: HashMap<String, TxLocation>,
}

pub struct FsBlockStore {
    dir: PathBuf,
    meta_path: PathBuf,
    meta: Mutex<StoreMeta>,
    cache: Mutex<LruCache<Hash32, Block>>,
}

impl FsBlockStore {
    /// Open or create a block store at `root`.
    ///
    /// If metadata is missing or corrupted, it will be rebuilt from block files.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;

        let meta_path = dir.join(META_FILE_NAME);

        // Best-effort cleanup of stale temp files from previous crashes.
        if let Err(e) = Self::cleanup_tmp_files(&dir) {
            warn!("temp cleanup failed: {e}");
        }

        let (meta, rebuild_meta) = read_json_or_default::<StoreMeta>(&meta_path, "block store metadata")?;

        let store = Self {
            dir,
            meta_path,
            meta: Mutex::new(meta),
            cache: Mutex::new({
                let cap = NonZeroUsize::new(CACHE_SIZE).unwrap_or_else(|| {
                    warn!("CACHE_SIZE=0, falling back to 1");
                    NonZeroUsize::new(1).unwrap()
                });
                LruCache::new(cap)
            }),
        };

        if rebuild_meta || (store.meta.lock().by_height.is_empty() && store.contains_any_blocks()?) {
            store.rebuild_metadata()?;
        }

        Ok(store)
    }

    fn cleanup_tmp_files(root: &Path) -> io::Result<()> {
        if !root.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(root)? {
            let entry = entry?;
            let path = entry.path();

            if path.is_file() {
                if path.extension().and_then(|e| e.to_str()) == Some("tmp") {
                    let _ = fs::remove_file(&path);
                }
                continue;
            }

            if path.is_dir() {
                for file in fs::read_dir(&path)? {
                    let file = file?;
                    let fpath = file.path();
                    if fpath.extension().and_then(|e| e.to_str()) == Some("tmp") {
                        let _ = fs::remove_file(&fpath);
                    }
                }
            }
        }

        Ok(())
    }

    fn contains_any_blocks(&self) -> io::Result<bool> {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if !path.is_dir() {
                continue;
            }

            for file in fs::read_dir(path)? {
                let file = file?;
                let fpath = file.path();
                if fpath.is_file() && fpath.extension().and_then(|e| e.to_str()) == Some("bin") {
                    return Ok(true);
                }
            }
        }
        Ok(false)
    }

    fn shard_dir_for_id(&self, id: &Hash32) -> PathBuf {
        let hex_id = hex_str(id);
        let (shard, _) = hex_id.split_at(2);
        self.dir.join(shard)
    }

    fn block_path(&self, id: &Hash32) -> PathBuf {
        let hex_id = hex_str(id);
        let (shard, rest) = hex_id.split_at(2);
        self.dir.join(shard).join(format!("{rest}.bin"))
    }

    fn ensure_block_dir(&self, id: &Hash32) -> io::Result<()> {
        fs::create_dir_all(self.shard_dir_for_id(id))
    }

    fn atomic_write(&self, path: &Path, data: &[u8]) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        let tmp_path = path.with_extension("tmp");

        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(data)?;
            tmp.sync_all()?;
        }

        fs::rename(&tmp_path, path)?;

        if let Some(parent) = path.parent() {
            if let Err(e) = sync_dir(parent) {
                warn!("directory sync failed for {}: {}", parent.display(), e);
            }
        }

        Ok(())
    }

    fn persist_meta(&self) -> io::Result<()> {
        let snapshot = self.meta.lock().clone();
        let data = serde_json::to_string_pretty(&snapshot).map_err(json_to_io)?;
        self.atomic_write(&self.meta_path, data.as_bytes())
    }

    fn read_block_file(&self, path: &Path, expected_id: &Hash32) -> io::Result<Block> {
        let mut f = File::open(path)?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;

        let block: Block = bincode::deserialize(&buf).map_err(bincode_to_io)?;
        let actual_id = block.id();

        if &actual_id != expected_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "block id mismatch for {}: expected {}, got {}",
                    path.display(),
                    hex_str(expected_id),
                    hex_str(&actual_id)
                ),
            ));
        }

        Ok(block)
    }

    fn scan_blocks<F>(&self, mut f: F) -> io::Result<()>
    where
        F: FnMut(Hash32, String, Block),
    {
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let shard_dir = entry.path();

            if !shard_dir.is_dir() {
                continue;
            }

            let shard = match shard_dir.file_name().and_then(|s| s.to_str()) {
                Some(s) if s.len() == 2 => s.to_owned(),
                _ => continue,
            };

            for file in fs::read_dir(&shard_dir)? {
                let file = file?;
                let path = file.path();

                if !path.is_file() {
                    continue;
                }

                let name = match path.file_name().and_then(|s| s.to_str()) {
                    Some(s) if s.ends_with(".bin") => s,
                    _ => continue,
                };

                let stem = &name[..name.len() - 4];
                let id_hex = format!("{shard}{stem}");

                let expected_id = match parse_hash32_hex(&id_hex) {
                    Some(id) => id,
                    None => {
                        warn!("skipping malformed block filename {}", path.display());
                        continue;
                    }
                };

                match self.read_block_file(&path, &expected_id) {
                    Ok(block) => f(expected_id, id_hex, block),
                    Err(e) => warn!("skipping invalid block {}: {}", path.display(), e),
                }
            }
        }

        Ok(())
    }

    /// Safer block write path that returns an error.
    pub fn put_checked(&self, block: Block) -> io::Result<()> {
        let id = block.id();
        let id_hex = hex_str(&id);
        let path = self.block_path(&id);

        self.ensure_block_dir(&id)?;

        let bytes = bincode::serialize(&block).map_err(bincode_to_io)?;

        // 1. Persist the block first.
        self.atomic_write(&path, &bytes)?;

        // 2. Precompute tx index updates.
        let tx_updates: Vec<(String, TxLocation)> = block
            .txs
            .iter()
            .enumerate()
            .map(|(i, tx)| {
                let tx_hash = crate::types::tx_hash(tx);
                (
                    hex::encode(tx_hash.0),
                    TxLocation {
                        block_height: block.header.height,
                        block_id: id_hex.clone(),
                        tx_index: i,
                    },
                )
            })
            .collect();

        // 3. Update metadata in memory.
        let old_block_id = {
            let mut meta = self.meta.lock();

            let old = meta.by_height.insert(block.header.height, id_hex.clone());
            if block.header.height > meta.best_height {
                meta.best_height = block.header.height;
            }

            if let Some(ref old_hex) = old {
                meta.tx_locs.retain(|_, loc| loc.block_id != *old_hex);
            }

            for (tx_hex, loc) in tx_updates {
                meta.tx_locs.insert(tx_hex, loc);
            }

            old
        };

        // 4. Persist metadata atomically.
        self.persist_meta()?;

        // 5. Best-effort cleanup of overwritten canonical block file and cache entry.
        if let Some(old_hex) = old_block_id {
            if old_hex != id_hex {
                if let Some(old_id) = parse_hash32_hex(&old_hex) {
                    let old_path = self.block_path(&old_id);

                    if let Err(e) = fs::remove_file(&old_path) {
                        if e.kind() != io::ErrorKind::NotFound {
                            warn!("failed to remove overwritten block {}: {}", old_hex, e);
                        }
                    }

                    self.cache.lock().pop(&old_id);

                    if let Some(parent) = old_path.parent() {
                        let _ = fs::remove_dir(parent);
                    }
                }
            }
        }

        // 6. Update cache last.
        self.cache.lock().put(id, block);
        Ok(())
    }

    /// Remove a block file and all metadata references to it.
    ///
    /// Returns `true` if the block file existed on disk.
    pub fn remove_block(&self, id: &Hash32) -> io::Result<bool> {
        let path = self.block_path(id);
        let existed = path.exists();
        let id_hex = hex_str(id);

        if existed {
            fs::remove_file(&path)?;
        }

        {
            let mut meta = self.meta.lock();

            let height_to_remove = meta
                .by_height
                .iter()
                .find(|(_, v)| **v == id_hex)
                .map(|(h, _)| *h);

            if let Some(h) = height_to_remove {
                meta.by_height.remove(&h);
                if h == meta.best_height {
                    meta.best_height = meta.by_height.keys().max().copied().unwrap_or(0);
                }
            }

            meta.tx_locs.retain(|_, loc| loc.block_id != id_hex);
        }

        self.persist_meta()?;
        self.cache.lock().pop(id);

        if let Some(parent) = path.parent() {
            let _ = fs::remove_dir(parent);
        }

        Ok(existed)
    }

    /// Rebuild all metadata by scanning on-disk block files.
    pub fn rebuild_metadata(&self) -> io::Result<()> {
        debug!("rebuilding block-store metadata from disk...");

        let mut rebuilt = StoreMeta::default();

        self.scan_blocks(|_id, id_hex, block| {
            let h = block.header.height;
            rebuilt.by_height.insert(h, id_hex.clone());
            if h > rebuilt.best_height {
                rebuilt.best_height = h;
            }

            for (i, tx) in block.txs.iter().enumerate() {
                let tx_hash = crate::types::tx_hash(tx);
                rebuilt.tx_locs.insert(
                    hex::encode(tx_hash.0),
                    TxLocation {
                        block_height: h,
                        block_id: id_hex.clone(),
                        tx_index: i,
                    },
                );
            }
        })?;

        *self.meta.lock() = rebuilt;
        self.persist_meta()?;

        debug!(
            "metadata rebuilt: best_height={}, tx_entries={}",
            self.best_height(),
            self.meta.lock().tx_locs.len()
        );

        Ok(())
    }

    /// Verify that:
    /// - every height index entry points to a valid block
    /// - the block height matches the indexed height
    /// - every tx index entry points to a valid block and valid tx index
    pub fn verify_integrity(&self) -> io::Result<()> {
        let meta = self.meta.lock().clone();

        for (height, id_hex) in &meta.by_height {
            let id = parse_hash32_hex(id_hex).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, format!("invalid block hex id: {id_hex}"))
            })?;

            let path = self.block_path(&id);
            let block = self.read_block_file(&path, &id)?;
            if &block.header.height != height {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "height index mismatch for {}: indexed {}, actual {}",
                        id_hex, height, block.header.height
                    ),
                ));
            }
        }

        for (tx_hash_hex, loc) in &meta.tx_locs {
            let block_id = parse_hash32_hex(&loc.block_id).ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid tx location block id for tx {tx_hash_hex}: {}", loc.block_id),
                )
            })?;

            let path = self.block_path(&block_id);
            let block = self.read_block_file(&path, &block_id)?;

            if block.header.height != loc.block_height {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "tx location height mismatch for tx {}: indexed {}, actual {}",
                        tx_hash_hex, loc.block_height, block.header.height
                    ),
                ));
            }

            if loc.tx_index >= block.txs.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "tx index out of bounds for tx {}: index {}, block tx count {}",
                        tx_hash_hex,
                        loc.tx_index,
                        block.txs.len()
                    ),
                ));
            }

            let actual_tx_hash = crate::types::tx_hash(&block.txs[loc.tx_index]);
            if hex::encode(actual_tx_hash.0) != *tx_hash_hex {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!(
                        "tx hash mismatch at indexed location for tx {} in block {}",
                        tx_hash_hex, loc.block_id
                    ),
                ));
            }
        }

        Ok(())
    }

    /// Returns the canonical best height.
    pub fn best_height(&self) -> Height {
        self.meta.lock().best_height
    }

    /// Returns the canonical block id for a height.
    pub fn block_id_by_height(&self, h: Height) -> Option<Hash32> {
        let meta = self.meta.lock();
        let hex_id = meta.by_height.get(&h)?;
        parse_hash32_hex(hex_id)
    }

    /// Lookup block location for a transaction hash.
    pub fn tx_location(&self, tx_hash: &Hash32) -> Option<TxLocation> {
        let key = hex::encode(tx_hash.0);
        self.meta.lock().tx_locs.get(&key).cloned()
    }
}

impl crate::consensus::BlockStore for FsBlockStore {
    fn get(&self, id: &Hash32) -> Option<Block> {
        {
            let mut cache = self.cache.lock();
            if let Some(block) = cache.get(id) {
                debug!("block cache hit: {}", hex_str(id));
                return Some(block.clone());
            }
        }

        let path = self.block_path(id);
        let block = match self.read_block_file(&path, id) {
            Ok(block) => block,
            Err(e) => {
                debug!("failed to read block {} from {}: {}", hex_str(id), path.display(), e);
                return None;
            }
        };

        self.cache.lock().put(id.clone(), block.clone());
        Some(block)
    }

    fn put(&self, block: Block) {
        if let Err(e) = self.put_checked(block) {
            error!("failed to persist block: {}", e);
        }
    }
}
