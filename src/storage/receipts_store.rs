//! Persistent storage for transaction receipts.
//!
//! Each receipt set is stored as a separate JSON file named by the transaction hash.
//! Writes are atomic (write to temp file then rename) to prevent corruption.
//!
//! # Example
//!
//! ```
//! use iona::storage::receipts_store::ReceiptsStore;
//! use iona::types::{Hash32, Receipt};
//!
//! let store = ReceiptsStore::open("./data/receipts").unwrap();
//! let hash = Hash32([0xAA; 32]);
//! let receipts = vec![/* ... */];
//! store.put(&hash, &receipts).unwrap();
//! let loaded = store.get(&hash).unwrap();
//! ```

use crate::types::{Hash32, Receipt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// ReceiptsStore
// -----------------------------------------------------------------------------

/// Store for transaction receipts, one file per transaction hash.
///
/// This store is **not** internally synchronized. If multiple threads may write
/// the same hash concurrently, external synchronization (e.g., a `Mutex`) is required.
#[derive(Debug, Clone)]
pub struct ReceiptsStore {
    dir: PathBuf,
}

impl ReceiptsStore {
    /// Opens a receipt store at the given directory. Creates the directory if missing.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;
        debug!(path = %dir.display(), "opened receipts store");
        Ok(Self { dir })
    }

    /// Returns the file path for a given transaction hash.
    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(id.0)))
    }

    /// Stores a list of receipts for a transaction.
    ///
    /// The write is atomic: data is first written to a temporary file, then renamed.
    pub fn put(&self, id: &Hash32, receipts: &[Receipt]) -> io::Result<()> {
        let path = self.path_for(id);
        let tmp_path = path.with_extension("tmp");

        debug!(hash = %hex::encode(id.0), count = receipts.len(), "storing receipts");

        let json = serde_json::to_string_pretty(receipts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("receipt encode: {}", e)))?;

        // Write to temporary file.
        if let Err(e) = fs::write(&tmp_path, &json) {
            error!(path = %tmp_path.display(), error = %e, "failed to write temporary receipts file");
            return Err(e);
        }

        // Atomically replace the target file.
        if let Err(e) = fs::rename(&tmp_path, &path) {
            error!(from = %tmp_path.display(), to = %path.display(), error = %e, "failed to rename receipts file");
            return Err(e);
        }

        debug!(path = %path.display(), "receipts stored");
        Ok(())
    }

    /// Retrieves the list of receipts for a transaction, if any.
    pub fn get(&self, id: &Hash32) -> io::Result<Option<Vec<Receipt>>> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }

        let s = fs::read_to_string(&path).map_err(|e| {
            error!(path = %path.display(), error = %e, "failed to read receipts file");
            e
        })?;

        let receipts = serde_json::from_str(&s).map_err(|e| {
            error!(path = %path.display(), error = %e, "failed to parse receipts JSON");
            io::Error::new(io::ErrorKind::InvalidData, format!("receipt decode: {}", e))
        })?;

        debug!(hash = %hex::encode(id.0), count = receipts.len(), "loaded receipts");
        Ok(Some(receipts))
    }

    /// Checks if receipts exist for a given transaction.
    pub fn exists(&self, id: &Hash32) -> bool {
        self.path_for(id).exists()
    }

    /// Deletes the receipts file for a transaction.
    pub fn delete(&self, id: &Hash32) -> io::Result<()> {
        let path = self.path_for(id);
        if path.exists() {
            debug!(hash = %hex::encode(id.0), "deleting receipts file");
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Returns the number of stored receipt files (not the number of receipts).
    pub fn len(&self) -> io::Result<usize> {
        let mut count = 0;
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            if entry.path().extension().map(|ext| ext == "json").unwrap_or(false) {
                count += 1;
            }
        }
        Ok(count)
    }

    /// Returns `true` if the store contains no receipt files.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Clears all receipt files from the store.
    pub fn clear(&self) -> io::Result<()> {
        debug!(dir = %self.dir.display(), "clearing all receipts");
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                fs::remove_file(path)?;
            }
        }
        Ok(())
    }

    /// Iterates over all stored receipt files, returning `(hash, receipts)` pairs.
    /// This may be expensive for large stores.
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
            self.index += 1;
            let path = entry.path();
            if path.extension().map(|ext| ext == "json").unwrap_or(false) {
                let file_stem = path.file_stem()?.to_str()?;
                let hash_bytes = hex::decode(file_stem).ok()?;
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
    fn test_put_and_get() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xaa; 32]);

        let receipts = vec![
            dummy_receipt(&hash, true),
            dummy_receipt(&hash, false),
        ];

        store.put(&hash, &receipts).unwrap();
        let loaded = store.get(&hash).unwrap().unwrap();
        assert_eq!(loaded.len(), receipts.len());
        assert_eq!(loaded[0].success, true);
        assert_eq!(loaded[1].success, false);
    }

    #[test]
    fn test_get_nonexistent() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xbb; 32]);
        assert!(store.get(&hash).unwrap().is_none());
    }

    #[test]
    fn test_exists() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xcc; 32]);
        assert!(!store.exists(&hash));
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
    }

    #[test]
    fn test_delete() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xdd; 32]);
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash));
    }

    #[test]
    fn test_atomic_write_does_not_leave_tmp() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xee; 32]);
        store.put(&hash, &[]).unwrap();
        let tmp_path = store.path_for(&hash).with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    #[test]
    fn test_len_and_is_empty() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        assert!(store.is_empty().unwrap());
        assert_eq!(store.len().unwrap(), 0);

        let hash1 = Hash32([0x11; 32]);
        let hash2 = Hash32([0x22; 32]);
        store.put(&hash1, &[]).unwrap();
        assert_eq!(store.len().unwrap(), 1);
        assert!(!store.is_empty().unwrap());

        store.put(&hash2, &[]).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        store.delete(&hash1).unwrap();
        assert_eq!(store.len().unwrap(), 1);
    }

    #[test]
    fn test_clear() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash1 = Hash32([0x33; 32]);
        let hash2 = Hash32([0x44; 32]);
        store.put(&hash1, &[]).unwrap();
        store.put(&hash2, &[]).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        store.clear().unwrap();
        assert_eq!(store.len().unwrap(), 0);
        assert!(store.is_empty().unwrap());
    }

    #[test]
    fn test_iter() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();

        let hash1 = Hash32([0x55; 32]);
        let hash2 = Hash32([0x66; 32]);
        let receipts1 = vec![dummy_receipt(&hash1, true)];
        let receipts2 = vec![dummy_receipt(&hash2, true), dummy_receipt(&hash2, false)];

        store.put(&hash1, &receipts1).unwrap();
        store.put(&hash2, &receipts2).unwrap();

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
    }
}
