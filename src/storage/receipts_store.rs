//! Persistent storage for transaction receipts.
//!
//! Each receipt set is stored as a separate JSON file named by the transaction hash.
//! Writes are atomic (write to temp file then rename) to prevent corruption.

use crate::data_layout::DataLayout;
use crate::types::{Hash32, Receipt};
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// Store for transaction receipts, one file per transaction hash.
///
/// This store is **not** internally synchronized. If multiple threads may write
/// the same hash concurrently, external synchronization (e.g., a `Mutex`) is required.
#[derive(Clone)]
pub struct ReceiptsStore {
    dir: PathBuf,
}

impl ReceiptsStore {
    /// Opens a receipt store at the given directory. Creates the directory if missing.
    pub fn open<P: Into<PathBuf>>(root: P) -> io::Result<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;
        Ok(Self { dir })
    }

    /// Opens a receipt store using the `receipts_dir()` from a `DataLayout`.
    pub fn from_layout(layout: &DataLayout) -> io::Result<Self> {
        Self::open(layout.receipts_dir())
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

        // Serialize to JSON.
        let json = serde_json::to_string_pretty(receipts)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("receipt encode: {e}")))?;

        // Write to temporary file.
        fs::write(&tmp_path, &json)?;

        // Atomically replace the target file.
        fs::rename(&tmp_path, &path)?;

        Ok(())
    }

    /// Retrieves the list of receipts for a transaction, if any.
    pub fn get(&self, id: &Hash32) -> io::Result<Option<Vec<Receipt>>> {
        let path = self.path_for(id);
        if !path.exists() {
            return Ok(None);
        }
        let s = fs::read_to_string(path)?;
        let receipts = serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("receipt decode: {e}")))?;
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
            fs::remove_file(path)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    // Helper to create a dummy receipt (simplified for test).
    fn dummy_receipt() -> Receipt {
        // Replace with actual construction if Receipt is complex.
        // For now, we use a placeholder. In a real test, you'd create a proper Receipt.
        unimplemented!("Replace with actual Receipt creation for tests");
    }

    #[test]
    fn test_put_and_get() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0u8; 32]); // dummy hash

        let receipts = vec![dummy_receipt()]; // in real test, populate

        store.put(&hash, &receipts).unwrap();
        let loaded = store.get(&hash).unwrap().unwrap();
        assert_eq!(loaded.len(), receipts.len());
        // Additional equality checks if Receipt implements PartialEq.
    }

    #[test]
    fn test_get_nonexistent() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([1u8; 32]);
        assert!(store.get(&hash).unwrap().is_none());
    }

    #[test]
    fn test_exists() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([2u8; 32]);
        assert!(!store.exists(&hash));
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
    }

    #[test]
    fn test_delete() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([3u8; 32]);
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash));
    }

    #[test]
    fn test_atomic_write_does_not_leave_tmp() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([4u8; 32]);
        store.put(&hash, &[]).unwrap();
        let tmp_path = store.path_for(&hash).with_extension("tmp");
        assert!(!tmp_path.exists());
    }
}
