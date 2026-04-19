//! Persistent storage for known peer multiaddresses.
//!
//! The data is stored as a JSON file containing a list of addresses.
//! Writes are atomic (write to temp file then rename) to prevent corruption.
//!
//! # Example
//!
//! ```
//! use iona::storage::peer_store::PeerStore;
//!
//! let mut store = PeerStore::open("./data/peers.json").unwrap();
//! store.add("/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW...".to_string()).unwrap();
//! let addrs = store.addrs();
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Internal file representation
// -----------------------------------------------------------------------------

/// Internal representation of the peer store file.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PeerStoreFile {
    /// List of peer multiaddresses.
    addrs: Vec<String>,
}

// -----------------------------------------------------------------------------
// PeerStore
// -----------------------------------------------------------------------------

/// Persistent store for known peer multiaddresses.
///
/// The store is **not** internally synchronized. If multiple threads may write
/// concurrently, external synchronization (e.g., a `Mutex`) is required.
#[derive(Debug, Clone)]
pub struct PeerStore {
    path: PathBuf,
    data: PeerStoreFile,
}

impl PeerStore {
    /// Open the peer store at the given path.
    ///
    /// If the file does not exist, an empty store is created.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        debug!(path = %path.display(), "opening peer store");

        let data = if path.exists() {
            let s = fs::read_to_string(&path)?;
            match serde_json::from_str(&s) {
                Ok(data) => data,
                Err(e) => {
                    warn!(path = %path.display(), error = %e, "failed to parse peer store, using default");
                    PeerStoreFile::default()
                }
            }
        } else {
            PeerStoreFile::default()
        };

        Ok(Self { path, data })
    }

    /// Returns a copy of all known peer addresses.
    pub fn addrs(&self) -> Vec<String> {
        self.data.addrs.clone()
    }

    /// Number of known peer addresses.
    pub fn len(&self) -> usize {
        self.data.addrs.len()
    }

    /// Returns `true` if the store contains no addresses.
    pub fn is_empty(&self) -> bool {
        self.data.addrs.is_empty()
    }

    /// Adds a new peer address if it is not already present.
    /// Persists the change atomically.
    pub fn add(&mut self, addr: String) -> io::Result<()> {
        if !self.data.addrs.contains(&addr) {
            debug!(addr = %addr, "adding new peer address");
            self.data.addrs.push(addr);
            self.persist()?;
        } else {
            debug!(addr = %addr, "peer address already present, skipping");
        }
        Ok(())
    }

    /// Removes a peer address if present.
    /// Persists the change atomically.
    pub fn remove(&mut self, addr: &str) -> io::Result<()> {
        if let Some(pos) = self.data.addrs.iter().position(|x| x == addr) {
            debug!(addr = %addr, "removing peer address");
            self.data.addrs.remove(pos);
            self.persist()?;
        } else {
            debug!(addr = %addr, "peer address not found, skipping");
        }
        Ok(())
    }

    /// Replaces the entire list of addresses.
    /// Persists atomically.
    pub fn set_addrs(&mut self, new_addrs: Vec<String>) -> io::Result<()> {
        debug!(count = new_addrs.len(), "replacing all peer addresses");
        self.data.addrs = new_addrs;
        self.persist()
    }

    /// Clears all peer addresses.
    pub fn clear(&mut self) -> io::Result<()> {
        self.set_addrs(Vec::new())
    }

    /// Writes the current data to disk atomically.
    fn persist(&self) -> io::Result<()> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize to JSON.
        let json = serde_json::to_string_pretty(&self.data)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encode error: {}", e)))?;

        // Write atomically: temp file then rename.
        let tmp_path = self.path.with_extension("tmp");
        match fs::write(&tmp_path, &json) {
            Ok(_) => {}
            Err(e) => {
                error!(path = %tmp_path.display(), error = %e, "failed to write temporary peer store file");
                return Err(e);
            }
        }
        match fs::rename(&tmp_path, &self.path) {
            Ok(_) => {
                debug!(path = %self.path.display(), "peer store persisted");
                Ok(())
            }
            Err(e) => {
                error!(from = %tmp_path.display(), to = %self.path.display(), error = %e, "failed to rename peer store file");
                Err(e)
            }
        }
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
        let mut store = PeerStore::open(&path).unwrap();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        let addrs = store.addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "/ip4/1.2.3.4/tcp/9000");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        // Adding duplicate does nothing.
        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        assert_eq!(store.addrs().len(), 1);
    }

    #[test]
    fn test_remove() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        store.add("addr1".to_string()).unwrap();
        store.add("addr2".to_string()).unwrap();
        assert_eq!(store.len(), 2);

        store.remove("addr1").unwrap();
        assert_eq!(store.addrs(), vec!["addr2"]);
        assert_eq!(store.len(), 1);

        store.remove("nonexistent").unwrap(); // no‑op
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_set_addrs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        store.set_addrs(vec!["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(store.addrs(), vec!["a", "b"]);
        assert_eq!(store.len(), 2);
    }

    #[test]
    fn test_clear() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        store.add("a".to_string()).unwrap();
        store.add("b".to_string()).unwrap();
        assert_eq!(store.len(), 2);

        store.clear().unwrap();
        assert!(store.is_empty());
        assert_eq!(store.addrs(), Vec::<String>::new());
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        {
            let mut store = PeerStore::open(&path).unwrap();
            store.add("persist-me".to_string()).unwrap();
        } // store dropped

        // Reopen and verify data is still there.
        let store = PeerStore::open(&path).unwrap();
        assert_eq!(store.addrs(), vec!["persist-me"]);
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        fs::write(&path, "this is not json").unwrap();

        let err = PeerStore::open(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("failed to parse"));
    }

    #[test]
    fn test_empty_file_creates_default() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        // File does not exist -> should create empty store.
        let mut store = PeerStore::open(&path).unwrap();
        assert!(store.is_empty());
        // After adding, file is created.
        store.add("test".to_string()).unwrap();
        assert!(path.exists());
    }

    #[test]
    fn test_atomic_write() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();
        store.add("test".to_string()).unwrap();
        let tmp_path = path.with_extension("tmp");
        assert!(!tmp_path.exists());
    }
}
