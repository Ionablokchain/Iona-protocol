//! Persistent storage for known peer multiaddresses.
//!
//! The data is stored as a JSON file containing a list of addresses.
//! Writes are atomic (write to temp file then rename) to prevent corruption.

use crate::data_layout::DataLayout;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

/// Internal representation of the peer store file.
#[derive(Default, Debug, Serialize, Deserialize)]
struct PeerStoreFile {
    /// List of peer multiaddresses (e.g., "/ip4/127.0.0.1/tcp/9000/p2p/Qm...")
    addrs: Vec<String>,
}

/// Thread-safe handle to the peer store.
///
/// All operations that modify the store acquire an internal mutex,
/// so it is safe to share across threads.
#[derive(Clone)]
pub struct PeerStore {
    inner: Arc<Mutex<PeerStoreInner>>,
}

struct PeerStoreInner {
    path: PathBuf,
    data: PeerStoreFile,
}

impl PeerStore {
    /// Opens the peer store at the path provided by `DataLayout::peers_path()`.
    pub fn open(layout: &DataLayout) -> io::Result<Self> {
        let path = layout.peers_path();
        Self::open_path(path)
    }

    /// Opens the peer store at an explicit path (useful for testing or custom locations).
    pub fn open_path(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        let data = if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("failed to parse peer store JSON: {}", e),
                )
            })?
        } else {
            PeerStoreFile::default()
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(PeerStoreInner { path, data })),
        })
    }

    /// Returns a copy of all known peer addresses.
    pub fn addrs(&self) -> Vec<String> {
        let inner = self.inner.lock().unwrap();
        inner.data.addrs.clone()
    }

    /// Adds a new peer address if it is not already present.
    /// Persists the change atomically.
    pub fn add(&self, addr: String) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if !inner.data.addrs.contains(&addr) {
            inner.data.addrs.push(addr);
            inner.persist()?;
        }
        Ok(())
    }

    /// Removes a peer address if present.
    /// Persists the change atomically.
    pub fn remove(&self, addr: &str) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        if let Some(pos) = inner.data.addrs.iter().position(|x| x == addr) {
            inner.data.addrs.remove(pos);
            inner.persist()?;
        }
        Ok(())
    }

    /// Replaces the entire list of addresses.
    /// Persists atomically.
    pub fn set_addrs(&self, new_addrs: Vec<String>) -> io::Result<()> {
        let mut inner = self.inner.lock().unwrap();
        inner.data.addrs = new_addrs;
        inner.persist()
    }
}

impl PeerStoreInner {
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
        fs::write(&tmp_path, &json)?;
        fs::rename(&tmp_path, &self.path)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_add_and_get() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        assert!(store.addrs().is_empty());

        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        let addrs = store.addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "/ip4/1.2.3.4/tcp/9000");

        // Adding duplicate does nothing.
        store.add("/ip4/1.2.3.4/tcp/9000".to_string()).unwrap();
        assert_eq!(store.addrs().len(), 1);
    }

    #[test]
    fn test_remove() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        store.add("addr1".to_string()).unwrap();
        store.add("addr2".to_string()).unwrap();
        assert_eq!(store.addrs().len(), 2);

        store.remove("addr1").unwrap();
        assert_eq!(store.addrs().len(), 1);
        assert_eq!(store.addrs()[0], "addr2");

        store.remove("nonexistent").unwrap(); // no-op
        assert_eq!(store.addrs().len(), 1);
    }

    #[test]
    fn test_set_addrs() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open_path(&path).unwrap();

        store.set_addrs(vec!["a".to_string(), "b".to_string()]).unwrap();
        assert_eq!(store.addrs(), vec!["a", "b"]);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        {
            let store = PeerStore::open_path(&path).unwrap();
            store.add("persist-me".to_string()).unwrap();
        } // store dropped

        // Reopen and verify data is still there.
        let store = PeerStore::open_path(&path).unwrap();
        assert_eq!(store.addrs(), vec!["persist-me"]);
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        fs::write(&path, "this is not json").unwrap();

        let err = PeerStore::open_path(&path).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
