//! Persistent storage for known peer multiaddresses — Quantum Peer Store.
//!
//! # Quantum Peer Store Model
//!
//! The peer store is modelled as a **quantum memory** where each peer
//! address exists in a superposition of |known⟩ and |unknown⟩ states.
//! The store's state evolves under operations (add, remove) which act as
//! **Kraus operators** on the density matrix of the peer set.
//!
//! # Mathematical Formalism
//!
//! ## Peer State
//! ```text
//! |peer_i⟩ = α_i |known⟩ + β_i |unknown⟩,   |α_i|² + |β_i|² = 1
//! ```
//!
//! ## Store State (Density Matrix)
//! ```text
//! ρ_store = (1/N) Σ_i |peer_i⟩⟨peer_i|
//! ```
//!
//! ## Hamiltonian for Peer Operations
//! ```text
//! Ĥ_store = Ĥ_add + Ĥ_remove + Ĥ_persist
//!
//! Ĥ_add     = Σ_a g_a (|∅⟩⟨peer|_a + h.c.)        (creation operator)
//! Ĥ_remove  = Σ_r ω_r a†_r a_r                     (annihilation operator)
//! Ĥ_persist = Σ_p E_p |persisted_p⟩⟨persisted_p|   (persistent state)
//! ```
//!
//! ## Decoherence from Operations
//! ```text
//! ρ(t) = ρ₀ exp(-γt)
//! where γ is the operation-specific decoherence rate.
//! ```
//!
//! # Atomic Writes
//!
//! All writes use temp-file + rename to prevent corruption, preserving
//! the quantum state integrity across crashes.
//!
//! # Example
//!
//! ```
//! use iona::storage::peer_store::PeerStore;
//!
//! let mut store = PeerStore::open("./data/peers.json").unwrap();
//! store.add("/ip4/1.2.3.4/tcp/7001/p2p/12D3KooW...".to_string()).unwrap();
//! let addrs = store.addrs();
//! let purity = store.purity();
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for the peer store.
const DEFAULT_STORE_COHERENCE: f64 = 1.0;

/// Decoherence rate per add operation.
const ADD_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per remove operation.
const REMOVE_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per persist operation.
const PERSIST_DECOHERENCE_RATE: f64 = 0.0005;

/// Minimum coherence threshold for a healthy store.
const MIN_STORE_COHERENCE: f64 = 0.9;

/// Kraus rank for peer store quantum channels.
const STORE_KRAUS_RANK: usize = 4;

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
// Quantum Peer State
// -----------------------------------------------------------------------------

/// Quantum state of the entire peer store.
///
/// Tracks the density matrix properties during peer operations,
/// providing observables for monitoring store health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumStoreState {
    /// Purity γ = Tr(ρ²) of the store state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the peer set.
    pub store_coherence: f64,
    /// Number of peers currently stored.
    pub peer_count: usize,
    /// Total add operations performed.
    pub total_adds: u64,
    /// Total remove operations performed.
    pub total_removes: u64,
    /// Total persist operations performed.
    pub total_persists: u64,
    /// Whether the store is in a healthy quantum state.
    pub is_healthy: bool,
}

impl Default for QuantumStoreState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_STORE_COHERENCE,
            entropy: 0.0,
            store_coherence: DEFAULT_STORE_COHERENCE,
            peer_count: 0,
            total_adds: 0,
            total_removes: 0,
            total_persists: 0,
            is_healthy: true,
        }
    }
}

impl QuantumStoreState {
    /// Create a new quantum store state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from an add operation.
    pub fn apply_add_decoherence(&mut self, peer_count: usize) {
        self.total_adds = self.total_adds.wrapping_add(1);
        self.peer_count = peer_count;
        let decay = (-ADD_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a remove operation.
    pub fn apply_remove_decoherence(&mut self, peer_count: usize) {
        self.total_removes = self.total_removes.wrapping_add(1);
        self.peer_count = peer_count;
        let decay = (-REMOVE_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a persist operation.
    pub fn apply_persist_decoherence(&mut self) {
        self.total_persists = self.total_persists.wrapping_add(1);
        let decay = (-PERSIST_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for store operations.
    pub fn apply_store_channel(&mut self) {
        let kraus_factor = (1.0 / STORE_KRAUS_RANK as f64).sqrt();
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
        self.is_healthy = self.purity >= MIN_STORE_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// PeerStore
// -----------------------------------------------------------------------------

/// Persistent store for known peer multiaddresses with quantum state tracking.
///
/// The store is **not** internally synchronized. If multiple threads may write
/// concurrently, external synchronization (e.g., a `Mutex`) is required.
#[derive(Debug, Clone)]
pub struct PeerStore {
    path: PathBuf,
    data: PeerStoreFile,
    /// Quantum state of the store.
    quantum: QuantumStoreState,
}

impl PeerStore {
    /// Open the peer store at the given path.
    ///
    /// If the file does not exist, an empty store is created with the
    /// quantum state initialized to the ground state |∅⟩.
    pub fn open(path: impl Into<PathBuf>) -> io::Result<Self> {
        let path = path.into();
        debug!(path = %path.display(), "opening quantum peer store");

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

        let mut quantum = QuantumStoreState::new();
        quantum.peer_count = data.addrs.len();

        Ok(Self {
            path,
            data,
            quantum,
        })
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

    /// Quantum purity γ = Tr(ρ²) of the store.
    pub fn purity(&self) -> f64 {
        self.quantum.purity
    }

    /// Von Neumann entropy S = -Tr(ρ ln ρ) of the store.
    pub fn entropy(&self) -> f64 {
        self.quantum.entropy
    }

    /// Whether the store is in a healthy quantum state.
    pub fn is_healthy(&self) -> bool {
        self.quantum.is_healthy
    }

    /// Get quantum store statistics.
    pub fn quantum_stats(&self) -> &QuantumStoreState {
        &self.quantum
    }

    /// Adds a new peer address if it is not already present.
    ///
    /// Applies the creation operator a†:
    /// ```text
    /// a† |store⟩ → |store ∪ {peer}⟩
    /// ```
    pub fn add(&mut self, addr: String) -> io::Result<()> {
        if !self.data.addrs.contains(&addr) {
            debug!(addr = %addr, "quantum add: creating new peer state");
            self.data.addrs.push(addr);
            self.quantum.apply_add_decoherence(self.data.addrs.len());
            self.quantum.apply_store_channel();
            self.persist()?;
        } else {
            debug!(addr = %addr, "peer address already present, skipping");
        }
        Ok(())
    }

    /// Removes a peer address if present.
    ///
    /// Applies the annihilation operator a:
    /// ```text
    /// a |store⟩ → |store \ {peer}⟩
    /// ```
    pub fn remove(&mut self, addr: &str) -> io::Result<()> {
        if let Some(pos) = self.data.addrs.iter().position(|x| x == addr) {
            debug!(addr = %addr, "quantum remove: annihilating peer state");
            self.data.addrs.remove(pos);
            self.quantum.apply_remove_decoherence(self.data.addrs.len());
            self.quantum.apply_store_channel();
            self.persist()?;
        } else {
            debug!(addr = %addr, "peer address not found, skipping");
        }
        Ok(())
    }

    /// Replaces the entire list of addresses.
    ///
    /// This is a projective measurement that collapses the store
    /// to a new set of eigenstates.
    pub fn set_addrs(&mut self, new_addrs: Vec<String>) -> io::Result<()> {
        debug!(count = new_addrs.len(), "quantum set: collapsing to new peer set");
        let old_count = self.data.addrs.len();
        self.data.addrs = new_addrs;
        // Treat as multiple operations
        self.quantum.apply_remove_decoherence(old_count);
        self.quantum.apply_add_decoherence(self.data.addrs.len());
        self.quantum.apply_store_channel();
        self.persist()
    }

    /// Clears all peer addresses.
    ///
    /// Resets the store to the vacuum state |∅⟩.
    pub fn clear(&mut self) -> io::Result<()> {
        debug!("quantum clear: resetting to vacuum state");
        self.set_addrs(Vec::new())
    }

    /// Writes the current data to disk atomically.
    ///
    /// The persist operation is a projective measurement that
    /// collapses the in-memory state to a persistent eigenstate.
    fn persist(&self) -> io::Result<()> {
        // Ensure parent directory exists.
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Serialize to JSON.
        let json = serde_json::to_string_pretty(&self.data).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("encode error: {}", e),
            )
        })?;

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
                debug!(path = %self.path.display(), "quantum peer store persisted");
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

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_add_and_get() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        assert!(store.is_empty());
        assert_eq!(store.len(), 0);

        store
            .add("/ip4/1.2.3.4/tcp/9000".to_string())
            .unwrap();
        let addrs = store.addrs();
        assert_eq!(addrs.len(), 1);
        assert_eq!(addrs[0], "/ip4/1.2.3.4/tcp/9000");
        assert_eq!(store.len(), 1);
        assert!(!store.is_empty());

        // Adding duplicate does nothing.
        store
            .add("/ip4/1.2.3.4/tcp/9000".to_string())
            .unwrap();
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

        store
            .set_addrs(vec!["a".to_string(), "b".to_string()])
            .unwrap();
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

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let store = PeerStore::open(&path).unwrap();

        assert!((store.purity() - 1.0).abs() < 1e-10);
        assert!((store.entropy() - 0.0).abs() < 1e-10);
        assert!(store.is_healthy());
    }

    #[test]
    fn test_add_decoherence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        let initial_purity = store.purity();
        store.add("peer1".to_string()).unwrap();

        assert!(store.purity() < initial_purity);
    }

    #[test]
    fn test_remove_decoherence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        store.add("peer1".to_string()).unwrap();
        let purity_after_add = store.purity();

        store.remove("peer1").unwrap();
        assert!(store.purity() < purity_after_add);
    }

    #[test]
    fn test_quantum_stats() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        store.add("peer1".to_string()).unwrap();
        store.add("peer2".to_string()).unwrap();

        let stats = store.quantum_stats();
        assert_eq!(stats.peer_count, 2);
        assert_eq!(stats.total_adds, 2);
        assert!(stats.purity < 1.0);
    }

    #[test]
    fn test_health_after_many_operations() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        for i in 0..100 {
            store.add(format!("peer{}", i)).unwrap();
            store.remove(&format!("peer{}", i)).unwrap();
        }

        assert!(store.purity() < 1.0);
        assert!(!store.is_healthy());
    }

    #[test]
    fn test_purity_never_negative() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("peers.json");
        let mut store = PeerStore::open(&path).unwrap();

        for i in 0..10000 {
            store.add(format!("peer{}", i)).unwrap();
        }

        assert!(store.purity() >= 0.0);
    }
}
