//! Persistent storage for transaction receipts — Quantum Receipts Store.
//!
//! # Quantum Receipts Model
//!
//! Each receipt set is modelled as a **quantum state** |receipts_i⟩ in the
//! Hilbert space of transaction outcomes. The store's density matrix evolves
//! under CRUD operations which act as **Kraus operators**.
//!
//! # Mathematical Formalism
//!
//! ## Receipt State
//! ```text
//! |receipts⟩ = ⊗_i |receipt_i⟩
//! ρ_store = (1/N) Σ_i |receipts_i⟩⟨receipts_i|
//! ```
//!
//! ## Hamiltonian for Receipt Operations
//! ```text
//! Ĥ_receipts = Ĥ_put + Ĥ_get + Ĥ_delete + Ĥ_persist
//!
//! Ĥ_put     = Σ_p g_p (|∅⟩⟨receipts|_p + h.c.)        (creation operator)
//! Ĥ_get     = Σ_q ω_q a†_q a_q                          (measurement)
//! Ĥ_delete  = Σ_r E_r |∅⟩⟨receipts|_r                   (annihilation)
//! Ĥ_persist = Σ_s κ_s |persisted_s⟩⟨persisted_s|        (persistent eigenstate)
//! ```
//!
//! ## Decoherence from Operations
//! ```text
//! ρ(t) = ρ₀ exp(-γt)
//! where γ is the operation-specific decoherence rate.
//! ```

use crate::types::{Hash32, Receipt};
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

/// Minimum coherence threshold for a healthy store.
const MIN_RECEIPTS_COHERENCE: f64 = 0.9;

/// Kraus rank for receipts store quantum channels.
const RECEIPTS_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Quantum Receipts State
// -----------------------------------------------------------------------------

/// Quantum state of the receipts store.
///
/// Tracks the density matrix properties during receipt operations,
/// providing observables for monitoring store health.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumReceiptsState {
    /// Purity γ = Tr(ρ²) of the store state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the receipt set.
    pub store_coherence: f64,
    /// Number of receipt files currently stored.
    pub receipt_count: usize,
    /// Total put operations performed.
    pub total_puts: u64,
    /// Total get operations performed.
    pub total_gets: u64,
    /// Total delete operations performed.
    pub total_deletes: u64,
    /// Total persist operations performed.
    pub total_persists: u64,
    /// Whether the store is in a healthy quantum state.
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
    /// Create a new quantum receipts state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a put operation.
    pub fn apply_put_decoherence(&mut self, receipt_count: usize) {
        self.total_puts = self.total_puts.wrapping_add(1);
        self.receipt_count = receipt_count;
        let decay = (-PUT_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a get operation (measurement).
    pub fn apply_get_decoherence(&mut self) {
        self.total_gets = self.total_gets.wrapping_add(1);
        let decay = (-GET_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a delete operation.
    pub fn apply_delete_decoherence(&mut self, receipt_count: usize) {
        self.total_deletes = self.total_deletes.wrapping_add(1);
        self.receipt_count = receipt_count;
        let decay = (-DELETE_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a clear operation.
    pub fn apply_clear_decoherence(&mut self) {
        self.total_deletes = self.total_deletes.wrapping_add(self.receipt_count as u64);
        self.receipt_count = 0;
        let decay = (-CLEAR_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a persist operation.
    pub fn apply_persist_decoherence(&mut self) {
        self.total_persists = self.total_persists.wrapping_add(1);
        let decay = (-DELETE_DECOHERENCE_RATE).exp();
        self.store_coherence = (self.store_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for store operations.
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
// ReceiptsStore
// -----------------------------------------------------------------------------

/// Store for transaction receipts, one file per transaction hash.
///
/// This store is **not** internally synchronized. If multiple threads may write
/// the same hash concurrently, external synchronization (e.g., a `Mutex`) is required.
#[derive(Debug, Clone)]
pub struct ReceiptsStore {
    dir: PathBuf,
    /// Quantum state of the receipts store.
    quantum: QuantumReceiptsState,
}

impl ReceiptsStore {
    /// Opens a receipt store at the given directory. Creates the directory if missing.
    /// Initializes the quantum state from existing receipt files.
    pub fn open(root: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = root.into();
        fs::create_dir_all(&dir)?;

        let receipt_count = Self::count_files(&dir)?;
        let mut quantum = QuantumReceiptsState::new();
        quantum.receipt_count = receipt_count;

        debug!(
            path = %dir.display(),
            receipt_count = receipt_count,
            purity = quantum.purity,
            "opened quantum receipts store"
        );

        Ok(Self { dir, quantum })
    }

    /// Count the number of JSON files in the directory.
    fn count_files(dir: &Path) -> io::Result<usize> {
        let mut count = 0;
        if dir.exists() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                if entry
                    .path()
                    .extension()
                    .map(|ext| ext == "json")
                    .unwrap_or(false)
                {
                    count += 1;
                }
            }
        }
        Ok(count)
    }

    /// Returns the file path for a given transaction hash.
    fn path_for(&self, id: &Hash32) -> PathBuf {
        self.dir.join(format!("{}.json", hex::encode(id.0)))
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
    pub fn quantum_stats(&self) -> &QuantumReceiptsState {
        &self.quantum
    }

    /// Stores a list of receipts for a transaction.
    ///
    /// Applies the creation operator a†:
    /// ```text
    /// a† |∅⟩ → |receipts⟩
    /// ```
    pub fn put(&mut self, id: &Hash32, receipts: &[Receipt]) -> io::Result<()> {
        let path = self.path_for(id);
        let tmp_path = path.with_extension("tmp");

        debug!(
            hash = %hex::encode(id.0),
            count = receipts.len(),
            "quantum put: creating receipt state"
        );

        let json = serde_json::to_string_pretty(receipts).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("receipt encode: {}", e),
            )
        })?;

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

        // Update quantum state.
        let receipt_count = Self::count_files(&self.dir)?;
        self.quantum.apply_put_decoherence(receipt_count);
        self.quantum.apply_store_channel();

        debug!(
            path = %path.display(),
            purity = self.quantum.purity,
            "receipts stored"
        );
        Ok(())
    }

    /// Retrieves the list of receipts for a transaction, if any.
    ///
    /// This is a quantum measurement that collapses the retrieval state:
    /// ```text
    /// M_get |store⟩ → |receipts⟩ or |∅⟩
    /// ```
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
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("receipt decode: {}", e),
            )
        })?;

        debug!(
            hash = %hex::encode(id.0),
            count = receipts.len(),
            "loaded receipts (measurement)"
        );
        Ok(Some(receipts))
    }

    /// Retrieves receipts with quantum state tracking.
    ///
    /// Returns both the receipts and the updated quantum state.
    pub fn get_quantum(
        &mut self,
        id: &Hash32,
    ) -> io::Result<(Option<Vec<Receipt>>, QuantumReceiptsState)> {
        let result = self.get(id)?;
        self.quantum.apply_get_decoherence();
        Ok((result, self.quantum.clone()))
    }

    /// Checks if receipts exist for a given transaction.
    pub fn exists(&self, id: &Hash32) -> bool {
        self.path_for(id).exists()
    }

    /// Deletes the receipts file for a transaction.
    ///
    /// Applies the annihilation operator a:
    /// ```text
    /// a |receipts⟩ → |∅⟩
    /// ```
    pub fn delete(&mut self, id: &Hash32) -> io::Result<()> {
        let path = self.path_for(id);
        if path.exists() {
            debug!(hash = %hex::encode(id.0), "quantum delete: annihilating receipt state");
            fs::remove_file(path)?;

            let receipt_count = Self::count_files(&self.dir)?;
            self.quantum.apply_delete_decoherence(receipt_count);
            self.quantum.apply_store_channel();
        }
        Ok(())
    }

    /// Returns the number of stored receipt files (not the number of receipts).
    pub fn len(&self) -> io::Result<usize> {
        Self::count_files(&self.dir)
    }

    /// Returns `true` if the store contains no receipt files.
    pub fn is_empty(&self) -> io::Result<bool> {
        Ok(self.len()? == 0)
    }

    /// Clears all receipt files from the store.
    ///
    /// Resets the store to the vacuum state |∅⟩ with strong decoherence.
    pub fn clear(&mut self) -> io::Result<()> {
        debug!(dir = %self.dir.display(), "quantum clear: collapsing to vacuum state");
        for entry in fs::read_dir(&self.dir)? {
            let entry = entry?;
            let path = entry.path();
            if path
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
            {
                fs::remove_file(path)?;
            }
        }
        self.quantum.apply_clear_decoherence();
        self.quantum.apply_store_channel();
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
            if path
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
            {
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
            error: if success {
                None
            } else {
                Some("test error".into())
            },
            data: None,
        }
    }

    // ── Classical Tests ──────────────────────────────────────────────
    @test
    fn test_put_and_get() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xaa; 32]);

        let receipts = vec![dummy_receipt(&hash, true), dummy_receipt(&hash, false)];

        store.put(&hash, &receipts).unwrap();
        let loaded = store.get(&hash).unwrap().unwrap();
        assert_eq!(loaded.len(), receipts.len());
        assert_eq!(loaded[0].success, true);
        assert_eq!(loaded[1].success, false);
    }

    @test
    fn test_get_nonexistent() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xbb; 32]);
        assert!(store.get(&hash).unwrap().is_none());
    }

    @test
    fn test_exists() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xcc; 32]);
        assert!(!store.exists(&hash));
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
    }

    @test
    fn test_delete() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xdd; 32]);
        store.put(&hash, &[]).unwrap();
        assert!(store.exists(&hash));
        store.delete(&hash).unwrap();
        assert!(!store.exists(&hash));
    }

    @test
    fn test_atomic_write_does_not_leave_tmp() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0xee; 32]);
        store.put(&hash, &[]).unwrap();
        let tmp_path = store.path_for(&hash).with_extension("tmp");
        assert!(!tmp_path.exists());
    }

    @test
    fn test_len_and_is_empty() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
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

    @test
    fn test_clear() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash1 = Hash32([0x33; 32]);
        let hash2 = Hash32([0x44; 32]);
        store.put(&hash1, &[]).unwrap();
        store.put(&hash2, &[]).unwrap();
        assert_eq!(store.len().unwrap(), 2);

        store.clear().unwrap();
        assert_eq!(store.len().unwrap(), 0);
        assert!(store.is_empty().unwrap());
    }

    @test
    fn test_iter() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();

        let hash1 = Hash32([0x55; 32]);
        let hash2 = Hash32([0x66; 32]);
        let receipts1 = vec![dummy_receipt(&hash1, true)];
        let receipts2 = vec![
            dummy_receipt(&hash2, true),
            dummy_receipt(&hash2, false),
        ];

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

    // ── Quantum Tests ────────────────────────────────────────────────
    @test
    fn test_quantum_state_initialization() {
        let dir = tempdir().unwrap();
        let store = ReceiptsStore::open(dir.path()).unwrap();

        assert!((store.purity() - 1.0).abs() < 1e-10);
        assert!((store.entropy() - 0.0).abs() < 1e-10);
        assert!(store.is_healthy());
    }

    @test
    fn test_put_decoherence() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let initial_purity = store.purity();

        let hash = Hash32([0x77; 32]);
        store.put(&hash, &[]).unwrap();

        assert!(store.purity() < initial_purity);
    }

    @test
    fn test_get_quantum_decoherence() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0x88; 32]);
        store.put(&hash, &[]).unwrap();

        let purity_before_get = store.purity();
        let (result, qstate) = store.get_quantum(&hash).unwrap();

        assert!(result.is_some());
        assert!(qstate.purity < purity_before_get);
        assert_eq!(qstate.total_gets, 1);
    }

    @test
    fn test_delete_decoherence() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let hash = Hash32([0x99; 32]);
        store.put(&hash, &[]).unwrap();

        let purity_after_put = store.purity();
        store.delete(&hash).unwrap();

        assert!(store.purity() < purity_after_put);
    }

    @test
    fn test_clear_decoherence_strong() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();

        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[]).unwrap();
        }

        let purity_before_clear = store.purity();
        store.clear().unwrap();

        assert!(store.purity() < purity_before_clear);
        assert_eq!(store.quantum_stats().receipt_count, 0);
    }

    @test
    fn test_quantum_stats() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();

        let hash1 = Hash32([0xAA; 32]);
        let hash2 = Hash32([0xBB; 32]);
        store.put(&hash1, &[]).unwrap();
        store.put(&hash2, &[]).unwrap();

        let stats = store.quantum_stats();
        assert_eq!(stats.receipt_count, 2);
        assert_eq!(stats.total_puts, 2);
        assert!(stats.purity < 1.0);
    }

    @test
    fn test_health_after_many_operations() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();

        for i in 0..50 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[]).unwrap();
            store.delete(&Hash32(hash)).unwrap();
        }

        assert!(store.purity() < 1.0);
        assert!(!store.is_healthy());
    }

    @test
    fn test_purity_never_negative() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();

        for i in 0..10000 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[]).unwrap();
        }

        assert!(store.purity() >= 0.0);
    }

    @test
    fn test_entropy_increases() {
        let dir = tempdir().unwrap();
        let mut store = ReceiptsStore::open(dir.path()).unwrap();
        let initial_entropy = store.entropy();

        for i in 0..10 {
            let mut hash = [0u8; 32];
            hash[0] = i as u8;
            store.put(&Hash32(hash), &[]).unwrap();
        }

        assert!(store.entropy() > initial_entropy);
    }
}
