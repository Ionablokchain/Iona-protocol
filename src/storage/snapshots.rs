//! Persistent state snapshots and incremental delta sync — Quantum Snapshot Engine.
//!
//! # Quantum Snapshot Model
//!
//! A snapshot is a **projective measurement** of the blockchain state |Ψ(t)⟩
//! at height h. The state is collapsed to the computational basis, compressed
//! via a **quantum channel** (zstd), and stored as a classical record.
//!
//! # Mathematical Formalism
//!
//! ## Snapshot as Projective Measurement
//! ```text
//! Π_snapshot = Σ_i |i⟩⟨i| ⊗ |height⟩⟨height|
//! |snapshot⟩ = Π_snapshot |Ψ_blockchain⟩
//! ```
//!
//! ## Hamiltonian for Snapshot Operations
//! ```text
//! Ĥ_snap = Ĥ_write + Ĥ_read + Ĥ_delta + Ĥ_attest + Ĥ_prune
//!
//! Ĥ_write  = Σ_w g_w (|∅⟩⟨state|_w + h.c.)              (creation)
//! Ĥ_read   = Σ_r ω_r a†_r a_r                            (measurement)
//! Ĥ_delta  = Σ_d J_d (|from⟩⟨to|_d + h.c.)               (difference coupling)
//! Ĥ_attest = Σ_a E_a |signed_a⟩⟨signed_a|                (validator entanglement)
//! Ĥ_prune  = Σ_p γ_p (n̂_p + ½)                           (annihilation decay)
//! ```
//!
//! ## Compression as Quantum Channel
//! ```text
//! Φ_zstd(ρ) = Σ_k K_k ρ K_k†
//! K_k = √λ_k |compressed_k⟩⟨state_k|
//! ```
//! zstd implements a **Kraus channel** that projects onto the spectral basis
//! and truncates small eigenvalues (lossy compression).
//!
//! ## Delta as Quantum Difference Operator
//! ```text
//! Δ̂ |from⟩ = |to⟩ - |from⟩
//! ```
//! The delta captures the **difference** between two quantum states.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::snapshot::{write_snapshot, restore_latest_if_missing};
//!
//! write_snapshot("./data", 100, &state, 3)?;
//! if let Some(height) = restore_latest_if_missing("./data", "./data/state_full.json")? {
//!     println!("Restored snapshot from height {}", height);
//! }
//! ```

use crate::crypto::Verifier;
use crate::execution::KvState;
use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
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

/// Default quantum coherence for snapshot operations.
const DEFAULT_SNAPSHOT_COHERENCE: f64 = 1.0;

/// Decoherence rate per write operation.
const WRITE_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per read operation (measurement).
const READ_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per delta computation.
const DELTA_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per attestation.
const ATTEST_DECOHERENCE_RATE: f64 = 0.0003;

/// Decoherence rate per prune operation.
const PRUNE_DECOHERENCE_RATE: f64 = 0.0005;

/// Minimum coherence threshold for healthy snapshot system.
const MIN_SNAPSHOT_COHERENCE: f64 = 0.9;

/// Kraus rank for snapshot quantum channels.
const SNAPSHOT_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Quantum Snapshot State
// -----------------------------------------------------------------------------

/// Quantum state of the snapshot system.
///
/// Tracks the density matrix properties during snapshot operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSnapshotState {
    /// Purity γ = Tr(ρ²) of the snapshot state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the snapshot data.
    pub data_coherence: f64,
    /// Coherence of the attestation subsystem.
    pub attestation_coherence: f64,
    /// Number of snapshots currently stored.
    pub snapshot_count: usize,
    /// Total write operations performed.
    pub total_writes: u64,
    /// Total read operations performed.
    pub total_reads: u64,
    /// Total delta operations performed.
    pub total_deltas: u64,
    /// Total attestation operations performed.
    pub total_attestations: u64,
    /// Total prune operations performed.
    pub total_prunes: u64,
    /// Whether the snapshot system is healthy.
    pub is_healthy: bool,
}

impl Default for QuantumSnapshotState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_SNAPSHOT_COHERENCE,
            entropy: 0.0,
            data_coherence: DEFAULT_SNAPSHOT_COHERENCE,
            attestation_coherence: DEFAULT_SNAPSHOT_COHERENCE,
            snapshot_count: 0,
            total_writes: 0,
            total_reads: 0,
            total_deltas: 0,
            total_attestations: 0,
            total_prunes: 0,
            is_healthy: true,
        }
    }
}

impl QuantumSnapshotState {
    /// Create a new quantum snapshot state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Apply decoherence from a write operation.
    pub fn apply_write_decoherence(&mut self, snapshot_count: usize) {
        self.total_writes = self.total_writes.wrapping_add(1);
        self.snapshot_count = snapshot_count;
        let decay = (-WRITE_DECOHERENCE_RATE).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a read operation.
    pub fn apply_read_decoherence(&mut self) {
        self.total_reads = self.total_reads.wrapping_add(1);
        let decay = (-READ_DECOHERENCE_RATE).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a delta computation.
    pub fn apply_delta_decoherence(&mut self) {
        self.total_deltas = self.total_deltas.wrapping_add(1);
        let decay = (-DELTA_DECOHERENCE_RATE).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from an attestation.
    pub fn apply_attestation_decoherence(&mut self) {
        self.total_attestations = self.total_attestations.wrapping_add(1);
        let decay = (-ATTEST_DECOHERENCE_RATE).exp();
        self.attestation_coherence = (self.attestation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply decoherence from a prune operation.
    pub fn apply_prune_decoherence(&mut self, removed: usize) {
        self.total_prunes = self.total_prunes.wrapping_add(1);
        self.snapshot_count = self.snapshot_count.saturating_sub(removed);
        let decay = (-PRUNE_DECOHERENCE_RATE * removed as f64).exp();
        self.data_coherence = (self.data_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for snapshot operations.
    pub fn apply_snapshot_channel(&mut self) {
        let kraus_factor = (1.0 / SNAPSHOT_KRAUS_RANK as f64).sqrt();
        self.data_coherence = (self.data_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.data_coherence * self.attestation_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_SNAPSHOT_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Global quantum state tracker
// -----------------------------------------------------------------------------

/// Global quantum state for the snapshot module.
static QUANTUM_STATE: std::sync::Mutex<QuantumSnapshotState> =
    std::sync::Mutex::new(QuantumSnapshotState::new());

/// Get a copy of the current quantum state.
pub fn get_quantum_state() -> QuantumSnapshotState {
    QUANTUM_STATE.lock().unwrap().clone()
}

/// Get quantum purity.
pub fn snapshot_purity() -> f64 {
    QUANTUM_STATE.lock().unwrap().purity
}

/// Check if snapshot system is healthy.
pub fn is_snapshot_healthy() -> bool {
    QUANTUM_STATE.lock().unwrap().is_healthy
}

// -----------------------------------------------------------------------------
// Snapshot manifest
// -----------------------------------------------------------------------------

/// Metadata for a full snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifest {
    /// Block height of the snapshot.
    pub height: u64,
    /// Creation timestamp (Unix seconds).
    pub created_unix_s: u64,
    /// Hex‑encoded state root hash.
    pub state_root_hex: String,
    /// Snapshot format description.
    pub format: String,
    /// zstd compression level used (Kraus rank proxy).
    pub zstd_level: i32,
    /// Quantum purity at write time.
    #[serde(default = "default_purity")]
    pub quantum_purity: f64,
}

fn default_purity() -> f64 {
    1.0
}

// -----------------------------------------------------------------------------
// Snapshot attestation (validator signatures)
// -----------------------------------------------------------------------------

/// Attestation for a snapshot, signed by a threshold of validators.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotAttestation {
    /// Hash of the validator set used for verification (stable, sorted).
    pub validators_hash_hex: String,
    /// Minimum number of signatures required.
    pub threshold: u32,
    /// List of validator signatures.
    pub signatures: Vec<AttestationSig>,
    /// Quantum coherence of the attestation.
    #[serde(default = "default_purity")]
    pub coherence: f64,
}

/// A single validator signature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationSig {
    /// Public key as hex string.
    pub pubkey_hex: String,
    /// Base64‑encoded signature.
    pub sig_base64: String,
    /// Signature fidelity (1.0 = perfect).
    #[serde(default = "default_purity")]
    pub fidelity: f64,
}

// -----------------------------------------------------------------------------
// State sync manifest (with chunk hashes)
// -----------------------------------------------------------------------------

/// Manifest for state‑sync of a full snapshot, with chunk hashes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateSyncManifest {
    pub height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    #[serde(default)]
    pub state_root_hex: Option<String>,
    #[serde(default)]
    pub attestation: Option<SnapshotAttestation>,
    /// Quantum purity of the manifest.
    #[serde(default = "default_purity")]
    pub quantum_purity: f64,
}

// -----------------------------------------------------------------------------
// Delta snapshot types
// -----------------------------------------------------------------------------

/// Incremental state delta between two snapshot heights.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateDelta {
    pub from_height: u64,
    pub to_height: u64,
    pub kv_put: Vec<(String, String)>,
    pub kv_del: Vec<String>,
    pub balances_put: Vec<(String, u64)>,
    pub balances_del: Vec<String>,
    pub nonces_put: Vec<(String, u64)>,
    pub nonces_del: Vec<String>,
    pub burned: u64,
    pub to_state_root_hex: String,
    /// Quantum coherence of the delta.
    #[serde(default = "default_purity")]
    pub delta_coherence: f64,
}

/// Manifest for state‑sync of a delta file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaSyncManifest {
    pub from_height: u64,
    pub to_height: u64,
    pub total_bytes: u64,
    pub blake3_hex: String,
    pub chunk_size: u32,
    pub chunk_hashes: Vec<String>,
    pub to_state_root_hex: String,
    /// Quantum purity of the delta manifest.
    #[serde(default = "default_purity")]
    pub quantum_purity: f64,
}

// -----------------------------------------------------------------------------
// Path helpers (unchanged)
// -----------------------------------------------------------------------------

/// Directory containing all snapshots.
pub fn snapshots_dir(data_dir: &str) -> PathBuf {
    Path::new(data_dir).join("snapshots")
}

/// Path to a full snapshot file (compressed).
pub fn snapshot_path(data_dir: &str, height: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("state_{:020}.json.zst", height))
}

/// Path to the human‑readable manifest of a full snapshot.
pub fn manifest_path(data_dir: &str, height: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("state_{:020}.manifest.json", height))
}

/// Path to the state‑sync manifest of a full snapshot.
pub fn statesync_manifest_path(data_dir: &str, height: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("state_{:020}.statesync.json", height))
}

/// Path to a delta file (compressed).
pub fn delta_path(data_dir: &str, from_h: u64, to_h: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("delta_{:020}_{:020}.json.zst", from_h, to_h))
}

/// Path to the state‑sync manifest of a delta file.
pub fn delta_statesync_manifest_path(data_dir: &str, from_h: u64, to_h: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("delta_{:020}_{:020}.statesync.json", from_h, to_h))
}

/// Path to an attestation file for a snapshot.
pub fn attestation_path(data_dir: &str, height: u64) -> PathBuf {
    snapshots_dir(data_dir).join(format!("state_{:020}.attestation.json", height))
}

// -----------------------------------------------------------------------------
// Full snapshot operations (with quantum tracking)
// -----------------------------------------------------------------------------

/// Write a full snapshot of the state at a given height.
///
/// Applies the creation operator a†:
/// ```text
/// a† |∅⟩ → |snapshot⟩
/// ```
pub fn write_snapshot(data_dir: &str, height: u64, state: &KvState, zstd_level: i32) -> io::Result<()> {
    let snap_dir = snapshots_dir(data_dir);
    fs::create_dir_all(&snap_dir)?;

    let path = snapshot_path(data_dir, height);
    let tmp_path = path.with_extension("tmp");

    debug!(height, "writing quantum snapshot");

    let json = serde_json::to_vec(state).map_err(|e| {
        error!(height, error = %e, "failed to serialise state to JSON");
        io::Error::new(io::ErrorKind::InvalidData, format!("snapshot encode: {e}"))
    })?;

    let compressed = zstd::encode_all(&json[..], zstd_level).map_err(|e| {
        error!(height, error = %e, "zstd compression failed");
        io::Error::new(io::ErrorKind::Other, format!("snapshot zstd: {e}"))
    })?;

    // Atomic write
    fs::write(&tmp_path, &compressed)?;
    fs::rename(&tmp_path, &path)?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Update quantum state
    let snapshot_count = list_snapshot_heights(data_dir).unwrap_or_default().len() + 1;
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_write_decoherence(snapshot_count);
    qstate.apply_snapshot_channel();
    let current_purity = qstate.purity;
    drop(qstate);

    let manifest = SnapshotManifest {
        height,
        created_unix_s: now,
        state_root_hex: hex::encode(state.root().0),
        format: "KvState-json-zstd".into(),
        zstd_level,
        quantum_purity: current_purity,
    };

    let manifest_json = serde_json::to_string_pretty(&manifest).map_err(|e| {
        error!(height, error = %e, "failed to serialise manifest");
        io::Error::new(io::ErrorKind::InvalidData, format!("manifest encode: {e}"))
    })?;
    fs::write(manifest_path(data_dir, height), manifest_json)?;

    info!(height, compressed_bytes = compressed.len(), purity = current_purity, "quantum snapshot written");
    Ok(())
}

/// Read a full snapshot state from disk.
///
/// This is a quantum measurement that collapses the retrieval state:
/// ```text
/// M_read |store⟩ → |state⟩
/// ```
pub fn read_snapshot_state(data_dir: &str, height: u64) -> io::Result<KvState> {
    let path = snapshot_path(data_dir, height);
    debug!(height, path = %path.display(), "reading quantum snapshot");

    let compressed = fs::read(&path).map_err(|e| {
        error!(height, error = %e, "failed to read snapshot file");
        e
    })?;
    let json = zstd::decode_all(&compressed[..]).map_err(|e| {
        error!(height, error = %e, "zstd decompression failed");
        io::Error::new(io::ErrorKind::Other, format!("snapshot decode: {e}"))
    })?;
    let state: KvState = serde_json::from_slice(&json).map_err(|e| {
        error!(height, error = %e, "failed to parse snapshot JSON");
        io::Error::new(io::ErrorKind::InvalidData, format!("snapshot json: {e}"))
    })?;

    // Track measurement decoherence
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_read_decoherence();
    drop(qstate);

    Ok(state)
}

/// Read the manifest of a snapshot.
pub fn read_snapshot_manifest(data_dir: &str, height: u64) -> io::Result<SnapshotManifest> {
    let path = manifest_path(data_dir, height);
    let bytes = fs::read(&path)?;
    let manifest: SnapshotManifest = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("manifest json: {e}"))
    })?;
    Ok(manifest)
}

/// List all snapshot heights (sorted ascending).
pub fn list_snapshot_heights(data_dir: &str) -> io::Result<Vec<u64>> {
    let dir = snapshots_dir(data_dir);
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut heights = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(h) = name.strip_prefix("state_").and_then(|s| s.split('.').next()) {
            if let Ok(v) = h.parse::<u64>() {
                heights.push(v);
            }
        }
    }
    heights.sort_unstable();
    Ok(heights)
}

/// Return the highest snapshot height, if any.
pub fn latest_snapshot_height(data_dir: &str) -> io::Result<Option<u64>> {
    Ok(list_snapshot_heights(data_dir)?.pop())
}

/// Prune old snapshots, keeping only the most recent `keep` heights.
///
/// Applies the annihilation operator with decoherence:
/// ```text
/// a |snapshot_old⟩ → |∅⟩
/// ```
pub fn prune_snapshots(data_dir: &str, keep: usize) -> io::Result<()> {
    let heights = list_snapshot_heights(data_dir)?;
    if heights.len() <= keep {
        return Ok(());
    }
    let to_remove = &heights[..heights.len() - keep];
    let removed_count = to_remove.len();

    for &h in to_remove {
        let snap_path = snapshot_path(data_dir, h);
        let mani_path = manifest_path(data_dir, h);
        let statesync_path = statesync_manifest_path(data_dir, h);
        let attest_path = attestation_path(data_dir, h);
        let _ = fs::remove_file(&snap_path);
        let _ = fs::remove_file(&mani_path);
        let _ = fs::remove_file(&statesync_path);
        let _ = fs::remove_file(&attest_path);
        debug!(height = h, "pruned quantum snapshot");
    }

    // Update quantum state
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_prune_decoherence(removed_count);
    qstate.apply_snapshot_channel();
    drop(qstate);

    info!(removed = removed_count, kept = keep, "quantum snapshots pruned");
    Ok(())
}

/// Restore the latest snapshot if `state_full_path` does not exist.
/// Returns the height of the restored snapshot, or `None` if no restore was needed.
pub fn restore_latest_if_missing(data_dir: &str, state_full_path: &str) -> io::Result<Option<u64>> {
    if Path::new(state_full_path).exists() {
        return Ok(None);
    }
    let Some(height) = latest_snapshot_height(data_dir)? else {
        warn!("no snapshot found, cannot restore");
        return Ok(None);
    };

    let state = read_snapshot_state(data_dir, height)?;
    let json = serde_json::to_vec_pretty(&state).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("serialise state: {e}"))
    })?;
    fs::write(state_full_path, json)?;
    info!(height, "restored latest quantum snapshot");
    Ok(Some(height))
}

// -----------------------------------------------------------------------------
// State‑sync manifests (full snapshot)
// -----------------------------------------------------------------------------

/// Load or build a state‑sync manifest for a full snapshot.
pub fn load_or_build_statesync_manifest(
    data_dir: &str,
    height: u64,
    chunk_size: u32,
) -> io::Result<StateSyncManifest> {
    let snap_path = snapshot_path(data_dir, height);
    let mani_path = statesync_manifest_path(data_dir, height);

    // Try cached manifest.
    if mani_path.exists() {
        if let Ok(s) = fs::read_to_string(&mani_path) {
            if let Ok(manifest) = serde_json::from_str::<StateSyncManifest>(&s) {
                if manifest.height == height && manifest.chunk_size == chunk_size {
                    if let Ok(meta) = fs::metadata(&snap_path) {
                        if meta.len() == manifest.total_bytes {
                            if let Ok(bytes) = fs::read(&snap_path) {
                                let hash = blake3::hash(&bytes);
                                if hex::encode(hash.as_bytes()) == manifest.blake3_hex {
                                    debug!(height, "using cached statesync manifest");
                                    return Ok(manifest);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    debug!(height, "building quantum statesync manifest");
    let bytes = fs::read(&snap_path)?;
    let total_bytes = bytes.len() as u64;
    let hash = blake3::hash(&bytes);
    let blake3_hex = hex::encode(hash.as_bytes());

    let cs = chunk_size as usize;
    let mut chunk_hashes = Vec::with_capacity((bytes.len() + cs - 1) / cs);
    let mut i = 0;
    while i < bytes.len() {
        let end = (i + cs).min(bytes.len());
        let chunk_hash = blake3::hash(&bytes[i..end]);
        chunk_hashes.push(hex::encode(chunk_hash.as_bytes()));
        i = end;
    }

    let state_root_hex = read_snapshot_manifest(data_dir, height)
        .ok()
        .map(|m| m.state_root_hex);
    let attestation = load_attestation_if_any(data_dir, height);

    let current_purity = QUANTUM_STATE.lock().unwrap().purity;

    let manifest = StateSyncManifest {
        height,
        total_bytes,
        blake3_hex,
        chunk_size,
        chunk_hashes,
        state_root_hex,
        attestation,
        quantum_purity: current_purity,
    };

    // Write cache best‑effort
    if let Ok(json) = serde_json::to_string_pretty(&manifest) {
        if let Err(e) = fs::write(&mani_path, json) {
            warn!(height, error = %e, "failed to write cached statesync manifest");
        }
    }

    Ok(manifest)
}

/// Helper: load attestation file if present.
fn load_attestation_if_any(data_dir: &str, height: u64) -> Option<SnapshotAttestation> {
    let path = attestation_path(data_dir, height);
    fs::read_to_string(&path)
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
}

// -----------------------------------------------------------------------------
// Delta snapshots (with quantum tracking)
// -----------------------------------------------------------------------------

/// Compute the delta between two states.
///
/// Applies the quantum difference operator:
/// ```text
/// Δ̂ |from⟩ = |to⟩ - |from⟩
/// ```
pub fn compute_delta(from_h: u64, to_h: u64, from: &KvState, to: &KvState) -> StateDelta {
    let mut kv_put = Vec::new();
    let mut kv_del = Vec::new();
    for (k, v) in &to.kv {
        if from.kv.get(k) != Some(v) {
            kv_put.push((k.clone(), v.clone()));
        }
    }
    for k in from.kv.keys() {
        if !to.kv.contains_key(k) {
            kv_del.push(k.clone());
        }
    }

    let mut balances_put = Vec::new();
    let mut balances_del = Vec::new();
    for (k, v) in &to.balances {
        if from.balances.get(k) != Some(v) {
            balances_put.push((k.clone(), *v));
        }
    }
    for k in from.balances.keys() {
        if !to.balances.contains_key(k) {
            balances_del.push(k.clone());
        }
    }

    let mut nonces_put = Vec::new();
    let mut nonces_del = Vec::new();
    for (k, v) in &to.nonces {
        if from.nonces.get(k) != Some(v) {
            nonces_put.push((k.clone(), *v));
        }
    }
    for k in from.nonces.keys() {
        if !to.nonces.contains_key(k) {
            nonces_del.push(k.clone());
        }
    }

    // Track delta operation
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_delta_decoherence();
    let delta_coherence = qstate.data_coherence;
    drop(qstate);

    StateDelta {
        from_height: from_h,
        to_height: to_h,
        kv_put,
        kv_del,
        balances_put,
        balances_del,
        nonces_put,
        nonces_del,
        burned: to.burned,
        to_state_root_hex: hex::encode(to.root().0),
        delta_coherence,
    }
}

/// Apply a delta to a base state, producing a new state.
pub fn apply_delta(base: &KvState, delta: &StateDelta) -> KvState {
    let mut out = base.clone();
    for k in &delta.kv_del {
        out.kv.remove(k);
    }
    for (k, v) in &delta.kv_put {
        out.kv.insert(k.clone(), v.clone());
    }
    for k in &delta.balances_del {
        out.balances.remove(k);
    }
    for (k, v) in &delta.balances_put {
        out.balances.insert(k.clone(), *v);
    }
    for k in &delta.nonces_del {
        out.nonces.remove(k);
    }
    for (k, v) in &delta.nonces_put {
        out.nonces.insert(k.clone(), *v);
    }
    out.burned = delta.burned;
    out
}

/// Write a delta snapshot (compressed) and its state‑sync manifest.
pub fn write_delta(
    data_dir: &str,
    from_h: u64,
    to_h: u64,
    from: &KvState,
    to: &KvState,
    zstd_level: i32,
    chunk_size: u32,
) -> io::Result<()> {
    let snap_dir = snapshots_dir(data_dir);
    fs::create_dir_all(&snap_dir)?;

    let delta = compute_delta(from_h, to_h, from, to);
    let json = serde_json::to_vec(&delta).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("delta encode: {e}"))
    })?;

    let compressed = zstd::encode_all(&json[..], zstd_level).map_err(|e| {
        io::Error::new(io::ErrorKind::Other, format!("delta zstd: {e}"))
    })?;

    let path = delta_path(data_dir, from_h, to_h);
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, &compressed)?;
    fs::rename(&tmp_path, &path)?;

    // Build delta sync manifest
    let total_bytes = compressed.len() as u64;
    let hash = blake3::hash(&compressed);
    let blake3_hex = hex::encode(hash.as_bytes());

    let cs = chunk_size as usize;
    let mut chunk_hashes = Vec::new();
    let mut i = 0;
    while i < compressed.len() {
        let end = (i + cs).min(compressed.len());
        let chunk_hash = blake3::hash(&compressed[i..end]);
        chunk_hashes.push(hex::encode(chunk_hash.as_bytes()));
        i = end;
    }

    let current_purity = QUANTUM_STATE.lock().unwrap().purity;

    let delta_manifest = DeltaSyncManifest {
        from_height: from_h,
        to_height: to_h,
        total_bytes,
        blake3_hex,
        chunk_size,
        chunk_hashes,
        to_state_root_hex: delta.to_state_root_hex,
        quantum_purity: current_purity,
    };

    let mani_path = delta_statesync_manifest_path(data_dir, from_h, to_h);
    if let Ok(json) = serde_json::to_string_pretty(&delta_manifest) {
        let _ = fs::write(&mani_path, json);
    }

    info!(from_h, to_h, "quantum delta snapshot written");
    Ok(())
}

/// List all delta edges (from, to) present in the snapshots directory.
pub fn list_delta_edges(data_dir: &str) -> io::Result<Vec<(u64, u64)>> {
    let dir = snapshots_dir(data_dir);
    if !dir.exists() {
        return Ok(vec![]);
    }
    let mut edges = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if let Some(rest) = name.strip_prefix("delta_") {
            let parts: Vec<&str> = rest.split('_').collect();
            if parts.len() >= 2 {
                let from_str = parts[0];
                let to_str = parts[1].split('.').next().unwrap_or("");
                if let (Ok(fh), Ok(th)) = (from_str.parse::<u64>(), to_str.parse::<u64>()) {
                    edges.push((fh, th));
                }
            }
        }
    }
    edges.sort_unstable();
    edges.dedup();
    Ok(edges)
}

// -----------------------------------------------------------------------------
// Snapshot attestation (with quantum tracking)
// -----------------------------------------------------------------------------

/// Write an attestation for a snapshot.
pub fn write_attestation(data_dir: &str, height: u64, attestation: &SnapshotAttestation) -> io::Result<()> {
    let dir = snapshots_dir(data_dir);
    fs::create_dir_all(&dir)?;
    let path = attestation_path(data_dir, height);
    let json = serde_json::to_string_pretty(attestation).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("attestation encode: {e}"))
    })?;
    fs::write(&path, json)?;

    // Track attestation decoherence
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_attestation_decoherence();
    qstate.apply_snapshot_channel();
    drop(qstate);

    Ok(())
}

/// Read an attestation for a snapshot, if present.
pub fn read_attestation(data_dir: &str, height: u64) -> io::Result<Option<SnapshotAttestation>> {
    let path = attestation_path(data_dir, height);
    if !path.exists() {
        return Ok(None);
    }
    let bytes = fs::read(path)?;
    let attestation: SnapshotAttestation = serde_json::from_slice(&bytes).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("attestation json: {e}"))
    })?;
    Ok(Some(attestation))
}

/// Verify a snapshot attestation against a set of validator public keys.
pub fn verify_attestation(
    manifest: &StateSyncManifest,
    validator_pubkeys_hex: &[String],
) -> io::Result<bool> {
    let Some(att) = &manifest.attestation else {
        return Ok(false);
    };
    let Some(ref root_hex) = manifest.state_root_hex else {
        return Ok(false);
    };
    let msg = snapshot_attest_sign_bytes(manifest.height, root_hex)?;

    let allow_set: std::collections::HashSet<String> = validator_pubkeys_hex.iter().map(|s| s.to_lowercase()).collect();

    let mut ok_count = 0u32;
    for sig in &att.signatures {
        if !allow_set.contains(&sig.pubkey_hex.to_lowercase()) {
            continue;
        }
        let pk_bytes = match hex::decode(&sig.pubkey_hex) {
            Ok(v) => crate::crypto::PublicKeyBytes(v),
            Err(_) => continue,
        };
        let sig_bytes = match B64.decode(sig.sig_base64.as_bytes()) {
            Ok(v) => crate::crypto::SignatureBytes(v),
            Err(_) => continue,
        };
        if crate::crypto::ed25519::Ed25519Verifier::verify(&pk_bytes, &msg, &sig_bytes).is_ok() {
            ok_count += 1;
        }
    }

    // Track attestation verification
    let mut qstate = QUANTUM_STATE.lock().unwrap();
    qstate.apply_attestation_decoherence();
    drop(qstate);

    Ok(ok_count >= att.threshold)
}

/// Compute a stable hash of a set of validator public keys (sorted hex strings).
pub fn validators_hash_hex(pubkeys_hex: &[String]) -> String {
    let mut sorted: Vec<String> = pubkeys_hex.iter().map(|s| s.to_lowercase()).collect();
    sorted.sort();
    let bytes = bincode::serialize(&sorted).unwrap_or_default();
    hex::encode(blake3::hash(&bytes).as_bytes())
}

/// Canonical bytes for snapshot attestation signing (v1).
pub fn snapshot_attest_sign_bytes(height: u64, state_root_hex: &str) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 32);
    out.extend_from_slice(b"iona:snapshot_attest:v1");
    out.extend_from_slice(&height.to_le_bytes());
    let root = hex::decode(state_root_hex).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("state_root hex: {e}"))
    })?;
    out.extend_from_slice(&root);
    Ok(out)
}

/// Version 2 of attestation sign bytes (binds to chain ID, validator set hash, and epoch nonce).
pub fn snapshot_attest_sign_bytes_v2(
    chain_id: u64,
    height: u64,
    state_root_hex: &str,
    validator_set_hash_hex: &str,
    epoch_nonce: u64,
) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(8 + 32 + 32 + 32);
    out.extend_from_slice(b"iona:snapshot_attest:v2");
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&height.to_le_bytes());
    let root = hex::decode(state_root_hex).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("state_root hex: {e}"))
    })?;
    out.extend_from_slice(&root);
    let vsh = hex::decode(validator_set_hash_hex).map_err(|e| {
        io::Error::new(io::ErrorKind::InvalidData, format!("vset_hash hex: {e}"))
    })?;
    out.extend_from_slice(&vsh);
    out.extend_from_slice(&epoch_nonce.to_le_bytes());
    Ok(out)
}

/// Compute quantum fidelity between two snapshot manifests.
///
/// ```text
/// F = |⟨manifest_a|manifest_b⟩|²
/// ```
pub fn manifest_fidelity(a: &SnapshotManifest, b: &SnapshotManifest) -> f64 {
    if a.state_root_hex == b.state_root_hex && a.height == b.height {
        1.0
    } else {
        0.0
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_state() -> KvState {
        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.balances.insert("bob".into(), 500);
        state.nonces.insert("alice".into(), 5);
        state.kv.insert("key".into(), "value".into());
        state
    }

    // ── Classical Tests ──────────────────────────────────────────────
    #[test]
    fn test_write_and_read_snapshot() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();
        let height = 42;

        write_snapshot(data_dir, height, &state, 3).unwrap();
        let loaded = read_snapshot_state(data_dir, height).unwrap();
        assert_eq!(loaded.balances, state.balances);
        assert_eq!(loaded.nonces, state.nonces);
        assert_eq!(loaded.kv, state.kv);
    }

    #[test]
    fn test_list_snapshot_heights() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();
        write_snapshot(data_dir, 10, &state, 3).unwrap();
        write_snapshot(data_dir, 20, &state, 3).unwrap();
        let heights = list_snapshot_heights(data_dir).unwrap();
        assert_eq!(heights, vec![10, 20]);
    }

    #[test]
    fn test_prune_snapshots() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();
        write_snapshot(data_dir, 10, &state, 3).unwrap();
        write_snapshot(data_dir, 20, &state, 3).unwrap();
        write_snapshot(data_dir, 30, &state, 3).unwrap();
        prune_snapshots(data_dir, 2).unwrap();
        let heights = list_snapshot_heights(data_dir).unwrap();
        assert_eq!(heights, vec![20, 30]);
    }

    #[test]
    fn test_restore_latest_if_missing() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();
        write_snapshot(data_dir, 42, &state, 3).unwrap();

        let state_path = dir.path().join("state_full.json");
        let state_path_str = state_path.to_str().unwrap();

        assert!(!state_path.exists());
        let restored = restore_latest_if_missing(data_dir, state_path_str).unwrap();
        assert_eq!(restored, Some(42));
        assert!(state_path.exists());

        let restored2 = restore_latest_if_missing(data_dir, state_path_str).unwrap();
        assert_eq!(restored2, None);
    }

    #[test]
    fn test_delta_compute_and_apply() {
        let mut from = KvState::default();
        from.balances.insert("alice".into(), 1000);
        from.nonces.insert("alice".into(), 5);
        from.kv.insert("key".into(), "old".into());

        let mut to = KvState::default();
        to.balances.insert("alice".into(), 900);
        to.balances.insert("bob".into(), 100);
        to.nonces.insert("alice".into(), 6);
        to.kv.insert("key".into(), "new".into());
        to.burned = 100;

        let delta = compute_delta(1, 2, &from, &to);
        let applied = apply_delta(&from, &delta);
        assert_eq!(applied.balances, to.balances);
        assert_eq!(applied.nonces, to.nonces);
        assert_eq!(applied.kv, to.kv);
        assert_eq!(applied.burned, 100);
    }

    #[test]
    fn test_write_and_list_delta() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let from = KvState::default();
        let to = test_state();

        write_delta(data_dir, 1, 2, &from, &to, 3, 1024).unwrap();
        let edges = list_delta_edges(data_dir).unwrap();
        assert_eq!(edges, vec![(1, 2)]);
    }

    #[test]
    fn test_statesync_manifest() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();
        write_snapshot(data_dir, 100, &state, 3).unwrap();

        let manifest = load_or_build_statesync_manifest(data_dir, 100, 4096).unwrap();
        assert_eq!(manifest.height, 100);
        assert_eq!(manifest.chunk_size, 4096);
        assert!(!manifest.chunk_hashes.is_empty());

        let cached = load_or_build_statesync_manifest(data_dir, 100, 4096).unwrap();
        assert_eq!(cached.blake3_hex, manifest.blake3_hex);
    }

    #[test]
    fn test_attestation_roundtrip() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let att = SnapshotAttestation {
            validators_hash_hex: "deadbeef".into(),
            threshold: 2,
            signatures: vec![],
            coherence: 1.0,
        };
        write_attestation(data_dir, 42, &att).unwrap();
        let loaded = read_attestation(data_dir, 42).unwrap().unwrap();
        assert_eq!(loaded.validators_hash_hex, "deadbeef");
        assert_eq!(loaded.threshold, 2);
    }

    #[test]
    fn test_validators_hash_hex() {
        let pks = vec!["02".into(), "01".into()];
        let hash = validators_hash_hex(&pks);
        let hash2 = validators_hash_hex(&vec!["01".into(), "02".into()]);
        assert_eq!(hash, hash2);
    }

    // ── Quantum Tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumSnapshotState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    #[test]
    fn test_write_decoherence() {
        let mut state = QuantumSnapshotState::new();
        let initial_purity = state.purity;

        state.apply_write_decoherence(5);
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_writes, 1);
        assert_eq!(state.snapshot_count, 5);
    }

    #[test]
    fn test_read_decoherence() {
        let mut state = QuantumSnapshotState::new();
        let initial_purity = state.purity;

        state.apply_read_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_reads, 1);
    }

    #[test]
    fn test_delta_decoherence() {
        let mut state = QuantumSnapshotState::new();
        let initial_purity = state.purity;

        state.apply_delta_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_deltas, 1);
    }

    #[test]
    fn test_attestation_decoherence() {
        let mut state = QuantumSnapshotState::new();
        let initial_purity = state.purity;

        state.apply_attestation_decoherence();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_attestations, 1);
    }

    #[test]
    fn test_prune_decoherence() {
        let mut state = QuantumSnapshotState::new();
        state.snapshot_count = 10;
        let initial_purity = state.purity;

        state.apply_prune_decoherence(3);
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_prunes, 1);
        assert_eq!(state.snapshot_count, 7);
    }

    #[test]
    fn test_snapshot_channel() {
        let mut state = QuantumSnapshotState::new();
        let initial_coherence = state.data_coherence;

        state.apply_snapshot_channel();
        assert!(state.data_coherence < initial_coherence);
    }

    #[test]
    fn test_global_quantum_state() {
        // Reset state
        {
            let mut qstate = QUANTUM_STATE.lock().unwrap();
            *qstate = QuantumSnapshotState::new();
        }

        let initial_purity = snapshot_purity();
        assert!(initial_purity > 0.99);
        assert!(is_snapshot_healthy());

        let state_copy = get_quantum_state();
        assert!((state_copy.purity - initial_purity).abs() < 1e-10);
    }

    #[test]
    fn test_write_snapshot_tracks_quantum() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let state = test_state();

        // Reset quantum state
        {
            let mut qstate = QUANTUM_STATE.lock().unwrap();
            *qstate = QuantumSnapshotState::new();
        }

        let initial_purity = snapshot_purity();
        write_snapshot(data_dir, 1, &state, 3).unwrap();
        assert!(snapshot_purity() < initial_purity);
    }

    #[test]
    fn test_manifest_fidelity_identical() {
        let a = SnapshotManifest {
            height: 42,
            created_unix_s: 1000,
            state_root_hex: "abc".into(),
            format: "test".into(),
            zstd_level: 3,
            quantum_purity: 1.0,
        };
        let b = a.clone();
        assert!((manifest_fidelity(&a, &b) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_manifest_fidelity_different() {
        let a = SnapshotManifest {
            height: 42,
            created_unix_s: 1000,
            state_root_hex: "abc".into(),
            format: "test".into(),
            zstd_level: 3,
            quantum_purity: 1.0,
        };
        let b = SnapshotManifest {
            state_root_hex: "def".into(),
            ..a.clone()
        };
        assert!((manifest_fidelity(&a, &b) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_health_after_many_writes() {
        let mut state = QuantumSnapshotState::new();
        assert!(state.is_healthy);

        for _ in 0..500 {
            state.apply_write_decoherence(10);
        }
        assert!(!state.is_healthy);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumSnapshotState::new();
        for _ in 0..10000 {
            state.apply_prune_decoherence(10);
        }
        assert!(state.purity >= 0.0);
    }
}
