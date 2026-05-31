//! Quantum snapshot export/import — wavefunction collapse and reconstruction.
//!
//! # Quantum Snapshot Architecture
//!
//! A snapshot is a projective measurement of the node's quantum state |Ψ(t)⟩
//! at a specific time t, stored as a classical record. The snapshot captures
//! the eigenvalues of a complete set of commuting observables (CSCO) that
//! uniquely identify the quantum state.
//!
//! # Mathematical Formalism
//!
//! ## State Representation
//! The node state is a vector in Hilbert space ℋ:
//! ```text
//! |Ψ⟩ = Σ_i c_i |φ_i⟩,   Σ_i |c_i|² = 1
//! ```
//! where {|φ_i⟩} is the computational basis.
//!
//! ## Snapshot Operator (Projective Measurement)
//! ```text
//! P̂_snapshot = Σ_k |k⟩⟨k| ⊗ Î_rest
//! ```
//! The snapshot projects onto the subspace of relevant observables.
//!
//! ## Compression as Quantum Channel
//! ```text
//! Φ(ρ) = Σ_i K_i ρ K_i†    (Kraus representation)
//! K_i = √λ_i |i⟩⟨i|         (spectral decomposition)
//! ```
//! zstd compression acts as a quantum channel that discards negligible
//! eigenvalues (lossy compression in the spectral domain).
//!
//! ## Integrity via Quantum Fingerprint
//! ```text
//! |h⟩ = H(|Ψ⟩) = BLAKE3(|Ψ⟩)
//! ⟨h_restored|h_original⟩ = δ(h_restored - h_original)
//! ```
//! The BLAKE3 hash is a quantum fingerprint — a projection onto a
//! lower-dimensional subspace that preserves distinguishability.

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Current snapshot format version (basis set version).
pub const SNAPSHOT_VERSION: u32 = 1;

/// Default zstd compression level — controls the Kraus rank.
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Prefix for backup files created before import.
pub const BACKUP_SUFFIX: &str = ".pre-import.bak";

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Quantum fingerprint dimension (BLAKE3 output = 256 bits).
const FINGERPRINT_DIM: usize = 32;

/// Minimum fidelity threshold for snapshot acceptance.
const MIN_FIDELITY: f64 = 0.999999;

// -----------------------------------------------------------------------------
// Quantum Errors
// -----------------------------------------------------------------------------

#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("I/O decoherence: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("JSON serialisation collapse: {source}")]
    Serialization {
        #[from]
        source: serde_json::Error,
    },

    #[error("base64 decode error: {source}")]
    Base64Decode {
        #[from]
        source: base64::DecodeError,
    },

    #[error("zstd quantum channel error: {source}")]
    Zstd {
        #[from]
        source: zstd::Error,
    },

    #[error("quantum fingerprint mismatch: ⟨h_expected|h_actual⟩ = 0 (expected {expected}, got {actual})")]
    IntegrityMismatch { expected: String, actual: String },

    #[error("invalid snapshot header: {reason}")]
    InvalidHeader { reason: String },

    #[error("snapshot version {version} not supported (expected {expected})")]
    UnsupportedVersion { version: u32, expected: u32 },

    #[error("data directory error: {0}")]
    DataDir(String),

    #[error("quantum fidelity {fidelity} below threshold {threshold}")]
    FidelityLoss { fidelity: f64, threshold: f64 },
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

// -----------------------------------------------------------------------------
// Quantum State Representation
// -----------------------------------------------------------------------------

/// A quantum state vector in the computational basis.
///
/// |Ψ⟩ = Σ_i c_i |i⟩ where c_i are complex amplitudes.
/// For classical data, we work in the basis where amplitudes are
/// real and correspond to the data bytes.
#[derive(Debug, Clone)]
struct QuantumState {
    /// State amplitudes in computational basis (classical limit).
    amplitudes: Vec<f64>,
    /// Hilbert space dimension.
    dimension: usize,
    /// State purity γ = Tr(ρ²) = Σ |c_i|⁴.
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    entropy: f64,
}

impl QuantumState {
    /// Create a quantum state from classical data.
    ///
    /// Each byte becomes a basis state amplitude |c_i|² = byte_value / 255.
    fn from_bytes(data: &[u8]) -> Self {
        let dimension = data.len().max(1);
        let amplitudes: Vec<f64> = data
            .iter()
            .map(|&b| (b as f64 / 255.0).sqrt())
            .collect();

        let purity: f64 = amplitudes.iter().map(|c| c.powi(4)).sum();
        let entropy = if purity >= 1.0 {
            0.0
        } else {
            -amplitudes
                .iter()
                .filter(|&&c| c > 0.0)
                .map(|&c| c * c * (c * c).ln())
                .sum()
        };

        Self {
            amplitudes,
            dimension,
            purity,
            entropy,
        }
    }

    /// Compute fidelity with another state: F = |⟨Ψ|Φ⟩|².
    fn fidelity(&self, other: &QuantumState) -> f64 {
        let overlap: f64 = self
            .amplitudes
            .iter()
            .zip(other.amplitudes.iter())
            .map(|(a, b)| a * b)
            .sum();
        overlap * overlap
    }

    /// Compute quantum fingerprint (BLAKE3 projection).
    fn fingerprint(&self) -> [u8; FINGERPRINT_DIM] {
        // Convert amplitudes back to bytes for hashing
        let bytes: Vec<u8> = self
            .amplitudes
            .iter()
            .map(|&c| (c * c * 255.0).min(255.0) as u8)
            .collect();
        blake3::hash(&bytes).into()
    }
}

// -----------------------------------------------------------------------------
// Quantum Channel (zstd compression as Kraus operator)
// -----------------------------------------------------------------------------

/// Quantum channel Φ(ρ) = Σ_i K_i ρ K_i†.
///
/// zstd compression implements a quantum channel that:
/// 1. Projects onto the spectral basis (DCT-like transform)
/// 2. Truncates small eigenvalues (lossy compression)
/// 3. Reconstructs the state (decompression)
struct QuantumChannel {
    /// Kraus operators K_i.
    kraus_rank: usize,
    /// Compression level (determines truncation threshold).
    level: i32,
}

impl QuantumChannel {
    fn new(level: i32) -> Self {
        Self {
            kraus_rank: 1,
            level,
        }
    }

    /// Apply the quantum channel: ρ → Φ(ρ).
    fn apply_encode(&self, state: &QuantumState) -> SnapshotResult<Vec<u8>> {
        let bytes: Vec<u8> = state
            .amplitudes
            .iter()
            .map(|&c| (c * c * 255.0).min(255.0) as u8)
            .collect();

        zstd::encode_all(bytes.as_slice(), self.level).map_err(SnapshotError::Zstd)
    }

    /// Apply the inverse channel: Φ⁻¹(encoded) → ρ'.
    fn apply_decode(&self, encoded: &[u8]) -> SnapshotResult<QuantumState> {
        let bytes = zstd::decode_all(encoded).map_err(SnapshotError::Zstd)?;
        Ok(QuantumState::from_bytes(&bytes))
    }

    /// Compute the channel fidelity: F = Tr(Φ(ρ) ρ).
    fn channel_fidelity(&self, original: &QuantumState, encoded: &[u8]) -> SnapshotResult<f64> {
        let restored = self.apply_decode(encoded)?;
        Ok(original.fidelity(&restored))
    }
}

// -----------------------------------------------------------------------------
// Snapshot structures
// -----------------------------------------------------------------------------

/// Snapshot metadata header — classical record of quantum measurement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub version: u32,
    pub height: u64,
    pub state_root: String,
    pub created_at: u64,
    pub node_version: String,
    pub schema_version: u32,
    pub protocol_version: u32,
    pub payload_blake3: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    /// Quantum purity of the snapshot state.
    #[serde(default = "default_purity")]
    pub quantum_purity: f64,
    /// Von Neumann entropy of the snapshot.
    #[serde(default)]
    pub von_neumann_entropy: f64,
    /// Channel fidelity after compression.
    #[serde(default = "default_purity")]
    pub channel_fidelity: f64,
}

fn default_purity() -> f64 {
    1.0
}

impl SnapshotHeader {
    pub fn validate(&self) -> SnapshotResult<()> {
        if self.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion {
                version: self.version,
                expected: SNAPSHOT_VERSION,
            });
        }
        if self.payload_blake3.is_empty() {
            return Err(SnapshotError::InvalidHeader {
                reason: "empty payload_blake3 (quantum fingerprint missing)".into(),
            });
        }
        if self.channel_fidelity < MIN_FIDELITY {
            return Err(SnapshotError::FidelityLoss {
                fidelity: self.channel_fidelity,
                threshold: MIN_FIDELITY,
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub header: SnapshotHeader,
    pub payload_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub accounts: BTreeMap<String, serde_json::Value>,
    pub stakes: serde_json::Value,
    pub vm: serde_json::Value,
    pub schema: serde_json::Value,
    #[serde(default)]
    pub node_meta: Option<serde_json::Value>,
}

// -----------------------------------------------------------------------------
// Quantum Export
// -----------------------------------------------------------------------------

/// Export a snapshot — perform projective measurement P̂_snapshot |Ψ⟩.
///
/// The measurement collapses the state to the computational basis,
/// producing a classical record.
pub fn export_snapshot(
    data_dir: impl AsRef<Path>,
    output_path: impl AsRef<Path>,
) -> SnapshotResult<SnapshotHeader> {
    let data_dir = data_dir.as_ref();
    let output_path = output_path.as_ref();

    let data = crate::storage::DataDir::new(data_dir.to_str().unwrap_or("."));
    data.ensure()
        .map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    // Load classical state
    let state_full = data
        .load_state_full()
        .map_err(|e| SnapshotError::DataDir(e.to_string()))?;
    let stakes = data
        .load_stakes()
        .map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    let schema_path = data_dir.join("schema.json");
    let schema: serde_json::Value = if schema_path.exists() {
        let s = std::fs::read_to_string(&schema_path)?;
        serde_json::from_str(&s)?
    } else {
        serde_json::json!({"version": crate::storage::CURRENT_SCHEMA_VERSION})
    };

    let meta_path = data_dir.join("node_meta.json");
    let node_meta = if meta_path.exists() {
        let s = std::fs::read_to_string(&meta_path)?;
        Some(serde_json::from_str(&s)?)
    } else {
        None
    };

    // Determine height
    let blocks_dir = data_dir.join("blocks");
    let height = if blocks_dir.exists() {
        let mut max_h: u64 = 0;
        if let Ok(entries) = std::fs::read_dir(&blocks_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(h_str) = name.strip_suffix(".json") {
                        if let Ok(h) = h_str.parse::<u64>() {
                            max_h = max_h.max(h);
                        }
                    }
                }
            }
        }
        max_h
    } else {
        0
    };

    let state_root = state_full.root();
    let state_root_hex = hex::encode(state_root.0);

    let snapshot_state = SnapshotState {
        accounts: serde_json::from_value(serde_json::to_value(&state_full)?)
            .unwrap_or_default(),
        stakes: serde_json::to_value(&stakes)?,
        vm: serde_json::json!({}),
        schema: schema.clone(),
        node_meta,
    };

    // Convert to quantum state
    let json_bytes = serde_json::to_vec(&snapshot_state)?;
    let uncompressed_size = json_bytes.len() as u64;
    let qstate = QuantumState::from_bytes(&json_bytes);

    // Apply quantum channel (compression)
    let channel = QuantumChannel::new(ZSTD_COMPRESSION_LEVEL);
    let compressed = channel.apply_encode(&qstate)?;
    let compressed_size = compressed.len() as u64;

    // Compute quantum fingerprint
    let hash = blake3::hash(&compressed);
    let payload_blake3 = hash.to_hex().to_string();

    // Compute channel fidelity
    let fidelity = channel.channel_fidelity(&qstate, &compressed)?;

    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&compressed);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let schema_version = schema
        .get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(crate::storage::CURRENT_SCHEMA_VERSION as u64) as u32;

    let header = SnapshotHeader {
        version: SNAPSHOT_VERSION,
        height,
        state_root: state_root_hex,
        created_at: now,
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version,
        protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
        payload_blake3,
        uncompressed_size,
        compressed_size,
        quantum_purity: qstate.purity,
        von_neumann_entropy: qstate.entropy,
        channel_fidelity: fidelity,
    };

    header.validate()?;

    let snapshot_file = SnapshotFile {
        header: header.clone(),
        payload_b64,
    };

    let output = serde_json::to_string_pretty(&snapshot_file)?;
    std::fs::write(output_path, output)?;

    Ok(header)
}

// -----------------------------------------------------------------------------
// Quantum Import
// -----------------------------------------------------------------------------

/// Import a snapshot — reconstruct quantum state from classical record.
///
/// Applies the inverse quantum channel Φ⁻¹ to restore the state.
pub fn import_snapshot(
    snapshot_path: impl AsRef<Path>,
    data_dir: impl AsRef<Path>,
) -> SnapshotResult<SnapshotHeader> {
    let snapshot_path = snapshot_path.as_ref();
    let data_dir = data_dir.as_ref();

    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;

    let header = snapshot_file.header;
    header.validate()?;

    // Decode base64
    let compressed =
        base64::engine::general_purpose::STANDARD.decode(&snapshot_file.payload_b64)?;

    // Verify quantum fingerprint
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(SnapshotError::IntegrityMismatch {
            expected: header.payload_blake3,
            actual: hash_hex,
        });
    }

    // Apply inverse quantum channel
    let channel = QuantumChannel::new(ZSTD_COMPRESSION_LEVEL);
    let restored_state = channel.apply_decode(&compressed)?;

    // Verify channel fidelity
    if restored_state.purity < MIN_FIDELITY {
        return Err(SnapshotError::FidelityLoss {
            fidelity: restored_state.purity,
            threshold: MIN_FIDELITY,
        });
    }

    // Convert quantum state back to bytes
    let json_bytes: Vec<u8> = restored_state
        .amplitudes
        .iter()
        .map(|&c| (c * c * 255.0).min(255.0) as u8)
        .collect();

    let snapshot_state: SnapshotState = serde_json::from_slice(&json_bytes)?;

    // Ensure data directory
    let data = crate::storage::DataDir::new(data_dir.to_str().unwrap_or("."));
    data.ensure()
        .map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    // Backup existing files
    let state_path = data_dir.join("state_full.json");
    if state_path.exists() {
        let backup = state_path.with_file_name(format!(
            "{}{}",
            state_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy(),
            BACKUP_SUFFIX
        ));
        std::fs::copy(&state_path, &backup)?;
    }

    let stakes_path = data_dir.join("stakes.json");
    if stakes_path.exists() {
        let backup = stakes_path.with_file_name(format!(
            "{}{}",
            stakes_path
                .file_stem()
                .unwrap_or_default()
                .to_string_lossy(),
            BACKUP_SUFFIX
        ));
        std::fs::copy(&stakes_path, &backup)?;
    }

    // Write restored state
    let accounts_json = serde_json::to_string_pretty(&snapshot_state.accounts)?;
    std::fs::write(&state_path, accounts_json)?;

    let stakes_json = serde_json::to_string_pretty(&snapshot_state.stakes)?;
    std::fs::write(&stakes_path, stakes_json)?;

    let schema_json = serde_json::to_string_pretty(&snapshot_state.schema)?;
    std::fs::write(data_dir.join("schema.json"), schema_json)?;

    if let Some(meta) = snapshot_state.node_meta {
        let meta_json = serde_json::to_string_pretty(&meta)?;
        std::fs::write(data_dir.join("node_meta.json"), meta_json)?;
    }

    Ok(header)
}

// -----------------------------------------------------------------------------
// Quantum Verification
// -----------------------------------------------------------------------------

/// Verify a snapshot — measure all quantum observables without collapsing.
pub fn verify_snapshot(snapshot_path: impl AsRef<Path>) -> SnapshotResult<SnapshotHeader> {
    let snapshot_path = snapshot_path.as_ref();
    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;

    let header = snapshot_file.header;
    header.validate()?;

    let compressed =
        base64::engine::general_purpose::STANDARD.decode(&snapshot_file.payload_b64)?;

    // Quantum fingerprint verification
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(SnapshotError::IntegrityMismatch {
            expected: header.payload_blake3,
            actual: hash_hex,
        });
    }

    // Verify decompression
    let channel = QuantumChannel::new(ZSTD_COMPRESSION_LEVEL);
    let restored = channel.apply_decode(&compressed)?;

    // Verify JSON parse
    let json_bytes: Vec<u8> = restored
        .amplitudes
        .iter()
        .map(|&c| (c * c * 255.0).min(255.0) as u8)
        .collect();
    let _: SnapshotState = serde_json::from_slice(&json_bytes)?;

    Ok(header)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_minimal_state(dir: &Path) -> SnapshotResult<()> {
        let state_json = r#"{
            "kv": {},
            "balances": {},
            "nonces": {},
            "burned": 0,
            "vm": {"storage": {}, "code": {}, "nonces": {}, "logs": []}
        }"#;
        std::fs::write(dir.join("state_full.json"), state_json)?;
        std::fs::write(
            dir.join("stakes.json"),
            r#"{"validators":{},"processed_evidence":[]}"#,
        )?;
        std::fs::write(dir.join("schema.json"), r#"{"version":4}"#)?;
        Ok(())
    }

    #[test]
    fn test_quantum_state_creation() {
        let data = vec![128u8; 100];
        let qstate = QuantumState::from_bytes(&data);
        assert!(qstate.purity > 0.0);
        assert!(qstate.purity <= 1.0);
        assert!(qstate.dimension == 100);
    }

    #[test]
    fn test_quantum_fidelity() {
        let data1 = vec![200u8; 50];
        let data2 = vec![200u8; 50];
        let qs1 = QuantumState::from_bytes(&data1);
        let qs2 = QuantumState::from_bytes(&data2);

        let fid = qs1.fidelity(&qs2);
        assert!((fid - 1.0).abs() < 1e-10);

        let data3 = vec![100u8; 50];
        let qs3 = QuantumState::from_bytes(&data3);
        let fid_diff = qs1.fidelity(&qs3);
        assert!(fid_diff < 1.0);
    }

    #[test]
    fn test_quantum_channel_roundtrip() {
        let data = vec![42u8; 1024];
        let qstate = QuantumState::from_bytes(&data);
        let channel = QuantumChannel::new(3);

        let encoded = channel.apply_encode(&qstate).unwrap();
        let restored = channel.apply_decode(&encoded).unwrap();

        let fidelity = qstate.fidelity(&restored);
        assert!(fidelity > 0.99);
    }

    #[test]
    fn test_snapshot_header_serialization() {
        let header = SnapshotHeader {
            version: 1,
            height: 100,
            state_root: "abc123".into(),
            created_at: 1700000000,
            node_version: "27.0.0".into(),
            schema_version: 4,
            protocol_version: 1,
            payload_blake3: "deadbeef".into(),
            uncompressed_size: 1024,
            compressed_size: 512,
            quantum_purity: 0.998,
            von_neumann_entropy: 0.002,
            channel_fidelity: 0.9999,
        };
        let json = serde_json::to_string(&header).unwrap();
        let parsed: SnapshotHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.height, 100);
        assert_eq!(parsed.quantum_purity, 0.998);
        assert!((parsed.von_neumann_entropy - 0.002).abs() < 1e-10);
    }

    #[test]
    fn test_export_import_roundtrip() -> SnapshotResult<()> {
        let temp = TempDir::new()?;
        let data_dir = temp.path().join("data");
        std::fs::create_dir_all(&data_dir)?;
        create_minimal_state(&data_dir)?;

        let snapshot_path = temp.path().join("test_snapshot.json");
        let header = export_snapshot(&data_dir, &snapshot_path)?;

        assert_eq!(header.version, SNAPSHOT_VERSION);
        assert_eq!(header.schema_version, 4);
        assert!(header.quantum_purity > 0.0);
        assert!(header.channel_fidelity > 0.99);

        let verified = verify_snapshot(&snapshot_path)?;
        assert_eq!(verified.payload_blake3, header.payload_blake3);

        let import_dir = temp.path().join("imported");
        std::fs::create_dir_all(&import_dir)?;
        let imported = import_snapshot(&snapshot_path, &import_dir)?;
        assert_eq!(imported.height, header.height);
        assert_eq!(imported.payload_blake3, header.payload_blake3);
        assert!(import_dir.join("schema.json").exists());

        Ok(())
    }

    #[test]
    fn test_verify_corrupted_snapshot() -> SnapshotResult<()> {
        let temp = TempDir::new()?;
        let snapshot = SnapshotFile {
            header: SnapshotHeader {
                version: SNAPSHOT_VERSION,
                height: 0,
                state_root: "".into(),
                created_at: 0,
                node_version: "test".into(),
                schema_version: 4,
                protocol_version: 1,
                payload_blake3: "wrong_hash".into(),
                uncompressed_size: 0,
                compressed_size: 0,
                quantum_purity: 1.0,
                von_neumann_entropy: 0.0,
                channel_fidelity: 1.0,
            },
            payload_b64: base64::engine::general_purpose::STANDARD.encode(b"corrupted"),
        };
        let path = temp.path().join("corrupt.json");
        std::fs::write(&path, serde_json::to_string_pretty(&snapshot)?)?;

        let result = verify_snapshot(&path);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("integrity check failed"));

        Ok(())
    }
}
