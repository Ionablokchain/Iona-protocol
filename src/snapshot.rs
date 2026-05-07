//! Snapshot export/import tool for IONA.
//!
//! Provides functionality to:
//! - Export the current node state to a compressed snapshot file
//! - Import a snapshot file to restore node state
//! - Verify snapshot integrity using blake3 hashes
//!
//! Snapshot format:
//! - JSON‑serialised state compressed with zstd
//! - blake3 hash for integrity verification
//! - Metadata header with height, state_root, timestamp

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Current snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Default zstd compression level (3 = good balance).
pub const ZSTD_COMPRESSION_LEVEL: i32 = 3;

/// Prefix for backup files created before import.
pub const BACKUP_SUFFIX: &str = ".pre-import.bak";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during snapshot export, import or verification.
#[derive(Debug, Error)]
pub enum SnapshotError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("JSON serialisation error: {source}")]
    Serialization {
        #[from]
        source: serde_json::Error,
    },

    #[error("base64 decode error: {source}")]
    Base64Decode {
        #[from]
        source: base64::DecodeError,
    },

    #[error("zstd compression/decompression error: {source}")]
    Zstd(String),

    #[error("snapshot integrity check failed: expected {expected}, got {actual}")]
    IntegrityMismatch { expected: String, actual: String },

    #[error("invalid snapshot header: {reason}")]
    InvalidHeader { reason: String },

    #[error("snapshot version {version} not supported (expected {expected})")]
    UnsupportedVersion { version: u32, expected: u32 },

    #[error("data directory error: {0}")]
    DataDir(String),
}

pub type SnapshotResult<T> = Result<T, SnapshotError>;

impl From<zstd::Error> for SnapshotError {
    fn from(err: zstd::Error) -> Self {
        Self::Zstd(err.to_string())
    }
}

// -----------------------------------------------------------------------------
// Snapshot structures
// -----------------------------------------------------------------------------

/// Snapshot metadata header.
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
}

impl SnapshotHeader {
    /// Validate the snapshot header.
    pub fn validate(&self) -> SnapshotResult<()> {
        if self.version != SNAPSHOT_VERSION {
            return Err(SnapshotError::UnsupportedVersion {
                version: self.version,
                expected: SNAPSHOT_VERSION,
            });
        }
        if self.payload_blake3.is_empty() {
            return Err(SnapshotError::InvalidHeader {
                reason: "empty payload_blake3".into(),
            });
        }
        if self.compressed_size == 0 && self.uncompressed_size > 0 {
            return Err(SnapshotError::InvalidHeader {
                reason: "compressed size zero but uncompressed non‑zero".into(),
            });
        }
        Ok(())
    }
}

/// Complete snapshot file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub header: SnapshotHeader,
    /// Base64‑encoded zstd‑compressed payload.
    pub payload_b64: String,
}

/// State data included in a snapshot.
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
// Export
// -----------------------------------------------------------------------------

/// Export a snapshot from the data directory.
///
/// Reads `state_full.json`, `stakes.json`, `schema.json`, `node_meta.json`
/// and packages them into a compressed snapshot file.
pub fn export_snapshot(data_dir: impl AsRef<Path>, output_path: impl AsRef<Path>) -> SnapshotResult<SnapshotHeader> {
    let data_dir = data_dir.as_ref();
    let output_path = output_path.as_ref();

    let data = crate::storage::DataDir::new(data_dir.to_str().unwrap_or("."));
    data.ensure().map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    // Load state
    let state_full = data.load_state_full().map_err(|e| SnapshotError::DataDir(e.to_string()))?;
    let stakes = data.load_stakes().map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    // Read schema.json
    let schema_path = data_dir.join("schema.json");
    let schema: serde_json::Value = if schema_path.exists() {
        let s = std::fs::read_to_string(&schema_path)?;
        serde_json::from_str(&s)?
    } else {
        serde_json::json!({"version": crate::storage::CURRENT_SCHEMA_VERSION})
    };

    // Read node_meta.json
    let meta_path = data_dir.join("node_meta.json");
    let node_meta = if meta_path.exists() {
        let s = std::fs::read_to_string(&meta_path)?;
        Some(serde_json::from_str(&s)?)
    } else {
        None
    };

    // Determine height from blocks directory
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

    // Compute state root
    let state_root = state_full.root();
    let state_root_hex = hex::encode(state_root.0);

    // Serialise state
    let snapshot_state = SnapshotState {
        accounts: serde_json::from_value(serde_json::to_value(&state_full)?).unwrap_or_default(),
        stakes: serde_json::to_value(&stakes)?,
        vm: serde_json::json!({}),
        schema: schema.clone(),
        node_meta,
    };

    let json_bytes = serde_json::to_vec(&snapshot_state)?;
    let uncompressed_size = json_bytes.len() as u64;

    let compressed = zstd::encode_all(json_bytes.as_slice(), ZSTD_COMPRESSION_LEVEL)?;
    let compressed_size = compressed.len() as u64;

    let hash = blake3::hash(&compressed);
    let payload_blake3 = hash.to_hex().to_string();

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
// Import
// -----------------------------------------------------------------------------

/// Import a snapshot file into the data directory.
///
/// Verifies blake3 hash integrity, decompresses, and restores state files.
pub fn import_snapshot(snapshot_path: impl AsRef<Path>, data_dir: impl AsRef<Path>) -> SnapshotResult<SnapshotHeader> {
    let snapshot_path = snapshot_path.as_ref();
    let data_dir = data_dir.as_ref();

    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;

    let header = snapshot_file.header;
    header.validate()?;

    // Decode base64 payload
    let compressed = base64::engine::general_purpose::STANDARD.decode(&snapshot_file.payload_b64)?;

    // Verify blake3 hash
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(SnapshotError::IntegrityMismatch {
            expected: header.payload_blake3,
            actual: hash_hex,
        });
    }

    // Decompress
    let json_bytes = zstd::decode_all(compressed.as_slice())?;

    let snapshot_state: SnapshotState = serde_json::from_slice(&json_bytes)?;

    // Ensure data directory exists
    let data = crate::storage::DataDir::new(data_dir.to_str().unwrap_or("."));
    data.ensure().map_err(|e| SnapshotError::DataDir(e.to_string()))?;

    // Backup existing state files
    let state_path = data_dir.join("state_full.json");
    if state_path.exists() {
        let backup = state_path.with_extension("json").with_file_name(format!("{}{}", state_path.file_stem().unwrap_or_default().to_string_lossy(), BACKUP_SUFFIX));
        std::fs::copy(&state_path, &backup)?;
    }

    let stakes_path = data_dir.join("stakes.json");
    if stakes_path.exists() {
        let backup = stakes_path.with_extension("json").with_file_name(format!("{}{}", stakes_path.file_stem().unwrap_or_default().to_string_lossy(), BACKUP_SUFFIX));
        std::fs::copy(&stakes_path, &backup)?;
    }

    // Write state files
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
// Verification
// -----------------------------------------------------------------------------

/// Verify a snapshot file without importing it.
///
/// Checks: file format, blake3 hash, decompression, JSON parse.
pub fn verify_snapshot(snapshot_path: impl AsRef<Path>) -> SnapshotResult<SnapshotHeader> {
    let snapshot_path = snapshot_path.as_ref();

    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;

    let header = snapshot_file.header;
    header.validate()?;

    let compressed = base64::engine::general_purpose::STANDARD.decode(&snapshot_file.payload_b64)?;

    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(SnapshotError::IntegrityMismatch {
            expected: header.payload_blake3,
            actual: hash_hex,
        });
    }

    // Verify decompression
    let json_bytes = zstd::decode_all(compressed.as_slice())?;

    // Verify JSON parse
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
        std::fs::write(dir.join("stakes.json"), r#"{"validators":{},"processed_evidence":[]}"#)?;
        std::fs::write(dir.join("schema.json"), r#"{"version":4}"#)?;
        Ok(())
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
        };
        let json = serde_json::to_string(&header).unwrap();
        let parsed: SnapshotHeader = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.height, 100);
        assert_eq!(parsed.state_root, "abc123");
        assert_eq!(parsed.schema_version, 4);
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
