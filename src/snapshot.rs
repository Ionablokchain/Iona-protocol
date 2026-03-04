//! Snapshot export/import tool for IONA.
//!
//! Provides functionality to:
//! - Export the current node state to a compressed snapshot file
//! - Import a snapshot file to restore node state
//! - Verify snapshot integrity using blake3 hashes
//!
//! Snapshot format:
//! - JSON-serialized state compressed with zstd
//! - blake3 hash for integrity verification
//! - Metadata header with height, state_root, timestamp

use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io;
use std::path::Path;

/// Snapshot metadata header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    /// Snapshot format version.
    pub version: u32,
    /// Block height at which this snapshot was taken.
    pub height: u64,
    /// Hex-encoded state root hash.
    pub state_root: String,
    /// Unix timestamp when the snapshot was created.
    pub created_at: u64,
    /// Node software version that created this snapshot.
    pub node_version: String,
    /// Schema version of the data.
    pub schema_version: u32,
    /// Protocol version at this height.
    pub protocol_version: u32,
    /// blake3 hash of the compressed payload (hex).
    pub payload_blake3: String,
    /// Uncompressed payload size in bytes.
    pub uncompressed_size: u64,
    /// Compressed payload size in bytes.
    pub compressed_size: u64,
}

/// Complete snapshot file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub header: SnapshotHeader,
    /// Base64-encoded zstd-compressed payload.
    pub payload_b64: String,
}

/// State data included in a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    /// Account balances and state.
    pub accounts: BTreeMap<String, serde_json::Value>,
    /// Stake ledger.
    pub stakes: serde_json::Value,
    /// VM storage (contracts, code, nonces).
    pub vm: serde_json::Value,
    /// Schema metadata.
    pub schema: serde_json::Value,
    /// Node metadata (protocol version, etc).
    #[serde(default)]
    pub node_meta: Option<serde_json::Value>,
}

/// Export a snapshot from the data directory.
///
/// Reads state_full.json, stakes.json, schema.json, node_meta.json
/// and packages them into a compressed snapshot file.
pub fn export_snapshot(data_dir: &str, output_path: &str) -> io::Result<SnapshotHeader> {
    let data = crate::storage::DataDir::new(data_dir);
    data.ensure()?;

    // Load state
    let state_full = data.load_state_full()?;
    let stakes = data.load_stakes()?;

    // Read schema.json
    let schema_path = format!("{}/schema.json", data_dir);
    let schema: serde_json::Value = if Path::new(&schema_path).exists() {
        let s = std::fs::read_to_string(&schema_path)?;
        serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("schema.json: {e}")))?
    } else {
        serde_json::json!({"version": crate::storage::CURRENT_SCHEMA_VERSION})
    };

    // Read node_meta.json
    let meta_path = format!("{}/node_meta.json", data_dir);
    let node_meta: Option<serde_json::Value> = if Path::new(&meta_path).exists() {
        let s = std::fs::read_to_string(&meta_path)?;
        Some(serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("node_meta.json: {e}")))?)
    } else {
        None
    };

    // Get height from block store
    let blocks_dir = format!("{}/blocks", data_dir);
    let height = if Path::new(&blocks_dir).exists() {
        let mut max_h: u64 = 0;
        if let Ok(entries) = std::fs::read_dir(&blocks_dir) {
            for entry in entries.flatten() {
                if let Some(name) = entry.file_name().to_str() {
                    if let Some(h_str) = name.strip_suffix(".json") {
                        if let Ok(h) = h_str.parse::<u64>() {
                            if h > max_h {
                                max_h = h;
                            }
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

    // Serialize state
    let snapshot_state = SnapshotState {
        accounts: serde_json::from_value(serde_json::to_value(&state_full)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?)
            .unwrap_or_default(),
        stakes: serde_json::to_value(&stakes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?,
        vm: serde_json::json!({}),
        schema: schema.clone(),
        node_meta,
    };

    let json_bytes = serde_json::to_vec(&snapshot_state)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let uncompressed_size = json_bytes.len() as u64;

    // Compress with zstd (level 3 for good balance)
    let compressed = zstd::encode_all(json_bytes.as_slice(), 3)
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("zstd compress: {e}")))?;
    let compressed_size = compressed.len() as u64;

    // Compute blake3 hash of compressed data
    let hash = blake3::hash(&compressed);
    let payload_blake3 = hash.to_hex().to_string();

    // Encode payload as base64
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&compressed);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let schema_version = schema.get("version")
        .and_then(|v| v.as_u64())
        .unwrap_or(crate::storage::CURRENT_SCHEMA_VERSION as u64) as u32;

    let header = SnapshotHeader {
        version: 1,
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

    let snapshot_file = SnapshotFile {
        header: header.clone(),
        payload_b64,
    };

    let output = serde_json::to_string_pretty(&snapshot_file)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(output_path, output)?;

    Ok(header)
}

/// Import a snapshot file into the data directory.
///
/// Verifies blake3 hash integrity, decompresses, and restores state files.
pub fn import_snapshot(snapshot_path: &str, data_dir: &str) -> io::Result<SnapshotHeader> {
    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("snapshot parse: {e}")))?;

    let header = &snapshot_file.header;

    // Decode base64 payload
    use base64::Engine;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&snapshot_file.payload_b64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode: {e}")))?;

    // Verify blake3 hash
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "snapshot integrity check failed: expected blake3={}, got={}",
                header.payload_blake3, hash_hex
            ),
        ));
    }

    // Decompress
    let json_bytes = zstd::decode_all(compressed.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("zstd decompress: {e}")))?;

    let snapshot_state: SnapshotState = serde_json::from_slice(&json_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state parse: {e}")))?;

    // Ensure data directory exists
    let data = crate::storage::DataDir::new(data_dir);
    data.ensure()?;

    // Backup existing state if present
    let state_path = format!("{}/state_full.json", data_dir);
    if Path::new(&state_path).exists() {
        let backup = format!("{}.pre-import.bak", state_path);
        std::fs::copy(&state_path, &backup)?;
    }

    let stakes_path = format!("{}/stakes.json", data_dir);
    if Path::new(&stakes_path).exists() {
        let backup = format!("{}.pre-import.bak", stakes_path);
        std::fs::copy(&stakes_path, &backup)?;
    }

    // Write state files
    let accounts_json = serde_json::to_string_pretty(&snapshot_state.accounts)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(&state_path, &accounts_json)?;

    let stakes_json = serde_json::to_string_pretty(&snapshot_state.stakes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(&stakes_path, &stakes_json)?;

    // Write schema.json
    let schema_json = serde_json::to_string_pretty(&snapshot_state.schema)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    std::fs::write(format!("{}/schema.json", data_dir), &schema_json)?;

    // Write node_meta.json if present
    if let Some(ref meta) = snapshot_state.node_meta {
        let meta_json = serde_json::to_string_pretty(meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
        std::fs::write(format!("{}/node_meta.json", data_dir), &meta_json)?;
    }

    Ok(snapshot_file.header)
}

/// Verify a snapshot file without importing it.
///
/// Checks: file format, blake3 hash, decompression, JSON parse.
pub fn verify_snapshot(snapshot_path: &str) -> io::Result<SnapshotHeader> {
    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("snapshot parse: {e}")))?;

    let header = &snapshot_file.header;

    // Decode base64 payload
    use base64::Engine;
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&snapshot_file.payload_b64)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("base64 decode: {e}")))?;

    // Verify blake3 hash
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "snapshot integrity check failed: expected blake3={}, got={}",
                header.payload_blake3, hash_hex
            ),
        ));
    }

    // Verify decompression works
    let json_bytes = zstd::decode_all(compressed.as_slice())
        .map_err(|e| io::Error::new(io::ErrorKind::Other, format!("zstd decompress: {e}")))?;

    // Verify JSON parse works
    let _: SnapshotState = serde_json::from_slice(&json_bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state parse: {e}")))?;

    Ok(snapshot_file.header.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_snapshot_state_serialization() {
        let state = SnapshotState {
            accounts: BTreeMap::new(),
            stakes: serde_json::json!({}),
            vm: serde_json::json!({}),
            schema: serde_json::json!({"version": 4}),
            node_meta: None,
        };
        let json = serde_json::to_string(&state).unwrap();
        let parsed: SnapshotState = serde_json::from_str(&json).unwrap();
        assert!(parsed.accounts.is_empty());
    }

    #[test]
    fn test_export_import_roundtrip() {
        let tmp = std::env::temp_dir().join("iona_snapshot_test");
        let data_dir = tmp.join("data");
        let _ = std::fs::create_dir_all(&data_dir);

        // Create minimal state files matching KvState structure
        std::fs::write(
            data_dir.join("state_full.json"),
            r#"{"kv":{},"balances":{},"nonces":{},"burned":0,"vm":{"storage":{},"code":{},"nonces":{},"logs":[]}}"#
        ).unwrap();
        std::fs::write(
            data_dir.join("stakes.json"),
            r#"{"validators":{},"processed_evidence":[]}"#
        ).unwrap();
        std::fs::write(
            data_dir.join("schema.json"),
            r#"{"version":4}"#
        ).unwrap();

        let snapshot_path = tmp.join("test_snapshot.json");
        let header = export_snapshot(
            data_dir.to_str().unwrap(),
            snapshot_path.to_str().unwrap(),
        ).unwrap();

        assert_eq!(header.version, 1);
        assert_eq!(header.schema_version, 4);

        // Verify the snapshot
        let verified = verify_snapshot(snapshot_path.to_str().unwrap()).unwrap();
        assert_eq!(verified.payload_blake3, header.payload_blake3);

        // Import into a new directory
        let import_dir = tmp.join("imported");
        let _ = std::fs::create_dir_all(&import_dir);
        let imported = import_snapshot(
            snapshot_path.to_str().unwrap(),
            import_dir.to_str().unwrap(),
        ).unwrap();

        assert_eq!(imported.height, header.height);
        assert_eq!(imported.payload_blake3, header.payload_blake3);

        // Verify imported files exist
        assert!(import_dir.join("schema.json").exists());

        // Cleanup
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn test_verify_corrupted_snapshot() {
        let tmp = std::env::temp_dir().join("iona_snapshot_corrupt_test");
        let _ = std::fs::create_dir_all(&tmp);

        let snapshot = SnapshotFile {
            header: SnapshotHeader {
                version: 1,
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

        let path = tmp.join("corrupt.json");
        std::fs::write(&path, serde_json::to_string(&snapshot).unwrap()).unwrap();

        let result = verify_snapshot(path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("integrity check failed"));

        let _ = std::fs::remove_dir_all(&tmp);
    }
}
