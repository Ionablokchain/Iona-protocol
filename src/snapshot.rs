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

use crate::execution::KvState;
use crate::economics::staking::StakeLedger;
use crate::storage::layout::DataLayout;
use crate::types::{Hash32, Height};
use crate::vm::state::VmStorage;
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

/// Snapshot format version.
pub const SNAPSHOT_VERSION: u32 = 1;

/// Zstd compression level (1‑22). 3 is a good balance.
const ZSTD_LEVEL: i32 = 3;

// -----------------------------------------------------------------------------
// Snapshot metadata
// -----------------------------------------------------------------------------

/// Snapshot metadata header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotHeader {
    pub version: u32,
    pub height: Height,
    pub state_root: String,
    pub created_at: u64,
    pub node_version: String,
    pub schema_version: u32,
    pub protocol_version: u32,
    pub payload_blake3: String,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
}

/// Complete snapshot file structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotFile {
    pub header: SnapshotHeader,
    /// Base64-encoded zstd-compressed payload.
    pub payload_b64: String,
}

/// State data included in a snapshot (full node state).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotState {
    pub kv_state: KvState,
    pub stakes: StakeLedger,
    pub vm: VmStorage,
    pub schema: serde_json::Value,
    pub node_meta: Option<serde_json::Value>,
    pub last_height: Height,
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Export the current node state to a compressed snapshot file.
pub fn export_snapshot(data_dir: &str, output_path: &str) -> anyhow::Result<SnapshotHeader> {
    let layout = DataLayout::new(data_dir);
    layout.ensure()?;

    // Load state components
    let kv_state = layout.load_state_full()?;
    let stakes = layout.load_stakes()?;
    let vm = kv_state.vm.clone(); // vm is already part of KvState
    let schema = layout.load_schema()?;
    let node_meta = layout.load_node_meta()?;
    let last_height = layout.latest_height()?;

    // Build snapshot state
    let snapshot_state = SnapshotState {
        kv_state,
        stakes,
        vm,
        schema,
        node_meta,
        last_height,
    };

    // Serialize to JSON
    let json_bytes = serde_json::to_vec(&snapshot_state)?;
    let uncompressed_size = json_bytes.len() as u64;

    // Compress using streaming encoder to avoid loading all at once (though we already have it in memory)
    let compressed = compress_stream(&json_bytes)?;
    let compressed_size = compressed.len() as u64;

    // Compute hash
    let hash = blake3::hash(&compressed);
    let payload_blake3 = hash.to_hex().to_string();

    // Encode payload as base64
    let payload_b64 = base64::engine::general_purpose::STANDARD.encode(&compressed);

    // Create header
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let header = SnapshotHeader {
        version: SNAPSHOT_VERSION,
        height: last_height,
        state_root: hex::encode(kv_state.root().0),
        created_at: now,
        node_version: env!("CARGO_PKG_VERSION").to_string(),
        schema_version: snapshot_state.schema["version"]
            .as_u64()
            .unwrap_or(crate::storage::meta::CURRENT_SCHEMA_VERSION as u64) as u32,
        protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
        payload_blake3,
        uncompressed_size,
        compressed_size,
    };

    let snapshot_file = SnapshotFile {
        header: header.clone(),
        payload_b64,
    };

    // Write atomically
    let out_path = Path::new(output_path);
    let tmp_path = out_path.with_extension("tmp");
    let json_out = serde_json::to_string_pretty(&snapshot_file)?;
    std::fs::write(&tmp_path, json_out)?;
    std::fs::rename(&tmp_path, out_path)?;

    info!(height = last_height, path = output_path, "snapshot exported");
    Ok(header)
}

/// Import a snapshot file into the data directory.
pub fn import_snapshot(snapshot_path: &str, data_dir: &str) -> anyhow::Result<SnapshotHeader> {
    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;
    let header = snapshot_file.header;

    // Decode base64 payload
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&snapshot_file.payload_b64)
        .map_err(|e| anyhow::anyhow!("base64 decode: {}", e))?;

    // Verify blake3 hash
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        anyhow::bail!(
            "snapshot integrity check failed: expected blake3={}, got={}",
            header.payload_blake3,
            hash_hex
        );
    }

    // Decompress
    let json_bytes = decompress_stream(&compressed)?;

    // Parse snapshot state
    let snapshot_state: SnapshotState = serde_json::from_slice(&json_bytes)?;

    // Validate state root
    let computed_root = snapshot_state.kv_state.root();
    let expected_root = Hash32::from_hex(&header.state_root);
    if computed_root != expected_root {
        anyhow::bail!(
            "state root mismatch: computed {} != header {}",
            hex::encode(computed_root.0),
            hex::encode(expected_root.0)
        );
    }

    // Ensure data directory exists
    let layout = DataLayout::new(data_dir);
    layout.ensure()?;

    // Create temporary directory for atomic restore
    let tmp_dir = layout.tmp_dir().join("snapshot_import");
    let _ = std::fs::remove_dir_all(&tmp_dir);
    std::fs::create_dir_all(&tmp_dir)?;

    // Write state files to temporary directory
    let tmp_layout = DataLayout::new(tmp_dir.to_str().unwrap());
    tmp_layout.save_state_full(&snapshot_state.kv_state)?;
    tmp_layout.save_stakes(&snapshot_state.stakes)?;
    tmp_layout.save_schema(&snapshot_state.schema)?;
    if let Some(meta) = &snapshot_state.node_meta {
        tmp_layout.save_node_meta(meta)?;
    }
    // Optionally write a height marker (optional)
    // For now, we rely on the block store; but the node will rebuild from state.

    // Atomic rename: replace entire data directory with temporary one
    // But we cannot replace the whole directory easily. Instead, we move each file.
    // Safer: remove existing data and move new files.
    // We'll keep a backup of the original directory if needed, but for simplicity we just move.
    let target_files = [
        layout.state_full_path(),
        layout.stakes_path(),
        layout.schema_path(),
        layout.node_meta_path(),
    ];
    let tmp_files = [
        tmp_layout.state_full_path(),
        tmp_layout.stakes_path(),
        tmp_layout.schema_path(),
        tmp_layout.node_meta_path(),
    ];

    // Move each file (rename)
    for (tmp, target) in tmp_files.iter().zip(target_files.iter()) {
        if tmp.exists() {
            // Remove existing target if any
            if target.exists() {
                std::fs::remove_file(target)?;
            }
            std::fs::rename(tmp, target)?;
        }
    }

    // Cleanup temporary directory
    let _ = std::fs::remove_dir_all(&tmp_dir);

    info!(height = header.height, path = snapshot_path, "snapshot imported");
    Ok(header)
}

/// Verify a snapshot file without importing it.
pub fn verify_snapshot(snapshot_path: &str) -> anyhow::Result<SnapshotHeader> {
    let raw = std::fs::read_to_string(snapshot_path)?;
    let snapshot_file: SnapshotFile = serde_json::from_str(&raw)?;
    let header = snapshot_file.header;

    // Decode base64 payload
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(&snapshot_file.payload_b64)
        .map_err(|e| anyhow::anyhow!("base64 decode: {}", e))?;

    // Verify blake3 hash
    let hash = blake3::hash(&compressed);
    let hash_hex = hash.to_hex().to_string();
    if hash_hex != header.payload_blake3 {
        anyhow::bail!(
            "snapshot integrity check failed: expected blake3={}, got={}",
            header.payload_blake3,
            hash_hex
        );
    }

    // Decompress
    let json_bytes = decompress_stream(&compressed)?;

    // Parse snapshot state (to ensure it's valid)
    let snapshot_state: SnapshotState = serde_json::from_slice(&json_bytes)?;

    // Validate state root
    let computed_root = snapshot_state.kv_state.root();
    let expected_root = Hash32::from_hex(&header.state_root);
    if computed_root != expected_root {
        anyhow::bail!(
            "state root mismatch: computed {} != header {}",
            hex::encode(computed_root.0),
            hex::encode(expected_root.0)
        );
    }

    Ok(header)
}

// -----------------------------------------------------------------------------
// Helpers: streaming compression / decompression
// -----------------------------------------------------------------------------

/// Compress a byte slice using zstd (streaming encoder, but simple for now).
fn compress_stream(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut compressed = Vec::new();
    let mut encoder = zstd::stream::Encoder::new(&mut compressed, ZSTD_LEVEL)?;
    encoder.write_all(data)?;
    encoder.finish()?;
    Ok(compressed)
}

/// Decompress a byte slice using zstd.
fn decompress_stream(data: &[u8]) -> anyhow::Result<Vec<u8>> {
    let mut decoder = zstd::stream::Decoder::new(data)?;
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;
    use crate::types::Hash32;
    use tempfile::tempdir;

    fn setup_test_state() -> (tempfile::TempDir, DataLayout, KvState) {
        let dir = tempdir().unwrap();
        let layout = DataLayout::new(dir.path().to_str().unwrap());
        layout.ensure().unwrap();

        let mut state = KvState::default();
        state.balances.insert("alice".into(), 1000);
        state.kv.insert("key".into(), "value".into());
        let root = state.root();

        layout.save_state_full(&state).unwrap();
        layout.save_stakes(&Default::default()).unwrap();
        layout.save_schema(&serde_json::json!({"version": 4})).unwrap();
        layout.save_node_meta(&serde_json::json!({})).unwrap();

        (dir, layout, state)
    }

    #[test]
    fn test_export_import_roundtrip() {
        let (data_dir, layout, original_state) = setup_test_state();

        let snapshot_path = data_dir.path().join("snapshot.json");
        let header = export_snapshot(
            data_dir.path().to_str().unwrap(),
            snapshot_path.to_str().unwrap(),
        )
        .unwrap();

        // Verify
        let verified = verify_snapshot(snapshot_path.to_str().unwrap()).unwrap();
        assert_eq!(verified.height, header.height);
        assert_eq!(verified.payload_blake3, header.payload_blake3);

        // Import into a new directory
        let import_dir = tempdir().unwrap();
        let imported = import_snapshot(
            snapshot_path.to_str().unwrap(),
            import_dir.path().to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(imported.height, header.height);

        // Load imported state and compare
        let imported_layout = DataLayout::new(import_dir.path().to_str().unwrap());
        let imported_state = imported_layout.load_state_full().unwrap();
        assert_eq!(imported_state.root(), original_state.root());
    }

    #[test]
    fn test_verify_corrupted_snapshot() {
        let (data_dir, _layout, _) = setup_test_state();
        let snapshot_path = data_dir.path().join("snapshot.json");

        // Export a valid snapshot
        export_snapshot(data_dir.path().to_str().unwrap(), snapshot_path.to_str().unwrap()).unwrap();

        // Corrupt the file
        let mut content = std::fs::read_to_string(&snapshot_path).unwrap();
        content.push_str("extra junk");
        std::fs::write(&snapshot_path, content).unwrap();

        let result = verify_snapshot(snapshot_path.to_str().unwrap());
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("integrity"));
    }
}
