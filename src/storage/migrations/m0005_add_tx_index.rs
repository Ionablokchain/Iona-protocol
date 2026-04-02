//! Migration v4 → v5: Add transaction index for fast tx‑by‑hash lookup.
//!
//! Creates a `tx_index.json` mapping `tx_hash -> (block_height, tx_position)`
//! by scanning existing block files. This migration is idempotent: if
//! `tx_index.json` already exists, it is skipped.
//!
//! This is a **background** migration — the node can serve requests while
//! the index is being built. Reads fall back to linear scan until complete.
//!
//! # Steps
//!
//! 1. Check if `tx_index.json` already exists. If yes, skip.
//! 2. Scan the `blocks/` directory for all `.json` files.
//! 3. For each block, extract the height and transaction hashes.
//! 4. Build an in‑memory index: `tx_hash → (block_height, tx_position)`.
//! 5. Write the index atomically (temporary file + rename).
//! 6. Update the migration log in `SchemaMeta`.

use crate::storage::SchemaMeta;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{info, warn};

// -----------------------------------------------------------------------------
// Index entry
// -----------------------------------------------------------------------------

/// Index entry: block height + position within block.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct TxIndexEntry {
    pub block_height: u64,
    pub tx_position: u32,
}

// -----------------------------------------------------------------------------
// Migration function
// -----------------------------------------------------------------------------

/// Execute the v4 → v5 migration.
///
/// # Arguments
/// * `data_dir` – Path to the node's data directory.
/// * `meta` – Mutable reference to the schema metadata (used to log the migration).
///
/// # Returns
/// `Ok(())` on success, `Err` with an error message on failure.
pub fn migrate(data_dir: &str, meta: &mut SchemaMeta) -> io::Result<()> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let index_path = Path::new(data_dir).join("tx_index.json");

    if index_path.exists() {
        info!(path = %index_path.display(), "tx_index.json already exists, skipping migration");
        meta.migration_log.push(format!(
            "[{timestamp}] v4 -> v5: tx_index.json already exists, skipping"
        ));
        return Ok(());
    }

    info!("Building transaction index from block files");
    let index = build_index(data_dir)?;

    // Write index atomically.
    let tmp_path = index_path.with_extension("tmp");
    let out = serde_json::to_string_pretty(&index)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(&tmp_path, &out)?;
    fs::rename(&tmp_path, &index_path)?;

    info!(entries = index.len(), path = %index_path.display(), "tx_index.json created");

    meta.migration_log.push(format!(
        "[{timestamp}] v4 -> v5: tx_index.json created with {} entries",
        index.len()
    ));

    Ok(())
}

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Build the transaction index by scanning the blocks directory.
fn build_index(data_dir: &str) -> io::Result<BTreeMap<String, TxIndexEntry>> {
    let blocks_dir = Path::new(data_dir).join("blocks");
    let mut index = BTreeMap::new();

    if !blocks_dir.exists() {
        info!(path = %blocks_dir.display(), "blocks directory does not exist, creating empty index");
        return Ok(index);
    }

    // Collect and sort block files by name (assumes files are named like "height.json").
    let mut entries: Vec<fs::DirEntry> = fs::read_dir(&blocks_dir)?
        .filter_map(|e| e.ok())
        .filter(|e| {
            e.path()
                .extension()
                .map(|ext| ext == "json")
                .unwrap_or(false)
        })
        .collect();

    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to read block file, skipping");
                continue;
            }
        };

        let value: serde_json::Value = match serde_json::from_str(&content) {
            Ok(v) => v,
            Err(e) => {
                warn!(path = %path.display(), error = %e, "failed to parse block JSON, skipping");
                continue;
            }
        };

        // Extract height from header.
        let height = value
            .get("header")
            .and_then(|h| h.get("height"))
            .and_then(|h| h.as_u64())
            .unwrap_or(0);

        // Extract transactions.
        if let Some(txs) = value.get("txs").and_then(|t| t.as_array()) {
            for (pos, tx) in txs.iter().enumerate() {
                let hash = match tx.get("hash").and_then(|h| h.as_str()) {
                    Some(h) => h,
                    None => {
                        warn!(path = %path.display(), pos, "transaction missing hash, skipping");
                        continue;
                    }
                };
                index.insert(
                    hash.to_string(),
                    TxIndexEntry {
                        block_height: height,
                        tx_position: pos as u32,
                    },
                );
            }
        }
    }

    Ok(index)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn create_block_file(dir: &Path, height: u64, txs: Vec<(&str, &str)>) -> io::Result<()> {
        let mut block = serde_json::json!({
            "header": {
                "height": height
            },
            "txs": []
        });

        let txs_array = txs
            .into_iter()
            .map(|(hash, _)| serde_json::json!({ "hash": hash }))
            .collect::<Vec<_>>();
        block["txs"] = serde_json::Value::Array(txs_array);

        let block_path = dir.join(format!("{}.json", height));
        let content = serde_json::to_string_pretty(&block)?;
        fs::write(block_path, content)?;
        Ok(())
    }

    #[test]
    fn test_build_index_empty_dir() {
        let dir = tempdir().unwrap();
        let index = build_index(dir.path().to_str().unwrap()).unwrap();
        assert!(index.is_empty());
    }

    #[test]
    fn test_build_index_with_blocks() {
        let dir = tempdir().unwrap();
        let blocks_dir = dir.path().join("blocks");
        fs::create_dir_all(&blocks_dir).unwrap();

        // Create block 1 with two transactions.
        create_block_file(
            &blocks_dir,
            1,
            vec![
                ("0xaaa", "tx1"),
                ("0xbbb", "tx2"),
            ],
        )
        .unwrap();

        // Create block 2 with one transaction.
        create_block_file(
            &blocks_dir,
            2,
            vec![("0xccc", "tx3")],
        )
        .unwrap();

        let index = build_index(dir.path().to_str().unwrap()).unwrap();

        assert_eq!(index.len(), 3);
        assert_eq!(
            index.get("0xaaa").unwrap(),
            &TxIndexEntry {
                block_height: 1,
                tx_position: 0
            }
        );
        assert_eq!(
            index.get("0xbbb").unwrap(),
            &TxIndexEntry {
                block_height: 1,
                tx_position: 1
            }
        );
        assert_eq!(
            index.get("0xccc").unwrap(),
            &TxIndexEntry {
                block_height: 2,
                tx_position: 0
            }
        );
    }

    #[test]
    fn test_migration_creates_index() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        // Create a block file.
        let blocks_dir = dir.path().join("blocks");
        fs::create_dir_all(&blocks_dir).unwrap();
        create_block_file(&blocks_dir, 1, vec![("0xdeadbeef", "tx1")]).unwrap();

        migrate(data_dir, &mut meta).unwrap();

        let index_path = dir.path().join("tx_index.json");
        assert!(index_path.exists());

        let content = fs::read_to_string(&index_path).unwrap();
        let index: BTreeMap<String, TxIndexEntry> = serde_json::from_str(&content).unwrap();
        assert_eq!(index.len(), 1);
        assert!(index.contains_key("0xdeadbeef"));

        // Migration log should contain an entry.
        assert!(!meta.migration_log.is_empty());
        assert!(meta.migration_log[0].contains("v4 -> v5"));
    }

    #[test]
    fn test_migration_skips_if_exists() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        let index_path = dir.path().join("tx_index.json");
        fs::write(&index_path, "{}").unwrap();

        migrate(data_dir, &mut meta).unwrap();

        // File should still be empty.
        let content = fs::read_to_string(&index_path).unwrap();
        assert_eq!(content, "{}");
        assert!(meta.migration_log[0].contains("already exists"));
    }

    #[test]
    fn test_migration_atomic_write() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        migrate(data_dir, &mut meta).unwrap();

        let index_path = dir.path().join("tx_index.json");
        let tmp_path = index_path.with_extension("tmp");

        // Temporary file should be gone.
        assert!(!tmp_path.exists());
        // Final file should be valid JSON.
        let content = fs::read_to_string(&index_path).unwrap();
        let _: BTreeMap<String, TxIndexEntry> = serde_json::from_str(&content).unwrap();
    }

    #[test]
    fn test_migration_handles_corrupt_block() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        let blocks_dir = dir.path().join("blocks");
        fs::create_dir_all(&blocks_dir).unwrap();

        // Create a valid block.
        create_block_file(&blocks_dir, 1, vec![("0xaaa", "tx1")]).unwrap();

        // Create a corrupt block file.
        let corrupt_path = blocks_dir.join("corrupt.json");
        fs::write(&corrupt_path, "this is not json").unwrap();

        migrate(data_dir, &mut meta).unwrap();

        let index_path = dir.path().join("tx_index.json");
        let content = fs::read_to_string(&index_path).unwrap();
        let index: BTreeMap<String, TxIndexEntry> = serde_json::from_str(&content).unwrap();

        // Only the valid transaction should be indexed.
        assert_eq!(index.len(), 1);
        assert!(index.contains_key("0xaaa"));
    }
}
