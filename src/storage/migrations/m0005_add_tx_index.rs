//! Migration v4 -> v5: Add transaction index for fast tx-by-hash lookup.
//!
//! Creates a `tx_index.json` mapping `tx_hash -> (block_height, tx_position)`
//! by scanning existing block files. This migration is idempotent: if
//! `tx_index.json` already exists, it is skipped.
//!
//! This is a **background** migration — the node can serve requests while
//! the index is being built. Reads fall back to linear scan until complete.

use crate::storage::SchemaMeta;
use std::{collections::BTreeMap, fs, io, path::Path};

/// Index entry: block height + position within block.
#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct TxIndexEntry {
    pub block_height: u64,
    pub tx_position: u32,
}

pub fn migrate(data_dir: &str, meta: &mut SchemaMeta) -> io::Result<()> {
    let timestamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    let index_path = format!("{data_dir}/tx_index.json");

    if Path::new(&index_path).exists() {
        meta.migration_log.push(format!(
            "[{timestamp}] v4 -> v5: tx_index.json already exists, skipping"
        ));
        return Ok(());
    }

    // Scan blocks directory to build index.
    let blocks_dir = format!("{data_dir}/blocks");
    let mut index: BTreeMap<String, TxIndexEntry> = BTreeMap::new();

    if Path::new(&blocks_dir).exists() {
        let mut entries: Vec<_> = fs::read_dir(&blocks_dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map(|ext| ext == "json").unwrap_or(false))
            .collect();
        entries.sort_by_key(|e| e.file_name());

        for entry in entries {
            if let Ok(content) = fs::read_to_string(entry.path()) {
                if let Ok(val) = serde_json::from_str::<serde_json::Value>(&content) {
                    let height = val.get("header")
                        .and_then(|h| h.get("height"))
                        .and_then(|h| h.as_u64())
                        .unwrap_or(0);
                    if let Some(txs) = val.get("txs").and_then(|t| t.as_array()) {
                        for (pos, tx) in txs.iter().enumerate() {
                            if let Some(hash) = tx.get("hash").and_then(|h| h.as_str()) {
                                index.insert(hash.to_string(), TxIndexEntry {
                                    block_height: height,
                                    tx_position: pos as u32,
                                });
                            }
                        }
                    }
                }
            }
        }
    }

    // Write index atomically.
    let tmp = format!("{index_path}.tmp");
    let out = serde_json::to_string_pretty(&index)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, &index_path)?;

    meta.migration_log.push(format!(
        "[{timestamp}] v4 -> v5: tx_index.json created with {} entries",
        index.len()
    ));

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migrate_empty_data_dir() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        migrate(data_dir, &mut meta).unwrap();

        // Should create tx_index.json with empty index.
        let index_path = format!("{data_dir}/tx_index.json");
        assert!(Path::new(&index_path).exists());

        let content = fs::read_to_string(&index_path).unwrap();
        let index: BTreeMap<String, TxIndexEntry> = serde_json::from_str(&content).unwrap();
        assert!(index.is_empty());
    }

    #[test]
    fn test_migrate_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = SchemaMeta {
            version: 4,
            migrated_at: None,
            migration_log: Vec::new(),
        };

        // Run twice — should not error.
        migrate(data_dir, &mut meta).unwrap();
        migrate(data_dir, &mut meta).unwrap();
        assert_eq!(meta.migration_log.len(), 2);
    }
}
