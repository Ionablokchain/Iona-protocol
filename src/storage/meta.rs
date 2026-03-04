//! Persistent node metadata stored alongside the data directory.
//!
//! `NodeMeta` tracks:
//!   - `schema_version` — current on-disk storage format.
//!   - `protocol_version` — last protocol version this node produced/validated.
//!   - `node_version` — semver of the binary that last wrote this file.
//!   - `migration_state` — crash-safe migration resume marker.
//!
//! This file is read at startup to detect whether migrations or protocol
//! upgrades are needed.
//!
//! # Dual-Read Support (UPGRADE_SPEC section 6.2)
//!
//! When a schema migration changes the storage format:
//! ```text
//! Read(key):  try new format, fallback to old format
//! Write(key): always write new format
//! ```
//! The `migration_state` field tracks in-progress migrations so that
//! a crash during migration can be safely resumed.

use serde::{Deserialize, Serialize};
use std::{fs, io, path::Path};

/// In-progress migration state for crash-safe resume.
///
/// If the node crashes mid-migration, this field records which step
/// was in progress so it can be resumed on next startup.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationState {
    /// Schema version we're migrating FROM.
    pub from_sv: u32,
    /// Schema version we're migrating TO.
    pub to_sv: u32,
    /// Human-readable description of the current step.
    pub step: String,
    /// Timestamp when migration started.
    pub started_at: String,
}

/// Persistent metadata written to `<data_dir>/node_meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMeta {
    /// On-disk storage schema version (matches `storage::CURRENT_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// Last protocol version this node operated under.
    pub protocol_version: u32,
    /// Semver of the node binary that last wrote this file.
    pub node_version: String,
    /// ISO-8601 timestamp of last update.
    #[serde(default)]
    pub updated_at: Option<String>,
    /// If non-null, a migration is in progress (crash-safe resume).
    /// Set before migration starts, cleared after migration completes.
    #[serde(default)]
    pub migration_state: Option<MigrationState>,
}

impl NodeMeta {
    /// Create a fresh `NodeMeta` for a new data directory.
    pub fn new_current() -> Self {
        Self {
            schema_version: crate::storage::CURRENT_SCHEMA_VERSION,
            protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            updated_at: Some(now_iso8601()),
            migration_state: None,
        }
    }

    /// Mark a migration as in-progress (for crash-safe resume).
    pub fn begin_migration(&mut self, from_sv: u32, to_sv: u32, step: &str, data_dir: &str) -> io::Result<()> {
        self.migration_state = Some(MigrationState {
            from_sv,
            to_sv,
            step: step.to_string(),
            started_at: now_iso8601(),
        });
        self.save(data_dir)
    }

    /// Clear the migration state (migration completed successfully).
    pub fn end_migration(&mut self, data_dir: &str) -> io::Result<()> {
        self.migration_state = None;
        self.save(data_dir)
    }

    /// Check if there's a pending migration that needs to be resumed.
    pub fn has_pending_migration(&self) -> bool {
        self.migration_state.is_some()
    }

    /// Load from disk, or return `None` if the file doesn't exist.
    pub fn load(data_dir: &str) -> io::Result<Option<Self>> {
        let path = format!("{data_dir}/node_meta.json");
        if !Path::new(&path).exists() {
            return Ok(None);
        }
        let s = fs::read_to_string(&path)?;
        let meta: Self = serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("node_meta.json: {e}")))?;
        Ok(Some(meta))
    }

    /// Persist to disk (atomic write via tmp + rename).
    pub fn save(&mut self, data_dir: &str) -> io::Result<()> {
        self.updated_at = Some(now_iso8601());
        let path = format!("{data_dir}/node_meta.json");
        let tmp = format!("{path}.tmp");
        let out = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("node_meta.json encode: {e}")))?;
        fs::write(&tmp, &out)?;
        fs::rename(&tmp, &path)?;
        Ok(())
    }

    /// Check if the on-disk meta is compatible with this binary.
    /// Returns `Err` with a human-readable message if not.
    pub fn check_compatibility(&self) -> Result<(), String> {
        // Schema too new: this binary can't read the data.
        if self.schema_version > crate::storage::CURRENT_SCHEMA_VERSION {
            return Err(format!(
                "on-disk schema v{} is newer than this binary (v{}); please upgrade",
                self.schema_version,
                crate::storage::CURRENT_SCHEMA_VERSION,
            ));
        }
        // Protocol version too new: this binary doesn't know the rules.
        if !crate::protocol::version::is_supported(self.protocol_version) {
            return Err(format!(
                "on-disk protocol v{} is not supported by this binary; supported: {:?}",
                self.protocol_version,
                crate::protocol::version::SUPPORTED_PROTOCOL_VERSIONS,
            ));
        }
        Ok(())
    }
}

fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Simple ISO-like timestamp without pulling in chrono.
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_current() {
        let meta = NodeMeta::new_current();
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        assert_eq!(meta.protocol_version, crate::protocol::version::CURRENT_PROTOCOL_VERSION);
        assert!(!meta.node_version.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = NodeMeta::new_current();
        meta.save(data_dir).unwrap();

        let loaded = NodeMeta::load(data_dir).unwrap().unwrap();
        assert_eq!(loaded.schema_version, meta.schema_version);
        assert_eq!(loaded.protocol_version, meta.protocol_version);
        assert_eq!(loaded.node_version, meta.node_version);
    }

    #[test]
    fn test_check_compatibility_ok() {
        let meta = NodeMeta::new_current();
        assert!(meta.check_compatibility().is_ok());
    }

    #[test]
    fn test_check_compatibility_schema_too_new() {
        let meta = NodeMeta {
            schema_version: 999,
            protocol_version: 1,
            node_version: "99.0.0".into(),
            updated_at: None,
            migration_state: None,
        };
        assert!(meta.check_compatibility().is_err());
    }

    #[test]
    fn test_migration_state_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let mut meta = NodeMeta::new_current();
        assert!(!meta.has_pending_migration());

        meta.begin_migration(3, 4, "adding node_meta.json", data_dir).unwrap();
        assert!(meta.has_pending_migration());

        // Reload from disk and verify migration_state is persisted
        let loaded = NodeMeta::load(data_dir).unwrap().unwrap();
        assert!(loaded.has_pending_migration());
        let ms = loaded.migration_state.unwrap();
        assert_eq!(ms.from_sv, 3);
        assert_eq!(ms.to_sv, 4);

        meta.end_migration(data_dir).unwrap();
        assert!(!meta.has_pending_migration());

        let loaded2 = NodeMeta::load(data_dir).unwrap().unwrap();
        assert!(!loaded2.has_pending_migration());
    }
}
