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

use crate::data_layout::DataLayout;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Custom error type for NodeMeta operations.
#[derive(Debug, thiserror::Error)]
pub enum NodeMetaError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization/deserialization error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("Schema version mismatch: on-disk v{on_disk}, binary v{binary}")]
    SchemaVersionMismatch { on_disk: u32, binary: u32 },

    #[error("Protocol version {0} not supported")]
    UnsupportedProtocol(u32),

    #[error("Corrupted node_meta.json: {0}")]
    Corrupted(String),
}

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
    /// Unix timestamp (seconds) when migration started.
    pub started_at: u64,
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
    /// Unix timestamp (seconds) of last update.
    #[serde(default)]
    pub updated_at: Option<u64>,
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
            updated_at: Some(now_unix_secs()),
            migration_state: None,
        }
    }

    /// Mark a migration as in-progress (for crash-safe resume).
    pub fn begin_migration(&mut self, from_sv: u32, to_sv: u32, step: &str, layout: &DataLayout) -> Result<(), NodeMetaError> {
        self.migration_state = Some(MigrationState {
            from_sv,
            to_sv,
            step: step.to_string(),
            started_at: now_unix_secs(),
        });
        self.save(layout)
    }

    /// Clear the migration state (migration completed successfully).
    pub fn end_migration(&mut self, layout: &DataLayout) -> Result<(), NodeMetaError> {
        self.migration_state = None;
        self.save(layout)
    }

    /// Check if there's a pending migration that needs to be resumed.
    pub fn has_pending_migration(&self) -> bool {
        self.migration_state.is_some()
    }

    /// Load from disk using the provided `DataLayout`.
    /// Returns `Ok(None)` if the file does not exist.
    pub fn load(layout: &DataLayout) -> Result<Option<Self>, NodeMetaError> {
        let path = layout.node_meta_path();
        if !path.exists() {
            return Ok(None);
        }
        let s = fs::read_to_string(&path)?;
        let meta: Self = serde_json::from_str(&s)
            .map_err(|e| NodeMetaError::Corrupted(format!("{}", e)))?;

        // Basic validation: ensure schema_version and protocol_version are within reasonable bounds.
        if meta.schema_version > 10_000 {  // arbitrary upper bound
            return Err(NodeMetaError::Corrupted("schema_version out of range".into()));
        }
        if meta.protocol_version > 1_000 {
            return Err(NodeMetaError::Corrupted("protocol_version out of range".into()));
        }

        Ok(Some(meta))
    }

    /// Persist to disk atomically using `DataLayout`'s atomic write.
    pub fn save(&mut self, layout: &DataLayout) -> Result<(), NodeMetaError> {
        self.updated_at = Some(now_unix_secs());
        let path = layout.node_meta_path();
        let json = serde_json::to_string_pretty(self)?;
        // Ensure parent directory exists (it should, but just in case)
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        layout.atomic_write(&path, json.as_bytes())?;
        Ok(())
    }

    /// Check if the on-disk meta is compatible with this binary.
    /// Returns `Err(NodeMetaError)` with a descriptive error if not.
    pub fn check_compatibility(&self) -> Result<(), NodeMetaError> {
        // Schema too new: this binary can't read the data.
        if self.schema_version > crate::storage::CURRENT_SCHEMA_VERSION {
            return Err(NodeMetaError::SchemaVersionMismatch {
                on_disk: self.schema_version,
                binary: crate::storage::CURRENT_SCHEMA_VERSION,
            });
        }
        // Protocol version too new: this binary doesn't know the rules.
        if !crate::protocol::version::is_supported(self.protocol_version) {
            return Err(NodeMetaError::UnsupportedProtocol(self.protocol_version));
        }
        Ok(())
    }
}

/// Returns current Unix timestamp in seconds.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_layout::DataLayout;
    use tempfile::tempdir;

    // Mock constants for testing (replace with real ones if needed)
    mod storage {
        pub const CURRENT_SCHEMA_VERSION: u32 = 5;
    }
    mod protocol {
        pub mod version {
            pub const CURRENT_PROTOCOL_VERSION: u32 = 3;
            pub const SUPPORTED_PROTOCOL_VERSIONS: &[u32] = &[2, 3];
            pub fn is_supported(v: u32) -> bool {
                SUPPORTED_PROTOCOL_VERSIONS.contains(&v)
            }
        }
    }

    #[test]
    fn test_new_current() {
        let meta = NodeMeta::new_current();
        assert_eq!(meta.schema_version, storage::CURRENT_SCHEMA_VERSION);
        assert_eq!(meta.protocol_version, protocol::version::CURRENT_PROTOCOL_VERSION);
        assert!(!meta.node_version.is_empty());
    }

    #[test]
    fn test_save_and_load() {
        let dir = tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.ensure_all().unwrap();

        let mut meta = NodeMeta::new_current();
        meta.save(&layout).unwrap();

        let loaded = NodeMeta::load(&layout).unwrap().unwrap();
        assert_eq!(loaded.schema_version, meta.schema_version);
        assert_eq!(loaded.protocol_version, meta.protocol_version);
        assert_eq!(loaded.node_version, meta.node_version);
    }

    #[test]
    fn test_load_nonexistent() {
        let dir = tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        assert!(NodeMeta::load(&layout).unwrap().is_none());
    }

    #[test]
    fn test_check_compatibility_ok() {
        let meta = NodeMeta::new_current();
        assert!(meta.check_compatibility().is_ok());
    }

    #[test]
    fn test_check_compatibility_schema_too_new() {
        let meta = NodeMeta {
            schema_version: 99,
            protocol_version: protocol::version::CURRENT_PROTOCOL_VERSION,
            node_version: "99.0.0".into(),
            updated_at: None,
            migration_state: None,
        };
        let err = meta.check_compatibility().unwrap_err();
        match err {
            NodeMetaError::SchemaVersionMismatch { on_disk, binary } => {
                assert_eq!(on_disk, 99);
                assert_eq!(binary, storage::CURRENT_SCHEMA_VERSION);
            }
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_check_compatibility_unsupported_protocol() {
        let meta = NodeMeta {
            schema_version: storage::CURRENT_SCHEMA_VERSION,
            protocol_version: 99,
            node_version: "99.0.0".into(),
            updated_at: None,
            migration_state: None,
        };
        let err = meta.check_compatibility().unwrap_err();
        match err {
            NodeMetaError::UnsupportedProtocol(v) => assert_eq!(v, 99),
            _ => panic!("Unexpected error: {:?}", err),
        }
    }

    #[test]
    fn test_migration_state_roundtrip() {
        let dir = tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.ensure_all().unwrap();

        let mut meta = NodeMeta::new_current();
        assert!(!meta.has_pending_migration());

        meta.begin_migration(3, 4, "upgrade node_meta.json", &layout).unwrap();
        assert!(meta.has_pending_migration());

        // Reload from disk and verify migration_state is persisted
        let loaded = NodeMeta::load(&layout).unwrap().unwrap();
        assert!(loaded.has_pending_migration());
        let ms = loaded.migration_state.unwrap();
        assert_eq!(ms.from_sv, 3);
        assert_eq!(ms.to_sv, 4);
        assert_eq!(ms.step, "upgrade node_meta.json");
        assert!(ms.started_at > 0);

        meta.end_migration(&layout).unwrap();
        assert!(!meta.has_pending_migration());

        let loaded2 = NodeMeta::load(&layout).unwrap().unwrap();
        assert!(!loaded2.has_pending_migration());
    }

    #[test]
    fn test_corrupted_file() {
        let dir = tempdir().unwrap();
        let layout = DataLayout::new(dir.path());
        layout.ensure_all().unwrap();

        let path = layout.node_meta_path();
        fs::write(&path, "this is not json").unwrap();

        let err = NodeMeta::load(&layout).unwrap_err();
        match err {
            NodeMetaError::Corrupted(_) => {} // expected
            _ => panic!("Expected Corrupted error, got {:?}", err),
        }
    }
}
