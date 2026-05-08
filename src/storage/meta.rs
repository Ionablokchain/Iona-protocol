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
//!
//! # Example
//!
//! ```
//! use iona::storage::meta::NodeMeta;
//!
//! let mut meta = NodeMeta::load_or_create("./data/node")?;
//! if meta.has_pending_migration() {
//!     // Resume migration
//! }
//! meta.begin_migration(3, 4, "adding node_meta.json", "./data/node")?;
//! // ... do migration work ...
//! meta.end_migration("./data/node")?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use serde::{Deserialize, Serialize};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// File name for node metadata.
const NODE_META_FILE: &str = "node_meta.json";

/// Temporary file extension for atomic writes.
const TMP_EXTENSION: &str = "tmp";

/// Default format version (not used, kept for future extensions).
const META_FORMAT_VERSION: u32 = 1;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during metadata operations.
#[derive(Debug, Error)]
pub enum MetaError {
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

    #[error("invalid migration state: {reason}")]
    InvalidMigrationState { reason: String },

    #[error("incompatible metadata: {reason}")]
    Incompatible { reason: String },
}

pub type MetaResult<T> = Result<T, MetaError>;

// -----------------------------------------------------------------------------
// MigrationState
// -----------------------------------------------------------------------------

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
    /// Timestamp when migration started (Unix seconds).
    pub started_at: String,
}

impl MigrationState {
    /// Validate the migration state (basic sanity checks).
    pub fn validate(&self) -> MetaResult<()> {
        if self.from_sv >= self.to_sv {
            return Err(MetaError::InvalidMigrationState {
                reason: format!("from_sv {} >= to_sv {}", self.from_sv, self.to_sv),
            });
        }
        if self.step.is_empty() {
            return Err(MetaError::InvalidMigrationState {
                reason: "step description is empty".into(),
            });
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// NodeMeta
// -----------------------------------------------------------------------------

/// Persistent metadata written to `<data_dir>/node_meta.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMeta {
    /// On-disk storage schema version (matches `storage::CURRENT_SCHEMA_VERSION`).
    pub schema_version: u32,
    /// Last protocol version this node operated under.
    pub protocol_version: u32,
    /// Semver of the node binary that last wrote this file.
    pub node_version: String,
    /// ISO‑8601 timestamp of last update (simplified to Unix seconds).
    #[serde(default)]
    pub updated_at: Option<String>,
    /// If non-null, a migration is in progress (crash-safe resume).
    /// Set before migration starts, cleared after migration completes.
    #[serde(default)]
    pub migration_state: Option<MigrationState>,
}

impl NodeMeta {
    /// Create a fresh `NodeMeta` for a new data directory.
    #[must_use]
    pub fn new_current() -> Self {
        Self {
            schema_version: crate::storage::CURRENT_SCHEMA_VERSION,
            protocol_version: crate::protocol::version::CURRENT_PROTOCOL_VERSION,
            node_version: env!("CARGO_PKG_VERSION").to_string(),
            updated_at: Some(now_iso8601()),
            migration_state: None,
        }
    }

    /// Load metadata from disk, or return `None` if the file doesn't exist.
    pub fn load(data_dir: impl AsRef<Path>) -> MetaResult<Option<Self>> {
        let path = data_dir.as_ref().join(NODE_META_FILE);
        if !path.exists() {
            debug!(path = %path.display(), "node_meta.json not found");
            return Ok(None);
        }
        let content = fs::read_to_string(&path)?;
        let meta = serde_json::from_str(&content)?;
        debug!(
            path = %path.display(),
            schema = meta.schema_version,
            protocol = meta.protocol_version,
            "loaded node_meta"
        );
        Ok(Some(meta))
    }

    /// Load metadata, or create a fresh one if the file does not exist.
    ///
    /// The new file is **not** saved automatically; call `save()` if needed.
    pub fn load_or_create(data_dir: impl AsRef<Path>) -> MetaResult<Self> {
        if let Some(meta) = Self::load(&data_dir)? {
            Ok(meta)
        } else {
            info!(data_dir = %data_dir.as_ref().display(), "node_meta.json not found, creating new");
            Ok(Self::new_current())
        }
    }

    /// Load metadata, create if missing, and save it immediately.
    pub fn load_or_create_save(data_dir: impl AsRef<Path>) -> MetaResult<Self> {
        let mut meta = Self::load_or_create(&data_dir)?;
        if meta.updated_at.is_none() {
            meta.save(&data_dir)?;
        }
        Ok(meta)
    }

    /// Mark a migration as in-progress (for crash-safe resume).
    pub fn begin_migration(
        &mut self,
        from_sv: u32,
        to_sv: u32,
        step: &str,
        data_dir: impl AsRef<Path>,
    ) -> MetaResult<()> {
        let state = MigrationState {
            from_sv,
            to_sv,
            step: step.to_string(),
            started_at: now_iso8601(),
        };
        state.validate()?;
        self.migration_state = Some(state);
        info!(from = from_sv, to = to_sv, step, "migration started");
        self.save(data_dir)
    }

    /// Clear the migration state (migration completed successfully).
    pub fn end_migration(&mut self, data_dir: impl AsRef<Path>) -> MetaResult<()> {
        self.migration_state = None;
        info!("migration completed");
        self.save(data_dir)
    }

    /// Check if there's a pending migration that needs to be resumed.
    #[must_use]
    pub fn has_pending_migration(&self) -> bool {
        self.migration_state.is_some()
    }

    /// Get the pending migration state (if any).
    #[must_use]
    pub fn pending_migration(&self) -> Option<&MigrationState> {
        self.migration_state.as_ref()
    }

    /// Check if the on-disk meta is compatible with this binary.
    /// Returns `Err` with a human-readable message if not.
    pub fn check_compatibility(&self) -> MetaResult<()> {
        if self.schema_version > crate::storage::CURRENT_SCHEMA_VERSION {
            return Err(MetaError::Incompatible {
                reason: format!(
                    "on-disk schema v{} is newer than this binary (v{}); please upgrade",
                    self.schema_version,
                    crate::storage::CURRENT_SCHEMA_VERSION,
                ),
            });
        }
        if !crate::protocol::version::is_supported(self.protocol_version) {
            return Err(MetaError::Incompatible {
                reason: format!(
                    "on-disk protocol v{} is not supported by this binary; supported: {:?}",
                    self.protocol_version,
                    crate::protocol::version::SUPPORTED_PROTOCOL_VERSIONS,
                ),
            });
        }
        Ok(())
    }

    /// Save metadata to disk (atomic write via tmp + rename).
    pub fn save(&mut self, data_dir: impl AsRef<Path>) -> MetaResult<()> {
        self.updated_at = Some(now_iso8601());
        let dir = data_dir.as_ref();
        let path = dir.join(NODE_META_FILE);
        let tmp = path.with_extension(TMP_EXTENSION);
        let content = serde_json::to_string_pretty(self)?;
        fs::write(&tmp, &content)?;
        fs::rename(&tmp, &path)?;
        debug!(path = %path.display(), "saved node_meta");
        Ok(())
    }

    /// Update schema version and protocol version to current values and save.
    pub fn update_to_current(&mut self, data_dir: impl AsRef<Path>) -> MetaResult<()> {
        self.schema_version = crate::storage::CURRENT_SCHEMA_VERSION;
        self.protocol_version = crate::protocol::version::CURRENT_PROTOCOL_VERSION;
        self.node_version = env!("CARGO_PKG_VERSION").to_string();
        info!(
            schema = self.schema_version,
            protocol = self.protocol_version,
            "updating node_meta to current versions"
        );
        self.save(data_dir)
    }
}

// -----------------------------------------------------------------------------
// Helper: timestamp
// -----------------------------------------------------------------------------

/// Return the current Unix timestamp as a string (seconds since epoch).
#[must_use]
fn now_iso8601() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    secs.to_string()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_new_current() {
        let meta = NodeMeta::new_current();
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        assert_eq!(
            meta.protocol_version,
            crate::protocol::version::CURRENT_PROTOCOL_VERSION
        );
        assert!(!meta.node_version.is_empty());
        assert!(meta.updated_at.is_some());
        assert!(!meta.has_pending_migration());
    }

    #[test]
    fn test_save_and_load() -> MetaResult<()> {
        let dir = tempdir()?;
        let mut meta = NodeMeta::new_current();
        meta.save(dir.path())?;
        let loaded = NodeMeta::load(dir.path())?.unwrap();
        assert_eq!(loaded.schema_version, meta.schema_version);
        assert_eq!(loaded.protocol_version, meta.protocol_version);
        assert_eq!(loaded.node_version, meta.node_version);
        assert!(loaded.updated_at.is_some());
        Ok(())
    }

    #[test]
    fn test_load_or_create() -> MetaResult<()> {
        let dir = tempdir()?;
        let meta = NodeMeta::load_or_create(dir.path())?;
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        let path = dir.path().join(NODE_META_FILE);
        assert!(!path.exists());
        Ok(())
    }

    #[test]
    fn test_load_or_create_save() -> MetaResult<()> {
        let dir = tempdir()?;
        let meta = NodeMeta::load_or_create_save(dir.path())?;
        let path = dir.path().join(NODE_META_FILE);
        assert!(path.exists());
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        Ok(())
    }

    #[test]
    fn test_check_compatibility_ok() -> MetaResult<()> {
        let meta = NodeMeta::new_current();
        assert!(meta.check_compatibility().is_ok());
        Ok(())
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
        let err = meta.check_compatibility().unwrap_err();
        assert!(matches!(err, MetaError::Incompatible { .. }));
        assert!(err.to_string().contains("newer than this binary"));
    }

    #[test]
    fn test_check_compatibility_protocol_too_new() {
        let meta = NodeMeta {
            schema_version: crate::storage::CURRENT_SCHEMA_VERSION,
            protocol_version: 999,
            node_version: "99.0.0".into(),
            updated_at: None,
            migration_state: None,
        };
        let err = meta.check_compatibility().unwrap_err();
        assert!(matches!(err, MetaError::Incompatible { .. }));
        assert!(err.to_string().contains("not supported"));
    }

    #[test]
    fn test_migration_state_roundtrip() -> MetaResult<()> {
        let dir = tempdir()?;
        let mut meta = NodeMeta::new_current();
        assert!(!meta.has_pending_migration());

        meta.begin_migration(3, 4, "adding node_meta.json", dir.path())?;
        assert!(meta.has_pending_migration());

        let ms = meta.pending_migration().unwrap();
        assert_eq!(ms.from_sv, 3);
        assert_eq!(ms.to_sv, 4);
        assert_eq!(ms.step, "adding node_meta.json");

        let loaded = NodeMeta::load(dir.path())?.unwrap();
        assert!(loaded.has_pending_migration());
        let ms2 = loaded.pending_migration().unwrap();
        assert_eq!(ms2.from_sv, 3);
        assert_eq!(ms2.to_sv, 4);

        meta.end_migration(dir.path())?;
        assert!(!meta.has_pending_migration());

        let loaded2 = NodeMeta::load(dir.path())?.unwrap();
        assert!(!loaded2.has_pending_migration());
        Ok(())
    }

    #[test]
    fn test_update_to_current() -> MetaResult<()> {
        let dir = tempdir()?;
        let mut meta = NodeMeta {
            schema_version: 1,
            protocol_version: 1,
            node_version: "old".into(),
            updated_at: None,
            migration_state: None,
        };
        meta.update_to_current(dir.path())?;
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        assert_eq!(meta.protocol_version, crate::protocol::version::CURRENT_PROTOCOL_VERSION);
        assert_eq!(meta.node_version, env!("CARGO_PKG_VERSION"));
        assert!(meta.updated_at.is_some());
        Ok(())
    }

    #[test]
    fn test_atomic_write() -> MetaResult<()> {
        let dir = tempdir()?;
        let mut meta = NodeMeta::new_current();
        meta.save(dir.path())?;
        let path = dir.path().join(NODE_META_FILE);
        let tmp = path.with_extension(TMP_EXTENSION);
        assert!(!tmp.exists());
        Ok(())
    }

    #[test]
    fn test_invalid_migration_state() {
        let state = MigrationState {
            from_sv: 5,
            to_sv: 4,
            step: "test".into(),
            started_at: now_iso8601(),
        };
        assert!(state.validate().is_err());

        let state2 = MigrationState {
            from_sv: 3,
            to_sv: 4,
            step: "".into(),
            started_at: now_iso8601(),
        };
        assert!(state2.validate().is_err());
    }
}
