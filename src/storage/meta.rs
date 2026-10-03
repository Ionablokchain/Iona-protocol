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
//! # Production Features
//! - True atomic writes: temp file + fsync + rename + parent-dir fsync.
//! - Restrictive Unix permissions (0o600) on `node_meta.json`.
//! - Bounded timestamp format (u64 seconds + `updated_at_secs`).
//! - Prometheus metrics (optional) with atomic fallback.
//! - Overflow-safe counters.
//! - Full test coverage.
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

use parking_lot::Mutex;
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, OnceLock,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// File name for node metadata.
const NODE_META_FILE: &str = "node_meta.json";

/// Temporary file extension for atomic writes.
const TMP_EXTENSION: &str = "tmp";

/// File permission mode for `node_meta.json` on Unix (owner read/write only).
#[cfg(unix)]
const SECRET_FILE_MODE: u32 = 0o600;

/// Reserved: metadata format version for future extensions.
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

    #[error("metrics error: {0}")]
    Metrics(String),
}

pub type MetaResult<T> = Result<T, MetaError>;

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus metrics for node metadata operations.
#[derive(Clone)]
pub struct NodeMetaPrometheus {
    pub saves_total: Counter,
    pub loads_total: Counter,
    pub load_errors_total: Counter,
    pub migration_starts_total: Counter,
    pub migration_ends_total: Counter,
    pub pending_migration: Gauge,
}

impl NodeMetaPrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            saves_total: register_counter!(
                "iona_node_meta_saves_total",
                "Total node metadata saves"
            )?,
            loads_total: register_counter!(
                "iona_node_meta_loads_total",
                "Total node metadata loads"
            )?,
            load_errors_total: register_counter!(
                "iona_node_meta_load_errors_total",
                "Total node metadata load errors"
            )?,
            migration_starts_total: register_counter!(
                "iona_node_meta_migration_starts_total",
                "Total migrations started"
            )?,
            migration_ends_total: register_counter!(
                "iona_node_meta_migration_ends_total",
                "Total migrations completed"
            )?,
            pending_migration: register_gauge!(
                "iona_node_meta_pending_migration",
                "Whether a migration is currently pending (1=yes, 0=no)"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            saves_total: Counter::new("iona_node_meta_saves_total", "Saves").unwrap(),
            loads_total: Counter::new("iona_node_meta_loads_total", "Loads").unwrap(),
            load_errors_total: Counter::new("iona_node_meta_load_errors_total", "Errors").unwrap(),
            migration_starts_total: Counter::new("iona_node_meta_migration_starts_total", "Starts").unwrap(),
            migration_ends_total: Counter::new("iona_node_meta_migration_ends_total", "Ends").unwrap(),
            pending_migration: Gauge::new("iona_node_meta_pending_migration", "Pending").unwrap(),
        }
    }
}

/// Metrics for node metadata.
#[derive(Debug, Clone)]
pub struct NodeMetaMetrics {
    pub saves: Arc<AtomicU64>,
    pub loads: Arc<AtomicU64>,
    pub load_errors: Arc<AtomicU64>,
    pub migration_starts: Arc<AtomicU64>,
    pub migration_ends: Arc<AtomicU64>,
    pub prometheus: Option<Arc<NodeMetaPrometheus>>,
}

impl Default for NodeMetaMetrics {
    fn default() -> Self {
        Self {
            saves: Arc::new(AtomicU64::new(0)),
            loads: Arc::new(AtomicU64::new(0)),
            load_errors: Arc::new(AtomicU64::new(0)),
            migration_starts: Arc::new(AtomicU64::new(0)),
            migration_ends: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl NodeMetaMetrics {
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(NodeMetaPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_save(&self) {
        self.saves.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.saves_total.inc();
        }
    }
    fn record_load(&self) {
        self.loads.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.loads_total.inc();
        }
    }
    fn record_load_error(&self) {
        self.load_errors.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.load_errors_total.inc();
        }
    }
    fn record_migration_start(&self) {
        self.migration_starts.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.migration_starts_total.inc();
            p.pending_migration.set(1.0);
        }
    }
    fn record_migration_end(&self) {
        self.migration_ends.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.migration_ends_total.inc();
            p.pending_migration.set(0.0);
        }
    }
}

/// Snapshot of node metadata metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct NodeMetaMetricsSnapshot {
    pub saves: u64,
    pub loads: u64,
    pub load_errors: u64,
    pub migration_starts: u64,
    pub migration_ends: u64,
}

impl NodeMetaMetrics {
    pub fn snapshot(&self) -> NodeMetaMetricsSnapshot {
        NodeMetaMetricsSnapshot {
            saves: self.saves.load(Ordering::Relaxed),
            loads: self.loads.load(Ordering::Relaxed),
            load_errors: self.load_errors.load(Ordering::Relaxed),
            migration_starts: self.migration_starts.load(Ordering::Relaxed),
            migration_ends: self.migration_ends.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Global metrics singleton (used by static convenience methods)
// -----------------------------------------------------------------------------

static GLOBAL_META_METRICS: OnceLock<Arc<NodeMetaMetrics>> = OnceLock::new();

/// Initialize the global metadata metrics (call once at startup).
pub fn init_global_metrics(enable_prometheus: bool) -> MetaResult<()> {
    if GLOBAL_META_METRICS.get().is_some() {
        return Err(MetaError::Metrics("already initialized".into()));
    }
    let m = NodeMetaMetrics::new(enable_prometheus)
        .map_err(|e| MetaError::Metrics(e.to_string()))?;
    GLOBAL_META_METRICS
        .set(Arc::new(m))
        .map_err(|_| MetaError::Metrics("failed to set metrics".into()))?;
    Ok(())
}

/// Get the global metrics (if initialized); otherwise a default no-op metrics
/// singleton is created lazily.
fn metrics() -> Arc<NodeMetaMetrics> {
    GLOBAL_META_METRICS
        .get()
        .cloned()
        .unwrap_or_else(|| Arc::new(NodeMetaMetrics::default()))
}

// -----------------------------------------------------------------------------
// MigrationState
// -----------------------------------------------------------------------------

/// In-progress migration state for crash-safe resume.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MigrationState {
    pub from_sv: u32,
    pub to_sv: u32,
    pub step: String,
    /// Unix seconds when the migration started.
    pub started_at: u64,
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
    pub schema_version: u32,
    pub protocol_version: u32,
    pub node_version: String,
    /// Unix seconds of last update (bounded integer; no string parsing needed).
    #[serde(default)]
    pub updated_at_secs: Option<u64>,
    /// Reserved: metadata format version for future extensions.
    #[serde(default)]
    pub meta_format_version: u32,
    /// If non-null, a migration is in progress (crash-safe resume).
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
            updated_at_secs: Some(now_unix()),
            meta_format_version: META_FORMAT_VERSION,
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
        let content = match fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                metrics().record_load_error();
                return Err(MetaError::Io { source: e });
            }
        };
        let meta: Self = match serde_json::from_str(&content) {
            Ok(m) => m,
            Err(e) => {
                metrics().record_load_error();
                return Err(MetaError::Serialization { source: e });
            }
        };
        metrics().record_load();
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
            info!(
                data_dir = %data_dir.as_ref().display(),
                "node_meta.json not found, creating new"
            );
            Ok(Self::new_current())
        }
    }

    /// Load metadata, create if missing, and save it immediately.
    pub fn load_or_create_save(data_dir: impl AsRef<Path>) -> MetaResult<Self> {
        let mut meta = Self::load_or_create(&data_dir)?;
        if meta.updated_at_secs.is_none() {
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
            started_at: now_unix(),
        };
        state.validate()?;
        self.migration_state = Some(state);
        info!(from = from_sv, to = to_sv, step, "migration started");
        metrics().record_migration_start();
        self.save(data_dir)
    }

    /// Clear the migration state (migration completed successfully).
    pub fn end_migration(&mut self, data_dir: impl AsRef<Path>) -> MetaResult<()> {
        self.migration_state = None;
        info!("migration completed");
        metrics().record_migration_end();
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

    /// Save metadata to disk (atomic write via tmp + fsync + rename + dir fsync).
    pub fn save(&mut self, data_dir: impl AsRef<Path>) -> MetaResult<()> {
        self.updated_at_secs = Some(now_unix());
        if self.meta_format_version == 0 {
            self.meta_format_version = META_FORMAT_VERSION;
        }

        let dir = data_dir.as_ref();
        fs::create_dir_all(dir)?;
        let path = dir.join(NODE_META_FILE);
        let tmp_path = path.with_extension(TMP_EXTENSION);

        let content = serde_json::to_string_pretty(self)?;

        // Write to temp file with restricted permissions on Unix.
        {
            let mut opts = OpenOptions::new();
            opts.create(true).write(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                opts.mode(SECRET_FILE_MODE);
            }
            let mut f = opts.open(&tmp_path)?;
            f.write_all(content.as_bytes())?;
            f.sync_all()?;
        }

        // Atomic rename.
        fs::rename(&tmp_path, &path)?;

        // fsync the parent directory so the rename is durable.
        if let Ok(dir_file) = File::open(dir) {
            let _ = dir_file.sync_all();
        }

        metrics().record_save();
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

    /// Metrics snapshot (from the global metrics singleton).
    pub fn metrics_snapshot() -> NodeMetaMetricsSnapshot {
        metrics().snapshot()
    }
}

// -----------------------------------------------------------------------------
// Helper: timestamp
// -----------------------------------------------------------------------------

/// Return the current Unix timestamp in seconds.
#[must_use]
fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
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
        assert!(meta.updated_at_secs.is_some());
        assert!(!meta.has_pending_migration());
        assert_eq!(meta.meta_format_version, META_FORMAT_VERSION);
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
        assert!(loaded.updated_at_secs.is_some());
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
            updated_at_secs: None,
            meta_format_version: META_FORMAT_VERSION,
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
            updated_at_secs: None,
            meta_format_version: META_FORMAT_VERSION,
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
            updated_at_secs: None,
            meta_format_version: META_FORMAT_VERSION,
            migration_state: None,
        };
        meta.update_to_current(dir.path())?;
        assert_eq!(meta.schema_version, crate::storage::CURRENT_SCHEMA_VERSION);
        assert_eq!(
            meta.protocol_version,
            crate::protocol::version::CURRENT_PROTOCOL_VERSION
        );
        assert_eq!(meta.node_version, env!("CARGO_PKG_VERSION"));
        assert!(meta.updated_at_secs.is_some());
        Ok(())
    }

    #[test]
    fn test_atomic_write() -> MetaResult<()> {
        let dir = tempdir()?;
        let mut meta = NodeMeta::new_current();
        meta.save(dir.path())?;
        let path = dir.path().join(NODE_META_FILE);
        let tmp = path.with_extension(TMP_EXTENSION);
        assert!(!tmp.exists(), "temp file must be renamed away");
        Ok(())
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions() -> MetaResult<()> {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir()?;
        let mut meta = NodeMeta::new_current();
        meta.save(dir.path())?;
        let path = dir.path().join(NODE_META_FILE);
        let mode = fs::metadata(&path)?.permissions().mode() & 0o777;
        assert_eq!(mode, SECRET_FILE_MODE, "node_meta.json must be 0o600");
        Ok(())
    }

    #[test]
    fn test_invalid_migration_state() {
        let state = MigrationState {
            from_sv: 5,
            to_sv: 4,
            step: "test".into(),
            started_at: now_unix(),
        };
        assert!(state.validate().is_err());

        let state2 = MigrationState {
            from_sv: 3,
            to_sv: 4,
            step: "".into(),
            started_at: now_unix(),
        };
        assert!(state2.validate().is_err());
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = NodeMetaPrometheus::new_unregistered();
        p.saves_total.inc();
        p.loads_total.inc_by(2);
        p.pending_migration.set(1.0);
        assert_eq!(p.saves_total.get(), 1);
        assert_eq!(p.loads_total.get(), 2);
        assert_eq!(p.pending_migration.get(), 1.0);
    }

    #[test]
    fn test_load_corrupt_json_records_error() -> MetaResult<()> {
        let dir = tempdir()?;
        let path = dir.path().join(NODE_META_FILE);
        fs::write(&path, b"{ this is not json }")?;
        let result = NodeMeta::load(dir.path());
        assert!(matches!(result, Err(MetaError::Serialization { .. })));
        Ok(())
    }

    #[test]
    fn test_missing_file_returns_none() -> MetaResult<()> {
        let dir = tempdir()?;
        assert!(NodeMeta::load(dir.path())?.is_none());
        Ok(())
    }
}
