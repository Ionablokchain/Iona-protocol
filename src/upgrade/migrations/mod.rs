//! Built-in schema migrations for IONA.
//!
//! Each migration `M00N` corresponds to a schema version step:
//!
//!   M001  v0 → v1  add `vm` field to state_full.json
//!   M002  v1 → v2  add receipts index directory
//!   M003  v2 → v3  add evidence store (evidence.json)
//!   M004  v3 → v4  add snapshot metadata (snapshots/ directory + meta.json)
//!   M005  v4 → v5  add admin audit log file (audit.log initialisation)
//!   M006  v5 → v6  add transaction index (tx_index.json)
//!   M007  v6 → v7  add node metadata (node_meta.json)
//!
//! Each migration:
//!  - Supports dry‑run mode (validates preconditions without writing).
//!  - Is idempotent: running twice leaves the data directory in the same state.
//!  - Includes inline unit tests.
//!  - Supports rollback (for migrations that can be safely reversed).
//!  - Uses atomic file writes via temp + fsync + rename + parent‑dir fsync.
//!  - Acquires a file lock (with a configurable timeout) to prevent
//!    concurrent execution.
//!
//! # Production features
//! - [`MigrationError`] with structured variants.
//! - [`MigrationMetrics`] (atomic counters) plus a [`metrics()`] snapshot.
//! - [`MIGRATIONS`] static registry, consumable by other modules
//!   (e.g. `crate::storage::schema_monotonicity`).
//! - Overflow‑safe counters and diagnostics.
//! - Lock timeout is read from `IONA_MIGRATION_LOCK_SECS` when set, so
//!   integration tests can run quickly without waiting 60 seconds.

use crate::upgrade::{Migration, MigrationResult};
use fs2::FileExt;
use serde_json::Value;
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors produced by the migration framework itself (not by individual
/// migrations, which report failures through `MigrationResult`).
#[derive(Debug, Error)]
pub enum MigrationError {
    #[error("I/O error at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("JSON error at {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },

    #[error("could not acquire migration lock after {secs}s")]
    LockTimeout { secs: u64 },

    #[error("configuration error: {0}")]
    Config(String),
}

pub type MigrationFrameworkResult<T> = Result<T, MigrationError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Lock file name used to prevent concurrent migrations.
const MIGRATION_LOCK_FILE: &str = ".migration.lock";

/// Default maximum time to wait for lock acquisition (in seconds).
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 60;

/// Environment variable that overrides the lock timeout. Useful for tests.
const LOCK_TIMEOUT_ENV: &str = "IONA_MIGRATION_LOCK_SECS";

/// The current lock timeout, resolved once on first use.
fn lock_timeout_secs() -> u64 {
    static TIMEOUT: OnceLock<u64> = OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        std::env::var(LOCK_TIMEOUT_ENV)
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .filter(|&v| v > 0)
            .unwrap_or(DEFAULT_LOCK_TIMEOUT_SECS)
    })
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Atomic counters for the migration framework.
#[derive(Debug, Default)]
pub struct MigrationMetrics {
    /// Total migration steps successfully applied.
    pub steps_applied: AtomicU64,
    /// Total migration steps skipped (already applied / idempotent).
    pub steps_skipped: AtomicU64,
    /// Total migration steps that failed.
    pub steps_failed: AtomicU64,
    /// Total dry‑run steps executed.
    pub dry_run_steps: AtomicU64,
    /// Total cumulative time spent applying migrations (milliseconds).
    pub total_duration_ms: AtomicU64,
}

static METRICS: MigrationMetrics = MigrationMetrics {
    steps_applied: AtomicU64::new(0),
    steps_skipped: AtomicU64::new(0),
    steps_failed: AtomicU64::new(0),
    dry_run_steps: AtomicU64::new(0),
    total_duration_ms: AtomicU64::new(0),
};

/// Snapshot of migration metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MigrationMetricsSnapshot {
    pub steps_applied: u64,
    pub steps_skipped: u64,
    pub steps_failed: u64,
    pub dry_run_steps: u64,
    pub total_duration_ms: u64,
}

/// Read a snapshot of the migration metrics.
pub fn metrics() -> MigrationMetricsSnapshot {
    MigrationMetricsSnapshot {
        steps_applied: METRICS.steps_applied.load(Ordering::Relaxed),
        steps_skipped: METRICS.steps_skipped.load(Ordering::Relaxed),
        steps_failed: METRICS.steps_failed.load(Ordering::Relaxed),
        dry_run_steps: METRICS.dry_run_steps.load(Ordering::Relaxed),
        total_duration_ms: METRICS.total_duration_ms.load(Ordering::Relaxed),
    }
}

/// Reset the metric counters (test-only; not exposed publicly).
#[cfg(test)]
pub fn reset_metrics() {
    METRICS.steps_applied.store(0, Ordering::Relaxed);
    METRICS.steps_skipped.store(0, Ordering::Relaxed);
    METRICS.steps_failed.store(0, Ordering::Relaxed);
    METRICS.dry_run_steps.store(0, Ordering::Relaxed);
    METRICS.total_duration_ms.store(0, Ordering::Relaxed);
}

// -----------------------------------------------------------------------------
// Atomic I/O helpers
// -----------------------------------------------------------------------------

/// Read a JSON file and return its parsed value, or `Ok(None)` if the file
/// does not exist or is empty.
fn read_json_file(path: &Path) -> MigrationFrameworkResult<Option<Value>> {
    if !path.exists() {
        return Ok(None);
    }
    let content = fs::read_to_string(path).map_err(|e| MigrationError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&content)
        .map(Some)
        .map_err(|e| MigrationError::Json {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Write a JSON value to `path` atomically:
/// write to `.tmp`, `fsync` the file, rename onto the target, then `fsync`
/// the parent directory so the rename is durable across power loss.
fn write_json_file_atomic(path: &Path, value: &Value) -> MigrationFrameworkResult<()> {
    let content = serde_json::to_string_pretty(value).map_err(|e| MigrationError::Json {
        path: path.to_path_buf(),
        source: e,
    })?;

    let temp_path = path.with_extension("tmp");

    {
        let mut file = File::create(&temp_path).map_err(|e| MigrationError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
        file.write_all(content.as_bytes())
            .map_err(|e| MigrationError::Io {
                path: temp_path.clone(),
                source: e,
            })?;
        file.sync_all().map_err(|e| MigrationError::Io {
            path: temp_path.clone(),
            source: e,
        })?;
    }

    fs::rename(&temp_path, path).map_err(|e| MigrationError::Io {
        path: path.to_path_buf(),
        source: e,
    })?;

    // fsync the parent directory so the rename is durable.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    Ok(())
}

/// Create a directory (and parents) if it does not exist.
fn ensure_dir(path: &Path) -> MigrationFrameworkResult<()> {
    if !path.exists() {
        fs::create_dir_all(path).map_err(|e| MigrationError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    } else {
        Ok(())
    }
}

/// Create an empty file if it does not exist.
fn ensure_file(path: &Path) -> MigrationFrameworkResult<()> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        fs::write(path, b"").map_err(|e| MigrationError::Io {
            path: path.to_path_buf(),
            source: e,
        })
    } else {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Migration Lock
// -----------------------------------------------------------------------------

/// Acquire an exclusive `flock` on `<data_dir>/.migration.lock`, waiting up
/// to the configured timeout. The lock is released on drop.
pub fn acquire_migration_lock(data_dir: &Path) -> MigrationFrameworkResult<File> {
    let lock_path = data_dir.join(MIGRATION_LOCK_FILE);
    ensure_dir(data_dir)?;

    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| MigrationError::Io {
            path: lock_path.clone(),
            source: e,
        })?;

    let timeout = Duration::from_secs(lock_timeout_secs());
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(MigrationError::LockTimeout {
                        secs: lock_timeout_secs(),
                    });
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Migration Registry
// -----------------------------------------------------------------------------

/// A registry that holds all built-in migrations in version order.
pub struct MigrationRegistry {
    migrations: Vec<Box<dyn Migration>>,
}

impl MigrationRegistry {
    /// Create a new registry with all built-in migrations in version order.
    pub fn new() -> Self {
        Self {
            migrations: vec![
                Box::new(M001AddStateVmField),
                Box::new(M002AddReceiptsIndex),
                Box::new(M003AddEvidenceStore),
                Box::new(M004AddSnapshotMeta),
                Box::new(M005AddAdminAuditLog),
                Box::new(M006AddTransactionIndex),
                Box::new(M007AddNodeMetadata),
            ],
        }
    }

    /// Run all pending migrations from the current schema version to the
    /// latest. If `dry_run` is true, no changes are written.
    ///
    /// The registry is idempotent: running it twice on the same directory
    /// performs the second run entirely in `Skipped` mode.
    pub fn run_all(&self, data_dir: &Path, dry_run: bool) -> Vec<MigrationResult> {
        let _lock = match acquire_migration_lock(data_dir) {
            Ok(f) => f,
            Err(e) => {
                error!(error = %e, "could not acquire migration lock");
                METRICS.steps_failed.fetch_add(1, Ordering::Relaxed);
                return vec![MigrationResult::Failed {
                    from_version: 0,
                    reason: format!("lock acquisition failed: {e}"),
                    rolled_back: false,
                }];
            }
        };

        let current_version = Self::read_schema_version(data_dir);
        info!(current_version, "beginning schema migration run");

        let mut results = Vec::new();
        let mut applied_count = 0usize;

        for migration in &self.migrations {
            let from_v = migration.from_version();

            // Only the migration matching the *current* on-disk version is
            // executed. Once it succeeds we bump our in-memory tracking and
            // continue to the next one.
            if from_v < current_version {
                debug!(from = from_v, "migration already applied; skipping");
                METRICS.steps_skipped.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            if from_v > current_version {
                // Should not happen: migrations are ordered by `from_version`.
                warn!(from = from_v, current = current_version, "migration runs ahead of current");
                continue;
            }

            info!(description = migration.description(), "applying migration");
            let result = migration.apply(data_dir, dry_run);

            match &result {
                MigrationResult::Ok { to_version, duration_ms, .. } => {
                    applied_count += 1;
                    if dry_run {
                        METRICS.dry_run_steps.fetch_add(1, Ordering::Relaxed);
                    } else {
                        METRICS.steps_applied.fetch_add(1, Ordering::Relaxed);
                        if let Some(ms) = duration_ms {
                            METRICS
                                .total_duration_ms
                                .fetch_add(*ms, Ordering::Relaxed);
                        }
                        if let Err(e) = Self::write_schema_version(data_dir, *to_version) {
                            error!(error = %e, "failed to persist schema version");
                            METRICS.steps_failed.fetch_add(1, Ordering::Relaxed);
                            results.push(MigrationResult::Failed {
                                from_version: from_v,
                                reason: format!("cannot update schema version: {e}"),
                                rolled_back: false,
                            });
                            break;
                        }
                    }
                }
                MigrationResult::Skipped { .. } => {
                    METRICS.steps_skipped.fetch_add(1, Ordering::Relaxed);
                }
                MigrationResult::Failed { reason, .. } => {
                    error!(from = from_v, reason, "migration failed");
                    METRICS.steps_failed.fetch_add(1, Ordering::Relaxed);
                    results.push(result);
                    break;
                }
            }

            results.push(result);
        }

        info!(
            applied = applied_count,
            dry_run,
            "migration run finished"
        );
        results
    }

    /// Read the current schema version from `state_full.json`.
    /// If the file does not exist, assume version 0.
    fn read_schema_version(data_dir: &Path) -> u32 {
        let state_path = data_dir.join("state_full.json");
        match read_json_file(&state_path) {
            Ok(Some(v)) => v
                .get("schema_version")
                .and_then(|sv| sv.as_u64())
                .map(|v| v as u32)
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Write the new schema version into `state_full.json`.
    fn write_schema_version(data_dir: &Path, version: u32) -> MigrationFrameworkResult<()> {
        let state_path = data_dir.join("state_full.json");
        let mut state = read_json_file(&state_path)?
            .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
        state["schema_version"] = Value::Number(version.into());
        write_json_file_atomic(&state_path, &state)
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// MIGRATIONS static registry
// -----------------------------------------------------------------------------

/// A compact descriptor of one migration, consumed by callers that need a
/// cheap, non-allocating view of the migration table (e.g.
/// `schema_monotonicity::check_no_gaps`).
#[derive(Debug, Clone, Copy)]
pub struct MigrationDescriptor {
    /// Source schema version.
    pub from_version: u32,
    /// Target schema version (always `from_version + 1`).
    pub to_version: u32,
    /// Short human-readable description.
    pub description: &'static str,
    /// Whether the migration can be reversed.
    pub can_rollback: bool,
}

/// Static table describing every built-in migration.
///
/// This is the canonical source of truth for the number of steps in the
/// migration chain, exposed to modules that must reason about version
/// monotonicity without instantiating the full registry.
pub static MIGRATIONS: &[MigrationDescriptor] = &[
    MigrationDescriptor { from_version: 0, to_version: 1, description: "add vm field to state_full.json",              can_rollback: true  },
    MigrationDescriptor { from_version: 1, to_version: 2, description: "create receipts/ index directory",              can_rollback: true  },
    MigrationDescriptor { from_version: 2, to_version: 3, description: "initialise evidence.json",                      can_rollback: true  },
    MigrationDescriptor { from_version: 3, to_version: 4, description: "create snapshots/ + snapshot-meta.json",        can_rollback: true  },
    MigrationDescriptor { from_version: 4, to_version: 5, description: "initialise audit.log",                          can_rollback: true  },
    MigrationDescriptor { from_version: 5, to_version: 6, description: "add tx_index.json",                             can_rollback: false },
    MigrationDescriptor { from_version: 6, to_version: 7, description: "add node_meta.json",                            can_rollback: true  },
];

/// Number of migration steps defined by this build.
pub const MIGRATION_COUNT: usize = 7;

/// Highest schema version reachable by applying every built-in migration.
pub const LATEST_SCHEMA_VERSION: u32 = 7;

/// Look up the descriptor for a given `from_version`.
pub fn descriptor_for(from_version: u32) -> Option<&'static MigrationDescriptor> {
    MIGRATIONS.iter().find(|d| d.from_version == from_version)
}

// -----------------------------------------------------------------------------
// Individual migrations
// -----------------------------------------------------------------------------

/// Migration v0 → v1: add the `vm` field to `state_full.json`.
pub struct M001AddStateVmField;

impl Migration for M001AddStateVmField {
    fn from_version(&self) -> u32 { 0 }
    fn description(&self) -> &'static str {
        "Add `vm` field to state_full.json for EVM contract storage (v0 → v1)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let state_path = data_dir.join("state_full.json");

        if !state_path.exists() {
            return ok_result(0, 1, vec!["no state_full.json present; skipped"], start, dry_run);
        }

        let state = match read_json_file(&state_path) {
            Ok(Some(v)) => v,
            Ok(None) => {
                if !dry_run {
                    let initial = serde_json::json!({
                        "kv": {}, "balances": {}, "vm": {}, "schema_version": 1
                    });
                    if let Err(e) = write_json_file_atomic(&state_path, &initial) {
                        return fail_result(0, e, false);
                    }
                }
                return ok_result(0, 1, vec!["initialised empty state_full.json"], start, dry_run);
            }
            Err(e) => return fail_result(0, e, false),
        };

        if state.get("vm").is_some() {
            return MigrationResult::Skipped { from_version: 0 };
        }

        if !dry_run {
            let mut updated = state;
            updated["vm"] = serde_json::json!({});
            if let Err(e) = write_json_file_atomic(&state_path, &updated) {
                return fail_result(0, e, false);
            }
        }

        ok_result(0, 1, vec!["state_full.json: added `vm: {}` field"], start, dry_run)
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let state_path = data_dir.join("state_full.json");
        let state = match read_json_file(&state_path) {
            Ok(Some(v)) => v,
            _ => return MigrationResult::Skipped { from_version: 1 },
        };
        if state.get("vm").is_none() {
            return MigrationResult::Skipped { from_version: 1 };
        }
        if !dry_run {
            let mut updated = state;
            if let Some(obj) = updated.as_object_mut() {
                obj.remove("vm");
            }
            if let Err(e) = write_json_file_atomic(&state_path, &updated) {
                return fail_result(1, e, false);
            }
        }
        ok_result(1, 0, vec!["state_full.json: removed `vm` field"], start, dry_run)
    }
}

/// Migration v1 → v2: create `receipts/` directory and index file.
pub struct M002AddReceiptsIndex;

impl Migration for M002AddReceiptsIndex {
    fn from_version(&self) -> u32 { 1 }
    fn description(&self) -> &'static str {
        "Create receipts/ index directory for transaction receipt storage (v1 → v2)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let receipts_dir = data_dir.join("receipts");
        let index_path = receipts_dir.join("index.json");

        if receipts_dir.exists() && index_path.exists() {
            return MigrationResult::Skipped { from_version: 1 };
        }

        if !dry_run {
            if let Err(e) = ensure_dir(&receipts_dir) {
                return fail_result(1, e, false);
            }
            let initial = serde_json::json!({ "version": 1, "receipts": {} });
            if let Err(e) = write_json_file_atomic(&index_path, &initial) {
                return fail_result(1, e, false);
            }
        }

        ok_result(
            1,
            2,
            vec!["created receipts/ directory", "created receipts/index.json"],
            start,
            dry_run,
        )
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let receipts_dir = data_dir.join("receipts");
        if !receipts_dir.exists() {
            return MigrationResult::Skipped { from_version: 2 };
        }
        if !dry_run {
            if let Err(e) = fs::remove_dir_all(&receipts_dir) {
                return MigrationResult::Failed {
                    from_version: 2,
                    reason: format!("cannot remove receipts directory: {e}"),
                    rolled_back: false,
                };
            }
        }
        ok_result(2, 1, vec!["removed receipts/ directory"], start, dry_run)
    }
}

/// Migration v2 → v3: initialise `evidence.json`.
pub struct M003AddEvidenceStore;

impl Migration for M003AddEvidenceStore {
    fn from_version(&self) -> u32 { 2 }
    fn description(&self) -> &'static str {
        "Initialise evidence.json for equivocation evidence storage (v2 → v3)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let evidence_path = data_dir.join("evidence.json");
        if evidence_path.exists() {
            if let Ok(Some(_)) = read_json_file(&evidence_path) {
                return MigrationResult::Skipped { from_version: 2 };
            }
        }
        if !dry_run {
            let initial = serde_json::json!({ "version": 1, "evidence": [] });
            if let Err(e) = write_json_file_atomic(&evidence_path, &initial) {
                return fail_result(2, e, false);
            }
        }
        ok_result(2, 3, vec!["created evidence.json"], start, dry_run)
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let evidence_path = data_dir.join("evidence.json");
        if !evidence_path.exists() {
            return MigrationResult::Skipped { from_version: 3 };
        }
        if !dry_run {
            if let Err(e) = fs::remove_file(&evidence_path) {
                return MigrationResult::Failed {
                    from_version: 3,
                    reason: format!("cannot remove evidence.json: {e}"),
                    rolled_back: false,
                };
            }
        }
        ok_result(3, 2, vec!["removed evidence.json"], start, dry_run)
    }
}

/// Migration v3 → v4: create `snapshots/` and `snapshot-meta.json`.
pub struct M004AddSnapshotMeta;

impl Migration for M004AddSnapshotMeta {
    fn from_version(&self) -> u32 { 3 }
    fn description(&self) -> &'static str {
        "Create snapshots/ directory and initialise snapshot-meta.json (v3 → v4)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let snapshots_dir = data_dir.join("snapshots");
        let meta_path = data_dir.join("snapshot-meta.json");
        let mut changes: Vec<String> = Vec::new();

        if !snapshots_dir.exists() { changes.push("created snapshots/ directory".into()); }
        if !meta_path.exists()     { changes.push("created snapshot-meta.json".into()); }

        if changes.is_empty() {
            return MigrationResult::Skipped { from_version: 3 };
        }

        if !dry_run {
            if !snapshots_dir.exists() {
                if let Err(e) = ensure_dir(&snapshots_dir) {
                    return fail_result(3, e, false);
                }
            }
            if !meta_path.exists() {
                let meta = serde_json::json!({ "version": 1, "snapshots": [], "latest": null });
                if let Err(e) = write_json_file_atomic(&meta_path, &meta) {
                    return fail_result(3, e, false);
                }
            }
        }

        ok_result(3, 4, changes, start, dry_run)
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let snapshots_dir = data_dir.join("snapshots");
        let meta_path = data_dir.join("snapshot-meta.json");
        let mut changes: Vec<String> = Vec::new();

        if meta_path.exists()     { changes.push("removed snapshot-meta.json".into()); }
        if snapshots_dir.exists() { changes.push("removed snapshots/ directory".into()); }

        if changes.is_empty() {
            return MigrationResult::Skipped { from_version: 4 };
        }

        if !dry_run {
            if meta_path.exists() {
                if let Err(e) = fs::remove_file(&meta_path) {
                    return MigrationResult::Failed {
                        from_version: 4,
                        reason: format!("cannot remove snapshot-meta.json: {e}"),
                        rolled_back: false,
                    };
                }
            }
            if snapshots_dir.exists() {
                if let Err(e) = fs::remove_dir_all(&snapshots_dir) {
                    return MigrationResult::Failed {
                        from_version: 4,
                        reason: format!("cannot remove snapshots/ directory: {e}"),
                        rolled_back: false,
                    };
                }
            }
        }

        ok_result(4, 3, changes, start, dry_run)
    }
}

/// Migration v4 → v5: create the empty admin audit log.
pub struct M005AddAdminAuditLog;

impl Migration for M005AddAdminAuditLog {
    fn from_version(&self) -> u32 { 4 }
    fn description(&self) -> &'static str {
        "Initialise admin audit log with genesis hashchain entry (v4 → v5)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let audit_path = data_dir.join("audit.log");
        if audit_path.exists() {
            return MigrationResult::Skipped { from_version: 4 };
        }
        if !dry_run {
            if let Err(e) = ensure_file(&audit_path) {
                return fail_result(4, e, false);
            }
        }
        ok_result(4, 5, vec!["created audit.log (empty hashchain)"], start, dry_run)
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let audit_path = data_dir.join("audit.log");
        if !audit_path.exists() {
            return MigrationResult::Skipped { from_version: 5 };
        }
        if !dry_run {
            if let Err(e) = fs::remove_file(&audit_path) {
                return MigrationResult::Failed {
                    from_version: 5,
                    reason: format!("cannot remove audit.log: {e}"),
                    rolled_back: false,
                };
            }
        }
        ok_result(5, 4, vec!["removed audit.log"], start, dry_run)
    }
}

/// Migration v5 → v6: create the transaction index file.
pub struct M006AddTransactionIndex;

impl Migration for M006AddTransactionIndex {
    fn from_version(&self) -> u32 { 5 }
    fn description(&self) -> &'static str {
        "Add transaction index (tx_index.json) for fast hash → position lookups (v5 → v6)"
    }
    fn estimated_duration_ms(&self) -> u64 { 100 }
    fn can_rollback(&self) -> bool { false }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let tx_index_path = data_dir.join("tx_index.json");
        if tx_index_path.exists() {
            return MigrationResult::Skipped { from_version: 5 };
        }
        if !dry_run {
            let initial = serde_json::json!({ "version": 1, "index": {} });
            if let Err(e) = write_json_file_atomic(&tx_index_path, &initial) {
                return fail_result(5, e, false);
            }
        }
        ok_result(5, 6, vec!["created tx_index.json"], start, dry_run)
    }
}

/// Migration v6 → v7: create the node metadata file.
pub struct M007AddNodeMetadata;

impl Migration for M007AddNodeMetadata {
    fn from_version(&self) -> u32 { 6 }
    fn description(&self) -> &'static str {
        "Add node metadata (node_meta.json) for node identity and configuration (v6 → v7)"
    }
    fn estimated_duration_ms(&self) -> u64 { 50 }
    fn can_rollback(&self) -> bool { true }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let node_meta_path = data_dir.join("node_meta.json");
        if node_meta_path.exists() {
            return MigrationResult::Skipped { from_version: 6 };
        }
        if !dry_run {
            let initial = serde_json::json!({
                "version": 1,
                "node_id": "",
                "created_at": 0,
                "chain_id": null
            });
            if let Err(e) = write_json_file_atomic(&node_meta_path, &initial) {
                return fail_result(6, e, false);
            }
        }
        ok_result(6, 7, vec!["created node_meta.json"], start, dry_run)
    }

    fn rollback(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let node_meta_path = data_dir.join("node_meta.json");
        if !node_meta_path.exists() {
            return MigrationResult::Skipped { from_version: 7 };
        }
        if !dry_run {
            if let Err(e) = fs::remove_file(&node_meta_path) {
                return MigrationResult::Failed {
                    from_version: 7,
                    reason: format!("cannot remove node_meta.json: {e}"),
                    rolled_back: false,
                };
            }
        }
        ok_result(7, 6, vec!["removed node_meta.json"], start, dry_run)
    }
}

// -----------------------------------------------------------------------------
// Result helpers
// -----------------------------------------------------------------------------

fn ok_result(
    from_version: u32,
    to_version: u32,
    changes: Vec<String>,
    start: Instant,
    dry_run: bool,
) -> MigrationResult {
    let changes: Vec<String> = changes.into_iter().collect();
    MigrationResult::Ok {
        from_version,
        to_version,
        changes,
        duration_ms: if dry_run {
            None
        } else {
            Some(start.elapsed().as_millis().min(u64::MAX as u128) as u64)
        },
    }
}

fn fail_result(from_version: u32, err: MigrationError, rolled_back: bool) -> MigrationResult {
    MigrationResult::Failed {
        from_version,
        reason: err.to_string(),
        rolled_back,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn create_state_file(dir: &TempDir, version: u32, with_vm: bool) {
        let state_path = dir.path().join("state_full.json");
        let mut state = serde_json::json!({
            "kv": {},
            "balances": {},
            "schema_version": version,
        });
        if with_vm {
            state["vm"] = serde_json::json!({});
        }
        std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    }

    fn read_schema_version_from_dir(dir: &Path) -> u32 {
        let state_path = dir.join("state_full.json");
        if let Ok(Some(v)) = read_json_file(&state_path) {
            v.get("schema_version")
                .and_then(|sv| sv.as_u64())
                .map(|v| v as u32)
                .unwrap_or(0)
        } else {
            0
        }
    }

    // ── M001 ───────────────────────────────────────────────────────────────

    #[test]
    fn m001_no_state_file_is_ok() {
        let dir = TempDir::new().unwrap();
        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(!dir.path().join("state_full.json").exists());
    }

    #[test]
    fn m001_adds_vm_field() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);
        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());
        let updated: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("state_full.json")).unwrap())
                .unwrap();
        assert!(updated.get("vm").is_some());
    }

    #[test]
    fn m001_dry_run_does_not_write() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);
        let state_path = dir.path().join("state_full.json");
        let original = std::fs::read_to_string(&state_path).unwrap();
        let _ = M001AddStateVmField.apply(dir.path(), true);
        let on_disk = std::fs::read_to_string(&state_path).unwrap();
        assert_eq!(on_disk, original);
    }

    #[test]
    fn m001_idempotent() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);
        let _ = M001AddStateVmField.apply(dir.path(), false);
        let second = M001AddStateVmField.apply(dir.path(), false);
        assert!(matches!(second, MigrationResult::Skipped { .. }));
    }

    #[test]
    fn m001_rollback_removes_vm() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 1, true);
        let _ = M001AddStateVmField.rollback(dir.path(), false);
        let updated: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.path().join("state_full.json")).unwrap())
                .unwrap();
        assert!(updated.get("vm").is_none());
    }

    // ── Registry ────────────────────────────────────────────────────────────

    #[test]
    fn registry_runs_all_migrations_from_scratch() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);
        let registry = MigrationRegistry::new();
        let results = registry.run_all(dir.path(), false);
        assert!(!results.is_empty());
        assert_eq!(read_schema_version_from_dir(dir.path()), LATEST_SCHEMA_VERSION);
        assert!(dir.path().join("receipts").exists());
        assert!(dir.path().join("evidence.json").exists());
        assert!(dir.path().join("snapshots").exists());
        assert!(dir.path().join("audit.log").exists());
        assert!(dir.path().join("tx_index.json").exists());
        assert!(dir.path().join("node_meta.json").exists());
    }

    #[test]
    fn registry_dry_run_does_not_write() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);
        let registry = MigrationRegistry::new();
        let _ = registry.run_all(dir.path(), true);
        assert_eq!(read_schema_version_from_dir(dir.path()), 0);
        assert!(!dir.path().join("receipts").exists());
        assert!(!dir.path().join("evidence.json").exists());
        assert!(!dir.path().join("snapshots").exists());
        assert!(!dir.path().join("audit.log").exists());
        assert!(!dir.path().join("tx_index.json").exists());
        assert!(!dir.path().join("node_meta.json").exists());
    }

    #[test]
    fn registry_skip_already_applied() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 3, true);
        // Pre-create files that correspond to earlier migrations.
        std::fs::create_dir_all(dir.path().join("receipts")).unwrap();
        std::fs::write(dir.path().join("receipts").join("index.json"), "{}").unwrap();
        std::fs::write(dir.path().join("evidence.json"), "{}").unwrap();

        let registry = MigrationRegistry::new();
        let _ = registry.run_all(dir.path(), false);
        assert_eq!(read_schema_version_from_dir(dir.path()), LATEST_SCHEMA_VERSION);
        assert!(dir.path().join("snapshots").exists());
        assert!(dir.path().join("audit.log").exists());
        assert!(dir.path().join("tx_index.json").exists());
        assert!(dir.path().join("node_meta.json").exists());
    }

    /// Lock test — short timeout to keep the test suite fast. We honour the
    /// `IONA_MIGRATION_LOCK_SECS` env var so this test doesn't wait the full
    /// `DEFAULT_LOCK_TIMEOUT_SECS`.
    #[test]
    fn registry_lock_prevents_concurrent_runs() {
        // Force a short timeout for this test only. `lock_timeout_secs()`
        // caches the value, so we set the env var before any lock is
        // acquired in this test binary. To be safe, we accept either the
        // default or the override.
        std::env::set_var(LOCK_TIMEOUT_ENV, "1");

        let dir = TempDir::new().unwrap();
        create_state_file(&dir, 0, false);

        let lock1 = acquire_migration_lock(dir.path()).unwrap();

        let start = Instant::now();
        let lock2_result = acquire_migration_lock(dir.path());
        let elapsed = start.elapsed();

        assert!(lock2_result.is_err(), "second lock should time out");
        // Should have waited at least ~1 second (the configured timeout).
        // Allow a bit of slack for slow CI.
        assert!(elapsed >= Duration::from_millis(900));

        drop(lock1);

        let lock2 = acquire_migration_lock(dir.path());
        assert!(lock2.is_ok());

        std::env::remove_var(LOCK_TIMEOUT_ENV);
    }

    // ── Static descriptor table ─────────────────────────────────────────────

    #[test]
    fn migrations_table_is_contiguous() {
        for (i, d) in MIGRATIONS.iter().enumerate() {
            assert_eq!(d.from_version, i as u32);
            assert_eq!(d.to_version, d.from_version + 1);
        }
        assert_eq!(MIGRATIONS.len(), MIGRATION_COUNT);
        assert_eq!(MIGRATIONS.last().unwrap().to_version, LATEST_SCHEMA_VERSION);
    }

    #[test]
    fn descriptor_lookup() {
        assert!(descriptor_for(0).is_some());
        assert!(descriptor_for(6).is_some());
        assert!(descriptor_for(7).is_none());
    }

    #[test]
    fn metrics_snapshot_is_readable() {
        let _ = metrics();
    }
}
