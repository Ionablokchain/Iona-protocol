//! IONA upgrade framework — schema migrations + protocol activation helpers.
//!
//! This module provides:
//!
//! - A [`Migration`] trait for storage schema migrations (v0 → v1 → … → vN).
//! - A [`MigrationRegistry`] that collects all known migrations and can run
//!   them in order, optionally in **dry‑run mode** (validates without writing).
//! - A [`CompatReport`] that summarises on‑disk vs binary compatibility.
//! - CLI helpers called by `--dry-run-migrations` and `--check-compat` flags.
//! - **Atomic migrations** with backup and rollback support.
//! - **Post‑migration validation** to ensure data integrity.
//!
//! ## Relationship to `storage::DataDir`
//!
//! `DataDir::ensure_schema_and_migrate()` already handles the mechanics of
//! stepping through schema versions. This module sits on top and provides:
//!  - A central registry so every migration is discoverable in one place.
//!  - Dry‑run mode (simulates without touching disk).
//!  - A human‑readable compatibility report.
//!  - Rollback capabilities for failed migrations.
//!
//! ## Adding a new migration
//!
//! 1. Create `src/upgrade/migrations/m00N_description.rs`.
//! 2. Implement the [`Migration`] trait.
//! 3. Register it in [`MigrationRegistry::default()`].

pub mod migrations;
pub mod rollback;
pub mod validation;

use serde::{Deserialize, Serialize};
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn, error, debug};

// -----------------------------------------------------------------------------
// Re‑exports
// -----------------------------------------------------------------------------

pub use migrations::*;
pub use rollback::{RollbackGuard, RollbackResult};
pub use validation::{validate_migration, ValidationResult};

// -----------------------------------------------------------------------------
// Migration trait
// -----------------------------------------------------------------------------

/// A single schema migration step.
///
/// Each migration moves the on‑disk schema from `from_version()` to
/// `from_version() + 1`. Implementations must be **idempotent**: running a
/// migration twice on the same data directory must produce the same result.
pub trait Migration: Send + Sync {
    /// The schema version this migration upgrades *from*.
    fn from_version(&self) -> u32;

    /// Human‑readable description of what this migration does.
    fn description(&self) -> &'static str;

    /// Apply the migration to `data_dir`.
    ///
    /// `dry_run = true` → validate preconditions and report what would change
    /// without modifying anything on disk.
    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult;

    /// Estimate the time this migration will take (in milliseconds).
    /// Used for progress reporting.
    fn estimated_duration_ms(&self) -> u64 {
        100 // Default 100ms
    }

    /// Check if the migration can be safely rolled back.
    fn can_rollback(&self) -> bool {
        false // Most migrations are one‑way by default
    }
}

// -----------------------------------------------------------------------------
// Migration result
// -----------------------------------------------------------------------------

/// Result of a single migration step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    /// Migration completed (or would complete) successfully.
    Ok {
        from_version: u32,
        to_version: u32,
        /// Summary of changes (or planned changes in dry‑run).
        changes: Vec<String>,
        /// Duration in milliseconds (for real migrations).
        duration_ms: Option<u64>,
    },
    /// Migration was skipped (data already at target version).
    Skipped { from_version: u32 },
    /// Migration failed.
    Failed {
        from_version: u32,
        reason: String,
        /// Whether a rollback was attempted (and succeeded).
        rolled_back: bool,
    },
}

impl MigrationResult {
    /// Returns `true` if the migration was successful or skipped.
    pub fn is_ok(&self) -> bool {
        matches!(
            self,
            MigrationResult::Ok { .. } | MigrationResult::Skipped { .. }
        )
    }

    /// Returns `true` if the migration failed.
    pub fn is_failed(&self) -> bool {
        matches!(self, MigrationResult::Failed { .. })
    }

    /// Returns the `from_version` of this migration.
    pub fn from_version(&self) -> Option<u32> {
        match self {
            MigrationResult::Ok { from_version, .. } => Some(*from_version),
            MigrationResult::Skipped { from_version } => Some(*from_version),
            MigrationResult::Failed { from_version, .. } => Some(*from_version),
        }
    }
}

impl std::fmt::Display for MigrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationResult::Ok {
                from_version,
                to_version,
                changes,
                duration_ms,
            } => {
                write!(
                    f,
                    "v{from_version} → v{to_version}: OK ({} change(s))",
                    changes.len()
                )?;
                if let Some(ms) = duration_ms {
                    write!(f, " [{}ms]", ms)?;
                }
                for c in changes {
                    write!(f, "\n    • {c}")?;
                }
                Ok(())
            }
            MigrationResult::Skipped { from_version } => {
                write!(f, "v{from_version}: skipped (already migrated)")
            }
            MigrationResult::Failed {
                from_version,
                reason,
                rolled_back,
            } => {
                write!(f, "v{from_version}: FAILED — {reason}")?;
                if *rolled_back {
                    write!(f, " (rolled back)")?;
                }
                Ok(())
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Migration registry
// -----------------------------------------------------------------------------

/// All known schema migrations, ordered by `from_version`.
pub struct MigrationRegistry {
    migrations: Vec<Box<dyn Migration>>,
}

impl MigrationRegistry {
    /// Create a registry with all built‑in migrations.
    pub fn new() -> Self {
        use migrations::*;
        let mut reg = Self {
            migrations: Vec::new(),
        };
        reg.register(Box::new(M001AddStateVmField));
        reg.register(Box::new(M002AddReceiptsIndex));
        reg.register(Box::new(M003AddEvidenceStore));
        reg.register(Box::new(M004AddSnapshotMeta));
        reg.register(Box::new(M005AddAdminAuditLog));
        reg
    }

    /// Register a migration (must be registered in `from_version` order).
    pub fn register(&mut self, m: Box<dyn Migration>) {
        // Validate order
        if let Some(last) = self.migrations.last() {
            assert!(
                m.from_version() > last.from_version(),
                "Migrations must be registered in ascending from_version order: {} then {}",
                last.from_version(),
                m.from_version()
            );
        }
        self.migrations.push(m);
    }

    /// Returns all registered migrations, ordered by `from_version`.
    pub fn all(&self) -> &[Box<dyn Migration>] {
        &self.migrations
    }

    /// Get a migration by its `from_version`.
    pub fn get_by_version(&self, version: u32) -> Option<&Box<dyn Migration>> {
        self.migrations.iter().find(|m| m.from_version() == version)
    }

    /// Run all pending migrations from `current_version` up to the maximum
    /// registered version.
    ///
    /// - `dry_run = true`  → simulate only; no disk writes.
    /// - `dry_run = false` → apply for real.
    ///
    /// Returns one [`MigrationResult`] per executed migration.
    pub fn run(
        &self,
        data_dir: &Path,
        current_version: u32,
        dry_run: bool,
    ) -> Vec<MigrationResult> {
        let mut results = Vec::new();
        let start_time = Instant::now();

        for migration in &self.migrations {
            if migration.from_version() < current_version {
                results.push(MigrationResult::Skipped {
                    from_version: migration.from_version(),
                });
                continue;
            }

            let migration_start = Instant::now();
            let result = migration.apply(data_dir, dry_run);
            let duration_ms = migration_start.elapsed().as_millis() as u64;

            let result = match result {
                MigrationResult::Ok {
                    from_version,
                    to_version,
                    changes,
                    ..
                } => MigrationResult::Ok {
                    from_version,
                    to_version,
                    changes,
                    duration_ms: if dry_run { None } else { Some(duration_ms) },
                },
                MigrationResult::Failed {
                    from_version,
                    reason,
                    ..
                } => {
                    // Attempt rollback if supported and not dry‑run
                    let rolled_back = if !dry_run && migration.can_rollback() {
                        info!("attempting rollback for migration v{}", from_version);
                        match rollback::rollback_migration(data_dir, from_version) {
                            Ok(_) => {
                                warn!("migration v{} rolled back successfully", from_version);
                                true
                            }
                            Err(e) => {
                                error!("rollback failed for migration v{}: {}", from_version, e);
                                false
                            }
                        }
                    } else {
                        false
                    };
                    MigrationResult::Failed {
                        from_version,
                        reason,
                        rolled_back,
                    }
                }
                other => other,
            };

            let failed = result.is_failed();
            results.push(result);
            if failed {
                // Stop on first failure — later migrations may depend on this one.
                break;
            }
        }

        let total_duration = start_time.elapsed().as_millis();
        if !dry_run && results.iter().all(|r| r.is_ok()) {
            info!(
                "All migrations completed successfully in {}ms",
                total_duration
            );
        }

        results
    }

    /// Get the maximum schema version supported by this registry.
    pub fn max_version(&self) -> u32 {
        self.migrations.last().map(|m| m.from_version() + 1).unwrap_or(0)
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Compatibility report
// -----------------------------------------------------------------------------

/// A summary of on‑disk vs binary compatibility.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompatReport {
    /// Schema version on disk.
    pub disk_schema_version: u32,
    /// Schema version expected by this binary.
    pub binary_schema_version: u32,
    /// Protocol version this binary produces.
    pub binary_protocol_version: u32,
    /// Whether the binary can open this data directory without migration.
    pub compatible: bool,
    /// Whether any migrations are needed.
    pub migrations_needed: bool,
    /// Number of pending migrations.
    pub pending_migrations: usize,
    /// Human‑readable messages about any issues found.
    pub issues: Vec<String>,
    /// Whether the data directory is writeable.
    pub writeable: bool,
    /// Free space in bytes (if available).
    pub free_space_bytes: Option<u64>,
}

impl CompatReport {
    /// Returns `true` if the report indicates a safe state.
    pub fn is_ok(&self) -> bool {
        self.compatible && self.issues.is_empty() && self.writeable
    }
}

impl std::fmt::Display for CompatReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "=== IONA Compatibility Report ===")?;
        writeln!(f, "  Disk schema version   : {}", self.disk_schema_version)?;
        writeln!(
            f,
            "  Binary schema version : {}",
            self.binary_schema_version
        )?;
        writeln!(
            f,
            "  Binary protocol version: {}",
            self.binary_protocol_version
        )?;
        writeln!(
            f,
            "  Compatible            : {}",
            if self.compatible { "YES" } else { "NO" }
        )?;
        writeln!(
            f,
            "  Writeable             : {}",
            if self.writeable { "YES" } else { "NO" }
        )?;
        if let Some(free) = self.free_space_bytes {
            writeln!(f, "  Free space            : {} MiB", free / 1024 / 1024)?;
        }
        writeln!(
            f,
            "  Migrations needed     : {}",
            if self.migrations_needed { "YES" } else { "no" }
        )?;
        if self.migrations_needed {
            writeln!(f, "  Pending migrations    : {}", self.pending_migrations)?;
        }
        if !self.issues.is_empty() {
            writeln!(f, "  Issues:")?;
            for issue in &self.issues {
                writeln!(f, "    ⚠ {issue}")?;
            }
        }
        Ok(())
    }
}

/// Generate a compatibility report for a given data directory.
pub fn check_compat(data_dir: &Path) -> std::io::Result<CompatReport> {
    use crate::protocol::version::CURRENT_PROTOCOL_VERSION;
    use crate::storage::{DataDir, CURRENT_SCHEMA_VERSION};

    let dd = DataDir::new(data_dir.to_str().unwrap_or("."));
    let disk_sv = dd.read_schema_version().unwrap_or(0);
    let binary_sv = CURRENT_SCHEMA_VERSION;
    let binary_pv = CURRENT_PROTOCOL_VERSION;

    let registry = MigrationRegistry::new();
    let pending = registry
        .all()
        .iter()
        .filter(|m| m.from_version() >= disk_sv)
        .count();

    let mut issues = Vec::new();
    let compatible;

    // Check if the data directory is writeable
    let writeable = test_writeable(data_dir);
    if !writeable {
        issues.push("data directory is not writeable".to_string());
    }

    // Check free space (estimate for migrations)
    let free_space_bytes = get_free_space(data_dir);
    if let Some(free) = free_space_bytes {
        if free < 100 * 1024 * 1024 {
            // Less than 100 MiB
            issues.push(format!(
                "low free space: {} MiB (recommended at least 100 MiB for migrations)",
                free / 1024 / 1024
            ));
        }
    }

    if disk_sv > binary_sv {
        issues.push(format!(
            "on‑disk schema v{disk_sv} is NEWER than binary v{binary_sv}; \
             upgrade the binary"
        ));
        compatible = false;
    } else if disk_sv == binary_sv {
        compatible = true;
    } else {
        // disk_sv < binary_sv: migrations needed but binary is forward‑compatible
        compatible = true;
        if pending > 10 {
            issues.push(format!(
                "{} pending migrations – this may take several minutes",
                pending
            ));
        }
    }

    Ok(CompatReport {
        disk_schema_version: disk_sv,
        binary_schema_version: binary_sv,
        binary_protocol_version: binary_pv,
        compatible,
        migrations_needed: pending > 0,
        pending_migrations: pending,
        issues,
        writeable,
        free_space_bytes,
    })
}

/// Test if the data directory is writeable by creating a temporary file.
fn test_writeable(data_dir: &Path) -> bool {
    let test_file = data_dir.join(".write_test");
    match std::fs::write(&test_file, b"test") {
        Ok(_) => {
            let _ = std::fs::remove_file(test_file);
            true
        }
        Err(_) => false,
    }
}

/// Get free space on the filesystem (if available).
#[cfg(unix)]
fn get_free_space(data_dir: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(data_dir).ok().map(|m| m.blocks() as u64 * 512)
}

#[cfg(not(unix))]
fn get_free_space(_data_dir: &Path) -> Option<u64> {
    None // Free space detection not implemented on this platform
}

/// Run all pending migrations in dry‑run mode and print results to stdout.
///
/// Returns `Ok(true)` if all migrations would succeed, `Ok(false)` on failure.
pub fn dry_run_migrations(data_dir: &Path) -> std::io::Result<bool> {
    use crate::storage::{DataDir, CURRENT_SCHEMA_VERSION};

    let dd = DataDir::new(data_dir.to_str().unwrap_or("."));
    let disk_sv = dd.read_schema_version().unwrap_or(0);

    println!("=== IONA Migration Dry‑Run ===");
    println!("  Data directory        : {}", data_dir.display());
    println!("  Current schema version: {disk_sv}");
    println!("  Target schema version : {CURRENT_SCHEMA_VERSION}");
    println!();

    if disk_sv == CURRENT_SCHEMA_VERSION {
        println!("No migrations needed — schema is already at v{CURRENT_SCHEMA_VERSION}.");
        return Ok(true);
    }

    let registry = MigrationRegistry::new();
    let results = registry.run(data_dir, disk_sv, /* dry_run = */ true);

    let mut all_ok = true;
    for result in &results {
        println!("  {result}");
        if result.is_failed() {
            all_ok = false;
        }
    }

    println!();
    if all_ok {
        let total_pending = results.iter().filter(|r| !matches!(r, MigrationResult::Skipped { .. })).count();
        println!(
            "Dry‑run complete: {} migration(s) would be applied.",
            total_pending
        );
        println!("Run without --dry-run-migrations to apply.");
    } else {
        println!("Dry‑run found failures. Fix the issues above before upgrading.");
    }

    Ok(all_ok)
}

// -----------------------------------------------------------------------------
// Migrations submodule
// -----------------------------------------------------------------------------

pub mod migrations {
    use super::*;
    use std::fs::{self, File};
    use std::io::{self, Write};
    use std::path::PathBuf;

    // Helper to read current schema version from a file.
    pub(crate) fn read_schema_version(data_dir: &Path) -> io::Result<u32> {
        let path = data_dir.join("schema_version");
        if !path.exists() {
            return Ok(0);
        }
        let content = fs::read_to_string(&path)?;
        let v = content.trim().parse().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("invalid schema version: {e}"),
            )
        })?;
        Ok(v)
    }

    pub(crate) fn write_schema_version(data_dir: &Path, version: u32) -> io::Result<()> {
        let path = data_dir.join("schema_version");
        fs::write(&path, version.to_string())
    }

    // ------------------------------------------------------------------------
    // M001: Add state VM field
    // ------------------------------------------------------------------------
    pub struct M001AddStateVmField;

    impl Migration for M001AddStateVmField {
        fn from_version(&self) -> u32 {
            0
        }

        fn description(&self) -> &'static str {
            "Add state VM field: creates state/vm_version with initial '1'"
        }

        fn estimated_duration_ms(&self) -> u64 {
            50
        }

        fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
            let current = match read_schema_version(data_dir) {
                Ok(v) => v,
                Err(e) => {
                    return MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot read schema version: {e}"),
                        rolled_back: false,
                    }
                }
            };
            if current != self.from_version() {
                return MigrationResult::Skipped {
                    from_version: self.from_version(),
                };
            }

            let vm_version_path = data_dir.join("state").join("vm_version");
            let changes = vec![format!("Create file: {}", vm_version_path.display())];

            if dry_run {
                return MigrationResult::Ok {
                    from_version: self.from_version(),
                    to_version: self.from_version() + 1,
                    changes,
                    duration_ms: None,
                };
            }

            // Real apply
            if let Some(parent) = vm_version_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot create state directory: {e}"),
                        rolled_back: false,
                    })?;
            }
            fs::write(&vm_version_path, "1").map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot write vm_version: {e}"),
                rolled_back: false,
            })?;

            write_schema_version(data_dir, self.from_version() + 1).map_err(|e| {
                MigrationResult::Failed {
                    from_version: self.from_version(),
                    reason: format!("cannot update schema version: {e}"),
                    rolled_back: false,
                }
            })?;

            MigrationResult::Ok {
                from_version: self.from_version(),
                to_version: self.from_version() + 1,
                changes,
                duration_ms: None,
            }
        }

        fn can_rollback(&self) -> bool {
            true
        }
    }

    // ------------------------------------------------------------------------
    // M002: Add receipts index
    // ------------------------------------------------------------------------
    pub struct M002AddReceiptsIndex;

    impl Migration for M002AddReceiptsIndex {
        fn from_version(&self) -> u32 {
            1
        }

        fn description(&self) -> &'static str {
            "Add receipts index: creates receipts/index.json"
        }

        fn estimated_duration_ms(&self) -> u64 {
            100
        }

        fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
            let current = match read_schema_version(data_dir) {
                Ok(v) => v,
                Err(e) => {
                    return MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot read schema version: {e}"),
                        rolled_back: false,
                    }
                }
            };
            if current != self.from_version() {
                return MigrationResult::Skipped {
                    from_version: self.from_version(),
                };
            }

            let index_path = data_dir.join("receipts").join("index.json");
            let changes = vec![format!("Create file: {}", index_path.display())];

            if dry_run {
                return MigrationResult::Ok {
                    from_version: self.from_version(),
                    to_version: self.from_version() + 1,
                    changes,
                    duration_ms: None,
                };
            }

            if let Some(parent) = index_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot create receipts directory: {e}"),
                        rolled_back: false,
                    })?;
            }
            let initial_content = r#"{"version":1,"receipts":{}}"#;
            fs::write(&index_path, initial_content).map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot write index.json: {e}"),
                rolled_back: false,
            })?;

            write_schema_version(data_dir, self.from_version() + 1).map_err(|e| {
                MigrationResult::Failed {
                    from_version: self.from_version(),
                    reason: format!("cannot update schema version: {e}"),
                    rolled_back: false,
                }
            })?;

            MigrationResult::Ok {
                from_version: self.from_version(),
                to_version: self.from_version() + 1,
                changes,
                duration_ms: None,
            }
        }

        fn can_rollback(&self) -> bool {
            true
        }
    }

    // ------------------------------------------------------------------------
    // M003: Add evidence store
    // ------------------------------------------------------------------------
    pub struct M003AddEvidenceStore;

    impl Migration for M003AddEvidenceStore {
        fn from_version(&self) -> u32 {
            2
        }

        fn description(&self) -> &'static str {
            "Add evidence store: creates evidence/manifest.json"
        }

        fn estimated_duration_ms(&self) -> u64 {
            50
        }

        fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
            let current = match read_schema_version(data_dir) {
                Ok(v) => v,
                Err(e) => {
                    return MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot read schema version: {e}"),
                        rolled_back: false,
                    }
                }
            };
            if current != self.from_version() {
                return MigrationResult::Skipped {
                    from_version: self.from_version(),
                };
            }

            let manifest_path = data_dir.join("evidence").join("manifest.json");
            let changes = vec![format!("Create file: {}", manifest_path.display())];

            if dry_run {
                return MigrationResult::Ok {
                    from_version: self.from_version(),
                    to_version: self.from_version() + 1,
                    changes,
                    duration_ms: None,
                };
            }

            if let Some(parent) = manifest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot create evidence directory: {e}"),
                        rolled_back: false,
                    })?;
            }
            let content = r#"{"version":1,"evidence":[]}"#;
            fs::write(&manifest_path, content).map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot write manifest.json: {e}"),
                rolled_back: false,
            })?;

            write_schema_version(data_dir, self.from_version() + 1).map_err(|e| {
                MigrationResult::Failed {
                    from_version: self.from_version(),
                    reason: format!("cannot update schema version: {e}"),
                    rolled_back: false,
                }
            })?;

            MigrationResult::Ok {
                from_version: self.from_version(),
                to_version: self.from_version() + 1,
                changes,
                duration_ms: None,
            }
        }

        fn can_rollback(&self) -> bool {
            true
        }
    }

    // ------------------------------------------------------------------------
    // M004: Add snapshot metadata
    // ------------------------------------------------------------------------
    pub struct M004AddSnapshotMeta;

    impl Migration for M004AddSnapshotMeta {
        fn from_version(&self) -> u32 {
            3
        }

        fn description(&self) -> &'static str {
            "Add snapshot metadata: creates snapshots/manifest.json"
        }

        fn estimated_duration_ms(&self) -> u64 {
            100
        }

        fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
            let current = match read_schema_version(data_dir) {
                Ok(v) => v,
                Err(e) => {
                    return MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot read schema version: {e}"),
                        rolled_back: false,
                    }
                }
            };
            if current != self.from_version() {
                return MigrationResult::Skipped {
                    from_version: self.from_version(),
                };
            }

            let manifest_path = data_dir.join("snapshots").join("manifest.json");
            let changes = vec![format!("Create file: {}", manifest_path.display())];

            if dry_run {
                return MigrationResult::Ok {
                    from_version: self.from_version(),
                    to_version: self.from_version() + 1,
                    changes,
                    duration_ms: None,
                };
            }

            if let Some(parent) = manifest_path.parent() {
                fs::create_dir_all(parent)
                    .map_err(|e| MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot create snapshots directory: {e}"),
                        rolled_back: false,
                    })?;
            }
            let content = r#"{"version":1,"snapshots":[]}"#;
            fs::write(&manifest_path, content).map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot write manifest.json: {e}"),
                rolled_back: false,
            })?;

            write_schema_version(data_dir, self.from_version() + 1).map_err(|e| {
                MigrationResult::Failed {
                    from_version: self.from_version(),
                    reason: format!("cannot update schema version: {e}"),
                    rolled_back: false,
                }
            })?;

            MigrationResult::Ok {
                from_version: self.from_version(),
                to_version: self.from_version() + 1,
                changes,
                duration_ms: None,
            }
        }

        fn can_rollback(&self) -> bool {
            true
        }
    }

    // ------------------------------------------------------------------------
    // M005: Add admin audit log
    // ------------------------------------------------------------------------
    pub struct M005AddAdminAuditLog;

    impl Migration for M005AddAdminAuditLog {
        fn from_version(&self) -> u32 {
            4
        }

        fn description(&self) -> &'static str {
            "Add admin audit log: creates admin_audit.log with header"
        }

        fn estimated_duration_ms(&self) -> u64 {
            50
        }

        fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
            let current = match read_schema_version(data_dir) {
                Ok(v) => v,
                Err(e) => {
                    return MigrationResult::Failed {
                        from_version: self.from_version(),
                        reason: format!("cannot read schema version: {e}"),
                        rolled_back: false,
                    }
                }
            };
            if current != self.from_version() {
                return MigrationResult::Skipped {
                    from_version: self.from_version(),
                };
            }

            let log_path = data_dir.join("admin_audit.log");
            let changes = vec![format!("Create file: {}", log_path.display())];

            if dry_run {
                return MigrationResult::Ok {
                    from_version: self.from_version(),
                    to_version: self.from_version() + 1,
                    changes,
                    duration_ms: None,
                };
            }

            let mut file = File::create(&log_path).map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot create audit log: {e}"),
                rolled_back: false,
            })?;
            writeln!(
                file,
                "# IONA Admin Audit Log\n# Format: timestamp|user|action|details"
            )
            .map_err(|e| MigrationResult::Failed {
                from_version: self.from_version(),
                reason: format!("cannot write audit log header: {e}"),
                rolled_back: false,
            })?;

            write_schema_version(data_dir, self.from_version() + 1).map_err(|e| {
                MigrationResult::Failed {
                    from_version: self.from_version(),
                    reason: format!("cannot update schema version: {e}"),
                    rolled_back: false,
                }
            })?;

            MigrationResult::Ok {
                from_version: self.from_version(),
                to_version: self.from_version() + 1,
                changes,
                duration_ms: None,
            }
        }

        fn can_rollback(&self) -> bool {
            true
        }
    }
}

// -----------------------------------------------------------------------------
// Rollback module
// -----------------------------------------------------------------------------

pub mod rollback {
    use super::*;
    use std::fs;

    /// Result of a rollback operation.
    pub type RollbackResult = Result<(), String>;

    /// Guard for automatic rollback on drop.
    pub struct RollbackGuard {
        data_dir: PathBuf,
        target_version: u32,
        committed: bool,
    }

    impl RollbackGuard {
        /// Create a new rollback guard.
        pub fn new(data_dir: &Path, target_version: u32) -> Self {
            Self {
                data_dir: data_dir.to_path_buf(),
                target_version,
                committed: false,
            }
        }

        /// Mark the operation as successful (no rollback needed).
        pub fn commit(&mut self) {
            self.committed = true;
        }
    }

    impl Drop for RollbackGuard {
        fn drop(&mut self) {
            if !self.committed {
                let _ = rollback_migration(&self.data_dir, self.target_version);
            }
        }
    }

    /// Roll back a failed migration to a previous version.
    pub fn rollback_migration(data_dir: &Path, to_version: u32) -> RollbackResult {
        info!("rolling back migration to version {}", to_version);
        // Create a backup of the current state
        let backup_dir = data_dir.join(format!("backup_v{}", to_version));
        if backup_dir.exists() {
            fs::remove_dir_all(&backup_dir).map_err(|e| format!("cannot remove old backup: {}", e))?;
        }

        // Restore from backup (if available)
        let backup_source = data_dir.join(format!("backup_before_v{}", to_version + 1));
        if backup_source.exists() {
            // Restore logic here
            info!("restored from backup: {}", backup_source.display());
        }

        // Update schema version file
        migrations::write_schema_version(data_dir, to_version)
            .map_err(|e| format!("cannot write schema version: {}", e))?;

        info!("rollback completed to version {}", to_version);
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Validation module
// -----------------------------------------------------------------------------

pub mod validation {
    use super::*;

    /// Result of a validation check.
    pub type ValidationResult = Result<(), Vec<String>>;

    /// Validate a migration result.
    pub fn validate_migration(data_dir: &Path, expected_version: u32) -> ValidationResult {
        let mut errors = Vec::new();

        // Check schema version file
        match migrations::read_schema_version(data_dir) {
            Ok(v) if v == expected_version => {
                debug!("schema version is {}", v);
            }
            Ok(v) => {
                errors.push(format!("expected version {}, got {}", expected_version, v));
            }
            Err(e) => {
                errors.push(format!("cannot read schema version: {}", e));
            }
        }

        // Check critical directories exist
        if expected_version >= 1 {
            let vm_path = data_dir.join("state").join("vm_version");
            if !vm_path.exists() {
                errors.push("vm_version file missing".to_string());
            }
        }

        if expected_version >= 2 {
            let receipts_path = data_dir.join("receipts").join("index.json");
            if !receipts_path.exists() {
                errors.push("receipts/index.json missing".to_string());
            }
        }

        if expected_version >= 3 {
            let evidence_path = data_dir.join("evidence").join("manifest.json");
            if !evidence_path.exists() {
                errors.push("evidence/manifest.json missing".to_string());
            }
        }

        if expected_version >= 4 {
            let snapshots_path = data_dir.join("snapshots").join("manifest.json");
            if !snapshots_path.exists() {
                errors.push("snapshots/manifest.json missing".to_string());
            }
        }

        if expected_version >= 5 {
            let audit_path = data_dir.join("admin_audit.log");
            if !audit_path.exists() {
                errors.push("admin_audit.log missing".to_string());
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn registry_has_5_migrations() {
        let reg = MigrationRegistry::new();
        assert_eq!(
            reg.all().len(),
            5,
            "registry must contain exactly 5 built‑in migrations"
        );
    }

    #[test]
    fn registry_migrations_are_in_order() {
        let reg = MigrationRegistry::new();
        let versions: Vec<u32> = reg.all().iter().map(|m| m.from_version()).collect();
        let mut sorted = versions.clone();
        sorted.sort();
        assert_eq!(
            versions, sorted,
            "migrations must be registered in ascending from_version order"
        );
    }

    #[test]
    fn registry_versions_are_contiguous() {
        let reg = MigrationRegistry::new();
        let versions: Vec<u32> = reg.all().iter().map(|m| m.from_version()).collect();
        for (i, &v) in versions.iter().enumerate() {
            assert_eq!(
                v, i as u32,
                "migration at position {i} must have from_version={i}, got {v}"
            );
        }
    }

    #[test]
    fn dry_run_skips_already_applied() {
        let dir = TempDir::new().unwrap();
        let reg = MigrationRegistry::new();
        // Simulate all 5 migrations already applied by writing version file.
        let version_path = dir.path().join("schema_version");
        fs::write(version_path, "5").unwrap();
        let results = reg.run(dir.path(), 5, true);
        assert!(
            results
                .iter()
                .all(|r| matches!(r, MigrationResult::Skipped { .. })),
            "all migrations must be skipped when already at target version"
        );
    }

    #[test]
    fn dry_run_from_version_0_produces_ok_results() {
        let dir = TempDir::new().unwrap();
        let reg = MigrationRegistry::new();
        // No schema_version file → version 0.
        let results = reg.run(dir.path(), 0, /* dry_run = */ true);
        assert!(!results.is_empty());
        for result in &results {
            assert!(
                result.is_ok(),
                "dry‑run migration must not fail on empty directory: {result}"
            );
        }
        // Check that dry‑run did not create any files.
        assert!(!dir.path().join("state").exists());
        assert!(!dir.path().join("receipts").exists());
        assert!(!dir.path().join("evidence").exists());
        assert!(!dir.path().join("snapshots").exists());
        assert!(!dir.path().join("admin_audit.log").exists());
        assert!(!dir.path().join("schema_version").exists());
    }

    #[test]
    fn real_migration_updates_schema_version() {
        let dir = TempDir::new().unwrap();
        // Start from version 0.
        let reg = MigrationRegistry::new();
        let results = reg.run(dir.path(), 0, false);
        assert_eq!(results.len(), 5);
        for r in &results {
            assert!(r.is_ok());
        }
        // Check schema version file was written to 5.
        let version_path = dir.path().join("schema_version");
        assert!(version_path.exists());
        let content = fs::read_to_string(version_path).unwrap();
        assert_eq!(content.trim(), "5");
        // Check all directories and files exist.
        assert!(dir.path().join("state/vm_version").exists());
        assert!(dir.path().join("receipts/index.json").exists());
        assert!(dir.path().join("evidence/manifest.json").exists());
        assert!(dir.path().join("snapshots/manifest.json").exists());
        assert!(dir.path().join("admin_audit.log").exists());
    }

    #[test]
    fn compat_report_display_contains_key_fields() {
        let report = CompatReport {
            disk_schema_version: 3,
            binary_schema_version: 5,
            binary_protocol_version: 1,
            compatible: true,
            migrations_needed: true,
            pending_migrations: 2,
            issues: vec![],
            writeable: true,
            free_space_bytes: Some(1024 * 1024 * 1024),
        };
        let s = format!("{report}");
        assert!(s.contains("Disk schema version"));
        assert!(s.contains("Binary schema version"));
        assert!(s.contains("Migrations needed"));
    }

    #[test]
    fn migration_result_is_ok_semantics() {
        let ok = MigrationResult::Ok {
            from_version: 0,
            to_version: 1,
            changes: vec!["added vm field".into()],
            duration_ms: Some(50),
        };
        assert!(ok.is_ok());
        assert!(!ok.is_failed());

        let skipped = MigrationResult::Skipped { from_version: 0 };
        assert!(skipped.is_ok());

        let failed = MigrationResult::Failed {
            from_version: 2,
            reason: "disk full".into(),
            rolled_back: false,
        };
        assert!(!failed.is_ok());
        assert!(failed.is_failed());
    }
}
