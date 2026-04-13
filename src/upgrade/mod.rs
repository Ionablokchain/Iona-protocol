//! IONA upgrade framework — schema migrations + protocol activation helpers.
//!
//! This module provides:
//!
//! - A [`Migration`] trait for storage schema migrations (v0 → v1 → … → vN).
//! - A [`MigrationRegistry`] that collects all known migrations and can run
//!   them in order, optionally in **dry-run mode** (validates without writing).
//! - A [`CompatReport`] that summarises on-disk vs binary compatibility.
//! - CLI helpers called by `--dry-run-migrations` and `--check-compat` flags.
//!
//! ## Relationship to `storage::DataDir`
//!
//! `DataDir::ensure_schema_and_migrate()` already handles the mechanics of
//! stepping through schema versions.  This module sits on top and provides:
//!  - A central registry so every migration is discoverable in one place.
//!  - Dry-run mode (simulates without touching disk).
//!  - A human-readable compatibility report.
//!
//! ## Adding a new migration
//!
//! 1. Create `src/upgrade/migrations/m00N_description.rs`.
//! 2. Implement the [`Migration`] trait.
//! 3. Register it in [`MigrationRegistry::default()`].

pub mod migrations;

use serde::{Deserialize, Serialize};
use std::path::Path;

// ── Migration trait ────────────────────────────────────────────────────────

/// A single schema migration step.
///
/// Each migration moves the on-disk schema from `from_version()` to
/// `from_version() + 1`.  Implementations must be idempotent: running a
/// migration twice on the same data directory must produce the same result.
pub trait Migration: Send + Sync {
    /// The schema version this migration upgrades *from*.
    fn from_version(&self) -> u32;

    /// Human-readable description of what this migration does.
    fn description(&self) -> &'static str;

    /// Apply the migration to `data_dir`.
    ///
    /// `dry_run = true` → validate preconditions and report what would change
    /// without modifying anything on disk.
    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult;
}

/// Result of a single migration step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MigrationResult {
    /// Migration completed (or would complete) successfully.
    Ok {
        from_version: u32,
        to_version: u32,
        /// Summary of changes (or planned changes in dry-run).
        changes: Vec<String>,
    },
    /// Migration was skipped (data already at target version).
    Skipped { from_version: u32 },
    /// Migration failed.
    Failed { from_version: u32, reason: String },
}

impl MigrationResult {
    pub fn is_ok(&self) -> bool {
        matches!(
            self,
            MigrationResult::Ok { .. } | MigrationResult::Skipped { .. }
        )
    }

    pub fn is_failed(&self) -> bool {
        matches!(self, MigrationResult::Failed { .. })
    }
}

impl std::fmt::Display for MigrationResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MigrationResult::Ok {
                from_version,
                to_version,
                changes,
            } => {
                write!(
                    f,
                    "v{from_version} → v{to_version}: OK ({} change(s))",
                    changes.len()
                )?;
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
            } => write!(f, "v{from_version}: FAILED — {reason}"),
        }
    }
}

// ── Migration registry ─────────────────────────────────────────────────────

/// All known schema migrations, ordered by `from_version`.
pub struct MigrationRegistry {
    migrations: Vec<Box<dyn Migration>>,
}

impl MigrationRegistry {
    /// Create a registry with all built-in migrations.
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
        self.migrations.push(m);
    }

    /// Returns all registered migrations, ordered by `from_version`.
    pub fn all(&self) -> &[Box<dyn Migration>] {
        &self.migrations
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
        for migration in &self.migrations {
            if migration.from_version() < current_version {
                results.push(MigrationResult::Skipped {
                    from_version: migration.from_version(),
                });
                continue;
            }
            let result = migration.apply(data_dir, dry_run);
            let failed = result.is_failed();
            results.push(result);
            if failed {
                // Stop on first failure — later migrations may depend on this one.
                break;
            }
        }
        results
    }
}

impl Default for MigrationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ── Compatibility report ───────────────────────────────────────────────────

/// A summary of on-disk vs binary compatibility.
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
    /// Human-readable messages about any issues found.
    pub issues: Vec<String>,
}

impl CompatReport {
    pub fn is_ok(&self) -> bool {
        self.compatible && self.issues.is_empty()
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

    if disk_sv > binary_sv {
        issues.push(format!(
            "on-disk schema v{disk_sv} is NEWER than binary v{binary_sv}; \
             upgrade the binary"
        ));
        compatible = false;
    } else if disk_sv == binary_sv {
        compatible = true;
    } else {
        // disk_sv < binary_sv: migrations needed but binary is forward-compatible
        compatible = true;
    }

    Ok(CompatReport {
        disk_schema_version: disk_sv,
        binary_schema_version: binary_sv,
        binary_protocol_version: binary_pv,
        compatible,
        migrations_needed: pending > 0,
        pending_migrations: pending,
        issues,
    })
}

/// Run all pending migrations in dry-run mode and print results to stdout.
///
/// Returns `Ok(true)` if all migrations would succeed, `Ok(false)` on failure.
pub fn dry_run_migrations(data_dir: &Path) -> std::io::Result<bool> {
    use crate::storage::{DataDir, CURRENT_SCHEMA_VERSION};

    let dd = DataDir::new(data_dir.to_str().unwrap_or("."));
    let disk_sv = dd.read_schema_version().unwrap_or(0);

    println!("=== IONA Migration Dry-Run ===");
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
        println!("Dry-run complete: all migrations would succeed.");
        println!("Run without --dry-run-migrations to apply.");
    } else {
        println!("Dry-run found failures. Fix the issues above before upgrading.");
    }

    Ok(all_ok)
}

// ── Tests ──────────────────────────────────────────────────────────────────

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
            "registry must contain exactly 5 built-in migrations"
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
        // Simulate all 5 migrations already applied (current version = 5).
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
        let results = reg.run(dir.path(), 0, /* dry_run = */ true);
        assert!(!results.is_empty());
        for result in &results {
            assert!(
                result.is_ok(),
                "dry-run migration must not fail on empty directory: {result}"
            );
        }
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
        };
        assert!(ok.is_ok());
        assert!(!ok.is_failed());

        let skipped = MigrationResult::Skipped { from_version: 0 };
        assert!(skipped.is_ok());

        let failed = MigrationResult::Failed {
            from_version: 2,
            reason: "disk full".into(),
        };
        assert!(!failed.is_ok());
        assert!(failed.is_failed());
    }
}
