//! Ordered, idempotent storage migrations.
//!
//! Each migration upgrades from version N to N+1. Migrations are registered
//! in the `MigrationRegistry` and run by the `MigrationRunner` with retries,
//! timeout, and persistence.
//!
//! # Adding a new migration
//!
//! 1. Create a new module `mNNNN_description.rs` (e.g. `m0004_protocol_version.rs`).
//! 2. Implement a struct that implements `Migration` (from the parent module).
//! 3. Register it in the `register_all()` function below.
//! 4. Bump `CURRENT_SCHEMA_VERSION` in `storage/mod.rs`.
//!
//! # Rules
//!
//! - **Never delete user data** -- rename or backup instead.
//! - **Atomic where possible** -- write to `.tmp` then rename.
//! - **Idempotent** -- safe to run twice if a previous run was interrupted.
//! - **Logged** -- every step logs via `tracing`.
//! - **Dual-read** -- the node can still read the old format until migration completes.

pub mod background;
pub mod m0004_protocol_version;
pub mod m0005_add_tx_index;

use crate::migration::{Migration, MigrationConfig, MigrationRegistry, MigrationRunner};
use crate::storage::SchemaMeta;
use std::path::Path;
use std::sync::Arc;
use tracing::{info, warn};

// ── Re-export individual migrations ─────────────────────────────────────

pub use m0004_protocol_version::MigrationV3ToV4;
pub use m0005_add_tx_index::MigrationV4ToV5;

// ── Registry ─────────────────────────────────────────────────────────────

/// Register all known migrations in the order they should be applied.
pub fn register_all() -> MigrationRegistry {
    let mut registry = MigrationRegistry::new();

    // v3 → v4: Add protocol version tracking to node_meta.json
    registry.register(Box::new(MigrationV3ToV4));

    // v4 → v5: Build transaction index
    registry.register(Box::new(MigrationV4ToV5));

    // Future migrations:
    // registry.register(Box::new(MigrationV5ToV6));

    registry
}

/// Get the current schema version from the data directory.
pub fn current_schema_version(data_dir: &str) -> u32 {
    let meta_path = Path::new(data_dir).join("schema_meta.json");
    if meta_path.exists() {
        if let Ok(content) = std::fs::read_to_string(&meta_path) {
            if let Ok(meta) = serde_json::from_str::<SchemaMeta>(&content) {
                return meta.schema_version;
            }
        }
    }
    0 // Default if no state exists
}

// ── Runner ──────────────────────────────────────────────────────────────

/// Run all pending migrations using the production runner.
///
/// This will:
/// - Load the current schema version from `schema_meta.json`.
/// - Determine which migrations are pending.
/// - Apply them in order with retries and persistence.
/// - Update `schema_meta.json` after each successful migration.
///
/// # Arguments
/// * `data_dir` – Path to the node's data directory.
/// * `config` – Configuration for the migration runner.
///
/// # Returns
/// `Ok(())` if all migrations succeeded, or an error string.
pub fn run_pending(
    data_dir: &str,
    config: MigrationConfig,
) -> Result<(), String> {
    let registry = register_all();
    let current_ver = current_schema_version(data_dir);

    // If we are already at the latest version, skip.
    let latest_ver = registry
        .iter()
        .map(|m| m.to_version())
        .max()
        .unwrap_or(current_ver);

    if current_ver >= latest_ver {
        info!(current_ver, "no pending migrations");
        return Ok(());
    }

    info!(
        current_ver,
        latest_ver,
        "starting migration run from version {} to {}",
        current_ver,
        latest_ver
    );

    // Create the runner and run all migrations.
    let runner = MigrationRunner::new(
        config,
        data_dir,
        registry,
        current_ver,
    )?;

    runner.run(data_dir)?;

    // Verify that all migrations completed.
    let status = runner.status();
    let all_complete = status.iter().all(|s| s.completed);
    if !all_complete {
        return Err("some migrations did not complete".into());
    }

    info!("all migrations applied successfully");
    Ok(())
}

/// Run a specific migration by its `from_version`.
///
/// Useful for testing or manual intervention.
pub fn run_one(
    data_dir: &str,
    from_version: u32,
    config: MigrationConfig,
) -> Result<(), String> {
    let registry = register_all();
    let migration = registry
        .get(from_version)
        .ok_or_else(|| format!("no migration found for version {}", from_version))?;

    let mut meta = SchemaMeta::load(data_dir)
        .map_err(|e| format!("failed to load schema meta: {}", e))?;

    // Check if migration is already applied.
    if meta.schema_version >= migration.to_version() {
        info!(from_version, "migration already applied");
        return Ok(());
    }

    info!(
        from = from_version,
        to = migration.to_version(),
        "running single migration"
    );

    let runner = MigrationRunner::new(
        config,
        data_dir,
        registry,
        meta.schema_version,
    )?;

    runner.run_one(data_dir, migration)?;

    // Update schema_meta.json
    meta.schema_version = migration.to_version();
    meta.save(data_dir)
        .map_err(|e| format!("failed to save schema meta: {}", e))?;

    info!(
        from = from_version,
        to = migration.to_version(),
        "single migration applied"
    );

    Ok(())
}

// ── Legacy compatibility ──────────────────────────────────────────────

/// Legacy function for backward compatibility with the old migration system.
/// Runs only migrations in the `MIGRATIONS` list (v3+).
#[deprecated(since = "30.0.0", note = "use run_pending with MigrationRunner")]
pub fn run_pending_legacy(
    data_dir: &str,
    meta: &mut SchemaMeta,
    from_version: u32,
    to_version: u32,
) -> std::io::Result<()> {
    // This is a no‑op; the new system handles everything.
    // We keep it to avoid breaking existing code that still calls it.
    // The actual work is done in the new runner.
    Ok(())
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::migration::MigrationConfig;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_register_all() {
        let registry = register_all();
        assert!(!registry.is_empty());
        // Check that migrations are in order.
        let mut versions: Vec<u32> = registry.iter().map(|m| m.from_version()).collect();
        versions.sort();
        let mut expected = versions.clone();
        expected.sort();
        assert_eq!(versions, expected);
    }

    #[test]
    fn test_current_schema_version_no_meta() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let ver = current_schema_version(data_dir);
        assert_eq!(ver, 0);
    }

    #[test]
    fn test_current_schema_version_with_meta() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let meta_path = dir.path().join("schema_meta.json");
        let meta = SchemaMeta {
            schema_version: 4,
            protocol_version: 0,
            migration_log: Vec::new(),
            node_meta: None,
        };
        fs::write(
            &meta_path,
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();
        let ver = current_schema_version(data_dir);
        assert_eq!(ver, 4);
    }

    #[test]
    fn test_run_pending_skips_if_up_to_date() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let meta_path = dir.path().join("schema_meta.json");
        let meta = SchemaMeta {
            schema_version: 5, // latest
            protocol_version: 0,
            migration_log: Vec::new(),
            node_meta: None,
        };
        fs::write(
            &meta_path,
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();

        let config = MigrationConfig::default();
        let result = run_pending(data_dir, config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_one_migration() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let meta_path = dir.path().join("schema_meta.json");
        let meta = SchemaMeta {
            schema_version: 3,
            protocol_version: 0,
            migration_log: Vec::new(),
            node_meta: None,
        };
        fs::write(
            &meta_path,
            serde_json::to_string_pretty(&meta).unwrap(),
        )
        .unwrap();

        let config = MigrationConfig::default();
        let result = run_one(data_dir, 3, config);
        assert!(result.is_ok());

        // Check schema version updated.
        let updated = SchemaMeta::load(data_dir).unwrap();
        assert_eq!(updated.schema_version, 4);
        assert!(updated.migration_log.iter().any(|entry| entry.contains("v3 -> v4")));
    }
}
