//! Integration tests for schema versioning and migrations.
//!
//! Each test simulates a node data directory at an older schema version and
//! verifies that `ensure_schema_and_migrate()` upgrades it correctly.

use iona::storage::{DataDir, CURRENT_SCHEMA_VERSION};
use std::fs;
use tempfile::TempDir;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// File name for schema metadata.
const SCHEMA_FILE: &str = "schema.json";

/// File name for full state.
const STATE_FULL_FILE: &str = "state_full.json";

/// Legacy WAL file name (pre‑v3).
const WAL_LEGACY_FILE: &str = "wal.jsonl";

/// Backup suffix for v1 migration.
const BACKUP_V1_SUFFIX: &str = ".v1.bak";

/// Segment directory name.
const WAL_SEGMENT_DIR: &str = "wal";

/// First segment file name pattern.
const FIRST_SEGMENT: &str = "wal_00000000.jsonl";

/// Version numbers used in tests.
const V0_SCHEMA: u32 = 0;
const V1_SCHEMA: u32 = 1;
const V2_SCHEMA: u32 = 2;
const V3_SCHEMA: u32 = 3;
const V4_SCHEMA: u32 = 4;

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Create a temporary directory and a `DataDir` instance.
fn make_dir() -> (TempDir, DataDir) {
    let tmp = TempDir::new().unwrap();
    let data = DataDir::new(tmp.path().to_str().unwrap());
    (tmp, data)
}

/// Write a schema version to the data directory.
fn write_schema_version(data: &DataDir, version: u32) {
    data.ensure().unwrap();
    let meta = serde_json::json!({ "version": version });
    let path = data.root.join(SCHEMA_FILE);
    fs::write(path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
}

/// Read the schema version from the data directory.
fn read_schema_version(data: &DataDir) -> u32 {
    data.read_schema_version().unwrap()
}

/// Write a v1‑style state file (missing the `vm` field).
fn write_v1_state(data: &DataDir) {
    let old_state = serde_json::json!({
        "kv": { "hello": "world" },
        "balances": { "abcd": 1000 },
        "nonces": {}
    });
    let path = data.root.join(STATE_FULL_FILE);
    fs::write(path, serde_json::to_string_pretty(&old_state).unwrap()).unwrap();
}

/// Write a legacy flat WAL file (pre‑v3).
fn write_legacy_wal(data: &DataDir) {
    let path = data.root.join(WAL_LEGACY_FILE);
    fs::write(&path, b"{\"height\":1}\n{\"height\":2}\n").unwrap();
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[test]
fn schema_migration_fresh_dir_creates_schema() {
    let (_tmp, data) = make_dir();
    // No `schema.json` yet – treated as v0.
    assert_eq!(read_schema_version(&data), V0_SCHEMA);
    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);
}

#[test]
fn schema_migration_already_current_is_noop() {
    let (_tmp, data) = make_dir();
    write_schema_version(&data, CURRENT_SCHEMA_VERSION);
    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);
}

#[test]
fn schema_migration_v1_to_current_normalises_state_full() {
    let (_tmp, data) = make_dir();
    data.ensure().unwrap();
    write_schema_version(&data, V1_SCHEMA);
    write_v1_state(&data);

    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);

    // `state_full.json` should now have a `vm` field.
    let path = data.root.join(STATE_FULL_FILE);
    let raw = fs::read_to_string(&path).unwrap();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(
        val.get("vm").is_some(),
        "vm field should be injected by migration"
    );
    // Original data must be preserved.
    assert_eq!(val["kv"]["hello"], "world");

    // Backup must exist.
    let backup = data.root.join(format!("{}{}", STATE_FULL_FILE, BACKUP_V1_SUFFIX));
    assert!(
        backup.exists(),
        "backup file should be created"
    );
}

#[test]
fn schema_migration_v2_migrates_flat_wal_to_segments() {
    let (_tmp, data) = make_dir();
    data.ensure().unwrap();
    write_schema_version(&data, V2_SCHEMA);
    write_legacy_wal(&data);

    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);

    // Old file should be gone (renamed).
    let old_wal = data.root.join(WAL_LEGACY_FILE);
    assert!(
        !old_wal.exists(),
        "old wal.jsonl should be renamed"
    );
    // Segment 0 should exist with original content.
    let seg0 = data.root.join(WAL_SEGMENT_DIR).join(FIRST_SEGMENT);
    assert!(
        seg0.exists(),
        "segment 0 should be created"
    );
    let content = fs::read_to_string(&seg0).unwrap();
    assert!(content.contains("\"height\":1"));
}

#[test]
fn schema_migration_future_version_returns_error() {
    let (_tmp, data) = make_dir();
    write_schema_version(&data, CURRENT_SCHEMA_VERSION + 1);
    let result = data.ensure_schema_and_migrate();
    assert!(
        result.is_err(),
        "should error when on‑disk version is newer than binary"
    );
    let msg = result.unwrap_err().to_string();
    assert!(
        msg.contains("newer than this binary"),
        "error message should explain the issue: {msg}"
    );
}

#[test]
fn schema_migration_log_is_populated() {
    let (_tmp, data) = make_dir();
    // Start from v0 so we exercise all migration steps.
    data.ensure_schema_and_migrate().unwrap();

    let path = data.root.join(SCHEMA_FILE);
    let raw = fs::read_to_string(&path).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let log = meta["migration_log"].as_array().unwrap();
    assert!(
        !log.is_empty(),
        "migration log should be populated after migrations"
    );
    assert!(meta["migrated_at"].is_string());
}

#[test]
fn schema_migration_idempotent_second_run() {
    let (_tmp, data) = make_dir();
    data.ensure_schema_and_migrate().unwrap();
    // Running a second time must succeed without error.
    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);
}
