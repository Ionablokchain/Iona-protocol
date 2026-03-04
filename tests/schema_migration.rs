//! Integration tests for schema versioning and migrations.
//!
//! Each test simulates a node data directory at an older schema version and
//! verifies that `ensure_schema_and_migrate()` upgrades it correctly.

use iona::storage::{DataDir, CURRENT_SCHEMA_VERSION};
use std::fs;
use tempfile::TempDir;

fn make_dir() -> (TempDir, DataDir) {
    let tmp = TempDir::new().unwrap();
    let data = DataDir::new(tmp.path().to_str().unwrap());
    (tmp, data)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn write_schema_version(data: &DataDir, version: u32) {
    data.ensure().unwrap();
    let meta = serde_json::json!({ "version": version });
    let path = format!("{}/schema.json", data.root);
    fs::write(path, serde_json::to_string_pretty(&meta).unwrap()).unwrap();
}

fn read_schema_version(data: &DataDir) -> u32 {
    data.read_schema_version().unwrap()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[test]
fn schema_migration_fresh_dir_creates_schema() {
    let (_tmp, data) = make_dir();
    // No schema.json yet — treated as v0.
    assert_eq!(read_schema_version(&data), 0);
    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);
}

#[test]
fn schema_migration_already_current_is_noop() {
    let (_tmp, data) = make_dir();
    write_schema_version(&data, CURRENT_SCHEMA_VERSION);
    // Should succeed immediately without touching anything.
    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);
}

#[test]
fn schema_migration_v1_to_current_normalises_state_full() {
    let (_tmp, data) = make_dir();
    data.ensure().unwrap();
    write_schema_version(&data, 1);

    // Write a v1-era state_full.json that lacks the `vm` field.
    let old_state = serde_json::json!({
        "kv": { "hello": "world" },
        "balances": { "abcd": 1000 },
        "nonces": {}
    });
    fs::write(
        format!("{}/state_full.json", data.root),
        serde_json::to_string_pretty(&old_state).unwrap(),
    )
    .unwrap();

    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);

    // state_full.json should now have a `vm` field.
    let raw = fs::read_to_string(format!("{}/state_full.json", data.root)).unwrap();
    let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
    assert!(val.get("vm").is_some(), "vm field should be injected by migration");
    // Original data must be preserved.
    assert_eq!(val["kv"]["hello"], "world");

    // Backup must exist.
    assert!(
        std::path::Path::new(&format!("{}/state_full.json.v1.bak", data.root)).exists(),
        "backup file should be created"
    );
}

#[test]
fn schema_migration_v2_migrates_flat_wal_to_segments() {
    let (_tmp, data) = make_dir();
    data.ensure().unwrap();
    write_schema_version(&data, 2);

    // Write a flat wal.jsonl (pre-segmented format).
    let old_wal = format!("{}/wal.jsonl", data.root);
    fs::write(&old_wal, b"{\"height\":1}\n{\"height\":2}\n").unwrap();

    data.ensure_schema_and_migrate().unwrap();
    assert_eq!(read_schema_version(&data), CURRENT_SCHEMA_VERSION);

    // Old file should be gone (renamed).
    assert!(
        !std::path::Path::new(&old_wal).exists(),
        "old wal.jsonl should be renamed"
    );
    // Segment 0 should exist with original content.
    let seg0 = format!("{}/wal/wal_00000000.jsonl", data.root);
    assert!(
        std::path::Path::new(&seg0).exists(),
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
        "should error when on-disk version is newer than binary"
    );
    let msg = result.unwrap_err().to_string();
    assert!(msg.contains("newer than this binary"), "error message should explain the issue: {msg}");
}

#[test]
fn schema_migration_log_is_populated() {
    let (_tmp, data) = make_dir();
    // Start from v0 so we exercise all migration steps.
    data.ensure_schema_and_migrate().unwrap();

    let raw = fs::read_to_string(format!("{}/schema.json", data.root)).unwrap();
    let meta: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let log = meta["migration_log"].as_array().unwrap();
    assert!(
        !log.is_empty(),
        "migration log should be populated after migrations"
    );
    // migrated_at should be set.
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
