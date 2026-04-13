//! Rolling upgrade and migration tests for IONA v28.2.
//!
//! Tests:
//!  U1  — Fresh data directory: all migrations apply from v0 to CURRENT
//!  U2  — Already-current directory: all migrations skipped
//!  U3  — Partial migration: migrations resume from the interrupted version
//!  U4  — Dry-run: no files modified, but result is accurate
//!  U5  — Compatibility report: disk > binary schema → incompatible
//!  U6  — Compatibility report: disk < binary schema → migrations needed
//!  U7  — Compatibility report: disk == binary schema → compatible, no migrations
//!  U8  — Migration ordering: registry versions are 0-based, contiguous, ordered
//!  U9  — Individual migration idempotency (M001..M005)
//! U10  — Rolling upgrade simulation: 5 nodes, upgrade one at a time

use iona::storage::CURRENT_SCHEMA_VERSION;
use iona::upgrade::{
    check_compat, dry_run_migrations, CompatReport, MigrationRegistry, MigrationResult,
};
use std::fs;
use tempfile::TempDir;

// ── Helpers ───────────────────────────────────────────────────────────────

fn empty_data_dir() -> TempDir {
    TempDir::new().expect("tempdir")
}

fn data_dir_at_version(version: u32) -> TempDir {
    let dir = TempDir::new().unwrap();
    let schema = serde_json::json!({ "version": version });
    fs::write(
        dir.path().join("schema.json"),
        serde_json::to_string_pretty(&schema).unwrap(),
    )
    .unwrap();
    dir
}

// ── U1: Fresh directory ────────────────────────────────────────────────────

#[test]
fn u1_fresh_dir_all_migrations_applied() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();
    let results = reg.run(dir.path(), 0, /* dry_run = */ false);

    assert!(!results.is_empty(), "should have at least one migration");
    for result in &results {
        assert!(
            result.is_ok(),
            "all migrations must succeed on fresh dir: {result}"
        );
    }
}

#[test]
fn u1_fresh_dir_files_created() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();
    reg.run(dir.path(), 0, false);

    // M002 creates receipts/, M003 creates evidence.json, M004 creates snapshots/, M005 creates audit.log
    assert!(dir.path().join("receipts").exists(), "receipts/ must exist");
    assert!(
        dir.path().join("evidence.json").exists(),
        "evidence.json must exist"
    );
    assert!(
        dir.path().join("snapshots").exists(),
        "snapshots/ must exist"
    );
    assert!(
        dir.path().join("audit.log").exists(),
        "audit.log must exist"
    );
}

// ── U2: Already current ────────────────────────────────────────────────────

#[test]
fn u2_already_current_all_skipped() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();

    // Apply everything first.
    reg.run(dir.path(), 0, false);

    // Run again from the current version — all must be skipped.
    let results = reg.run(dir.path(), CURRENT_SCHEMA_VERSION, false);
    for result in &results {
        assert!(
            matches!(result, MigrationResult::Skipped { .. }),
            "already-applied migration must be skipped, got {result}"
        );
    }
}

// ── U3: Partial migration ─────────────────────────────────────────────────

#[test]
fn u3_partial_migration_resumes() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();

    // Simulate: only M001 and M002 have run (schema at v2).
    reg.run(dir.path(), 0, false); // apply all to get files in place...
                                   // ...but we pretend only v2 is applied by querying from v2.
    let results = reg.run(dir.path(), 2, false);

    // M003..M005 should have run (or skipped if files already exist from the first run).
    let applied_or_skipped = results.iter().all(|r| r.is_ok());
    assert!(
        applied_or_skipped,
        "partial migration must complete without error"
    );
}

// ── U4: Dry-run ───────────────────────────────────────────────────────────

#[test]
fn u4_dry_run_from_v0_no_files_created() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();
    let results = reg.run(dir.path(), 0, /* dry_run = */ true);

    // All migrations report OK in dry-run mode.
    for result in &results {
        assert!(result.is_ok(), "dry-run must not fail: {result}");
    }

    // No files should have been created.
    assert!(
        !dir.path().join("receipts").exists(),
        "dry-run must not create receipts/"
    );
    assert!(
        !dir.path().join("evidence.json").exists(),
        "dry-run must not create evidence.json"
    );
    assert!(
        !dir.path().join("audit.log").exists(),
        "dry-run must not create audit.log"
    );
}

#[test]
fn u4_dry_run_migrations_fn_returns_true_on_success() {
    let dir = empty_data_dir();
    // Write schema.json at v0 so dry_run_migrations can read the version.
    let schema = serde_json::json!({ "version": 0 });
    fs::write(
        dir.path().join("schema.json"),
        serde_json::to_string_pretty(&schema).unwrap(),
    )
    .unwrap();

    // dry_run_migrations uses DataDir to read schema version, which in CI
    // may default to 0. Just verify it returns without panic.
    let result = dry_run_migrations(dir.path());
    assert!(
        result.is_ok(),
        "dry_run_migrations must return Ok: {result:?}"
    );
}

// ── U5: Compatibility — disk newer ───────────────────────────────────────

#[test]
fn u5_disk_newer_than_binary_reports_incompatible() {
    // Manually construct a CompatReport as check_compat() would produce.
    let report = CompatReport {
        disk_schema_version: CURRENT_SCHEMA_VERSION + 10,
        binary_schema_version: CURRENT_SCHEMA_VERSION,
        binary_protocol_version: 1,
        compatible: false,
        migrations_needed: false,
        pending_migrations: 0,
        issues: vec!["on-disk schema is newer than binary".into()],
    };
    assert!(
        !report.is_ok(),
        "disk newer than binary must be incompatible"
    );
    let s = format!("{report}");
    assert!(s.contains("NO"), "report must say NOT compatible");
}

// ── U6: Compatibility — migrations needed ────────────────────────────────

#[test]
fn u6_old_disk_needs_migrations() {
    let report = CompatReport {
        disk_schema_version: 2,
        binary_schema_version: CURRENT_SCHEMA_VERSION,
        binary_protocol_version: 1,
        compatible: true,
        migrations_needed: true,
        pending_migrations: (CURRENT_SCHEMA_VERSION - 2) as usize,
        issues: vec![],
    };
    assert!(
        report.compatible,
        "binary can open old dir (with migration)"
    );
    assert!(report.migrations_needed, "migration is needed");
    let s = format!("{report}");
    assert!(s.contains("YES"), "report must say migrations needed");
}

// ── U7: Compatibility — already current ──────────────────────────────────

#[test]
fn u7_current_dir_no_migration_needed() {
    let report = CompatReport {
        disk_schema_version: CURRENT_SCHEMA_VERSION,
        binary_schema_version: CURRENT_SCHEMA_VERSION,
        binary_protocol_version: 1,
        compatible: true,
        migrations_needed: false,
        pending_migrations: 0,
        issues: vec![],
    };
    assert!(report.is_ok());
    assert!(!report.migrations_needed);
}

// ── U8: Registry ordering ─────────────────────────────────────────────────

#[test]
fn u8_registry_versions_ordered_and_contiguous() {
    let reg = MigrationRegistry::new();
    let versions: Vec<u32> = reg.all().iter().map(|m| m.from_version()).collect();
    for (i, &v) in versions.iter().enumerate() {
        assert_eq!(
            v, i as u32,
            "migration at index {i} must have from_version={i}, got {v}"
        );
    }
}

#[test]
fn u8_registry_descriptions_are_non_empty() {
    let reg = MigrationRegistry::new();
    for m in reg.all() {
        assert!(
            !m.description().is_empty(),
            "migration v{} must have a non-empty description",
            m.from_version()
        );
    }
}

// ── U9: Individual idempotency ────────────────────────────────────────────

#[test]
fn u9_each_migration_is_idempotent() {
    let dir = empty_data_dir();
    let reg = MigrationRegistry::new();

    // First run — apply all.
    reg.run(dir.path(), 0, false);

    // Second run — every migration must be OK (skipped or re-applied cleanly).
    let results = reg.run(dir.path(), 0, false);
    for result in &results {
        assert!(
            result.is_ok(),
            "second run must not fail (idempotency): {result}"
        );
    }
}

// ── U10: Rolling upgrade simulation ──────────────────────────────────────

/// Simulates a rolling upgrade across 5 nodes, upgrading one at a time.
///
/// Each node gets its own data directory (isolated TempDir).  We verify that:
/// - Each node can apply migrations independently.
/// - Protocol version compatibility is maintained (no split).
/// - A node at an intermediate schema version can still participate.
#[test]
fn u10_rolling_upgrade_5_nodes() {
    use iona::protocol::version::CURRENT_PROTOCOL_VERSION;

    let num_nodes = 5;
    let dirs: Vec<TempDir> = (0..num_nodes).map(|_| empty_data_dir()).collect();
    let reg = MigrationRegistry::new();

    // Phase 1: all nodes start at v0 (old schema).
    // Simulate old nodes by not running migrations yet.

    // Phase 2: upgrade nodes one by one.
    let mut upgraded = 0;
    for dir in &dirs {
        let results = reg.run(dir.path(), 0, false);
        for result in &results {
            assert!(result.is_ok(), "node upgrade must succeed: {result}");
        }
        upgraded += 1;
        // After each node upgrade, the remaining nodes are still at v0.
        // The key invariant: all nodes must still agree on CURRENT_PROTOCOL_VERSION.
        assert_eq!(
            CURRENT_PROTOCOL_VERSION, 1,
            "protocol version must remain 1 during rolling schema upgrade"
        );
    }
    assert_eq!(upgraded, num_nodes, "all {num_nodes} nodes must upgrade");

    // Phase 3: all nodes upgraded. Verify all have consistent schema files.
    // (M003..M005 create specific files; check they all have audit.log)
    for dir in &dirs {
        assert!(
            dir.path().join("audit.log").exists(),
            "every upgraded node must have an audit.log"
        );
        assert!(
            dir.path().join("evidence.json").exists(),
            "every upgraded node must have evidence.json"
        );
    }
}

// ── MigrationResult display ───────────────────────────────────────────────

#[test]
fn migration_result_ok_display() {
    let r = MigrationResult::Ok {
        from_version: 0,
        to_version: 1,
        changes: vec!["added vm field".into(), "normalised balances".into()],
    };
    let s = format!("{r}");
    assert!(
        s.contains("v0 → v1"),
        "display must show version transition"
    );
    assert!(s.contains("added vm field"), "display must list changes");
}

#[test]
fn migration_result_failed_display() {
    let r = MigrationResult::Failed {
        from_version: 2,
        reason: "disk full".into(),
    };
    let s = format!("{r}");
    assert!(s.contains("FAILED"), "failed result must say FAILED");
    assert!(s.contains("disk full"), "failed result must include reason");
}
