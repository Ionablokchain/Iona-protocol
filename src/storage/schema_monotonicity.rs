//! SchemaVersion monotonicity enforcement.
//!
//! Ensures that the on-disk schema version only ever increases, preventing
//! accidental downgrades that could corrupt data or lose migrations.
//!
//! # Rules
//!
//! | ID   | Name                      | Description                                    |
//! |------|---------------------------|------------------------------------------------|
//! | SM-1 | Strictly increasing       | SV(new) > SV(old) for any migration step       |
//! | SM-2 | No gaps                   | Migrations must be contiguous (no skipped SVs) |
//! | SM-3 | Binary >= disk            | Binary SV must be >= on-disk SV                |
//! | SM-4 | Checkpoint after step     | SV persisted after each migration step          |
//! | SM-5 | Idempotent re-run         | Running migration at current SV is a no-op      |

use crate::storage::{CURRENT_SCHEMA_VERSION, SchemaMeta};
use std::io;
use std::path::Path;

// ─── SM-1: Strictly increasing ──────────────────────────────────────────────

/// Verify that a proposed schema version bump is strictly increasing.
pub fn check_strictly_increasing(old_sv: u32, new_sv: u32) -> Result<(), String> {
    if new_sv <= old_sv {
        return Err(format!(
            "SM-1 VIOLATION: schema version not strictly increasing: \
             old={old_sv}, new={new_sv}"
        ));
    }
    Ok(())
}

// ─── SM-2: No gaps ──────────────────────────────────────────────────────────

/// Verify that the migration registry has no gaps between `from_sv` and `to_sv`.
pub fn check_no_gaps(from_sv: u32, to_sv: u32) -> Result<(), String> {
    let migrations = &crate::storage::migrations::MIGRATIONS;

    // Legacy migrations cover v0..v3 (handled by DataDir::run_migration).
    // New registry covers v3+.
    let legacy_max = 3u32; // v0->v1, v1->v2, v2->v3

    for sv in from_sv..to_sv {
        if sv < legacy_max {
            // Covered by legacy code path.
            continue;
        }
        let has_migration = migrations.iter().any(|&(from_v, _, _)| from_v == sv);
        if !has_migration {
            return Err(format!(
                "SM-2 VIOLATION: no migration found for SV {sv} -> {}",
                sv + 1
            ));
        }
    }
    Ok(())
}

// ─── SM-3: Binary >= disk ───────────────────────────────────────────────────

/// Verify that this binary supports the on-disk schema version.
pub fn check_binary_compat(disk_sv: u32) -> Result<(), String> {
    if disk_sv > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "SM-3 VIOLATION: on-disk SV={disk_sv} is newer than binary SV={CURRENT_SCHEMA_VERSION}; \
             upgrade the node binary"
        ));
    }
    Ok(())
}

// ─── SM-4: Checkpoint after step ────────────────────────────────────────────

/// Verify that a schema checkpoint file exists and contains the expected version.
pub fn check_checkpoint(data_dir: &str, expected_sv: u32) -> Result<(), String> {
    let path = format!("{data_dir}/schema.json");
    if !Path::new(&path).exists() {
        return Err(format!(
            "SM-4 VIOLATION: schema.json does not exist at {path}"
        ));
    }

    let content = std::fs::read_to_string(&path)
        .map_err(|e| format!("SM-4 ERROR: cannot read {path}: {e}"))?;
    let meta: SchemaMeta = serde_json::from_str(&content)
        .map_err(|e| format!("SM-4 ERROR: cannot parse {path}: {e}"))?;

    if meta.version != expected_sv {
        return Err(format!(
            "SM-4 VIOLATION: schema.json version={}, expected={expected_sv}",
            meta.version
        ));
    }
    Ok(())
}

// ─── SM-5: Idempotent re-run ────────────────────────────────────────────────

/// Verify that running a migration at the current version is a no-op.
pub fn check_idempotent(current_sv: u32, target_sv: u32) -> Result<bool, String> {
    if current_sv == target_sv {
        return Ok(true); // No migration needed; this is a no-op.
    }
    if current_sv > target_sv {
        return Err(format!(
            "SM-5 VIOLATION: cannot downgrade from SV={current_sv} to SV={target_sv}"
        ));
    }
    Ok(false) // Migration needed.
}

// ─── Aggregate check ────────────────────────────────────────────────────────

/// Result of schema monotonicity checks.
#[derive(Debug, Clone)]
pub struct MonotonicityReport {
    pub checks: Vec<MonotonicityCheck>,
    pub all_passed: bool,
}

#[derive(Debug, Clone)]
pub struct MonotonicityCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

impl std::fmt::Display for MonotonicityReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Schema Monotonicity: {}",
            if self.all_passed { "ALL PASSED" } else { "VIOLATIONS DETECTED" })?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {} — {}", c.id, c.name, c.detail)?;
        }
        Ok(())
    }
}

/// Run all monotonicity checks for a proposed migration.
pub fn check_monotonicity(
    current_sv: u32,
    target_sv: u32,
    data_dir: Option<&str>,
) -> MonotonicityReport {
    let mut checks = Vec::new();

    // SM-1: Strictly increasing (only if target != current).
    if target_sv != current_sv {
        let r = check_strictly_increasing(current_sv, target_sv);
        checks.push(MonotonicityCheck {
            id: "SM-1".into(),
            name: "Strictly increasing".into(),
            passed: r.is_ok(),
            detail: r.err().unwrap_or_else(|| {
                format!("SV {current_sv} -> {target_sv}: OK")
            }),
        });
    }

    // SM-2: No gaps.
    let r = check_no_gaps(current_sv, target_sv);
    checks.push(MonotonicityCheck {
        id: "SM-2".into(),
        name: "No gaps".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| {
            format!("migration path {current_sv}..{target_sv} contiguous")
        }),
    });

    // SM-3: Binary >= disk.
    let r = check_binary_compat(current_sv);
    checks.push(MonotonicityCheck {
        id: "SM-3".into(),
        name: "Binary >= disk".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| {
            format!("binary SV={CURRENT_SCHEMA_VERSION} >= disk SV={current_sv}")
        }),
    });

    // SM-4: Checkpoint (if data_dir provided).
    if let Some(dir) = data_dir {
        let r = check_checkpoint(dir, current_sv);
        checks.push(MonotonicityCheck {
            id: "SM-4".into(),
            name: "Checkpoint exists".into(),
            passed: r.is_ok(),
            detail: r.err().unwrap_or_else(|| {
                format!("schema.json at SV={current_sv}")
            }),
        });
    }

    // SM-5: Idempotent.
    let r = check_idempotent(current_sv, target_sv);
    checks.push(MonotonicityCheck {
        id: "SM-5".into(),
        name: "Idempotent re-run".into(),
        passed: r.is_ok(),
        detail: match r {
            Ok(true) => "already at target SV (no-op)".into(),
            Ok(false) => format!("migration needed: SV {current_sv} -> {target_sv}"),
            Err(e) => e,
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);
    MonotonicityReport { checks, all_passed }
}

/// Validate a migration step atomically: checks SM-1 through SM-3.
pub fn validate_migration_step(from_sv: u32, to_sv: u32) -> io::Result<()> {
    check_strictly_increasing(from_sv, to_sv)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if to_sv != from_sv + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SM-2: migration step must be +1: {from_sv} -> {to_sv}"),
        ));
    }

    check_binary_compat(from_sv)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(())
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strictly_increasing_ok() {
        assert!(check_strictly_increasing(1, 2).is_ok());
        assert!(check_strictly_increasing(4, 5).is_ok());
    }

    #[test]
    fn test_strictly_increasing_violation() {
        assert!(check_strictly_increasing(2, 2).is_err());
        assert!(check_strictly_increasing(3, 1).is_err());
    }

    #[test]
    fn test_no_gaps_ok() {
        // From current SV (5) to 5: no gaps needed.
        assert!(check_no_gaps(CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION).is_ok());
        // From 3 to 5: needs 3->4 and 4->5, both exist in MIGRATIONS.
        assert!(check_no_gaps(3, 5).is_ok());
    }

    #[test]
    fn test_no_gaps_violation() {
        // From 4 to 10: would need 5->6, 6->7, etc. which don't exist.
        assert!(check_no_gaps(4, 10).is_err());
    }

    #[test]
    fn test_binary_compat_ok() {
        assert!(check_binary_compat(CURRENT_SCHEMA_VERSION).is_ok());
        assert!(check_binary_compat(1).is_ok());
    }

    #[test]
    fn test_binary_compat_violation() {
        assert!(check_binary_compat(CURRENT_SCHEMA_VERSION + 1).is_err());
        assert!(check_binary_compat(999).is_err());
    }

    #[test]
    fn test_checkpoint_missing() {
        let r = check_checkpoint("/tmp/nonexistent_iona_test_dir", 5);
        assert!(r.is_err());
    }

    #[test]
    fn test_checkpoint_with_temp_dir() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schema.json");
        let meta = SchemaMeta {
            version: 5,
            migrated_at: None,
            migration_log: vec![],
        };
        std::fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(check_checkpoint(dir.path().to_str().unwrap(), 5).is_ok());
    }

    #[test]
    fn test_checkpoint_wrong_version() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("schema.json");
        let meta = SchemaMeta {
            version: 3,
            migrated_at: None,
            migration_log: vec![],
        };
        std::fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(check_checkpoint(dir.path().to_str().unwrap(), 5).is_err());
    }

    #[test]
    fn test_idempotent_noop() {
        assert_eq!(check_idempotent(5, 5).unwrap(), true);
    }

    #[test]
    fn test_idempotent_needs_migration() {
        assert_eq!(check_idempotent(4, 5).unwrap(), false);
    }

    #[test]
    fn test_idempotent_downgrade_rejected() {
        assert!(check_idempotent(5, 3).is_err());
    }

    #[test]
    fn test_monotonicity_report_all_pass() {
        let report = check_monotonicity(
            CURRENT_SCHEMA_VERSION,
            CURRENT_SCHEMA_VERSION,
            None,
        );
        assert!(report.all_passed, "report: {report}");
    }

    #[test]
    fn test_monotonicity_report_display() {
        let report = check_monotonicity(4, 5, None);
        let s = format!("{report}");
        assert!(s.contains("Schema Monotonicity"));
    }

    #[test]
    fn test_validate_migration_step_ok() {
        assert!(validate_migration_step(4, 5).is_ok());
    }

    #[test]
    fn test_validate_migration_step_skip() {
        // Cannot skip from 3 to 5 in one step.
        assert!(validate_migration_step(3, 5).is_err());
    }
}
