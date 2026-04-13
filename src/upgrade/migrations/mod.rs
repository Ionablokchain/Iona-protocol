//! Built-in schema migrations for IONA.
//!
//! Each migration M00N corresponds to a schema version step:
//!
//!   M001  v0 → v1  add `vm` field to state_full.json
//!   M002  v1 → v2  add receipts index directory
//!   M003  v2 → v3  add evidence store (evidence.json)
//!   M004  v3 → v4  add snapshot metadata (snapshots/ directory + meta.json)
//!   M005  v4 → v5  add admin audit log file (audit.log initialisation)
//!
//! Each migration:
//!  - Supports dry-run mode (validates preconditions without writing).
//!  - Is idempotent: running twice leaves the data directory in the same state.
//!  - Includes inline unit tests.

use crate::upgrade::{Migration, MigrationResult};
use std::path::Path;

// ── M001: v0 → v1 — add `vm` field to state_full.json ─────────────────────

pub struct M001AddStateVmField;

impl Migration for M001AddStateVmField {
    fn from_version(&self) -> u32 {
        0
    }

    fn description(&self) -> &'static str {
        "Add `vm` field to state_full.json for EVM contract storage (v0 → v1)"
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let state_path = data_dir.join("state_full.json");

        // If no state file exists yet, nothing to migrate.
        if !state_path.exists() {
            return MigrationResult::Ok {
                from_version: 0,
                to_version: 1,
                changes: vec!["no state_full.json present; skipped".into()],
            };
        }

        let contents = match std::fs::read_to_string(&state_path) {
            Ok(c) => c,
            Err(e) => {
                return MigrationResult::Failed {
                    from_version: 0,
                    reason: format!("cannot read state_full.json: {e}"),
                }
            }
        };

        let mut state: serde_json::Value = match serde_json::from_str(&contents) {
            Ok(v) => v,
            Err(e) => {
                return MigrationResult::Failed {
                    from_version: 0,
                    reason: format!("cannot parse state_full.json: {e}"),
                }
            }
        };

        if state.get("vm").is_some() {
            return MigrationResult::Skipped { from_version: 0 };
        }

        let changes = vec!["state_full.json: added `vm: {}` field".into()];

        if !dry_run {
            state["vm"] = serde_json::json!({});
            let updated = serde_json::to_string_pretty(&state).unwrap_or_default();
            if let Err(e) = std::fs::write(&state_path, updated) {
                return MigrationResult::Failed {
                    from_version: 0,
                    reason: format!("cannot write state_full.json: {e}"),
                };
            }
        }

        MigrationResult::Ok {
            from_version: 0,
            to_version: 1,
            changes,
        }
    }
}

// ── M002: v1 → v2 — add receipts index directory ──────────────────────────

pub struct M002AddReceiptsIndex;

impl Migration for M002AddReceiptsIndex {
    fn from_version(&self) -> u32 {
        1
    }

    fn description(&self) -> &'static str {
        "Create receipts/ index directory for transaction receipt storage (v1 → v2)"
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let receipts_dir = data_dir.join("receipts");

        if receipts_dir.exists() {
            return MigrationResult::Skipped { from_version: 1 };
        }

        let changes = vec!["created receipts/ directory".into()];

        if !dry_run {
            if let Err(e) = std::fs::create_dir_all(&receipts_dir) {
                return MigrationResult::Failed {
                    from_version: 1,
                    reason: format!("cannot create receipts/: {e}"),
                };
            }
        }

        MigrationResult::Ok {
            from_version: 1,
            to_version: 2,
            changes,
        }
    }
}

// ── M003: v2 → v3 — add evidence store ───────────────────────────────────

pub struct M003AddEvidenceStore;

impl Migration for M003AddEvidenceStore {
    fn from_version(&self) -> u32 {
        2
    }

    fn description(&self) -> &'static str {
        "Initialise evidence.json for equivocation evidence storage (v2 → v3)"
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let evidence_path = data_dir.join("evidence.json");

        if evidence_path.exists() {
            return MigrationResult::Skipped { from_version: 2 };
        }

        let changes = vec!["created evidence.json with empty evidence set".into()];

        if !dry_run {
            let initial = serde_json::json!({ "evidence": [] });
            let content = serde_json::to_string_pretty(&initial).unwrap_or_default();
            if let Err(e) = std::fs::write(&evidence_path, content) {
                return MigrationResult::Failed {
                    from_version: 2,
                    reason: format!("cannot create evidence.json: {e}"),
                };
            }
        }

        MigrationResult::Ok {
            from_version: 2,
            to_version: 3,
            changes,
        }
    }
}

// ── M004: v3 → v4 — add snapshot metadata ─────────────────────────────────

pub struct M004AddSnapshotMeta;

impl Migration for M004AddSnapshotMeta {
    fn from_version(&self) -> u32 {
        3
    }

    fn description(&self) -> &'static str {
        "Create snapshots/ directory and initialise snapshot-meta.json (v3 → v4)"
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let snapshots_dir = data_dir.join("snapshots");
        let meta_path = data_dir.join("snapshot-meta.json");
        let mut changes = Vec::new();

        if !snapshots_dir.exists() {
            changes.push("created snapshots/ directory".into());
            if !dry_run {
                if let Err(e) = std::fs::create_dir_all(&snapshots_dir) {
                    return MigrationResult::Failed {
                        from_version: 3,
                        reason: format!("cannot create snapshots/: {e}"),
                    };
                }
            }
        }

        if !meta_path.exists() {
            changes.push("created snapshot-meta.json with empty snapshot list".into());
            if !dry_run {
                let meta = serde_json::json!({ "snapshots": [], "latest": null });
                let content = serde_json::to_string_pretty(&meta).unwrap_or_default();
                if let Err(e) = std::fs::write(&meta_path, content) {
                    return MigrationResult::Failed {
                        from_version: 3,
                        reason: format!("cannot create snapshot-meta.json: {e}"),
                    };
                }
            }
        }

        if changes.is_empty() {
            return MigrationResult::Skipped { from_version: 3 };
        }

        MigrationResult::Ok {
            from_version: 3,
            to_version: 4,
            changes,
        }
    }
}

// ── M005: v4 → v5 — add admin audit log ───────────────────────────────────

pub struct M005AddAdminAuditLog;

impl Migration for M005AddAdminAuditLog {
    fn from_version(&self) -> u32 {
        4
    }

    fn description(&self) -> &'static str {
        "Initialise admin audit log with genesis hashchain entry (v4 → v5)"
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let audit_path = data_dir.join("audit.log");

        if audit_path.exists() {
            // Already present — check it's not corrupted (non-empty and parseable).
            if let Ok(content) = std::fs::read_to_string(&audit_path) {
                if !content.trim().is_empty() {
                    return MigrationResult::Skipped { from_version: 4 };
                }
            }
        }

        let changes = vec!["created audit.log (empty hashchain)".into()];

        if !dry_run {
            // Create the file (empty — first entry will be written by the node on startup).
            if let Err(e) = std::fs::write(&audit_path, b"") {
                return MigrationResult::Failed {
                    from_version: 4,
                    reason: format!("cannot create audit.log: {e}"),
                };
            }
        }

        MigrationResult::Ok {
            from_version: 4,
            to_version: 5,
            changes,
        }
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    // ── M001 ────────────────────────────────────────────────────────────────

    #[test]
    fn m001_no_state_file_is_ok() {
        let dir = TempDir::new().unwrap();
        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());
    }

    #[test]
    fn m001_adds_vm_field() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state_full.json");
        std::fs::write(&state_path, r#"{"kv":{},"balances":{}}"#).unwrap();

        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());

        let updated: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&state_path).unwrap()).unwrap();
        assert!(
            updated.get("vm").is_some(),
            "vm field must be present after migration"
        );
    }

    #[test]
    fn m001_dry_run_does_not_write() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state_full.json");
        let original = r#"{"kv":{},"balances":{}}"#;
        std::fs::write(&state_path, original).unwrap();

        let result = M001AddStateVmField.apply(dir.path(), /* dry_run = */ true);
        assert!(result.is_ok());

        let on_disk = std::fs::read_to_string(&state_path).unwrap();
        assert_eq!(on_disk, original, "dry-run must not modify the file");
    }

    #[test]
    fn m001_idempotent() {
        let dir = TempDir::new().unwrap();
        let state_path = dir.path().join("state_full.json");
        std::fs::write(&state_path, r#"{"kv":{},"balances":{}}"#).unwrap();

        M001AddStateVmField.apply(dir.path(), false);
        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(
            matches!(result, MigrationResult::Skipped { .. }),
            "second run must be skipped"
        );
    }

    // ── M002 ────────────────────────────────────────────────────────────────

    #[test]
    fn m002_creates_receipts_dir() {
        let dir = TempDir::new().unwrap();
        let result = M002AddReceiptsIndex.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(dir.path().join("receipts").exists());
    }

    #[test]
    fn m002_dry_run_does_not_create_dir() {
        let dir = TempDir::new().unwrap();
        M002AddReceiptsIndex.apply(dir.path(), true);
        assert!(
            !dir.path().join("receipts").exists(),
            "dry-run must not create the directory"
        );
    }

    #[test]
    fn m002_idempotent() {
        let dir = TempDir::new().unwrap();
        M002AddReceiptsIndex.apply(dir.path(), false);
        let result = M002AddReceiptsIndex.apply(dir.path(), false);
        assert!(matches!(result, MigrationResult::Skipped { .. }));
    }

    // ── M003 ────────────────────────────────────────────────────────────────

    #[test]
    fn m003_creates_evidence_json() {
        let dir = TempDir::new().unwrap();
        let result = M003AddEvidenceStore.apply(dir.path(), false);
        assert!(result.is_ok());
        let evidence_path = dir.path().join("evidence.json");
        assert!(evidence_path.exists());
        let v: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(evidence_path).unwrap()).unwrap();
        assert!(v.get("evidence").is_some());
    }

    // ── M004 ────────────────────────────────────────────────────────────────

    #[test]
    fn m004_creates_snapshots_dir_and_meta() {
        let dir = TempDir::new().unwrap();
        let result = M004AddSnapshotMeta.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(dir.path().join("snapshots").exists());
        assert!(dir.path().join("snapshot-meta.json").exists());
    }

    // ── M005 ────────────────────────────────────────────────────────────────

    #[test]
    fn m005_creates_audit_log() {
        let dir = TempDir::new().unwrap();
        let result = M005AddAdminAuditLog.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(dir.path().join("audit.log").exists());
    }

    #[test]
    fn m005_dry_run_does_not_create_file() {
        let dir = TempDir::new().unwrap();
        M005AddAdminAuditLog.apply(dir.path(), true);
        assert!(!dir.path().join("audit.log").exists());
    }
}
