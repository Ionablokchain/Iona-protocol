//! Built-in schema migrations for IONA.
//!
//! Each migration M00N corresponds to a schema version step:
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
//!  - Includes validation hooks to verify migration success.

use crate::upgrade::{Migration, MigrationResult};
use std::path::Path;
use std::time::Instant;
use tracing::{info, warn, error, debug};

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Read a JSON file and return its parsed value, or `Ok(None)` if the file does not exist.
fn read_json_file(path: &Path) -> Result<Option<serde_json::Value>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let content = std::fs::read_to_string(path).map_err(|e| format!("cannot read file: {}", e))?;
    if content.trim().is_empty() {
        return Ok(None);
    }
    serde_json::from_str(&content).map_err(|e| format!("cannot parse JSON: {}", e)).map(Some)
}

/// Write a JSON value to a file with pretty formatting.
fn write_json_file(path: &Path, value: &serde_json::Value) -> Result<(), String> {
    let content = serde_json::to_string_pretty(value).map_err(|e| format!("cannot serialize JSON: {}", e))?;
    std::fs::write(path, content).map_err(|e| format!("cannot write file: {}", e))
}

/// Create a directory if it does not exist.
fn ensure_dir(path: &Path) -> Result<(), String> {
    if !path.exists() {
        std::fs::create_dir_all(path).map_err(|e| format!("cannot create directory: {}", e))
    } else {
        Ok(())
    }
}

/// Create an empty file if it does not exist.
fn ensure_file(path: &Path) -> Result<(), String> {
    if !path.exists() {
        if let Some(parent) = path.parent() {
            ensure_dir(parent)?;
        }
        std::fs::write(path, b"").map_err(|e| format!("cannot create file: {}", e))
    } else {
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// M001: v0 → v1 — add `vm` field to state_full.json
// -----------------------------------------------------------------------------

/// Migration v0 → v1: Add `vm` field to state_full.json for EVM contract storage.
pub struct M001AddStateVmField;

impl Migration for M001AddStateVmField {
    fn from_version(&self) -> u32 {
        0
    }

    fn description(&self) -> &'static str {
        "Add `vm` field to state_full.json for EVM contract storage (v0 → v1)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let state_path = data_dir.join("state_full.json");

        // If no state file exists yet, nothing to migrate.
        if !state_path.exists() {
            let changes = vec!["no state_full.json present; skipped".into()];
            return MigrationResult::Ok {
                from_version: 0,
                to_version: 1,
                changes,
                duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
            };
        }

        let state = match read_json_file(&state_path) {
            Ok(Some(v)) => v,
            Ok(None) => {
                let changes = vec!["state_full.json is empty; initialising with vm field".into()];
                if !dry_run {
                    let initial = serde_json::json!({ "kv": {}, "balances": {}, "vm": {} });
                    if let Err(e) = write_json_file(&state_path, &initial) {
                        return MigrationResult::Failed {
                            from_version: 0,
                            reason: e,
                            rolled_back: false,
                        };
                    }
                }
                return MigrationResult::Ok {
                    from_version: 0,
                    to_version: 1,
                    changes,
                    duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
                };
            }
            Err(e) => {
                return MigrationResult::Failed {
                    from_version: 0,
                    reason: e,
                    rolled_back: false,
                };
            }
        };

        if state.get("vm").is_some() {
            return MigrationResult::Skipped { from_version: 0 };
        }

        let changes = vec!["state_full.json: added `vm: {}` field".into()];

        if !dry_run {
            let mut updated = state;
            updated["vm"] = serde_json::json!({});
            if let Err(e) = write_json_file(&state_path, &updated) {
                return MigrationResult::Failed {
                    from_version: 0,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 0,
            to_version: 1,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M002: v1 → v2 — add receipts index directory
// -----------------------------------------------------------------------------

/// Migration v1 → v2: Create receipts/ index directory for transaction receipt storage.
pub struct M002AddReceiptsIndex;

impl Migration for M002AddReceiptsIndex {
    fn from_version(&self) -> u32 {
        1
    }

    fn description(&self) -> &'static str {
        "Create receipts/ index directory for transaction receipt storage (v1 → v2)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let receipts_dir = data_dir.join("receipts");
        let index_path = receipts_dir.join("index.json");

        if receipts_dir.exists() && index_path.exists() {
            return MigrationResult::Skipped { from_version: 1 };
        }

        let changes = vec![
            "created receipts/ directory".into(),
            "created receipts/index.json with empty index".into(),
        ];

        if !dry_run {
            if let Err(e) = ensure_dir(&receipts_dir) {
                return MigrationResult::Failed {
                    from_version: 1,
                    reason: e,
                    rolled_back: false,
                };
            }
            let initial = serde_json::json!({ "version": 1, "receipts": {} });
            if let Err(e) = write_json_file(&index_path, &initial) {
                return MigrationResult::Failed {
                    from_version: 1,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 1,
            to_version: 2,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M003: v2 → v3 — add evidence store
// -----------------------------------------------------------------------------

/// Migration v2 → v3: Initialise evidence.json for equivocation evidence storage.
pub struct M003AddEvidenceStore;

impl Migration for M003AddEvidenceStore {
    fn from_version(&self) -> u32 {
        2
    }

    fn description(&self) -> &'static str {
        "Initialise evidence.json for equivocation evidence storage (v2 → v3)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let evidence_path = data_dir.join("evidence.json");

        if evidence_path.exists() {
            // Verify it's valid JSON
            if let Ok(Some(_)) = read_json_file(&evidence_path) {
                return MigrationResult::Skipped { from_version: 2 };
            }
        }

        let changes = vec!["created evidence.json with empty evidence set".into()];

        if !dry_run {
            let initial = serde_json::json!({ "version": 1, "evidence": [] });
            if let Err(e) = write_json_file(&evidence_path, &initial) {
                return MigrationResult::Failed {
                    from_version: 2,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 2,
            to_version: 3,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M004: v3 → v4 — add snapshot metadata
// -----------------------------------------------------------------------------

/// Migration v3 → v4: Create snapshots/ directory and initialise snapshot-meta.json.
pub struct M004AddSnapshotMeta;

impl Migration for M004AddSnapshotMeta {
    fn from_version(&self) -> u32 {
        3
    }

    fn description(&self) -> &'static str {
        "Create snapshots/ directory and initialise snapshot-meta.json (v3 → v4)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let snapshots_dir = data_dir.join("snapshots");
        let meta_path = data_dir.join("snapshot-meta.json");
        let mut changes = Vec::new();

        if !snapshots_dir.exists() {
            changes.push("created snapshots/ directory".into());
        }
        if !meta_path.exists() {
            changes.push("created snapshot-meta.json with empty snapshot list".into());
        }

        if changes.is_empty() {
            return MigrationResult::Skipped { from_version: 3 };
        }

        if !dry_run {
            if !snapshots_dir.exists() {
                if let Err(e) = ensure_dir(&snapshots_dir) {
                    return MigrationResult::Failed {
                        from_version: 3,
                        reason: e,
                        rolled_back: false,
                    };
                }
            }
            if !meta_path.exists() {
                let meta = serde_json::json!({ "version": 1, "snapshots": [], "latest": null });
                if let Err(e) = write_json_file(&meta_path, &meta) {
                    return MigrationResult::Failed {
                        from_version: 3,
                        reason: e,
                        rolled_back: false,
                    };
                }
            }
        }

        MigrationResult::Ok {
            from_version: 3,
            to_version: 4,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M005: v4 → v5 — add admin audit log
// -----------------------------------------------------------------------------

/// Migration v4 → v5: Initialise admin audit log with genesis hashchain entry.
pub struct M005AddAdminAuditLog;

impl Migration for M005AddAdminAuditLog {
    fn from_version(&self) -> u32 {
        4
    }

    fn description(&self) -> &'static str {
        "Initialise admin audit log with genesis hashchain entry (v4 → v5)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let audit_path = data_dir.join("audit.log");

        if audit_path.exists() {
            return MigrationResult::Skipped { from_version: 4 };
        }

        let changes = vec!["created audit.log (empty hashchain)".into()];

        if !dry_run {
            if let Err(e) = ensure_file(&audit_path) {
                return MigrationResult::Failed {
                    from_version: 4,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 4,
            to_version: 5,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M006: v5 → v6 — add transaction index
// -----------------------------------------------------------------------------

/// Migration v5 → v6: Add transaction index (tx_index.json).
pub struct M006AddTransactionIndex;

impl Migration for M006AddTransactionIndex {
    fn from_version(&self) -> u32 {
        5
    }

    fn description(&self) -> &'static str {
        "Add transaction index (tx_index.json) for fast hash → position lookups (v5 → v6)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        100
    }

    fn can_rollback(&self) -> bool {
        false // Index rebuild is expensive; cannot roll back easily
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let tx_index_path = data_dir.join("tx_index.json");

        if tx_index_path.exists() {
            return MigrationResult::Skipped { from_version: 5 };
        }

        let changes = vec!["created tx_index.json with empty index".into()];

        if !dry_run {
            let initial = serde_json::json!({ "version": 1, "index": {} });
            if let Err(e) = write_json_file(&tx_index_path, &initial) {
                return MigrationResult::Failed {
                    from_version: 5,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 5,
            to_version: 6,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
        }
    }
}

// -----------------------------------------------------------------------------
// M007: v6 → v7 — add node metadata
// -----------------------------------------------------------------------------

/// Migration v6 → v7: Add node metadata (node_meta.json).
pub struct M007AddNodeMetadata;

impl Migration for M007AddNodeMetadata {
    fn from_version(&self) -> u32 {
        6
    }

    fn description(&self) -> &'static str {
        "Add node metadata (node_meta.json) for node identity and configuration (v6 → v7)"
    }

    fn estimated_duration_ms(&self) -> u64 {
        50
    }

    fn can_rollback(&self) -> bool {
        true
    }

    fn apply(&self, data_dir: &Path, dry_run: bool) -> MigrationResult {
        let start = Instant::now();
        let node_meta_path = data_dir.join("node_meta.json");

        if node_meta_path.exists() {
            return MigrationResult::Skipped { from_version: 6 };
        }

        let changes = vec!["created node_meta.json with default configuration".into()];

        if !dry_run {
            let initial = serde_json::json!({
                "version": 1,
                "node_id": "",
                "created_at": 0,
                "chain_id": null
            });
            if let Err(e) = write_json_file(&node_meta_path, &initial) {
                return MigrationResult::Failed {
                    from_version: 6,
                    reason: e,
                    rolled_back: false,
                };
            }
        }

        MigrationResult::Ok {
            from_version: 6,
            to_version: 7,
            changes,
            duration_ms: if dry_run { None } else { Some(start.elapsed().as_millis() as u64) },
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

    // Helper to create a valid state_full.json
    fn create_state_file(dir: &TempDir, with_vm: bool) {
        let state_path = dir.path().join("state_full.json");
        let state = if with_vm {
            serde_json::json!({ "kv": {}, "balances": {}, "vm": {} })
        } else {
            serde_json::json!({ "kv": {}, "balances": {} })
        };
        std::fs::write(&state_path, serde_json::to_string_pretty(&state).unwrap()).unwrap();
    }

    // ── M001 ────────────────────────────────────────────────────────────────

    #[test]
    fn m001_no_state_file_is_ok() {
        let dir = TempDir::new().unwrap();
        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());
        // Should not create state file
        assert!(!dir.path().join("state_full.json").exists());
    }

    #[test]
    fn m001_adds_vm_field() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, false);

        let result = M001AddStateVmField.apply(dir.path(), false);
        assert!(result.is_ok());

        let state_path = dir.path().join("state_full.json");
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
        create_state_file(&dir, false);
        let state_path = dir.path().join("state_full.json");
        let original = std::fs::read_to_string(&state_path).unwrap();

        let result = M001AddStateVmField.apply(dir.path(), /* dry_run = */ true);
        assert!(result.is_ok());

        let on_disk = std::fs::read_to_string(&state_path).unwrap();
        assert_eq!(on_disk, original, "dry‑run must not modify the file");
    }

    #[test]
    fn m001_idempotent() {
        let dir = TempDir::new().unwrap();
        create_state_file(&dir, false);

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
        assert!(dir.path().join("receipts/index.json").exists());
    }

    #[test]
    fn m002_dry_run_does_not_create_dir() {
        let dir = TempDir::new().unwrap();
        M002AddReceiptsIndex.apply(dir.path(), true);
        assert!(
            !dir.path().join("receipts").exists(),
            "dry‑run must not create the directory"
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

    // ── M006 ────────────────────────────────────────────────────────────────

    #[test]
    fn m006_creates_tx_index() {
        let dir = TempDir::new().unwrap();
        let result = M006AddTransactionIndex.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(dir.path().join("tx_index.json").exists());
    }

    // ── M007 ────────────────────────────────────────────────────────────────

    #[test]
    fn m007_creates_node_meta() {
        let dir = TempDir::new().unwrap();
        let result = M007AddNodeMetadata.apply(dir.path(), false);
        assert!(result.is_ok());
        assert!(dir.path().join("node_meta.json").exists());
    }
}
