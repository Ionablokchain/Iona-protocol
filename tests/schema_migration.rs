//! Integration tests for schema versioning and migrations.
//!
//! Each test simulates a node data directory at an older schema version
//! and verifies that `ensure_schema_and_migrate()` upgrades it correctly.
//!
//! # What is verified
//!
//! * **Migration from every version** — for each `V` in `0..CURRENT`,
//!   a directory at version `V` migrates to `CURRENT_SCHEMA_VERSION`
//!   with the expected artifacts (state extension, WAL segmenting,
//!   `node_meta.json`, `tx_index.json`).
//! * **Idempotency** — a second `ensure_schema_and_migrate` after
//!   reaching `CURRENT` does not advance the version and does not add
//!   log entries.
//! * **Ordering** — migration log entries appear in strictly
//!   increasing version order (v0→v1, then v1→v2, …).
//! * **Refusal on future version** — a `schema.json` whose version is
//!   higher than `CURRENT_SCHEMA_VERSION` is rejected with a message
//!   that mentions "newer than this binary".
//! * **No partial migration** — if any intermediate step fails, the
//!   on-disk schema version remains at the pre-migration value, never
//!   at an intermediate value.
//! * **Skipping already-applied steps** — a directory at version `V`
//!   does not re-run steps for versions `< V`.
//! * **Large state** — 10 000 accounts migrate within the time budget.
//!
//! # What is **not** tested here
//!
//! * **Crash atomicity** — proving that a mid-migration power loss
//!   leaves a consistent directory requires process-kill hooks that
//!   the migration API does not expose. Atomicity under hard crash is
//!   covered by the on-disk file format's design (temp-file + rename)
//!   and would need a fault-injection harness to test here.
//! * **Lock-file behavior** — `.migration.lock` is a filesystem
//!   primitive; whether it exists at any given instant is a
//!   `flock`-level property that cannot be observed from a test
//!   without a second process.
//! * **Rollback under a later restart** — an operator downgrading the
//!   binary is out of scope; the migration API's contract is that
//!   *upgrading* works, not that *downgrading* is safe.
//!
//! # Assertions on log format
//!
//! Two tests assert the structure of migration-log entries in
//! `schema.json`: each entry is `"[<unix_ts>] v<from>→v<to>: <desc>"`.
//! If the format changes, `migration_log_entries_are_consistent` and
//! `all_migrations_applied_in_order` must change together with the
//! producer.

use std::fs;
use std::time::{Duration, Instant};

use iona::storage::{DataDir, CURRENT_SCHEMA_VERSION};
use tempfile::TempDir;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const SCHEMA_FILE:         &str = "schema.json";
const STATE_FULL_FILE:     &str = "state_full.json";
const WAL_LEGACY_FILE:     &str = "wal.jsonl";
const NODE_META_FILE:      &str = "node_meta.json";
const TX_INDEX_FILE:       &str = "tx_index.json";
const BACKUP_V1_SUFFIX:    &str = ".v1.bak";
const WAL_SEGMENT_DIR:     &str = "wal";
const BLOCKS_DIR:          &str = "blocks";
const FIRST_SEGMENT:       &str = "wal_00000000.jsonl";

/// Versions referenced by specific tests. Only the version numbers
/// whose *effects* are checked (`v1`, `v2`, `v3`, `v4`) are named;
/// everything else uses `CURRENT_SCHEMA_VERSION` and iterates from 0.
const V1: u32 = 1;
const V2: u32 = 2;
const V3: u32 = 3;
const V4: u32 = 4;

/// Account count for the "large state" test.
const LARGE_ACCOUNT_COUNT: usize = 10_000;

/// Generous per-test time budget for the large-state migration.
///
/// This is a smoke test for "no quadratic blow-up", not a benchmark.
/// 30 s gives even a loaded CI runner room to complete a linear
/// migration of 10 000 accounts. If it ever fails, that is a genuine
/// regression worth investigating.
const LARGE_MIGRATION_TIMEOUT_SECS: u64 = 30;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A temporary data directory plus the `DataDir` handle.
struct TestEnv {
    _tmp: TempDir,
    data: DataDir,
}

impl TestEnv {
    fn new() -> Self {
        let tmp = TempDir::new().expect("tempdir");
        let data = DataDir::new(tmp.path().to_str().expect("tempdir path utf-8"));
        Self { _tmp: tmp, data }
    }

    fn root(&self) -> &std::path::Path {
        &self._tmp.path()
    }

    /// Write `schema.json` at `version`. Passing `0` writes the file
    /// with `"version": 0`; passing anything else writes that value.
    fn write_schema_version(&self, version: u32) {
        self.data.ensure().expect("ensure");
        let meta = serde_json::json!({ "version": version });
        fs::write(
            self.root().join(SCHEMA_FILE),
            serde_json::to_string_pretty(&meta).expect("serialize schema"),
        )
        .expect("write schema");
    }

    fn read_schema_version(&self) -> u32 {
        self.data.read_schema_version().expect("read version")
    }

    fn write_v0_state(&self) {
        let state = serde_json::json!({
            "kv":       { "foo": "bar" },
            "balances": { "test": 500 },
        });
        fs::write(
            self.root().join(STATE_FULL_FILE),
            serde_json::to_string_pretty(&state).expect("serialize"),
        )
        .expect("write v0 state");
    }

    fn write_v1_state(&self) {
        let state = serde_json::json!({
            "kv":       { "hello": "world" },
            "balances": { "abcd": 1000 },
            "nonces":   {},
        });
        fs::write(
            self.root().join(STATE_FULL_FILE),
            serde_json::to_string_pretty(&state).expect("serialize"),
        )
        .expect("write v1 state");
    }

    fn write_legacy_wal(&self) {
        fs::write(
            self.root().join(WAL_LEGACY_FILE),
            b"{\"height\":1}\n{\"height\":2}\n",
        )
        .expect("write legacy wal");
    }

    fn write_blocks(&self, count: usize) {
        let dir = self.root().join(BLOCKS_DIR);
        fs::create_dir_all(&dir).expect("mkdir blocks");
        for i in 0..count {
            let block = serde_json::json!({
                "header": { "height": i },
                "txs": [
                    { "hash": format!("0x{:x}", i) },
                    { "hash": format!("0x{:x}", i + 100) },
                ],
            });
            fs::write(
                dir.join(format!("{i}.json")),
                serde_json::to_string_pretty(&block).expect("serialize block"),
            )
            .expect("write block");
        }
    }

    fn corrupt_file(&self, filename: &str) {
        let path = self.root().join(filename);
        fs::write(&path, b"this is not json").expect("corrupt file");
    }

    fn backup_exists(&self, suffix: &str) -> bool {
        self.root()
            .join(format!("{STATE_FULL_FILE}{suffix}"))
            .exists()
    }

    fn schema_meta(&self) -> serde_json::Value {
        let raw = fs::read_to_string(self.root().join(SCHEMA_FILE))
            .expect("read schema file");
        serde_json::from_str(&raw).expect("parse schema file")
    }

    fn migration_log(&self) -> Vec<String> {
        self.schema_meta()["migration_log"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn assert_log_contains(&self, needle: &str) {
        let log = self.migration_log();
        assert!(
            log.iter().any(|e| e.contains(needle)),
            "migration log should contain {needle:?}; got {log:?}",
        );
    }

    fn assert_log_does_not_contain(&self, needle: &str) {
        let log = self.migration_log();
        assert!(
            !log.iter().any(|e| e.contains(needle)),
            "migration log must NOT contain {needle:?}; got {log:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// Migration runner
//
// Runs `setup` against a fresh env, then migrates, then returns the env
// so the caller can assert on the resulting state without re-running
// the migration. The previous version of this file re-ran setup and
// migration in a second `TestEnv` inside several tests — that doubled
// the work AND could silently assert on a state different from the one
// the first pass produced.
// ---------------------------------------------------------------------------

fn run_migration<F>(start_version: u32, setup: F) -> TestEnv
where
    F: FnOnce(&TestEnv),
{
    let env = TestEnv::new();
    env.write_schema_version(start_version);
    setup(&env);
    env.data
        .ensure_schema_and_migrate()
        .expect("migration must succeed");
    env
}

// ---------------------------------------------------------------------------
// Per-version migration tests
// ---------------------------------------------------------------------------

#[test]
fn migrate_from_v0_with_state() {
    let env = run_migration(0, TestEnv::write_v0_state);

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);
    assert!(!env.migration_log().is_empty(), "migration log must not be empty");
}

#[test]
fn migrate_from_v1_injects_vm_field_and_backs_up_old_state() {
    let env = run_migration(V1, TestEnv::write_v1_state);

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);

    let raw = fs::read_to_string(env.root().join(STATE_FULL_FILE))
        .expect("state_full.json must exist after migration");
    let state: serde_json::Value = serde_json::from_str(&raw).expect("state must be valid JSON");

    assert!(state.get("vm").is_some(), "v1→v2 must inject a `vm` field");
    assert_eq!(state["kv"]["hello"], "world", "original kv data must be preserved");
    assert_eq!(state["balances"]["abcd"], 1000, "original balances must be preserved");
    assert!(env.backup_exists(BACKUP_V1_SUFFIX), "v1 state must be backed up before overwrite");
}

#[test]
fn migrate_from_v2_segments_legacy_wal() {
    let env = run_migration(V2, |e| {
        e.write_v1_state();
        e.write_legacy_wal();
    });

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);

    assert!(
        !env.root().join(WAL_LEGACY_FILE).exists(),
        "wal.jsonl must be renamed/removed by v2→v3",
    );

    let seg0 = env.root().join(WAL_SEGMENT_DIR).join(FIRST_SEGMENT);
    assert!(seg0.exists(), "wal/{FIRST_SEGMENT} must be created by v2→v3");

    let content = fs::read_to_string(&seg0).expect("read segment 0");
    assert!(content.contains("\"height\":1"), "segment must preserve original events");
    assert!(content.contains("\"height\":2"), "segment must preserve all original events");
}

#[test]
fn migrate_from_v3_creates_node_meta() {
    let env = run_migration(V3, |e| {
        e.write_v1_state();
        // v3 directories do not have wal.jsonl anymore (migrated in
        // v2→v3). Do not fabricate one here.
    });

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);
    assert!(!env.root().join(WAL_LEGACY_FILE).exists(),
        "no legacy WAL should exist after v3→v4");

    let meta_path = env.root().join(NODE_META_FILE);
    assert!(meta_path.exists(), "node_meta.json must be created by v3→v4");

    let meta: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&meta_path).expect("read node_meta"),
    )
    .expect("node_meta must be valid JSON");
    assert!(meta.get("protocol_version").is_some(),
        "node_meta must contain protocol_version");
    env.assert_log_contains("node_meta.json");
}

#[test]
fn migrate_from_v4_creates_tx_index() {
    let env = run_migration(V4, |e| {
        e.write_v1_state();
        e.write_blocks(10);
    });

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);

    let idx_path = env.root().join(TX_INDEX_FILE);
    assert!(idx_path.exists(), "tx_index.json must be created by v4→v5");

    let idx: serde_json::Value = serde_json::from_str(
        &fs::read_to_string(&idx_path).expect("read tx_index"),
    )
    .expect("tx_index must be valid JSON");
    assert!(idx.is_object(), "tx_index must be a JSON object");
    env.assert_log_contains("tx_index.json");
}

/// Migration from every version between v0 and CURRENT must succeed.
///
/// This replaces the previous `migrate_from_v5_to_current`,
/// `migrate_from_v6_to_current`, and `migrate_from_v7_to_current` tests,
/// which each checked one hard-coded version and could not catch a
/// regression in any version not named in the file.
#[test]
fn every_version_migrates_to_current() {
    for start in 0..CURRENT_SCHEMA_VERSION {
        let env = run_migration(start, |e| {
            // Populate every artifact that could be relevant to a
            // migration step. Each migration must be a no-op on
            // artifacts it doesn't touch.
            e.write_v1_state();
            e.write_legacy_wal();
            e.write_blocks(3);
        });

        assert_eq!(
            env.read_schema_version(),
            CURRENT_SCHEMA_VERSION,
            "migration from v{start} did not reach CURRENT_SCHEMA_VERSION",
        );
        assert!(
            !env.migration_log().is_empty(),
            "migration from v{start} produced no log entries",
        );
    }
}

// ---------------------------------------------------------------------------
// Idempotency
// ---------------------------------------------------------------------------

#[test]
fn migration_is_idempotent() {
    let env = TestEnv::new();
    env.write_schema_version(0);
    env.write_v0_state();
    env.data.ensure_schema_and_migrate().expect("first migration");

    let version_after_first = env.read_schema_version();
    let log_after_first = env.migration_log().len();

    env.data.ensure_schema_and_migrate().expect("second migration");

    assert_eq!(
        env.read_schema_version(),
        version_after_first,
        "version must not change on second migration",
    );
    assert_eq!(
        env.migration_log().len(),
        log_after_first,
        "log must not grow on second migration",
    );
}

// ---------------------------------------------------------------------------
// Refusal on future version
// ---------------------------------------------------------------------------

#[test]
fn migration_refuses_future_version() {
    let env = TestEnv::new();
    env.write_schema_version(CURRENT_SCHEMA_VERSION + 1);

    let err = env
        .data
        .ensure_schema_and_migrate()
        .expect_err("migration must refuse a future schema version");
    let msg = err.to_string();

    assert!(
        msg.contains("newer than this binary"),
        "error must explain that the disk version is newer than the binary; got {msg:?}",
    );
}

// ---------------------------------------------------------------------------
// Skipping already-applied steps
// ---------------------------------------------------------------------------

#[test]
fn migration_skips_steps_already_applied() {
    // Starting at V3 must apply V3→V4, V4→V5, … but NOT V1→V2 or V2→V3.
    let env = run_migration(V3, |e| {
        // A v3 directory has no `wal.jsonl` and has a `vm` field in
        // state — both artifacts of earlier steps. Fabricating them
        // here would let a bug that re-runs v1→v2 go undetected.
        e.write_v1_state();
    });

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);
    env.assert_log_does_not_contain("v1→v2");
    env.assert_log_does_not_contain("v2→v3");
    env.assert_log_contains("v3→v4");
}

// ---------------------------------------------------------------------------
// Atomicity: never leave a partial migration
// ---------------------------------------------------------------------------

/// If any intermediate step fails, the schema version must not advance
/// to an intermediate value. Either the migration succeeds (version
/// reaches `CURRENT_SCHEMA_VERSION`) or it fails (version stays at the
/// pre-migration value). A schema version between the two is a partial
/// migration — the worst possible outcome, because the next start
/// would try to resume from a state that was never fully written.
///
/// This replaces three tautological tests from the previous version
/// (`migration_continues_on_corrupted_state`,
/// `migration_atomic_write_prevents_corruption`,
/// `migration_detects_rollback_to_old_version`) that all asserted
/// `result.is_ok() || result.is_err()`.
#[test]
fn failed_migration_does_not_advance_schema_version() {
    let env = TestEnv::new();
    env.write_schema_version(V1);
    env.write_v1_state();
    env.corrupt_file(STATE_FULL_FILE);

    let result = env.data.ensure_schema_and_migrate();
    let version = env.read_schema_version();

    match result {
        Ok(()) => assert_eq!(
            version,
            CURRENT_SCHEMA_VERSION,
            "successful migration on corrupted input must reach CURRENT",
        ),
        Err(_) => assert_eq!(
            version,
            V1,
            "failed migration must leave the schema version at V1, \
             not at an intermediate value",
        ),
    }
}

// ---------------------------------------------------------------------------
// Progress tracking
// ---------------------------------------------------------------------------

#[test]
fn migration_progress_entries_are_well_formed() {
    let env = TestEnv::new();
    env.write_schema_version(0);
    env.write_v0_state();
    env.data.ensure_schema_and_migrate().expect("migration");

    let log = env.migration_log();
    assert!(!log.is_empty(), "migration log must have entries");

    for entry in &log {
        // Format: "[<unix_ts>] v<from>→v<to>: <description>"
        let open = entry
            .find('[')
            .unwrap_or_else(|| panic!("log entry missing '[': {entry:?}"));
        let close = entry
            .find(']')
            .unwrap_or_else(|| panic!("log entry missing ']': {entry:?}"));
        assert!(open < close, "log entry brackets reversed: {entry:?}");

        let ts = entry[open + 1..close]
            .parse::<u64>()
            .unwrap_or_else(|_| panic!("log timestamp must be a u64: {entry:?}"));
        assert!(ts > 0, "log timestamp must be positive: {ts}");

        let versions = extract_version_refs(entry);
        assert!(
            versions.len() >= 2,
            "log entry must reference a version transition (vX→vY): {entry:?}",
        );
    }
}

#[test]
fn schema_meta_records_migration_time() {
    let env = TestEnv::new();
    env.write_schema_version(0);
    env.data.ensure_schema_and_migrate().expect("migration");

    let meta = env.schema_meta();
    let migrated_at = meta
        .get("migrated_at")
        .and_then(|v| v.as_u64())
        .expect("schema.json must contain a numeric migrated_at");
    assert!(migrated_at > 0, "migrated_at must be a positive unix timestamp");
}

// ---------------------------------------------------------------------------
// Ordering
// ---------------------------------------------------------------------------

/// Migrations must run in strictly increasing version order.
///
/// Replaces the previous `all_migrations_applied_in_order`, which
/// collected matching version strings into a `HashSet` and asserted
/// `found.len() >= 2` — verifying that at least two versions appeared
/// *somewhere* in the log, not that they appeared *in order*.
#[test]
fn migrations_applied_in_increasing_version_order() {
    let env = TestEnv::new();
    env.write_schema_version(0);
    env.write_v0_state();
    env.write_legacy_wal();
    env.data.ensure_schema_and_migrate().expect("migration");

    let log = env.migration_log();
    assert!(log.len() >= 2, "at least two migrations must run from v0");

    // For each log entry, extract the "from" version (the first `v<N>`
    // reference). Transitions must be strictly increasing.
    let from_versions: Vec<u32> = log
        .iter()
        .filter_map(|entry| extract_version_refs(entry).into_iter().next())
        .collect();

    assert_eq!(
        from_versions.len(),
        log.len(),
        "every log entry must contain at least one version reference",
    );

    for w in from_versions.windows(2) {
        assert!(
            w[0] < w[1],
            "migration order broken: v{} ran before v{}",
            w[0],
            w[1],
        );
    }
}

/// Extract every `v<N>` reference in `entry` in order.
fn extract_version_refs(entry: &str) -> Vec<u32> {
    entry
        .split('v')
        .skip(1)
        .filter_map(|chunk| {
            let digits: String = chunk.chars().take_while(|c| c.is_ascii_digit()).collect();
            if digits.is_empty() {
                None
            } else {
                digits.parse::<u32>().ok()
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Large state
// ---------------------------------------------------------------------------

#[test]
fn migration_handles_large_state_within_budget() {
    let env = TestEnv::new();
    env.write_schema_version(V1);

    // 10 000 accounts — enough to catch accidental O(n²) behaviour in
    // any migration that iterates balances to rewrite keys or values.
    let mut state = serde_json::json!({
        "kv":       {},
        "balances": {},
        "nonces":   {},
    });
    for i in 0..LARGE_ACCOUNT_COUNT {
        state["kv"][format!("key_{i}")] = serde_json::Value::String(format!("value_{i}"));
        state["balances"][format!("addr_{i}")] =
            serde_json::Value::Number((i as u64 * 1_000).into());
    }
    fs::write(
        env.root().join(STATE_FULL_FILE),
        serde_json::to_string_pretty(&state).expect("serialize state"),
    )
    .expect("write large state");

    let start = Instant::now();
    env.data.ensure_schema_and_migrate().expect("migration");
    let elapsed = start.elapsed();

    assert_eq!(env.read_schema_version(), CURRENT_SCHEMA_VERSION);

    assert!(
        elapsed < Duration::from_secs(LARGE_MIGRATION_TIMEOUT_SECS),
        "migrating {LARGE_ACCOUNT_COUNT} accounts took {elapsed:?}, \
         exceeding the {LARGE_MIGRATION_TIMEOUT_SECS}s smoke-test budget",
    );
}
