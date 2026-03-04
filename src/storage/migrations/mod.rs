//! Ordered, idempotent storage migrations.
//!
//! Each migration is a function `fn(&DataDir, &mut SchemaMeta) -> io::Result<()>`
//! that upgrades from version N to N+1.
//!
//! # Adding a new migration
//!
//! 1. Create a new module `mNNNN_description.rs` (e.g. `m0004_add_tx_index.rs`).
//! 2. Implement `pub fn migrate(data_dir: &str, meta: &mut super::SchemaMeta) -> std::io::Result<()>`.
//! 3. Register it in the `MIGRATIONS` array below.
//! 4. Bump `CURRENT_SCHEMA_VERSION` in `storage/mod.rs`.
//!
//! # Rules
//!
//! - **Never delete user data** -- rename or backup instead.
//! - **Atomic where possible** -- write to `.tmp` then rename.
//! - **Idempotent** -- safe to run twice if a previous run was interrupted.
//! - **Logged** -- every step appends to `SchemaMeta.migration_log`.
//! - **Dual-read** -- the node can still read the old format until migration completes.

pub mod m0004_protocol_version;
pub mod m0005_add_tx_index;
pub mod background;

use crate::storage::SchemaMeta;
use std::io;

/// Migration function signature: (data_dir_root, schema_meta) -> Result.
type MigrateFn = fn(&str, &mut SchemaMeta) -> io::Result<()>;

/// Ordered list of migrations.  Index 0 = migration from v3 -> v4, etc.
/// Migrations for v0->v1, v1->v2, v2->v3 are handled by the legacy
/// `DataDir::run_migration` method in `storage/mod.rs`.
///
/// When adding new migrations, append to this list and bump CURRENT_SCHEMA_VERSION.
pub const MIGRATIONS: &[(u32, &str, MigrateFn)] = &[
    (3, "v3 -> v4: add protocol_version to node_meta", m0004_protocol_version::migrate),
    (4, "v4 -> v5: add tx_index for fast tx-by-hash lookup", m0005_add_tx_index::migrate),
];

/// Run all pending migrations from `from_version` up to `to_version`.
/// Only runs migrations that are in the new `MIGRATIONS` registry (v3+).
pub fn run_pending(
    data_dir: &str,
    meta: &mut SchemaMeta,
    from_version: u32,
    to_version: u32,
) -> io::Result<()> {
    for &(from_v, desc, migrate_fn) in MIGRATIONS {
        if from_v >= from_version && from_v < to_version {
            tracing::info!(from = from_v, to = from_v + 1, desc, "running migration");
            migrate_fn(data_dir, meta)?;
            meta.version = from_v + 1;
            tracing::info!(version = meta.version, "migration step complete");
        }
    }
    Ok(())
}
