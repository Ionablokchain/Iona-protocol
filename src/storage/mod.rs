//! Persistent storage for IONA.
//!
//! This module handles all on‑disk data:
//! - Schema versioning and migrations
//! - State (KV store, balances, nonces, VM)
//! - Staking ledger
//! - Keys (plain or encrypted)
//! - WAL (write‑ahead log) and blocks
//! - Evidence, receipts, etc.
//!
//! # Directory layout
//!
//! The data directory contains:
//! - `schema.json` – current schema version and migration log
//! - `node_meta.json` – node metadata (protocol version, etc.)
//! - `keys.json` / `keys.enc` – validator signing keys
//! - `state_full.json` – full node state
//! - `stakes.json` – staking ledger
//! - `wal.jsonl` (legacy) or `wal/` – write‑ahead log
//! - `blocks/` – committed blocks
//! - `receipts/` – transaction receipts
//! - `evidence.jsonl` – slashable evidence
//! - `snapshots/` – state snapshots
//!
//! # Migrations
//!
//! On startup, `ensure_schema_and_migrate()` upgrades the on‑disk schema
//! to the current version. Migrations are atomic and idempotent.
//!
//! # Example
//!
//! ```
//! use iona::storage::DataDir;
//!
//! let data_dir = DataDir::new("./data/node");
//! data_dir.ensure_schema_and_migrate()?;
//! let state = data_dir.load_state_full()?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use crate::crypto::ed25519::Ed25519Keypair;
use crate::execution::KvState;
use crate::slashing::StakeLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Re‑exports of submodules
// -----------------------------------------------------------------------------

pub mod block_store;
pub mod evidence_store;
pub mod layout;
pub mod meta;
pub mod migrations;
pub mod peer_store;
pub mod receipts_store;
pub mod schema_monotonicity;
pub mod snapshots;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Current on‑disk schema version. Bump this every time a breaking change is
/// made to any persistent format. Add a migration arm in `DataDir::run_migration`.
pub const CURRENT_SCHEMA_VERSION: u32 = 5;

/// File names.
const SCHEMA_FILE: &str = "schema.json";
const STATE_FULL_FILE: &str = "state_full.json";
const STAKES_FILE: &str = "stakes.json";
const KEYS_PLAIN_FILE: &str = "keys.json";
const KEYS_ENC_FILE: &str = "keys.enc";
const WAL_LEGACY_FILE: &str = "wal.jsonl";
const BLOCKS_DIR: &str = "blocks";
const RECEIPTS_DIR: &str = "receipts";
const EVIDENCE_FILE: &str = "evidence.jsonl";
const SNAPSHOTS_DIR: &str = "snapshots";
const STATE_LEGACY_FILE: &str = "state.json";

/// Temporary file extension for atomic writes.
const TMP_EXTENSION: &str = "tmp";

/// Backup suffix for old versions during migration.
const BACKUP_SUFFIX: &str = ".v1.bak";

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during storage operations.
#[derive(Debug, Error)]
pub enum StorageError {
    #[error("I/O error: {source}")]
    Io {
        #[from]
        source: io::Error,
    },

    #[error("JSON serialisation error: {source}")]
    Serialization {
        #[from]
        source: serde_json::Error,
    },

    #[error("invalid data: {reason}")]
    InvalidData { reason: String },

    #[error("unsupported schema migration from v{from} (binary too old)")]
    UnsupportedMigration { from: u32, to: u32 },

    #[error("on‑disk schema v{on_disk} is newer than binary (v{binary})")]
    SchemaNewer { on_disk: u32, binary: u32 },
}

pub type StorageResult<T> = Result<T, StorageError>;

impl From<StorageError> for io::Error {
    fn from(err: StorageError) -> Self {
        match err {
            StorageError::Io { source } => source,
            _ => io::Error::new(io::ErrorKind::Other, err.to_string()),
        }
    }
}

// -----------------------------------------------------------------------------
// SchemaMeta
// -----------------------------------------------------------------------------

/// Metadata stored in `<data_dir>/schema.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchemaMeta {
    pub version: u32,
    #[serde(default)]
    pub migrated_at: Option<String>,
    #[serde(default)]
    pub migration_log: Vec<String>,
}

impl SchemaMeta {
    fn new(version: u32) -> Self {
        Self {
            version,
            migrated_at: None,
            migration_log: Vec::new(),
        }
    }
}

// -----------------------------------------------------------------------------
// DataDir
// -----------------------------------------------------------------------------

/// Handle to a node's data directory.
#[derive(Clone)]
pub struct DataDir {
    pub root: PathBuf,
}

impl DataDir {
    /// Create a new `DataDir` instance.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self {
            root: root.into(),
        }
    }

    /// Helper: join a path component.
    fn join(&self, file: &str) -> PathBuf {
        self.root.join(file)
    }

    /// Ensure the root directory exists.
    pub fn ensure(&self) -> StorageResult<()> {
        fs::create_dir_all(&self.root)?;
        debug!(path = %self.root.display(), "data directory ensured");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Schema management
    // -------------------------------------------------------------------------

    fn schema_path(&self) -> PathBuf {
        self.join(SCHEMA_FILE)
    }

    /// Read the current on‑disk schema version (0 = pre‑schema, i.e. very old node).
    pub fn read_schema_version(&self) -> StorageResult<u32> {
        let path = self.schema_path();
        if !path.exists() {
            return Ok(0);
        }
        let content = fs::read_to_string(&path)?;
        let meta: SchemaMeta = serde_json::from_str(&content)
            .map_err(|e| StorageError::InvalidData {
                reason: format!("schema.json parse: {e}"),
            })?;
        debug!(version = meta.version, "read schema version");
        Ok(meta.version)
    }

    /// Persist the schema metadata atomically (write to `.tmp` then rename).
    fn write_schema(&self, meta: &SchemaMeta) -> StorageResult<()> {
        let path = self.schema_path();
        let tmp = path.with_extension(TMP_EXTENSION);
        let content = serde_json::to_string_pretty(meta)?;
        fs::write(&tmp, &content)?;
        fs::rename(&tmp, &path)?;
        debug!(path = %path.display(), "schema persisted");
        Ok(())
    }

    /// Run a single migration step from `from_version` to `from_version + 1`.
    fn run_migration(&self, from_version: u32, meta: &mut SchemaMeta) -> StorageResult<()> {
        let timestamp = now_secs();

        match from_version {
            // ── v0 → v1 ──────────────────────────────────────────────────────────
            // Introduce schema.json marker.
            0 => {
                meta.migration_log.push(format!(
                    "[{timestamp}] v0 → v1: schema.json marker created"
                ));
                info!("migration v0→v1: schema.json marker created");
            }

            // ── v1 → v2 ──────────────────────────────────────────────────────────
            // KvState gained the `vm: VmStorage` field (v26).
            1 => {
                let state_path = self.join(STATE_FULL_FILE);
                if state_path.exists() {
                    let backup = state_path.with_extension(BACKUP_SUFFIX);
                    if !backup.exists() {
                        fs::copy(&state_path, &backup)?;
                        debug!(path = %backup.display(), "created backup");
                    }
                    let raw = fs::read_to_string(&state_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("vm").or_insert_with(|| {
                            serde_json::json!({
                                "storage": {}, "code": {}, "nonces": {}, "logs": []
                            })
                        });
                        obj.entry("burned").or_insert(serde_json::Value::from(0u64));
                    }
                    let normalised = serde_json::to_string_pretty(&val)?;
                    fs::write(&state_path, normalised)?;
                }

                let stakes_path = self.join(STAKES_FILE);
                if stakes_path.exists() {
                    let backup = stakes_path.with_extension(BACKUP_SUFFIX);
                    if !backup.exists() {
                        fs::copy(&stakes_path, &backup)?;
                        debug!(path = %backup.display(), "created backup");
                    }
                    let raw = fs::read_to_string(&stakes_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| StorageError::InvalidData(e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("epoch_snapshots")
                            .or_insert_with(|| serde_json::json!([]));
                        obj.entry("params").or_insert_with(|| serde_json::json!({}));
                    }
                    let normalised = serde_json::to_string_pretty(&val)?;
                    fs::write(&stakes_path, normalised)?;
                }
                meta.migration_log.push(format!(
                    "[{timestamp}] v1 → v2: state_full.json + stakes.json normalised; backups created"
                ));
                info!("migration v1→v2: state and stakes normalised");
            }

            // ── v2 → v3 ──────────────────────────────────────────────────────────
            // WAL format: segment files moved from `wal.jsonl` (flat) to
            // `wal/wal_00000000.jsonl` (segmented).
            2 => {
                let old_wal = self.join(WAL_LEGACY_FILE);
                let wal_dir = self.join("wal");
                if old_wal.exists() && !wal_dir.exists() {
                    fs::create_dir_all(&wal_dir)?;
                    let new_seg = wal_dir.join("wal_00000000.jsonl");
                    fs::rename(&old_wal, &new_seg)?;
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: wal.jsonl migrated to wal/wal_00000000.jsonl"
                    ));
                    info!("migration v2→v3: WAL migrated to segmented format");
                } else {
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: WAL already in segmented format, nothing to do"
                    ));
                    debug!("WAL already segmented");
                }
            }

            // ── v3 → v4 ──────────────────────────────────────────────────────────
            // Introduce node_meta.json with protocol version tracking.
            3 => {
                migrations::m0004_protocol_version::migrate(&self.root, meta)?;
            }

            // ── v4 → v5 ──────────────────────────────────────────────────────────
            // Add tx_index.json for fast transaction lookup by hash.
            4 => {
                migrations::m0005_add_tx_index::migrate(&self.root, meta)?;
            }

            v => {
                error!(from = v, "unsupported migration version");
                return Err(StorageError::UnsupportedMigration {
                    from: v,
                    to: CURRENT_SCHEMA_VERSION,
                });
            }
        }

        Ok(())
    }

    /// Ensures on‑disk schema is at `CURRENT_SCHEMA_VERSION`, running automatic
    /// migrations if needed. Call this once at node startup before opening any
    /// other data files.
    pub fn ensure_schema_and_migrate(&self) -> StorageResult<()> {
        self.ensure()?;

        let on_disk = self.read_schema_version()?;
        let binary = CURRENT_SCHEMA_VERSION;

        if on_disk > binary {
            error!(on_disk, binary, "on‑disk schema is newer than binary");
            return Err(StorageError::SchemaNewer {
                on_disk,
                binary,
            });
        }

        if on_disk == binary {
            debug!("schema already up to date (v{binary})");
            return Ok(());
        }

        // Load or initialise metadata
        let mut meta = if on_disk == 0 {
            SchemaMeta::new(0)
        } else {
            let content = fs::read_to_string(self.schema_path())?;
            serde_json::from_str(&content)
                .map_err(|e| StorageError::InvalidData(format!("schema.json parse: {e}")))?
        };

        info!(from = on_disk, to = binary, "running schema migrations");

        let mut v = on_disk;
        while v < binary {
            self.run_migration(v, &mut meta)?;
            v += 1;
            meta.version = v;
            self.write_schema(&meta)?;
            info!(version = v, "schema migration step complete");
        }

        meta.migrated_at = Some(now_secs().to_string());
        self.write_schema(&meta)?;

        info!(version = binary, "schema fully migrated");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Key management
    // -------------------------------------------------------------------------

    /// Load or create keys (plain or encrypted) with password from env.
    pub fn load_or_create_keys(
        &self,
        seed: u64,
        keystore: &str,
        password_env: &str,
    ) -> StorageResult<Ed25519Keypair> {
        self.load_or_create_keys_with_fallback(seed, keystore, password_env, "")
    }

    /// Load or create keys with an optional fallback password from config.
    pub fn load_or_create_keys_with_fallback(
        &self,
        seed: u64,
        keystore: &str,
        password_env: &str,
        config_password: &str,
    ) -> StorageResult<Ed25519Keypair> {
        self.ensure()?;
        let plain_path = self.join(KEYS_PLAIN_FILE);
        let enc_path = self.join(KEYS_ENC_FILE);

        #[derive(Serialize, Deserialize)]
        struct K {
            seed32: [u8; 32],
        }

        let mode = keystore.trim().to_lowercase();
        if mode == "encrypted" {
            let password = std::env::var(password_env)
                .ok()
                .filter(|s| !s.is_empty())
                .or_else(|| {
                    if !config_password.is_empty() {
                        Some(config_password.to_string())
                    } else {
                        None
                    }
                })
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        format!(
                            "keystore=encrypted but no password provided. \
                             Set env {password_env} or keystore_password in config."
                        ),
                    )
                })?;

            if crate::crypto::keystore::keystore_exists(&enc_path) {
                let seed32 = crate::crypto::keystore::decrypt_seed32_from_file(&enc_path, &password)?;
                debug!("loaded encrypted keystore");
                Ok(Ed25519Keypair::from_seed(seed32))
            } else {
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let keypair = Ed25519Keypair::from_seed(seed32);
                crate::crypto::keystore::encrypt_seed32_to_file(&enc_path, seed32, &password)?;
                info!("generated new encrypted keystore");
                Ok(keypair)
            }
        } else {
            if plain_path.exists() {
                let content = fs::read_to_string(&plain_path)?;
                let k: K = serde_json::from_str(&content)?;
                debug!("loaded plain keystore");
                Ok(Ed25519Keypair::from_seed(k.seed32))
            } else {
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let keypair = Ed25519Keypair::from_seed(seed32);
                let out = serde_json::to_string_pretty(&K { seed32 })?;
                fs::write(&plain_path, out)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&plain_path, fs::Permissions::from_mode(0o600));
                }
                info!("generated new plain keystore");
                Ok(keypair)
            }
        }
    }

    // -------------------------------------------------------------------------
    // State (KV)
    // -------------------------------------------------------------------------

    /// Load legacy `state.json` (KV only). Prefer `load_state_full`.
    pub fn load_state_kv(&self) -> StorageResult<BTreeMap<String, String>> {
        self.ensure()?;
        let path = self.join(STATE_LEGACY_FILE);
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content).map_err(|e| StorageError::InvalidData(e.to_string()))
        } else {
            Ok(BTreeMap::new())
        }
    }

    /// Save legacy `state.json`.
    pub fn save_state_kv(&self, state: &BTreeMap<String, String>) -> StorageResult<()> {
        self.ensure()?;
        let path = self.join(STATE_LEGACY_FILE);
        let content = serde_json::to_string_pretty(state)?;
        fs::write(path, content)?;
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Full state (KvState)
    // -------------------------------------------------------------------------

    /// Load the full node state (`KvState`).
    pub fn load_state_full(&self) -> StorageResult<KvState> {
        self.ensure()?;
        let path = self.join(STATE_FULL_FILE);
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content)
                .map_err(|e| StorageError::InvalidData(format!("state_full.json parse: {e}")))
        } else {
            debug!("state_full.json not found, returning default");
            Ok(KvState::default())
        }
    }

    /// Save the full node state.
    pub fn save_state_full(&self, state: &KvState) -> StorageResult<()> {
        self.ensure()?;
        let path = self.join(STATE_FULL_FILE);
        let content = serde_json::to_string_pretty(state)?;
        fs::write(&path, content)?;
        debug!(path = %path.display(), "saved state_full");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Staking
    // -------------------------------------------------------------------------

    /// Load the stake ledger.
    pub fn load_stakes(&self) -> StorageResult<StakeLedger> {
        self.ensure()?;
        let path = self.join(STAKES_FILE);
        if path.exists() {
            let content = fs::read_to_string(&path)?;
            serde_json::from_str(&content)
                .map_err(|e| StorageError::InvalidData(format!("stakes.json parse: {e}")))
        } else {
            debug!("stakes.json not found, returning default demo ledger");
            Ok(StakeLedger::default_demo())
        }
    }

    /// Save the stake ledger.
    pub fn save_stakes(&self, stakes: &StakeLedger) -> StorageResult<()> {
        self.ensure()?;
        let path = self.join(STAKES_FILE);
        let content = serde_json::to_string_pretty(stakes)?;
        fs::write(path, content)?;
        debug!(path = %path.display(), "saved stakes");
        Ok(())
    }

    // -------------------------------------------------------------------------
    // Path helpers (for other modules)
    // -------------------------------------------------------------------------

    /// Path to the legacy WAL file (pre‑v3).
    pub fn wal_path(&self) -> PathBuf {
        self.join(WAL_LEGACY_FILE)
    }

    /// Path to the blocks directory.
    pub fn blocks_dir(&self) -> PathBuf {
        self.join(BLOCKS_DIR)
    }

    /// Path to the evidence file.
    pub fn evidence_path(&self) -> PathBuf {
        self.join(EVIDENCE_FILE)
    }

    /// Path to the receipts directory.
    pub fn receipts_dir(&self) -> PathBuf {
        self.join(RECEIPTS_DIR)
    }

    /// Path to the snapshots directory.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.join(SNAPSHOTS_DIR)
    }
}

// -----------------------------------------------------------------------------
// Helper: timestamp
// -----------------------------------------------------------------------------

/// Return the current Unix timestamp as a `u64`.
fn now_secs() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_data_dir_ensure() -> StorageResult<()> {
        let dir = tempdir()?;
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure()?;
        assert!(dir.path().exists());
        Ok(())
    }

    #[test]
    fn test_schema_version_new() -> StorageResult<()> {
        let dir = tempdir()?;
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure()?;
        let v = data_dir.read_schema_version()?;
        assert_eq!(v, 0);
        Ok(())
    }

    #[test]
    fn test_state_full_roundtrip() -> StorageResult<()> {
        let dir = tempdir()?;
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure()?;
        let state = KvState::default();
        data_dir.save_state_full(&state)?;
        let loaded = data_dir.load_state_full()?;
        assert_eq!(state.root(), loaded.root());
        Ok(())
    }

    #[test]
    fn test_keys_plain() -> StorageResult<()> {
        let dir = tempdir()?;
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure()?;
        let kp = data_dir.load_or_create_keys(42, "plain", "")?;
        let kp2 = data_dir.load_or_create_keys(42, "plain", "")?;
        assert_eq!(kp.to_seed(), kp2.to_seed());
        Ok(())
    }

    #[test]
    fn test_keys_encrypted_with_env() -> StorageResult<()> {
        let dir = tempdir()?;
        let data_dir = DataDir::new(dir.path());
        data_dir.ensure()?;
        std::env::set_var("TEST_PW", "secret");
        let kp = data_dir.load_or_create_keys(42, "encrypted", "TEST_PW")?;
        let kp2 = data_dir.load_or_create_keys(42, "encrypted", "TEST_PW")?;
        assert_eq!(kp.to_seed(), kp2.to_seed());
        std::env::remove_var("TEST_PW");
        Ok(())
    }
}
