//! Data directory management for IONA node.
//!
//! This module provides the `DataDir` struct which handles all on-disk data:
//! - Node identity and validator keys
//! - Blockchain state (KV, full state, stakes)
//! - Blocks, receipts, evidence, WAL
//! - Schema migrations and metadata
//!
//! It uses the underlying `DataLayout` for path management and atomic writes.

use crate::crypto::ed25519::Ed25519Keypair;
use crate::crypto::keystore;
use crate::data_layout::DataLayout;
use crate::execution::KvState;
use crate::node_meta::{NodeMeta, NodeMetaError};
use crate::slashing::StakeLedger;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

// Re-export current schema version for external use.
pub use crate::storage::CURRENT_SCHEMA_VERSION;

/// Metadata stored in `<data_dir>/schema.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchemaMeta {
    pub version: u32,
    /// Unix timestamp of the last migration (informational).
    #[serde(default)]
    pub migrated_at: Option<u64>,
    /// Human-readable history of applied migrations.
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

/// Main handle for node data directory.
#[derive(Clone)]
pub struct DataDir {
    layout: DataLayout,
}

impl DataDir {
    /// Creates a new `DataDir` with the given root path.
    pub fn new(root: impl Into<String>) -> Self {
        Self {
            layout: DataLayout::new(root.into()),
        }
    }

    /// Ensures the data directory exists (creates it if needed).
    pub fn ensure(&self) -> io::Result<()> {
        self.layout.ensure_all()
    }

    // ------------------------------------------------------------------------
    // Path helpers (compatibility with existing API)
    // ------------------------------------------------------------------------

    fn p(&self, file: &str) -> String {
        self.layout.root().join(file).display().to_string()
    }

    pub fn wal_path(&self) -> String {
        self.layout.wal_path().display().to_string()
    }

    pub fn blocks_dir(&self) -> String {
        self.layout.blocks_dir().display().to_string()
    }

    pub fn evidence_path(&self) -> String {
        self.layout.evidence_path().display().to_string()
    }

    pub fn receipts_dir(&self) -> String {
        self.layout.receipts_dir().display().to_string()
    }

    // ------------------------------------------------------------------------
    // Key management (plain or encrypted)
    // ------------------------------------------------------------------------

    /// Loads `keys.json` or creates it if absent.
    ///
    /// Notes:
    /// - For demos, keys are deterministically derived from `seed`.
    /// - In production, you should replace this with proper key management.
    pub fn load_or_create_keys(&self, seed: u64, keystore: &str, password_env: &str) -> io::Result<Ed25519Keypair> {
        self.load_or_create_keys_with_fallback(seed, keystore, password_env, "")
    }

    /// Load or create keys with an optional fallback password from config.
    /// Priority: env var > config password > error.
    pub fn load_or_create_keys_with_fallback(
        &self,
        seed: u64,
        keystore: &str,
        password_env: &str,
        config_password: &str,
    ) -> io::Result<Ed25519Keypair> {
        self.ensure()?;

        let plain_path = self.layout.p2p_key_path(); // was "keys.json"
        let enc_path = self.layout.validator_key_enc_path(); // was "keys.enc"

        #[derive(Serialize, Deserialize)]
        struct K {
            seed32: [u8; 32],
        }

        let mode = keystore.trim().to_lowercase();

        if mode == "encrypted" {
            // Encrypted keystore
            let pass = std::env::var(password_env)
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

            if enc_path.exists() {
                let seed32 = keystore::decrypt_seed32_from_file(&enc_path, &pass)?;
                Ok(Ed25519Keypair::from_seed(seed32))
            } else {
                // Derive deterministic seed32 from seed.
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);

                keystore::encrypt_seed32_to_file(&enc_path, seed32, &pass)?;
                Ok(kp)
            }
        } else {
            // Plain JSON (demo/dev) - unencrypted at rest.
            if plain_path.exists() {
                let s = fs::read_to_string(&plain_path)?;
                let k: K = serde_json::from_str(&s)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json parse: {e}")))?;
                Ok(Ed25519Keypair::from_seed(k.seed32))
            } else {
                // Derive deterministic seed32.
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);

                let out = serde_json::to_string_pretty(&K { seed32 })
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json encode: {e}")))?;
                fs::write(&plain_path, out)?;

                // Best-effort: make key file owner-readable only on unix.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&plain_path, fs::Permissions::from_mode(0o600));
                }

                Ok(kp)
            }
        }
    }

    // ------------------------------------------------------------------------
    // State (KV and full)
    // ------------------------------------------------------------------------

    pub fn load_state_kv(&self) -> io::Result<BTreeMap<String, String>> {
        self.ensure()?;
        let path = self.layout.state_kv_path(); // was "state.json"
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state.json parse: {e}")))
        } else {
            Ok(BTreeMap::new())
        }
    }

    pub fn save_state_kv(&self, state: &BTreeMap<String, String>) -> io::Result<()> {
        self.ensure()?;
        let path = self.layout.state_kv_path();
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state.json encode: {e}")))?;
        self.layout.atomic_write(&path, out.as_bytes())?;
        Ok(())
    }

    pub fn load_state_full(&self) -> io::Result<KvState> {
        self.ensure()?;
        let path = self.layout.state_full_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json parse: {e}")))
        } else {
            Ok(KvState::default())
        }
    }

    pub fn save_state_full(&self, state: &KvState) -> io::Result<()> {
        self.ensure()?;
        let path = self.layout.state_full_path();
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json encode: {e}")))?;
        self.layout.atomic_write(&path, out.as_bytes())?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Stakes
    // ------------------------------------------------------------------------

    pub fn load_stakes(&self) -> io::Result<StakeLedger> {
        self.ensure()?;
        let path = self.layout.stakes_path();
        if path.exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json parse: {e}")))
        } else {
            Ok(StakeLedger::default_demo())
        }
    }

    pub fn save_stakes(&self, stakes: &StakeLedger) -> io::Result<()> {
        self.ensure()?;
        let path = self.layout.stakes_path();
        let out = serde_json::to_string_pretty(stakes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json encode: {e}")))?;
        self.layout.atomic_write(&path, out.as_bytes())?;
        Ok(())
    }

    // ------------------------------------------------------------------------
    // Schema version & migrations
    // ------------------------------------------------------------------------

    /// Read the current on-disk schema version (0 = pre-schema, i.e., very old node).
    pub fn read_schema_version(&self) -> io::Result<u32> {
        let path = self.layout.schema_path();
        if !path.exists() {
            return Ok(0);
        }
        let s = fs::read_to_string(&path)?;
        let meta: SchemaMeta = serde_json::from_str(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("schema.json parse: {e}")))?;
        Ok(meta.version)
    }

    /// Persist the schema metadata atomically.
    fn write_schema(&self, meta: &SchemaMeta) -> io::Result<()> {
        let path = self.layout.schema_path();
        let json = serde_json::to_string_pretty(meta)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("schema.json encode: {e}")))?;
        self.layout.atomic_write(&path, json.as_bytes())
    }

    /// Run a single migration step from `from_version` to `from_version + 1`.
    fn run_migration(&self, from_version: u32, meta: &mut SchemaMeta) -> io::Result<()> {
        let timestamp = now_unix_secs();

        match from_version {
            // v0 → v1: Introduce schema.json marker.
            0 => {
                meta.migration_log.push(format!(
                    "[{timestamp}] v0 → v1: schema.json marker created"
                ));
            }

            // v1 → v2: Normalize state_full.json and stakes.json (add missing fields).
            1 => {
                // state_full.json
                let state_path = self.layout.state_full_path();
                if state_path.exists() {
                    let backup = state_path.with_extension("v1.bak");
                    if !backup.exists() {
                        fs::copy(&state_path, &backup)?;
                    }
                    let raw = fs::read_to_string(&state_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("vm").or_insert_with(|| serde_json::json!({
                            "storage": {}, "code": {}, "nonces": {}, "logs": []
                        }));
                        obj.entry("burned").or_insert(serde_json::Value::from(0u64));
                    }
                    let normalised = serde_json::to_string_pretty(&val)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    fs::write(&state_path, normalised)?;
                }

                // stakes.json
                let stakes_path = self.layout.stakes_path();
                if stakes_path.exists() {
                    let backup = stakes_path.with_extension("v1.bak");
                    if !backup.exists() {
                        fs::copy(&stakes_path, &backup)?;
                    }
                    let raw = fs::read_to_string(&stakes_path)?;
                    let mut val: serde_json::Value = serde_json::from_str(&raw)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    if let Some(obj) = val.as_object_mut() {
                        obj.entry("epoch_snapshots").or_insert_with(|| serde_json::json!([]));
                        obj.entry("params").or_insert_with(|| serde_json::json!({}));
                    }
                    let normalised = serde_json::to_string_pretty(&val)
                        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                    fs::write(&stakes_path, normalised)?;
                }

                meta.migration_log.push(format!(
                    "[{timestamp}] v1 → v2: state_full.json + stakes.json normalised; backups created"
                ));
            }

            // v2 → v3: Migrate WAL from flat file to segmented directory.
            2 => {
                let old_wal = self.layout.wal_flat_path(); // was "wal.jsonl"
                let wal_dir = self.layout.wal_dir();
                if old_wal.exists() && !wal_dir.exists() {
                    fs::create_dir_all(&wal_dir)?;
                    let new_seg = wal_dir.join("wal_00000000.jsonl");
                    fs::rename(&old_wal, &new_seg)?;
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: wal.jsonl migrated to wal/wal_00000000.jsonl"
                    ));
                } else {
                    meta.migration_log.push(format!(
                        "[{timestamp}] v2 → v3: WAL already in segmented format, nothing to do"
                    ));
                }
            }

            // v3 → v4: Introduce node_meta.json with protocol version.
            3 => {
                crate::migrations::m0004_protocol_version::migrate(&self.layout, meta)?;
            }

            // v4 → v5: Add tx_index.json.
            4 => {
                crate::migrations::m0005_add_tx_index::migrate(&self.layout, meta)?;
            }

            v => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported schema migration from v{v} — upgrade the node binary"),
                ));
            }
        }

        Ok(())
    }

    /// Ensures on-disk schema is at `CURRENT_SCHEMA_VERSION`, running automatic
    /// migrations if needed. Call this once at node startup before opening any
    /// other data files.
    pub fn ensure_schema_and_migrate(&self) -> io::Result<()> {
        self.ensure()?;

        let cur = self.read_schema_version()?;

        if cur > CURRENT_SCHEMA_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "on-disk schema v{cur} is newer than this binary (v{CURRENT_SCHEMA_VERSION}); \
                     please upgrade the node"
                ),
            ));
        }

        if cur == CURRENT_SCHEMA_VERSION {
            return Ok(());
        }

        // Load or initialise metadata.
        let mut meta = if cur == 0 {
            SchemaMeta::new(0)
        } else {
            let s = fs::read_to_string(self.layout.schema_path())?;
            serde_json::from_str::<SchemaMeta>(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
        };

        tracing::info!(
            from = cur,
            to = CURRENT_SCHEMA_VERSION,
            "running schema migrations"
        );

        // Step through each migration one version at a time.
        let mut v = cur;
        while v < CURRENT_SCHEMA_VERSION {
            self.run_migration(v, &mut meta)?;
            v += 1;
            meta.version = v;
            self.write_schema(&meta)?;
            tracing::info!(version = v, "schema migration step complete");
        }

        meta.migrated_at = Some(now_unix_secs());
        self.write_schema(&meta)?;

        tracing::info!(
            version = CURRENT_SCHEMA_VERSION,
            "schema fully migrated"
        );
        Ok(())
    }
}

/// Returns current Unix timestamp in seconds.
fn now_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
