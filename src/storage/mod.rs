use crate::crypto::ed25519::Ed25519Keypair;

pub mod block_store;
pub mod evidence_store;
pub mod meta;
pub mod migrations;
pub mod peer_store;
pub mod receipts_store;
pub mod snapshots;
pub mod schema_monotonicity;
pub mod layout;

use crate::slashing::StakeLedger;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, fs, io, path::Path};

/// Current on-disk schema version.  Bump this every time a breaking change is
/// made to any persistent format (state_full.json, blocks/, receipts/, WAL,
/// snapshots, stakes.json).  Add a migration arm in `run_migration` below.
pub const CURRENT_SCHEMA_VERSION: u32 = 5;

/// Metadata stored in `<data_dir>/schema.json`.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct SchemaMeta {
    pub version: u32,
    /// ISO-8601 timestamp of the last migration (informational, not load-bearing).
    #[serde(default)]
    pub migrated_at: Option<String>,
    /// Human-readable history of applied migrations.
    #[serde(default)]
    pub migration_log: Vec<String>,
}

impl SchemaMeta {
    fn new(version: u32) -> Self {
        Self { version, migrated_at: None, migration_log: Vec::new() }
    }
}


#[derive(Clone)]
pub struct DataDir {
    pub root: String,
}

impl DataDir {
    pub fn new(root: impl Into<String>) -> Self {
        Self { root: root.into() }
    }

    fn p(&self, file: &str) -> String {
        format!("{}/{}", self.root, file)
    }

    pub fn ensure(&self) -> io::Result<()> {
        fs::create_dir_all(&self.root)
    }


fn schema_path(&self) -> String { self.p("schema.json") }

/// Read the current on-disk schema version (0 = pre-schema, i.e. very old node).
pub fn read_schema_version(&self) -> io::Result<u32> {
    let path = self.schema_path();
    if !Path::new(&path).exists() {
        return Ok(0);
    }
    let s = fs::read_to_string(&path)?;
    let meta: SchemaMeta = serde_json::from_str(&s)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("schema.json parse: {e}")))?;
    Ok(meta.version)
}

/// Persist the schema metadata atomically (write to `.tmp` then rename).
fn write_schema(&self, meta: &SchemaMeta) -> io::Result<()> {
    let path = self.schema_path();
    let tmp = format!("{path}.tmp");
    let out = serde_json::to_string_pretty(meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("schema.json encode: {e}")))?;
    fs::write(&tmp, &out)?;
    fs::rename(&tmp, &path)?;
    Ok(())
}

/// Run a single migration step from `from_version` to `from_version + 1`.
///
/// Design principles:
///   - **Never delete user data** — rename or backup instead.
///   - **Atomic where possible** — write to `.tmp` then rename.
///   - **Idempotent** — safe to run twice if a previous run was interrupted.
///   - **Logged** — every step appends to `SchemaMeta.migration_log`.
fn run_migration(&self, from_version: u32, meta: &mut SchemaMeta) -> io::Result<()> {
    let timestamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };

    match from_version {
        // ── v0 → v1 ──────────────────────────────────────────────────────────
        // Introduce schema.json marker.  No structural changes to data files.
        0 => {
            meta.migration_log.push(format!(
                "[{timestamp}] v0 → v1: schema.json marker created"
            ));
        }

        // ── v1 → v2 ──────────────────────────────────────────────────────────
        // KvState gained the `vm: VmStorage` field (v26).
        // Old state_full.json files lack this field; serde's `#[serde(default)]`
        // already handles deserialization, but we add an explicit note + backup.
        1 => {
            let state_path = self.p("state_full.json");
            if Path::new(&state_path).exists() {
                let backup = format!("{state_path}.v1.bak");
                if !Path::new(&backup).exists() {
                    fs::copy(&state_path, &backup)?;
                }
                // Re-load and re-save to normalise any missing fields to defaults.
                let raw = fs::read_to_string(&state_path)?;
                let mut val: serde_json::Value = serde_json::from_str(&raw)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
                // Inject defaults for new fields if absent.
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
            // stakes.json: add missing `epoch_snapshots` field if absent.
            let stakes_path = self.p("stakes.json");
            if Path::new(&stakes_path).exists() {
                let backup = format!("{stakes_path}.v1.bak");
                if !Path::new(&backup).exists() {
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

        // ── v2 → v3 ──────────────────────────────────────────────────────────
        // WAL format: segment files moved from `wal.jsonl` (flat) to
        // `wal/wal_00000000.jsonl` (segmented, v20+).
        // If the old flat file exists and the wal/ directory doesn't, migrate.
        2 => {
            let old_wal = self.p("wal.jsonl");
            let wal_dir = format!("{}/wal", self.root);
            if Path::new(&old_wal).exists() && !Path::new(&wal_dir).exists() {
                fs::create_dir_all(&wal_dir)?;
                let new_seg = format!("{wal_dir}/wal_00000000.jsonl");
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

        // ── v3 → v4 ──────────────────────────────────────────────────────────
        // Introduce node_meta.json with protocol version tracking.
        // Delegated to the new migrations registry.
        3 => {
            migrations::m0004_protocol_version::migrate(&self.root, meta)?;
        }

        // ── v4 → v5 ──────────────────────────────────────────────────────────
        // Add tx_index.json for fast transaction lookup by hash.
        // Delegated to the new migrations registry.
        4 => {
            migrations::m0005_add_tx_index::migrate(&self.root, meta)?;
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
/// migrations if needed.  Call this once at node startup before opening any
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
        let s = fs::read_to_string(self.schema_path())?;
        serde_json::from_str::<SchemaMeta>(&s)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
    };

    tracing::info!(
        from = cur,
        to = CURRENT_SCHEMA_VERSION,
        "running schema migrations"
    );

    // Step through each migration one version at a time so that a failed
    // mid-run still leaves the schema at a consistent intermediate version.
    let mut v = cur;
    while v < CURRENT_SCHEMA_VERSION {
        self.run_migration(v, &mut meta)?;
        v += 1;
        meta.version = v;
        // Persist after every successful step so we can resume safely.
        self.write_schema(&meta)?;
        tracing::info!(version = v, "schema migration step complete");
    }

    // Final timestamp.
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs().to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    meta.migrated_at = Some(ts);
    self.write_schema(&meta)?;

    tracing::info!(
        version = CURRENT_SCHEMA_VERSION,
        "schema fully migrated"
    );
    Ok(())
}

    /// Loads `keys.json` or creates it if absent.
    ///
    /// Notes:
    /// - For demos, keys are deterministically derived from `seed`.
    /// - In production, you should replace this with proper key management (HSM/KMS, encrypted at rest).
    pub fn load_or_create_keys(&self, seed: u64, keystore: &str, password_env: &str) -> io::Result<Ed25519Keypair> {
        self.load_or_create_keys_with_fallback(seed, keystore, password_env, "")
    }

    /// Load or create keys with an optional fallback password from config.
    /// Priority: env var > config password > error.
    pub fn load_or_create_keys_with_fallback(&self, seed: u64, keystore: &str, password_env: &str, config_password: &str) -> io::Result<Ed25519Keypair> {
        self.ensure()?;
        let plain_path = self.p("keys.json");
        let enc_path = self.p("keys.enc");

        #[derive(Serialize, Deserialize)]
        struct K { seed32: [u8; 32] }

        let mode = keystore.trim().to_lowercase();
        if mode == "encrypted" {
            // Encrypted keystore: try env var first, then config password as fallback.
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

            if crate::crypto::keystore::keystore_exists(&enc_path) {
                let seed32 = crate::crypto::keystore::decrypt_seed32_from_file(&enc_path, &pass)?;
                Ok(Ed25519Keypair::from_seed(seed32))
            } else {
                // Derive deterministic seed32 from seed for reproducible demos.
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);

                crate::crypto::keystore::encrypt_seed32_to_file(&enc_path, seed32, &pass)?;

                Ok(kp)
            }
        } else {
            // Plain JSON (demo/dev). WARNING: unencrypted at rest.
            let path = plain_path;

            if Path::new(&path).exists() {
                let s = fs::read_to_string(&path)?;
                let k: K = serde_json::from_str(&s)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json parse: {e}")))?;
                Ok(Ed25519Keypair::from_seed(k.seed32))
            } else {
                // Derive deterministic seed32 from seed for reproducible demos.
                let mut seed32 = [0u8; 32];
                seed32[..8].copy_from_slice(&seed.to_le_bytes());
                let kp = Ed25519Keypair::from_seed(seed32);

                let out = serde_json::to_string_pretty(&K { seed32 })
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("keys.json encode: {e}")))?;
                fs::write(&path, out)?;

                // Best-effort: make key file owner-readable only on unix.
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
                }

                Ok(kp)
            }
        }
}

    pub fn load_state_kv(&self) -> io::Result<BTreeMap<String, String>> {
        self.ensure()?;
        let path = self.p("state.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state.json parse: {e}")))
        } else {
            Ok(BTreeMap::new())
        }
    }

    pub fn save_state_kv(&self, state: &BTreeMap<String, String>) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("state.json");
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state.json encode: {e}")))?;
        fs::write(path, out)
    }

    pub fn load_state_full(&self) -> io::Result<crate::execution::KvState> {
        self.ensure()?;
        let path = self.p("state_full.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json parse: {e}")))
        } else {
            Ok(crate::execution::KvState::default())
        }
    }

    pub fn save_state_full(&self, state: &crate::execution::KvState) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("state_full.json");
        let out = serde_json::to_string_pretty(state)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("state_full.json encode: {e}")))?;
        fs::write(path, out)
    }

    pub fn load_stakes(&self) -> io::Result<StakeLedger> {
        self.ensure()?;
        let path = self.p("stakes.json");
        if Path::new(&path).exists() {
            let s = fs::read_to_string(&path)?;
            serde_json::from_str(&s)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json parse: {e}")))
        } else {
            Ok(StakeLedger::default_demo())
        }
    }

    pub fn save_stakes(&self, stakes: &StakeLedger) -> io::Result<()> {
        self.ensure()?;
        let path = self.p("stakes.json");
        let out = serde_json::to_string_pretty(stakes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("stakes.json encode: {e}")))?;
        fs::write(path, out)
    }

    pub fn wal_path(&self) -> String {
        self.p("wal.jsonl")
    }

    pub fn blocks_dir(&self) -> String {
        format!("{}/blocks", self.root)
    }

    pub fn evidence_path(&self) -> String {
        self.p("evidence.jsonl")
    }

    pub fn receipts_dir(&self) -> String {
        format!("{}/receipts", self.root)
    }
}
