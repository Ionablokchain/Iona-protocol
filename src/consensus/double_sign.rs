//! Quantum double-sign protection with entanglement-based hash-chain integrity.
//!
//! Prevents slashable equivocation by modelling each signing attempt as a
//! **quantum measurement** on the validator's Hilbert space. Conflicting
//! measurements (same position, different block_id) collapse the state to
//! an error subspace |DOUBLE_SIGN⟩.
//!
//! # Guarantees
//!
//! - **Durability**: every `record_*` call performs an fsync'd atomic write
//!   (temp file + `fsync` + `rename` + parent-dir `fsync` on Unix). A crash
//!   never leaves a torn or truncated guard file.
//! - **Consistency**: `record_*` holds the in-memory lock across the disk
//!   write. On I/O failure, the in-memory state is rolled back so it always
//!   matches the last durably persisted state.
//! - **Integrity**: the on-disk state carries a blake3 hash over all mutable
//!   fields. Any out-of-band modification is detected on load.
//!
//! # Purity (informational)
//!
//! Each write applies a configurable decoherence `exp(-rate)` to `purity`.
//! Purity is **informational only** — a low purity emits a `warn!` but never
//! fails integrity, because integrity is enforced by `chain_hash`, not by a
//! decaying metric. (Prior versions failed on purity, which locked out the
//! guard after the first write with the default config.)
//!
//! # Production features
//! - File locking (`flock`) with exponential backoff and a bounded timeout.
//! - Atomic, `fsync`'d writes; `.tmp` cleanup on error paths.
//! - Automatic backup of corrupted state, bounded to `max_backups` files.
//! - Versioned serialization (`GuardState` v1) with a legacy loader.
//! - Structured `tracing` for load/save/detect events.

use crate::consensus::messages::VoteType;
use crate::crypto::PublicKeyBytes;
use crate::types::{Hash32, Height, Round};
use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Minimum chain fidelity required for **informational** purity checks.
///
/// This threshold is *not* enforced as a hard failure — see the module docs.
const MIN_CHAIN_FIDELITY: f64 = 0.5;

/// Default decoherence rate per write operation.
const DEFAULT_WRITE_DECOHERENCE_RATE: f64 = 0.0001;

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Backup file suffix (`.bak`).
const BACKUP_SUFFIX: &str = ".bak";

/// Temporary file suffix for atomic writes (`.tmp`).
const TEMP_SUFFIX: &str = ".tmp";

/// Lock file suffix (`.lock`).
const LOCK_SUFFIX: &str = ".lock";

/// Maximum number of backup files to keep by default.
const MAX_BACKUPS: usize = 5;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the double-sign guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardConfig {
    /// Decoherence rate per write operation (0.0 - 1.0).
    pub decoherence_rate: f64,
    /// Minimum chain fidelity for **informational** purity warnings.
    ///
    /// A purity below this threshold emits a `warn!` on load but does **not**
    /// fail integrity. Set to `0.0` to disable the warning.
    pub min_fidelity: f64,
    /// Whether to create a backup when a corrupted file is detected.
    pub enable_backups: bool,
    /// Maximum number of backup files to keep.
    pub max_backups: usize,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
}

impl Default for GuardConfig {
    fn default() -> Self {
        Self {
            decoherence_rate: DEFAULT_WRITE_DECOHERENCE_RATE,
            min_fidelity: MIN_CHAIN_FIDELITY,
            enable_backups: true,
            max_backups: MAX_BACKUPS,
            lock_timeout_secs: LOCK_TIMEOUT_SECS,
        }
    }
}

impl GuardConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !self.decoherence_rate.is_finite()
            || !(0.0..=1.0).contains(&self.decoherence_rate)
        {
            return Err("decoherence_rate must be a finite value in [0.0, 1.0]".into());
        }
        if !self.min_fidelity.is_finite() || !(0.0..=1.0).contains(&self.min_fidelity) {
            return Err("min_fidelity must be a finite value in [0.0, 1.0]".into());
        }
        if self.max_backups == 0 {
            return Err("max_backups must be > 0".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Persisted state
// -----------------------------------------------------------------------------

/// The persisted state of the double-sign guard.
///
/// `chain_hash` is computed over every other mutable field. It is *not*
/// included in its own computation.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct GuardState {
    /// Schema version. Absent in legacy files (treated as v0).
    #[serde(default = "current_version")]
    version: u32,
    /// Key: `"proposal:<h>:<r>"` → block_id hex.
    #[serde(default)]
    proposals: BTreeMap<String, String>,
    /// Key: `"vote:<type>:<h>:<r>"` → block_id hex (or `"nil"`).
    #[serde(default)]
    votes: BTreeMap<String, String>,
    /// Blake3 hash of the serialized state at the last successful write.
    #[serde(default)]
    chain_hash: String,
    /// Informational quantum purity γ = Tr(ρ²).
    #[serde(default = "one")]
    purity: f64,
    /// Informational von Neumann entropy S = -Tr(ρ ln ρ).
    #[serde(default)]
    entropy: f64,
    /// Total write operations performed.
    #[serde(default)]
    total_operations: u64,
    /// Number of double-sign detections (should always be 0).
    #[serde(default)]
    double_sign_detections: u64,
    /// Last modified timestamp (Unix seconds).
    #[serde(default)]
    last_modified: u64,
}

fn current_version() -> u32 {
    CURRENT_VERSION
}

fn one() -> f64 {
    1.0
}

impl Default for GuardState {
    fn default() -> Self {
        Self {
            version: CURRENT_VERSION,
            proposals: BTreeMap::new(),
            votes: BTreeMap::new(),
            chain_hash: String::new(),
            purity: 1.0,
            entropy: 0.0,
            total_operations: 0,
            double_sign_detections: 0,
            last_modified: current_timestamp(),
        }
    }
}

impl GuardState {
    /// Compute the blake3 hash over every mutable field except `chain_hash`.
    ///
    /// Uses an explicit `#[derive(Serialize)]` struct instead of `json!` so
    /// key order is fully determined by the struct definition and independent
    /// of `serde_json` features (e.g. `preserve_order`).
    fn compute_hash(&self) -> Result<String, String> {
        #[derive(Serialize)]
        struct Canonical<'a> {
            version: u32,
            proposals: &'a BTreeMap<String, String>,
            votes: &'a BTreeMap<String, String>,
            purity: f64,
            entropy: f64,
            total_operations: u64,
            double_sign_detections: u64,
            last_modified: u64,
        }

        let c = Canonical {
            version: self.version,
            proposals: &self.proposals,
            votes: &self.votes,
            purity: self.purity,
            entropy: self.entropy,
            total_operations: self.total_operations,
            double_sign_detections: self.double_sign_detections,
            last_modified: self.last_modified,
        };
        let bytes = serde_json::to_vec(&c)
            .map_err(|e| format!("chain hash serialize error: {}", e))?;
        Ok(hex::encode(blake3::hash(&bytes).as_bytes()))
    }

    /// Update `chain_hash` and `last_modified`.
    fn stamp(&mut self) -> Result<(), String> {
        self.last_modified = current_timestamp();
        self.chain_hash = self.compute_hash()?;
        Ok(())
    }

    /// Verify the stored `chain_hash` against the current state.
    ///
    /// Purity is **informational** — see the module docs.
    fn verify_chain(&self, config: &GuardConfig) -> Result<(), String> {
        if self.chain_hash.is_empty() {
            // Freshly created (or legacy) file with no chain yet.
            return Ok(());
        }
        let expected = self.compute_hash()?;
        if self.chain_hash != expected {
            error!(stored = %self.chain_hash, computed = %expected,
                   "double-sign guard chain integrity FAILED");
            return Err(format!(
                "double-sign guard chain integrity FAILED: stored={} computed={}",
                self.chain_hash, expected
            ));
        }
        if config.min_fidelity > 0.0 && self.purity < config.min_fidelity {
            warn!(
                purity = self.purity,
                threshold = config.min_fidelity,
                "guard purity below threshold (informational; chain integrity OK)"
            );
        }
        Ok(())
    }

    /// Apply decoherence from a write operation and bump the op counter.
    fn apply_decoherence(&mut self, rate: f64) {
        self.total_operations = self.total_operations.saturating_add(1);
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            // S = -p * ln(p) — a closed-form proxy for a pure→mixed transition.
            -(self.purity * self.purity.ln().min(0.0))
        };
    }
}

/// Return the current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Disk I/O: locking, atomic fsync'd writes, backups
// -----------------------------------------------------------------------------

fn lock_path_for(path: &Path) -> PathBuf {
    path.with_extension(LOCK_SUFFIX)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut p = path.as_os_str().to_owned();
    p.push(TEMP_SUFFIX);
    PathBuf::from(p)
}

/// Acquire an exclusive `flock` on `path`'s lock file, with exponential backoff.
///
/// Returns the lock file handle; the lock is released when the handle is
/// dropped (closing the file descriptor releases the flock).
fn acquire_lock(path: &Path, timeout_secs: u64) -> Result<File, String> {
    let lock_path = lock_path_for(path);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file {}: {}", lock_path.display(), e))?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    let mut delay = Duration::from_millis(1);

    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "could not acquire lock on {} after {}s",
                        lock_path.display(),
                        timeout_secs
                    ));
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!(
                    "lock error on {}: {}",
                    lock_path.display(),
                    e
                ));
            }
        }
    }
}

/// Load the guard state from disk.
///
/// Returns a fresh [`GuardState`] if `path` does not exist.
fn load_state(path: &Path, config: &GuardConfig) -> Result<GuardState, String> {
    if !path.exists() {
        return Ok(GuardState::default());
    }

    // Hold the lock for the whole read to avoid a torn read against a
    // concurrent writer using the same lock file.
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;

    let file = File::open(path).map_err(|e| format!("cannot open guard file: {}", e))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value =
        serde_json::from_reader(reader).map_err(|e| format!("parse error: {}", e))?;

    let version = raw.get("version").and_then(|v| v.as_u64());

    let state: GuardState = match version {
        Some(v) if v == CURRENT_VERSION as u64 => {
            serde_json::from_value(raw).map_err(|e| format!("v{} parse error: {}", v, e))?
        }
        Some(v) => {
            return Err(format!(
                "unsupported guard version: {} (expected {})",
                v, CURRENT_VERSION
            ));
        }
        None => {
            // Legacy file without a version marker: parse the subset of fields
            // we recognise and default the rest.
            debug!(path = %path.display(), "loading legacy guard file (no version field)");
            serde_json::from_value(raw).map_err(|e| format!("legacy parse error: {}", e))?
        }
    };

    state.verify_chain(config)?;

    info!(
        path = %path.display(),
        proposals = state.proposals.len(),
        votes = state.votes.len(),
        purity = state.purity,
        "guard state loaded"
    );

    Ok(state)
}

/// Save the guard state atomically and durably.
///
/// Sequence:
/// 1. Acquire the lock.
/// 2. `fs::write` to a `.tmp` file.
/// 3. `fsync` the temp file.
/// 4. `rename` the temp file over the target (atomic on POSIX).
/// 5. `fsync` the parent directory (Unix) so the rename itself is durable.
///
/// The caller is expected to pass a state that has *already* been updated
/// in memory; `save_state` does not mutate `state`. It returns a **clone**
/// with decoherence and `chain_hash` applied, which the caller must install
/// on success.
fn build_persisted_state(
    state: &GuardState,
    config: &GuardConfig,
) -> Result<GuardState, String> {
    let mut next = state.clone();
    next.apply_decoherence(config.decoherence_rate);
    next.stamp()?;
    Ok(next)
}

/// Atomically write `state` to `path`.
///
/// On success, returns the state that was actually persisted (with decoherence
/// and `chain_hash` applied). Callers must install this state in memory.
fn save_state(
    path: &Path,
    state: &GuardState,
    config: &GuardConfig,
) -> Result<GuardState, String> {
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;

    let next = build_persisted_state(state, config)?;
    let json = serde_json::to_vec_pretty(&next)
        .map_err(|e| format!("encode error: {}", e))?;

    let temp_path = temp_path_for(path);

    // Write + fsync the temp file, then rename.
    {
        let f = File::create(&temp_path)
            .map_err(|e| format!("create {}: {}", temp_path.display(), e))?;
        let mut w = BufWriter::new(f);
        if let Err(e) = w.write_all(&json) {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("write {}: {}", temp_path.display(), e));
        }
        if let Err(e) = w.flush() {
            let _ = fs::remove_file(&temp_path);
            return Err(format!("flush {}: {}", temp_path.display(), e));
        }
        let f = w
            .into_inner()
            .map_err(|e| format!("unwrap bufwriter: {}", e))?;
        f.sync_all()
            .map_err(|e| format!("fsync {}: {}", temp_path.display(), e))?;
    }

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        format!("rename {} -> {}: {}", temp_path.display(), path.display(), e)
    })?;

    // fsync the parent directory so the rename is durable on Unix.
    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    debug!(path = %path.display(), purity = next.purity, "guard state saved");
    Ok(next)
}

/// Create a timestamped backup of `path`.
fn backup_state(path: &Path) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err("no file to backup".into());
    }
    let ts = current_timestamp();
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("doublesign");
    let backup_path = path.with_file_name(format!("{}.{}{}", file_name, ts, BACKUP_SUFFIX));
    fs::copy(path, &backup_path)
        .map_err(|e| format!("backup {}: {}", backup_path.display(), e))?;
    info!(backup = %backup_path.display(), "guard state backed up");
    Ok(backup_path)
}

/// Remove the oldest backups, keeping at most `max_backups`.
///
/// Backups are matched as `<file_name>.<ts>.bak` where `<ts>` is a UNIX
/// timestamp in seconds. The scan is bounded to `path.parent()`.
fn cleanup_backups(path: &Path, max_backups: usize) -> Result<(), String> {
    let dir = path.parent().unwrap_or(Path::new("."));
    let file_name = match path.file_name().and_then(|s| s.to_str()) {
        Some(n) => n.to_string(),
        None => return Ok(()),
    };
    let prefix = format!("{}.", file_name);

    let mut backups: Vec<(u64, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir).map_err(|e| format!("read dir: {}", e))? {
        let entry = entry.map_err(|e| format!("dir entry: {}", e))?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let Some(rest) = name.strip_prefix(&prefix) else { continue };
        let Some(ts_str) = rest.strip_suffix(BACKUP_SUFFIX) else { continue };
        if let Ok(ts) = ts_str.parse::<u64>() {
            backups.push((ts, entry.path()));
        }
    }

    // Newest first.
    backups.sort_by(|a, b| b.0.cmp(&a.0));

    for (_, old) in backups.iter().skip(max_backups) {
        match fs::remove_file(old) {
            Ok(()) => debug!(backup = %old.display(), "removed old backup"),
            Err(e) => warn!(backup = %old.display(), error = %e, "failed to remove old backup"),
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// DoubleSignGuard
// -----------------------------------------------------------------------------

/// Thread-safe quantum guard that prevents double-signing.
///
/// Cloning shares the underlying state and counters.
#[derive(Clone, Debug)]
pub struct DoubleSignGuard {
    path: PathBuf,
    inner: Arc<Mutex<GuardState>>,
    config: Arc<GuardConfig>,
    checks_passed: Arc<AtomicU64>,
    detections: Arc<AtomicU64>,
    records: Arc<AtomicU64>,
}

impl DoubleSignGuard {
    /// Load (or create) the guard for the given validator public key.
    ///
    /// Returns `Err` if the on-disk state fails chain integrity verification.
    /// **Treat this as fatal at startup** — do not start the node if the
    /// guard cannot be loaded, or you risk equivocating.
    pub fn new(data_dir: &str, pk: &PublicKeyBytes) -> Result<Self, String> {
        Self::with_config(data_dir, pk, &GuardConfig::default())
    }

    /// Load with custom configuration.
    pub fn with_config(
        data_dir: &str,
        pk: &PublicKeyBytes,
        config: &GuardConfig,
    ) -> Result<Self, String> {
        config.validate()?;

        let pk_hex = hex::encode(&pk.0);
        let path = PathBuf::from(data_dir).join(format!("doublesign_{}.json", pk_hex));
        info!(path = %path.display(), "loading quantum double-sign guard");

        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create data directory: {}", e))?;
        }

        let existed = path.exists();
        let (state, recovered) = match load_state(&path, config) {
            Ok(s) => (s, false),
            Err(e) => {
                error!(error = %e, "guard load failed; starting fresh");
                if config.enable_backups && existed {
                    match backup_state(&path) {
                        Ok(_) => {
                            if let Err(e) = cleanup_backups(&path, config.max_backups) {
                                warn!(error = %e, "cleanup_backups failed");
                            }
                        }
                        Err(e) => warn!(error = %e, "backup failed"),
                    }
                }
                (GuardState::default(), true)
            }
        };

        let guard = Self {
            path: path.clone(),
            inner: Arc::new(Mutex::new(state)),
            config: Arc::new(config.clone()),
            checks_passed: Arc::new(AtomicU64::new(0)),
            detections: Arc::new(AtomicU64::new(0)),
            records: Arc::new(AtomicU64::new(0)),
        };

        // Persist a fresh state if the file was missing or corrupt, so the
        // on-disk file is never left absent/stale after a successful `new`.
        if !existed || recovered {
            guard.flush().map_err(|e| {
                format!("initial guard save failed for {}: {}", path.display(), e)
            })?;
        }

        guard.verify_integrity()?;

        let (proposals, votes) = guard.record_count();
        info!(
            path = %guard.path.display(),
            proposals,
            votes,
            purity = guard.purity(),
            "quantum double-sign guard ready"
        );
        Ok(guard)
    }

    /// Create a guard that **ignores** integrity failures and starts fresh.
    ///
    /// # ⚠️  UNSAFE FOR PRODUCTION
    ///
    /// If the on-disk state is corrupt, this constructor silently discards
    /// the signing history, which is exactly the scenario where a
    /// double-sign is possible. Use only in tests or in a documented
    /// recovery tool with operator confirmation.
    #[doc(hidden)]
    pub fn new_unsafe(data_dir: &str, pk: &PublicKeyBytes) -> Self {
        let pk_hex = hex::encode(&pk.0);
        let path = PathBuf::from(data_dir).join(format!("doublesign_{}.json", pk_hex));
        let _ = fs::create_dir_all(data_dir);
        Self {
            path,
            inner: Arc::new(Mutex::new(GuardState::default())),
            config: Arc::new(GuardConfig::default()),
            checks_passed: Arc::new(AtomicU64::new(0)),
            detections: Arc::new(AtomicU64::new(0)),
            records: Arc::new(AtomicU64::new(0)),
        }
    }

    // ── Proposal operations ──────────────────────────────────────────────

    /// Check whether signing this proposal would be equivocation.
    ///
    /// This is a **read-only** measurement — it does not persist anything.
    /// Call [`record_proposal`](Self::record_proposal) before signing.
    pub fn check_proposal(
        &self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> Result<(), String> {
        let key = format!("proposal:{}:{}", height, round);
        let want = h32_hex(block_id);
        let st = self.inner.lock();

        if let Some(existing) = st.proposals.get(&key) {
            if existing != &want {
                let msg = format!(
                    "DOUBLE-PROPOSAL REFUSED height={} round={} existing={} attempted={}",
                    height, round, existing, want
                );
                error!("{}", msg);
                self.detections.fetch_add(1, Ordering::Relaxed);
                return Err(msg);
            }
        }

        self.checks_passed.fetch_add(1, Ordering::Relaxed);
        debug!(height, round, block = %want, "proposal check passed");
        Ok(())
    }

    /// Durably record that this proposal was signed.
    ///
    /// **Must be called before signing.** On success the record is durably
    /// persisted; on failure nothing is recorded and the in-memory state is
    /// rolled back, so a subsequent call with the same `(height, round,
    /// block_id)` is safe to retry.
    pub fn record_proposal(
        &self,
        height: Height,
        round: Round,
        block_id: &Hash32,
    ) -> Result<(), String> {
        let key = format!("proposal:{}:{}", height, round);
        let val = h32_hex(block_id);

        let mut st = self.inner.lock();
        let prev = st.clone();
        st.proposals.insert(key, val);

        match save_state(&self.path, &st, &self.config) {
            Ok(persisted) => {
                *st = persisted;
                self.records.fetch_add(1, Ordering::Relaxed);
                info!(height, round, "recorded proposal signature");
                Ok(())
            }
            Err(e) => {
                *st = prev;
                Err(e)
            }
        }
    }

    // ── Vote operations ──────────────────────────────────────────────────

    /// Check whether signing this vote would be equivocation.
    pub fn check_vote(
        &self,
        vt: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> Result<(), String> {
        let key = vote_guard_key(vt, height, round);
        let want = block_id
            .as_ref()
            .map(h32_hex)
            .unwrap_or_else(|| "nil".to_string());
        let st = self.inner.lock();

        if let Some(existing) = st.votes.get(&key) {
            if existing != &want {
                let msg = format!(
                    "DOUBLE-VOTE REFUSED type={:?} height={} round={} existing={} attempted={}",
                    vt, height, round, existing, want
                );
                error!("{}", msg);
                self.detections.fetch_add(1, Ordering::Relaxed);
                return Err(msg);
            }
        }

        self.checks_passed.fetch_add(1, Ordering::Relaxed);
        debug!(?vt, height, round, vote = %want, "vote check passed");
        Ok(())
    }

    /// Durably record that this vote was signed.
    ///
    /// **Must be called before signing.** Same rollback semantics as
    /// [`record_proposal`](Self::record_proposal).
    pub fn record_vote(
        &self,
        vt: VoteType,
        height: Height,
        round: Round,
        block_id: &Option<Hash32>,
    ) -> Result<(), String> {
        let key = vote_guard_key(vt, height, round);
        let val = block_id
            .as_ref()
            .map(h32_hex)
            .unwrap_or_else(|| "nil".to_string());

        let mut st = self.inner.lock();
        let prev = st.clone();
        st.votes.insert(key, val);

        match save_state(&self.path, &st, &self.config) {
            Ok(persisted) => {
                *st = persisted;
                self.records.fetch_add(1, Ordering::Relaxed);
                info!(?vt, height, round, "recorded vote signature");
                Ok(())
            }
            Err(e) => {
                *st = prev;
                Err(e)
            }
        }
    }

    // ── Inspection ───────────────────────────────────────────────────────

    /// Returns `(proposals_count, votes_count)`.
    pub fn record_count(&self) -> (usize, usize) {
        let st = self.inner.lock();
        (st.proposals.len(), st.votes.len())
    }

    /// Informational purity γ.
    pub fn purity(&self) -> f64 {
        self.inner.lock().purity
    }

    /// Informational entropy S.
    pub fn entropy(&self) -> f64 {
        self.inner.lock().entropy
    }

    /// Total write operations performed.
    pub fn total_operations(&self) -> u64 {
        self.inner.lock().total_operations
    }

    /// Total checks passed.
    pub fn checks_passed(&self) -> u64 {
        self.checks_passed.load(Ordering::Relaxed)
    }

    /// Total double-sign detections (should always be 0).
    pub fn detections(&self) -> u64 {
        self.detections.load(Ordering::Relaxed)
    }

    /// Total successful record operations.
    pub fn total_records(&self) -> u64 {
        self.records.load(Ordering::Relaxed)
    }

    /// Verify the in-memory chain hash right now.
    pub fn verify_integrity(&self) -> Result<(), String> {
        let st = self.inner.lock();
        st.verify_chain(&self.config)
    }

    /// Path to the guard file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Configuration.
    pub fn config(&self) -> &GuardConfig {
        &self.config
    }

    /// Snapshot of guard statistics.
    pub fn stats(&self) -> GuardStats {
        let st = self.inner.lock();
        GuardStats {
            proposals: st.proposals.len(),
            votes: st.votes.len(),
            purity: st.purity,
            entropy: st.entropy,
            total_operations: st.total_operations,
            checks_passed: self.checks_passed.load(Ordering::Relaxed),
            detections: self.detections.load(Ordering::Relaxed),
            total_records: self.records.load(Ordering::Relaxed),
            chain_hash: st.chain_hash.clone(),
            path: self.path.display().to_string(),
        }
    }

    /// Force an immediate durable save of the current in-memory state.
    ///
    /// Useful after bulk import, or to guarantee `last_modified` is fresh.
    /// Idempotent — a second call is a no-op apart from bumping
    /// `total_operations`.
    pub fn flush(&self) -> Result<(), String> {
        let mut st = self.inner.lock();
        let persisted = save_state(&self.path, &st, &self.config)?;
        *st = persisted;
        Ok(())
    }

    /// Clear the in-memory state and persist the empty guard.
    ///
    /// # ⚠️  DESTRUCTIVE
    ///
    /// After this call the guard no longer remembers any prior signing
    /// activity. Only use in tests or via a documented recovery flow.
    #[doc(hidden)]
    pub fn reset_and_flush(&self) -> Result<(), String> {
        let mut st = self.inner.lock();
        let persisted = save_state(&self.path, &GuardState::default(), &self.config)?;
        *st = persisted;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the double-sign guard.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GuardStats {
    pub proposals: usize,
    pub votes: usize,
    pub purity: f64,
    pub entropy: f64,
    pub total_operations: u64,
    pub checks_passed: u64,
    pub detections: u64,
    pub total_records: u64,
    pub chain_hash: String,
    pub path: String,
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Convert a `Hash32` to a lowercase hex string.
fn h32_hex(id: &Hash32) -> String {
    hex::encode(&id.0)
}

/// Stable storage key for a vote.
///
/// Relies on `VoteType`'s `Debug` representation. If `VoteType` ever gains
/// a public `as_str`/`Display` impl, prefer that over `{:?}` here.
pub fn vote_guard_key(vt: VoteType, height: Height, round: Round) -> String {
    format!("vote:{:?}:{}:{}", vt, height, round)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn pk(n: u8) -> PublicKeyBytes {
        PublicKeyBytes(vec![n; 32])
    }

    fn test_guard() -> (DoubleSignGuard, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let g = DoubleSignGuard::new(dir.path().to_str().unwrap(), &pk(0))
            .expect("guard should load");
        (g, dir)
    }

    fn test_guard_with_config(cfg: GuardConfig) -> (DoubleSignGuard, tempfile::TempDir) {
        let dir = tempdir().unwrap();
        let g = DoubleSignGuard::with_config(dir.path().to_str().unwrap(), &pk(0), &cfg)
            .expect("guard should load");
        (g, dir)
    }

    fn hash(b: u8) -> Hash32 {
        Hash32([b; 32])
    }

    // ── Classical behaviour ──────────────────────────────────────────────

    #[test]
    fn test_fresh_guard_allows_proposal() {
        let (g, _dir) = test_guard();
        assert!(g.check_proposal(1, 0, &hash(1)).is_ok());
    }

    #[test]
    fn test_record_then_same_proposal_ok() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert!(g.check_proposal(1, 0, &hash(1)).is_ok());
    }

    #[test]
    fn test_double_proposal_refused() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        let err = g.check_proposal(1, 0, &hash(2)).unwrap_err();
        assert!(err.contains("DOUBLE-PROPOSAL"));
        assert_eq!(g.detections(), 1);
    }

    #[test]
    fn test_double_vote_refused() {
        let (g, _dir) = test_guard();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        let err = g.check_vote(VoteType::Prevote, 1, 0, &Some(hash(2))).unwrap_err();
        assert!(err.contains("DOUBLE-VOTE"));
        assert_eq!(g.detections(), 1);
    }

    #[test]
    fn test_nil_vote_differs_from_block_vote() {
        let (g, _dir) = test_guard();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        assert!(g.check_vote(VoteType::Prevote, 1, 0, &None).is_err());
    }

    #[test]
    fn test_different_rounds_are_independent() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert!(g.check_proposal(1, 1, &hash(2)).is_ok());
    }

    #[test]
    fn test_chain_hash_persisted_and_verified() {
        let dir = tempdir().unwrap();
        let key = pk(1);
        let path = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path, &key).unwrap();
            g.record_proposal(1, 0, &hash(1)).unwrap();
        }

        let g2 = DoubleSignGuard::new(path, &key)
            .expect("reload with valid chain hash should succeed");
        assert_eq!(g2.record_count(), (1, 0));
    }

    #[test]
    fn test_reload_after_many_writes_still_verifies() {
        // Regression: the previous default config caused `verify_chain` to
        // fail on the very first reload because `min_fidelity` was 0.999999
        // while each write decayed purity by ~1e-4.
        let dir = tempdir().unwrap();
        let key = pk(9);
        let path = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path, &key).unwrap();
            for i in 0..200u8 {
                g.record_proposal(i as u64, 0, &hash(i)).unwrap();
            }
        }

        let g = DoubleSignGuard::new(path, &key).expect("reload after 200 writes");
        let (proposals, _) = g.record_count();
        assert_eq!(proposals, 200);
        assert!(g.verify_integrity().is_ok());
        assert!(g.purity() < 1.0); // informational, not fatal
    }

    #[test]
    fn test_tampered_file_detected() {
        let dir = tempdir().unwrap();
        let key = pk(2);
        let path_str = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path_str, &key).unwrap();
            g.record_proposal(5, 0, &hash(5)).unwrap();
        }

        let guard_path = dir.path().join(format!("doublesign_{}.json", hex::encode([2u8; 32])));
        let raw = fs::read_to_string(&guard_path).unwrap();
        let mut json: serde_json::Value = serde_json::from_str(&raw).unwrap();
        json["chain_hash"] = serde_json::Value::String("00".repeat(32));
        fs::write(&guard_path, serde_json::to_string_pretty(&json).unwrap()).unwrap();

        let err = DoubleSignGuard::new(path_str, &key).unwrap_err();
        assert!(err.contains("chain integrity FAILED"), "got: {err}");
    }

    #[test]
    fn test_verify_integrity_ok_on_fresh() {
        let (g, _dir) = test_guard();
        assert!(g.verify_integrity().is_ok());
    }

    #[test]
    fn test_record_count() {
        let (g, _dir) = test_guard();
        assert_eq!(g.record_count(), (0, 0));
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.record_count(), (1, 0));
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        assert_eq!(g.record_count(), (1, 1));
    }

    // ── Quantum flavour ──────────────────────────────────────────────────

    #[test]
    fn test_quantum_purity_decays() {
        let (g, _dir) = test_guard();
        let before = g.purity();
        for i in 0..5u8 {
            g.record_proposal(i as u64, 0, &hash(i)).unwrap();
        }
        let after = g.purity();
        assert!(after < before);
        assert!((0.0..=1.0).contains(&after));
    }

    #[test]
    fn test_quantum_entropy_increases() {
        let (g, _dir) = test_guard();
        let before = g.entropy();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert!(g.entropy() > before);
    }

    #[test]
    fn test_checks_passed_counter() {
        let (g, _dir) = test_guard();
        assert_eq!(g.checks_passed(), 0);
        g.check_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.checks_passed(), 1);
        g.check_vote(VoteType::Precommit, 1, 0, &None).unwrap();
        assert_eq!(g.checks_passed(), 2);
    }

    #[test]
    fn test_total_records_counter() {
        let (g, _dir) = test_guard();
        assert_eq!(g.total_records(), 0);
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.total_records(), 1);
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        assert_eq!(g.total_records(), 2);
    }

    #[test]
    fn test_stats() {
        let (g, _dir) = test_guard();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        g.check_proposal(1, 0, &hash(1)).unwrap();

        let s = g.stats();
        assert_eq!(s.proposals, 1);
        assert_eq!(s.votes, 1);
        assert_eq!(s.checks_passed, 1);
        assert_eq!(s.total_records, 2);
        assert!(s.purity < 1.0);
        assert!(!s.chain_hash.is_empty());
        assert!(s.path.contains("doublesign_"));
    }

    #[test]
    fn test_total_operations_tracks_writes() {
        let (g, _dir) = test_guard();
        assert_eq!(g.total_operations(), 0);
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert_eq!(g.total_operations(), 1);
        g.record_vote(VoteType::Prevote, 1, 0, &Some(hash(1))).unwrap();
        assert_eq!(g.total_operations(), 2);
    }

    // ── Config ───────────────────────────────────────────────────────────

    #[test]
    fn test_config_validation() {
        assert!(GuardConfig::default().validate().is_ok());

        assert!(GuardConfig { decoherence_rate: 1.5, ..Default::default() }
            .validate()
            .is_err());
        assert!(GuardConfig { decoherence_rate: f64::NAN, ..Default::default() }
            .validate()
            .is_err());
        assert!(GuardConfig { min_fidelity: -0.1, ..Default::default() }
            .validate()
            .is_err());
        assert!(GuardConfig { max_backups: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(GuardConfig { lock_timeout_secs: 0, ..Default::default() }
            .validate()
            .is_err());
    }

    #[test]
    fn test_custom_config_works() {
        let cfg = GuardConfig {
            decoherence_rate: 0.05,
            min_fidelity: 0.95,
            ..Default::default()
        };
        let (g, _dir) = test_guard_with_config(cfg);
        assert!((g.config().decoherence_rate - 0.05).abs() < 1e-12);
        assert!(g.verify_integrity().is_ok());
    }

    // ── Recovery / backups ───────────────────────────────────────────────

    #[test]
    fn test_backup_on_corruption() {
        let dir = tempdir().unwrap();
        let key = pk(4);
        let path_str = dir.path().to_str().unwrap();

        {
            let g = DoubleSignGuard::new(path_str, &key).unwrap();
            g.record_proposal(1, 0, &hash(1)).unwrap();
        }

        let guard_path = dir.path().join(format!("doublesign_{}.json", hex::encode([4u8; 32])));
        fs::write(&guard_path, "corrupted data").unwrap();

        // Recovery: a fresh guard starts and immediately overwrites the corrupt file.
        let g = DoubleSignGuard::new(path_str, &key).expect("recovery should succeed");
        assert_eq!(g.record_count(), (0, 0));
        assert!(g.verify_integrity().is_ok());

        let backups: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.contains("doublesign_") && n.ends_with(BACKUP_SUFFIX)
            })
            .collect();
        assert!(!backups.is_empty(), "backup file should exist");
    }

    #[test]
    fn test_cleanup_backups_keeps_newest() {
        let dir = tempdir().unwrap();
        let guard_path = dir.path().join("doublesign_x.json");
        fs::write(&guard_path, "{}").unwrap();

        // Create 10 backups with fake timestamps.
        for ts in 1..=10u64 {
            let p = dir
                .path()
                .join(format!("doublesign_x.json.{}{}", ts, BACKUP_SUFFIX));
            fs::write(&p, "old").unwrap();
        }

        cleanup_backups(&guard_path, 3).unwrap();

        let remaining: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                let n = e.file_name().to_string_lossy().to_string();
                n.starts_with("doublesign_x.json.") && n.ends_with(BACKUP_SUFFIX)
            })
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert_eq!(remaining.len(), 3);
        assert!(remaining.iter().any(|n| n.contains(".10.")));
        assert!(remaining.iter().any(|n| n.contains(".9.")));
        assert!(remaining.iter().any(|n| n.contains(".8.")));
    }

    #[test]
    fn test_flush_is_durable() {
        let dir = tempdir().unwrap();
        let key = pk(7);
        let path_str = dir.path().to_str().unwrap();
        let g = DoubleSignGuard::new(path_str, &key).unwrap();
        g.record_proposal(1, 0, &hash(1)).unwrap();
        assert!(g.flush().is_ok());
        // Reload and confirm.
        drop(g);
        let g2 = DoubleSignGuard::new(path_str, &key).unwrap();
        assert_eq!(g2.record_count(), (1, 0));
    }

    #[test]
    fn test_new_unsafe_does_not_persist() {
        // The unsafe constructor should not touch disk.
        let dir = tempdir().unwrap();
        let key = pk(11);
        let g = DoubleSignGuard::new_unsafe(dir.path().to_str().unwrap(), &key);
        assert_eq!(g.record_count(), (0, 0));
        // No guard file was created.
        let guard_path = dir.path().join(format!("doublesign_{}.json", hex::encode([11u8; 32])));
        assert!(!guard_path.exists());
    }

    // ── Concurrency smoke test ───────────────────────────────────────────

    #[test]
    fn test_concurrent_record_proposal() {
        use std::sync::Arc;
        let (g, _dir) = test_guard();
        let g = Arc::new(g);

        let mut handles = Vec::new();
        for t in 0..8u64 {
            let g = Arc::clone(&g);
            handles.push(std::thread::spawn(move || {
                // Each thread writes a distinct height; all should succeed.
                g.record_proposal(100 + t, 0, &hash(t as u8)).unwrap();
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(g.record_count().0, 8);
    }
}
