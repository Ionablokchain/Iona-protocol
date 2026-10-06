//! Sub-second finality module for IONA — Adaptive Finality.
//!
//! # Model
//!
//! Finality tracking is a **classical** rolling-window estimator (average,
//! P95, sub-second detection) combined with a lightweight adaptive-timeout
//! controller. The "quantum" naming (purity, entropy, coherence) is
//! informational only — see `FinalityStats`.
//!
//! # Guarantees
//!
//! - **Durability**: `record_commit` (when `persist_state = true`) performs
//!   an `fsync`'d atomic write (temp file + `fsync` + `rename` + parent-dir
//!   `fsync` on Unix). A crash never leaves a torn file.
//! - **Concurrency**: the tracker lock is released *before* any disk I/O.
//!   Disk slowness does not block readers.
//! - **Recovery**: a corrupt on-disk file is renamed to
//!   `<file>.corrupt.<ts>` and a fresh tracker is started, with the corrupt
//!   file preserved for post-mortem.
//!
//! # Informational-only metrics
//!
//! `purity`, `entropy`, and `adaptation_coherence` decay with activity.
//! They **never** gate a decision and **never** cause an error. They are
//! exposed via [`FinalityStats`] so operators can correlate decoherence
//! trends with network events.

use crate::consensus::CommitCertificate;
use crate::types::{Hash32, Height};
use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::VecDeque,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default rolling window size for finality statistics.
pub const DEFAULT_WINDOW_SIZE: usize = 100;

/// Minimum propose timeout (ms).
pub const MIN_PROPOSE_MS: u64 = 50;

/// Minimum vote timeout (ms).
pub const MIN_VOTE_MS: u64 = 30;

/// Maximum propose timeout (ms).
pub const MAX_PROPOSE_MS: u64 = 500;

/// Maximum vote timeout (ms).
pub const MAX_VOTE_MS: u64 = 300;

/// Default initial propose timeout (ms).
pub const DEFAULT_PROPOSE_MS: u64 = 150;

/// Default initial prevote/precommit timeout (ms).
pub const DEFAULT_VOTE_MS: u64 = 100;

/// Default adaptation strength.
pub const DEFAULT_ADAPTATION_STRENGTH: f64 = 0.1;

/// Default decoherence rate per commit recording.
pub const DEFAULT_COMMIT_DECOHERENCE_RATE: f64 = 0.0005;

/// Default minimum samples for sub-second detection.
pub const MIN_SAMPLES_FOR_SUBSECOND: usize = 10;

/// Default P95 percentile.
pub const P95_PERCENTILE: f64 = 0.95;

/// Lock acquisition timeout.
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// Temporary file suffix for atomic writes.
const TEMP_SUFFIX: &str = ".tmp";

/// Lock file suffix.
const LOCK_SUFFIX: &str = ".lock";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default fast commits before shrink.
pub const DEFAULT_FAST_COMMITS_BEFORE_SHRINK: u64 = 5;

/// Default shrink threshold (ms).
pub const DEFAULT_SHRINK_THRESHOLD_MS: u64 = 500;

/// Default grow threshold (ms).
pub const DEFAULT_GROW_THRESHOLD_MS: u64 = 800;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the finality module.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinalityConfig {
    pub window_size: usize,
    pub min_propose_ms: u64,
    pub max_propose_ms: u64,
    pub min_vote_ms: u64,
    pub max_vote_ms: u64,
    pub initial_propose_ms: u64,
    pub initial_vote_ms: u64,
    pub fast_commits_before_shrink: u64,
    pub shrink_threshold_ms: u64,
    pub grow_threshold_ms: u64,
    pub adaptation_strength: f64,
    pub decoherence_rate: f64,
    pub min_samples_for_subsecond: usize,
    pub p95_percentile: f64,
    pub persist_state: bool,
}

impl Default for FinalityConfig {
    fn default() -> Self {
        Self {
            window_size: DEFAULT_WINDOW_SIZE,
            min_propose_ms: MIN_PROPOSE_MS,
            max_propose_ms: MAX_PROPOSE_MS,
            min_vote_ms: MIN_VOTE_MS,
            max_vote_ms: MAX_VOTE_MS,
            initial_propose_ms: DEFAULT_PROPOSE_MS,
            initial_vote_ms: DEFAULT_VOTE_MS,
            fast_commits_before_shrink: DEFAULT_FAST_COMMITS_BEFORE_SHRINK,
            shrink_threshold_ms: DEFAULT_SHRINK_THRESHOLD_MS,
            grow_threshold_ms: DEFAULT_GROW_THRESHOLD_MS,
            adaptation_strength: DEFAULT_ADAPTATION_STRENGTH,
            decoherence_rate: DEFAULT_COMMIT_DECOHERENCE_RATE,
            min_samples_for_subsecond: MIN_SAMPLES_FOR_SUBSECOND,
            p95_percentile: P95_PERCENTILE,
            persist_state: true,
        }
    }
}

impl FinalityConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.window_size == 0 {
            return Err("window_size must be > 0".into());
        }
        if self.min_propose_ms > self.max_propose_ms {
            return Err("min_propose_ms must be <= max_propose_ms".into());
        }
        if self.min_vote_ms > self.max_vote_ms {
            return Err("min_vote_ms must be <= max_vote_ms".into());
        }
        if self.initial_propose_ms < self.min_propose_ms
            || self.initial_propose_ms > self.max_propose_ms
        {
            return Err("initial_propose_ms out of range".into());
        }
        if self.initial_vote_ms < self.min_vote_ms || self.initial_vote_ms > self.max_vote_ms {
            return Err("initial_vote_ms out of range".into());
        }
        if self.fast_commits_before_shrink == 0 {
            return Err("fast_commits_before_shrink must be > 0".into());
        }
        if self.shrink_threshold_ms >= self.grow_threshold_ms {
            return Err("shrink_threshold_ms must be < grow_threshold_ms".into());
        }
        if !self.adaptation_strength.is_finite()
            || !(0.0..=1.0).contains(&self.adaptation_strength)
        {
            return Err("adaptation_strength must be a finite value in [0.0, 1.0]".into());
        }
        if !self.decoherence_rate.is_finite()
            || !(0.0..=1.0).contains(&self.decoherence_rate)
        {
            return Err("decoherence_rate must be a finite value in [0.0, 1.0]".into());
        }
        if self.min_samples_for_subsecond == 0 {
            return Err("min_samples_for_subsecond must be > 0".into());
        }
        if self.min_samples_for_subsecond > self.window_size {
            return Err("min_samples_for_subsecond must be <= window_size".into());
        }
        if !self.p95_percentile.is_finite()
            || !(0.0..=1.0).contains(&self.p95_percentile)
        {
            return Err("p95_percentile must be a finite value in [0.0, 1.0]".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Persisted state
// -----------------------------------------------------------------------------

/// Versioned on-disk representation of a [`FinalityTracker`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PersistentStateV1 {
    version: u32,
    recent_finality_ms: Vec<u64>,
    window_size: usize,
    consecutive_fast_commits: u64,
    total_finalized: u64,
    best_finality_ms: u64,
    worst_finality_ms: u64,
    adaptive_propose_ms: u64,
    adaptive_prevote_ms: u64,
    adaptive_precommit_ms: u64,
    start_height: Height,
    purity: f64,
    entropy: f64,
    adaptation_coherence: f64,
    last_modified: u64,
}

impl PersistentStateV1 {
    fn from_tracker(tracker: &FinalityTracker) -> Self {
        Self {
            version: CURRENT_VERSION,
            recent_finality_ms: tracker.recent_finality_ms.iter().copied().collect(),
            window_size: tracker.window_size,
            consecutive_fast_commits: tracker.consecutive_fast_commits,
            total_finalized: tracker.total_finalized,
            best_finality_ms: tracker.best_finality_ms,
            worst_finality_ms: tracker.worst_finality_ms,
            adaptive_propose_ms: tracker.adaptive_propose_ms,
            adaptive_prevote_ms: tracker.adaptive_prevote_ms,
            adaptive_precommit_ms: tracker.adaptive_precommit_ms,
            start_height: tracker.start_height,
            purity: tracker.purity,
            entropy: tracker.entropy,
            adaptation_coherence: tracker.adaptation_coherence,
            last_modified: current_timestamp(),
        }
    }

    fn into_tracker(self) -> FinalityTracker {
        let mut t = FinalityTracker {
            recent_finality_ms: VecDeque::from(self.recent_finality_ms),
            window_size: self.window_size.max(1),
            consecutive_fast_commits: self.consecutive_fast_commits,
            total_finalized: self.total_finalized,
            best_finality_ms: self.best_finality_ms,
            worst_finality_ms: self.worst_finality_ms,
            adaptive_propose_ms: self.adaptive_propose_ms,
            adaptive_prevote_ms: self.adaptive_prevote_ms,
            adaptive_precommit_ms: self.adaptive_precommit_ms,
            start_height: self.start_height,
            purity: self.purity.clamp(0.0, 1.0),
            entropy: self.entropy.max(0.0),
            adaptation_coherence: self.adaptation_coherence.clamp(0.0, 1.0),
        };
        while t.recent_finality_ms.len() > t.window_size {
            t.recent_finality_ms.pop_front();
        }
        t
    }
}

/// Current UNIX timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Disk I/O
// -----------------------------------------------------------------------------

fn lock_path_for(path: &Path) -> PathBuf {
    path.with_extension(LOCK_SUFFIX)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(TEMP_SUFFIX);
    PathBuf::from(s)
}

/// Acquire an exclusive lock on `path`'s lock file.
///
/// Only `WouldBlock` triggers a retry (with exponential backoff). Any other
/// I/O error is returned immediately.
fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = lock_path_for(path);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file {}: {}", lock_path.display(), e))?;

    let deadline = Instant::now() + LOCK_TIMEOUT;
    let mut delay = Duration::from_millis(1);

    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(format!(
                        "lock timeout on {} after {:?}",
                        lock_path.display(),
                        LOCK_TIMEOUT
                    ));
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(format!("lock error on {}: {}", lock_path.display(), e));
            }
        }
    }
}

/// Write `bytes` to `path` atomically and durably:
/// write temp + fsync + rename + fsync parent dir (Unix).
fn atomic_write_durable(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let temp_path = temp_path_for(path);

    {
        let f = File::create(&temp_path)
            .map_err(|e| format!("create {}: {}", temp_path.display(), e))?;
        let mut w = BufWriter::new(f);
        if let Err(e) = w.write_all(bytes) {
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

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

/// Load and verify the persistent state.
///
/// Returns `Ok(None)` if the file does not exist.
fn load_persistent_state(path: &Path) -> Result<Option<PersistentStateV1>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path).map_err(|e| format!("open {}: {}", path.display(), e))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value =
        serde_json::from_reader(reader).map_err(|e| format!("parse error: {}", e))?;

    match raw.get("version").and_then(|v| v.as_u64()) {
        Some(v) if v == CURRENT_VERSION as u64 => {
            let st: PersistentStateV1 = serde_json::from_value(raw)
                .map_err(|e| format!("v{} parse error: {}", v, e))?;
            Ok(Some(st))
        }
        Some(v) => Err(format!(
            "unsupported version: {} (expected {})",
            v, CURRENT_VERSION
        )),
        None => {
            // Legacy format: try to parse the tracker directly.
            debug!(path = %path.display(), "loading legacy finality file");
            let t: FinalityTracker = serde_json::from_value(raw)
                .map_err(|e| format!("legacy parse error: {}", e))?;
            Ok(Some(PersistentStateV1::from_tracker(&t)))
        }
    }
}

/// Save a tracker to disk atomically.
fn save_persistent_state(path: &Path, tracker: &FinalityTracker) -> Result<(), String> {
    let _lock = acquire_lock(path)?;
    let st = PersistentStateV1::from_tracker(tracker);
    let json = serde_json::to_vec_pretty(&st)
        .map_err(|e| format!("serialize error: {}", e))?;
    atomic_write_durable(path, &json)
}

/// Rename a corrupt file to `<path>.corrupt.<ts>` for post-mortem.
fn quarantine_corrupt_file(path: &Path) {
    if !path.exists() {
        return;
    }
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("finality_state.json");
    let backup = path.with_file_name(format!("{}.corrupt.{}", file_name, current_timestamp()));
    match fs::rename(path, &backup) {
        Ok(()) => info!(backup = %backup.display(), "quarantined corrupt finality file"),
        Err(e) => warn!(error = %e, "failed to quarantine corrupt finality file"),
    }
}

// -----------------------------------------------------------------------------
// Finality tracker
// -----------------------------------------------------------------------------

/// Rolling-window finality tracker with an adaptive-timeout controller.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct FinalityTracker {
    /// Rolling window of recent finality times (ms).
    pub recent_finality_ms: VecDeque<u64>,
    /// Maximum window size.
    pub window_size: usize,
    /// Consecutive single-round commits.
    pub consecutive_fast_commits: u64,
    /// Total blocks finalized.
    pub total_finalized: u64,
    /// Best (lowest) finality time observed.
    pub best_finality_ms: u64,
    /// Worst (highest) finality time observed.
    pub worst_finality_ms: u64,
    /// Current adaptive propose timeout (ms).
    pub adaptive_propose_ms: u64,
    /// Current adaptive prevote timeout (ms).
    pub adaptive_prevote_ms: u64,
    /// Current adaptive precommit timeout (ms).
    pub adaptive_precommit_ms: u64,
    /// Height at which finality tracking started.
    pub start_height: Height,
    /// Informational purity γ.
    #[serde(default = "default_one")]
    pub purity: f64,
    /// Informational entropy S.
    #[serde(default)]
    pub entropy: f64,
    /// Informational adaptation coherence.
    #[serde(default = "default_one")]
    pub adaptation_coherence: f64,
}

fn default_one() -> f64 {
    1.0
}

impl Default for FinalityTracker {
    fn default() -> Self {
        Self {
            recent_finality_ms: VecDeque::with_capacity(DEFAULT_WINDOW_SIZE),
            window_size: DEFAULT_WINDOW_SIZE,
            consecutive_fast_commits: 0,
            total_finalized: 0,
            best_finality_ms: u64::MAX,
            worst_finality_ms: 0,
            adaptive_propose_ms: DEFAULT_PROPOSE_MS,
            adaptive_prevote_ms: DEFAULT_VOTE_MS,
            adaptive_precommit_ms: DEFAULT_VOTE_MS,
            start_height: 0,
            purity: 1.0,
            entropy: 0.0,
            adaptation_coherence: 1.0,
        }
    }
}

impl FinalityTracker {
    /// Create a new tracker starting at the given height.
    #[must_use]
    pub fn new(start_height: Height) -> Self {
        Self { start_height, ..Default::default() }
    }

    /// Create a tracker with the config's initial timeouts and window size.
    #[must_use]
    pub fn with_config(start_height: Height, config: &FinalityConfig) -> Self {
        Self {
            window_size: config.window_size.max(1),
            adaptive_propose_ms: config.initial_propose_ms,
            adaptive_prevote_ms: config.initial_vote_ms,
            adaptive_precommit_ms: config.initial_vote_ms,
            start_height,
            ..Default::default()
        }
    }

    /// Record a successful commit.
    ///
    /// `finality_ms` is the elapsed time from proposal to commit.
    /// `round` is the round in which the commit occurred (0 = fast path).
    pub fn record_commit(&mut self, finality_ms: u64, round: u32, config: &FinalityConfig) {
        self.total_finalized = self.total_finalized.saturating_add(1);

        if round == 0 {
            self.consecutive_fast_commits = self.consecutive_fast_commits.saturating_add(1);
        } else {
            self.consecutive_fast_commits = 0;
        }

        if finality_ms < self.best_finality_ms {
            self.best_finality_ms = finality_ms;
        }
        if finality_ms > self.worst_finality_ms {
            self.worst_finality_ms = finality_ms;
        }

        self.recent_finality_ms.push_back(finality_ms);
        while self.recent_finality_ms.len() > self.window_size {
            self.recent_finality_ms.pop_front();
        }

        self.apply_decoherence(config);
        self.adapt_timeouts(config);
    }

    fn apply_decoherence(&mut self, config: &FinalityConfig) {
        let decay = (-config.decoherence_rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.adaptation_coherence = (self.adaptation_coherence * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -(self.purity * self.purity.ln().min(0.0))
        };
    }

    /// Average finality time over the recent window.
    #[must_use]
    pub fn average_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let sum: u64 = self.recent_finality_ms.iter().sum();
        sum / self.recent_finality_ms.len() as u64
    }

    /// P95 finality time over the recent window.
    #[must_use]
    pub fn p95_finality_ms(&self, config: &FinalityConfig) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let mut sorted: Vec<u64> = self.recent_finality_ms.iter().copied().collect();
        sorted.sort_unstable();
        let idx = (sorted.len() as f64 * config.p95_percentile) as usize;
        sorted[idx.min(sorted.len() - 1)]
    }

    /// Whether the recent window meets the sub-second criterion.
    #[must_use]
    pub fn is_sub_second(&self, config: &FinalityConfig) -> bool {
        self.recent_finality_ms.len() >= config.min_samples_for_subsecond
            && self.p95_finality_ms(config) < 1000
    }

    /// Adaptive-timeout controller.
    fn adapt_timeouts(&mut self, config: &FinalityConfig) {
        let avg = self.average_finality_ms();
        if avg == 0 {
            return;
        }

        let gamma = config.adaptation_strength * self.adaptation_coherence;

        if avg < config.shrink_threshold_ms
            && self.consecutive_fast_commits >= config.fast_commits_before_shrink
        {
            let factor = (-gamma).exp();
            self.adaptive_propose_ms = ((self.adaptive_propose_ms as f64 * factor) as u64)
                .max(config.min_propose_ms);
            self.adaptive_prevote_ms = ((self.adaptive_prevote_ms as f64 * factor) as u64)
                .max(config.min_vote_ms);
            self.adaptive_precommit_ms = ((self.adaptive_precommit_ms as f64 * factor) as u64)
                .max(config.min_vote_ms);
            // Good conditions preserve/increase coherence.
            self.adaptation_coherence = (self.adaptation_coherence * 1.001).min(1.0);
        } else if avg > config.grow_threshold_ms || self.consecutive_fast_commits == 0 {
            let factor = gamma.exp();
            self.adaptive_propose_ms = ((self.adaptive_propose_ms as f64 * factor) as u64)
                .min(config.max_propose_ms);
            self.adaptive_prevote_ms = ((self.adaptive_prevote_ms as f64 * factor) as u64)
                .min(config.max_vote_ms);
            self.adaptive_precommit_ms = ((self.adaptive_precommit_ms as f64 * factor) as u64)
                .min(config.max_vote_ms);
            // Stress causes decoherence.
            self.adaptation_coherence = (self.adaptation_coherence * 0.99).max(0.0);
        }
    }

    /// Current adaptive timeouts `(propose, prevote, precommit)`.
    #[must_use]
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        (
            self.adaptive_propose_ms,
            self.adaptive_prevote_ms,
            self.adaptive_precommit_ms,
        )
    }

    /// Snapshot of statistics.
    #[must_use]
    pub fn stats(&self, config: &FinalityConfig) -> FinalityStats {
        FinalityStats {
            total_finalized: self.total_finalized,
            average_finality_ms: self.average_finality_ms(),
            p95_finality_ms: self.p95_finality_ms(config),
            best_finality_ms: if self.best_finality_ms == u64::MAX {
                0
            } else {
                self.best_finality_ms
            },
            worst_finality_ms: self.worst_finality_ms,
            consecutive_fast_commits: self.consecutive_fast_commits,
            is_sub_second: self.is_sub_second(config),
            adaptive_propose_ms: self.adaptive_propose_ms,
            adaptive_prevote_ms: self.adaptive_prevote_ms,
            adaptive_precommit_ms: self.adaptive_precommit_ms,
            purity: self.purity,
            entropy: self.entropy,
            adaptation_coherence: self.adaptation_coherence,
        }
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Statistics snapshot from the finality tracker.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FinalityStats {
    pub total_finalized: u64,
    pub average_finality_ms: u64,
    pub p95_finality_ms: u64,
    pub best_finality_ms: u64,
    pub worst_finality_ms: u64,
    pub consecutive_fast_commits: u64,
    pub is_sub_second: bool,
    pub adaptive_propose_ms: u64,
    pub adaptive_prevote_ms: u64,
    pub adaptive_precommit_ms: u64,
    pub purity: f64,
    pub entropy: f64,
    pub adaptation_coherence: f64,
}

// -----------------------------------------------------------------------------
// Finality certificate
// -----------------------------------------------------------------------------

/// Proof that a block was finalized.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct FinalityCertificate {
    pub commit: CommitCertificate,
    pub finality_ms: u64,
    pub finality_round: u32,
    pub propose_timestamp_ms: u64,
    pub finality_timestamp_ms: u64,
}

// -----------------------------------------------------------------------------
// Pipeline state
// -----------------------------------------------------------------------------

/// Pipeline state for the next height.
#[derive(Clone, Debug, PartialEq)]
pub struct PipelineState {
    /// Pre-computed transactions for the next height.
    pub next_proposal_txs: Option<Vec<crate::types::Tx>>,
    /// Whether the pipeline is active.
    pub active: bool,
    /// Height the pipeline is preparing for.
    pub pipeline_height: Height,
    /// Informational entanglement fidelity.
    pub entanglement_fidelity: f64,
    /// Successful consumes.
    pub pipeline_hits: u64,
    /// Cancelled or mismatched consumes.
    pub pipeline_misses: u64,
}

impl Default for PipelineState {
    fn default() -> Self {
        Self {
            next_proposal_txs: None,
            active: false,
            pipeline_height: 0,
            entanglement_fidelity: 1.0,
            pipeline_hits: 0,
            pipeline_misses: 0,
        }
    }
}

impl PipelineState {
    /// Begin pipelining for `height`.
    pub fn begin_pipeline(&mut self, height: Height, txs: Vec<crate::types::Tx>) {
        self.active = true;
        self.pipeline_height = height;
        self.next_proposal_txs = Some(txs);
        self.entanglement_fidelity = 0.99;
    }

    /// Consume pipelined transactions if the height matches.
    pub fn take_pipelined_txs(&mut self, height: Height) -> Option<Vec<crate::types::Tx>> {
        if self.active && self.pipeline_height == height {
            self.active = false;
            self.pipeline_hits = self.pipeline_hits.saturating_add(1);
            self.entanglement_fidelity = 1.0;
            self.next_proposal_txs.take()
        } else {
            let was_active = self.active;
            self.active = false;
            self.next_proposal_txs = None;
            if was_active {
                self.pipeline_misses = self.pipeline_misses.saturating_add(1);
                self.entanglement_fidelity *= 0.9;
            }
            None
        }
    }

    /// Cancel the pipeline.
    pub fn cancel(&mut self) {
        if !self.active {
            return;
        }
        self.active = false;
        self.next_proposal_txs = None;
        self.pipeline_misses = self.pipeline_misses.saturating_add(1);
        self.entanglement_fidelity *= 0.8;
    }

    /// Success rate over all completed pipelines, `1.0` if none ran.
    #[must_use]
    pub fn success_rate(&self) -> f64 {
        let total = self.pipeline_hits + self.pipeline_misses;
        if total == 0 {
            1.0
        } else {
            self.pipeline_hits as f64 / total as f64
        }
    }
}

// -----------------------------------------------------------------------------
// Finality manager
// -----------------------------------------------------------------------------

/// Thread-safe, optionally persistent finality manager.
#[derive(Clone)]
pub struct FinalityManager {
    tracker: Arc<Mutex<FinalityTracker>>,
    pipeline: Arc<Mutex<PipelineState>>,
    config: Arc<FinalityConfig>,
    path: Option<PathBuf>,
    commits_recorded: Arc<AtomicU64>,
}

impl FinalityManager {
    /// Create a non-persistent manager (in-memory only).
    ///
    /// Even if `config.persist_state` is `true`, no file is written because no
    /// path is configured. Use [`FinalityManager::with_persistence`] for disk
    /// persistence.
    pub fn new(start_height: Height, config: FinalityConfig) -> Result<Self, String> {
        config.validate()?;
        let tracker = FinalityTracker::with_config(start_height, &config);
        Ok(Self {
            tracker: Arc::new(Mutex::new(tracker)),
            pipeline: Arc::new(Mutex::new(PipelineState::default())),
            config: Arc::new(config),
            path: None,
            commits_recorded: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a manager persisting to `<data_dir>/finality_state.json`.
    ///
    /// If the on-disk file is corrupt, it is quarantined to
    /// `<file>.corrupt.<ts>` and a fresh tracker is started.
    pub fn with_persistence(
        data_dir: &str,
        start_height: Height,
        config: FinalityConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        let path = PathBuf::from(data_dir).join("finality_state.json");

        let tracker = if path.exists() {
            match load_persistent_state(&path) {
                Ok(Some(st)) => {
                    let mut t = st.into_tracker();
                    if t.start_height == 0 {
                        t.start_height = start_height;
                    }
                    t.window_size = config.window_size.max(1);
                    while t.recent_finality_ms.len() > t.window_size {
                        t.recent_finality_ms.pop_front();
                    }
                    t
                }
                Ok(None) => FinalityTracker::with_config(start_height, &config),
                Err(e) => {
                    warn!(error = %e, "failed to load finality state; quarantining and starting fresh");
                    quarantine_corrupt_file(&path);
                    FinalityTracker::with_config(start_height, &config)
                }
            }
        } else {
            FinalityTracker::with_config(start_height, &config)
        };

        let tracker = Arc::new(Mutex::new(tracker));
        let pipeline = Arc::new(Mutex::new(PipelineState::default()));

        let manager = Self {
            tracker,
            pipeline,
            config: Arc::new(config),
            path: Some(path),
            commits_recorded: Arc::new(AtomicU64::new(0)),
        };

        if manager.config.persist_state {
            // Initial save is fatal: the user asked for persistence.
            let snapshot = manager.tracker.lock().clone();
            if let Some(p) = &manager.path {
                save_persistent_state(p, &snapshot).map_err(|e| {
                    format!("initial finality state save failed: {}", e)
                })?;
            }
        }
        Ok(manager)
    }

    /// Record a commit.
    ///
    /// The tracker lock is released before the disk write, so a slow disk
    /// does not block readers.
    pub fn record_commit(&self, finality_ms: u64, round: u32, height: Height) {
        let snapshot = {
            let mut t = self.tracker.lock();
            t.record_commit(finality_ms, round, &self.config);
            t.clone()
        };
        self.commits_recorded.fetch_add(1, Ordering::Relaxed);

        if self.config.persist_state {
            if let Some(path) = &self.path {
                if let Err(e) = save_persistent_state(path, &snapshot) {
                    warn!(error = %e, "failed to save finality state");
                }
            }
        }

        debug!(
            height,
            round,
            finality_ms,
            avg = snapshot.average_finality_ms(),
            purity = snapshot.purity,
            "commit recorded"
        );
    }

    /// Current statistics.
    #[must_use]
    pub fn stats(&self) -> FinalityStats {
        self.tracker.lock().stats(&self.config)
    }

    /// Current adaptive timeouts.
    #[must_use]
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        self.tracker.lock().adaptive_timeouts()
    }

    /// Snapshot of the pipeline state.
    #[must_use]
    pub fn pipeline_state(&self) -> PipelineState {
        self.pipeline.lock().clone()
    }

    /// Begin pipelining for the next height.
    pub fn begin_pipeline(&self, height: Height, txs: Vec<crate::types::Tx>) {
        let mut p = self.pipeline.lock();
        p.begin_pipeline(height, txs);
        debug!(height, "pipeline started");
    }

    /// Consume pipelined transactions.
    pub fn take_pipelined_txs(&self, height: Height) -> Option<Vec<crate::types::Tx>> {
        let mut p = self.pipeline.lock();
        let txs = p.take_pipelined_txs(height);
        if txs.is_some() {
            debug!(height, "pipeline hit");
        } else {
            debug!(height, "pipeline miss");
        }
        txs
    }

    /// Cancel the pipeline.
    pub fn cancel_pipeline(&self) {
        let mut p = self.pipeline.lock();
        p.cancel();
        debug!("pipeline cancelled");
    }

    /// Force an immediate durable save.
    ///
    /// No-op if this manager was created via [`FinalityManager::new`]
    /// (no path configured). Ignores `config.persist_state` — an explicit
    /// `flush` is always honored when a path exists.
    pub fn flush(&self) -> Result<(), String> {
        let Some(path) = &self.path else {
            return Ok(());
        };
        let snapshot = self.tracker.lock().clone();
        save_persistent_state(path, &snapshot)
    }

    /// Total commits recorded via this handle.
    #[must_use]
    pub fn total_commits(&self) -> u64 {
        self.commits_recorded.load(Ordering::Relaxed)
    }

    /// Configuration.
    #[must_use]
    pub fn config(&self) -> &FinalityConfig {
        &self.config
    }

    /// Whether this manager persists to disk.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        self.path.is_some()
    }

    /// Path to the persistence file, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    /// Height at which finality tracking started.
    #[must_use]
    pub fn start_height(&self) -> Height {
        self.tracker.lock().start_height
    }

    /// Informational purity.
    #[must_use]
    pub fn purity(&self) -> f64 {
        self.tracker.lock().purity
    }

    /// Informational entropy.
    #[must_use]
    pub fn entropy(&self) -> f64 {
        self.tracker.lock().entropy
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> FinalityConfig {
        FinalityConfig {
            window_size: 20,
            fast_commits_before_shrink: 3,
            adaptation_strength: 0.1,
            decoherence_rate: 0.001,
            ..Default::default()
        }
    }

    #[test]
    fn test_tracker_basic() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        for _ in 0..10 {
            t.record_commit(100, 0, &cfg);
        }
        assert_eq!(t.total_finalized, 10);
        assert_eq!(t.consecutive_fast_commits, 10);
        assert_eq!(t.average_finality_ms(), 100);
        assert!(t.is_sub_second(&cfg));
        assert!(t.purity < 1.0);
        assert!(t.purity > 0.0);
    }

    #[test]
    fn test_adaptation_down() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        for _ in 0..20 {
            t.record_commit(80, 0, &cfg);
        }
        assert!(t.adaptive_propose_ms < DEFAULT_PROPOSE_MS);
        assert!(t.adaptive_prevote_ms < DEFAULT_VOTE_MS);
    }

    #[test]
    fn test_adaptation_up() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        for _ in 0..10 {
            t.record_commit(900, 2, &cfg);
        }
        assert!(t.adaptive_propose_ms >= DEFAULT_PROPOSE_MS);
    }

    #[test]
    fn test_adaptation_respects_bounds() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        for _ in 0..1000 {
            t.record_commit(10, 0, &cfg);
        }
        // Never below minimum.
        assert!(t.adaptive_propose_ms >= cfg.min_propose_ms);
        assert!(t.adaptive_prevote_ms >= cfg.min_vote_ms);
        // Never above maximum.
        assert!(t.adaptive_propose_ms <= cfg.max_propose_ms);

        for _ in 0..1000 {
            t.record_commit(10_000, 3, &cfg);
        }
        assert!(t.adaptive_propose_ms <= cfg.max_propose_ms);
        assert!(t.adaptive_prevote_ms <= cfg.max_vote_ms);
    }

    #[test]
    fn test_pipeline() {
        let mut p = PipelineState::default();
        p.begin_pipeline(5, vec![]);
        assert!(p.active);
        assert_eq!(p.pipeline_height, 5);
        assert!(p.take_pipelined_txs(6).is_none());
        assert_eq!(p.pipeline_misses, 1);
        p.begin_pipeline(7, vec![]);
        assert!(p.take_pipelined_txs(7).is_some());
        assert_eq!(p.pipeline_hits, 1);
    }

    #[test]
    fn test_pipeline_cancel_when_inactive_is_noop() {
        let mut p = PipelineState::default();
        p.cancel();
        assert_eq!(p.pipeline_misses, 0);
    }

    #[test]
    fn test_manager_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        {
            let m = FinalityManager::with_persistence(path, 1, cfg.clone()).unwrap();
            m.record_commit(100, 0, 1);
            m.record_commit(120, 0, 2);
        }

        let m2 = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        let stats = m2.stats();
        assert_eq!(stats.total_finalized, 2);
        assert!(stats.average_finality_ms >= 100);
        assert_eq!(m2.start_height(), 1);
    }

    #[test]
    fn test_manager_adaptive_timeouts() {
        let cfg = test_config();
        let m = FinalityManager::new(1, cfg).unwrap();
        let (p, v, pc) = m.adaptive_timeouts();
        assert_eq!(p, DEFAULT_PROPOSE_MS);
        assert_eq!(v, DEFAULT_VOTE_MS);
        assert_eq!(pc, DEFAULT_VOTE_MS);

        for i in 0..20 {
            m.record_commit(50 + i, 0, i + 1);
        }
        let (p2, v2, pc2) = m.adaptive_timeouts();
        assert!(p2 < p);
        assert!(v2 < v);
        assert!(pc2 < pc);
    }

    #[test]
    fn test_manager_stats() {
        let cfg = test_config();
        let m = FinalityManager::new(1, cfg).unwrap();
        for i in 0..15 {
            m.record_commit(100 + i * 5, 0, i + 1);
        }
        let stats = m.stats();
        assert!(stats.is_sub_second);
        assert!(stats.average_finality_ms < 1000);
        assert!(stats.purity > 0.0);
        assert!(stats.purity <= 1.0);
        assert!(stats.entropy >= 0.0);
    }

    #[test]
    fn test_manager_pipeline() {
        let cfg = test_config();
        let m = FinalityManager::new(1, cfg).unwrap();
        let txs = vec![crate::types::Tx::default()];
        m.begin_pipeline(5, txs.clone());
        let state = m.pipeline_state();
        assert!(state.active);
        assert_eq!(state.pipeline_height, 5);

        let taken = m.take_pipelined_txs(5);
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().len(), 1);
        assert!(!m.pipeline_state().active);
    }

    #[test]
    fn test_persistence_corruption_recovery() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        {
            let m = FinalityManager::with_persistence(path, 1, cfg.clone()).unwrap();
            m.record_commit(100, 0, 1);
        }

        // Corrupt the file.
        let file_path = dir.path().join("finality_state.json");
        fs::write(&file_path, "corrupted").unwrap();

        let m2 = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        assert_eq!(m2.stats().total_finalized, 0);
        assert_eq!(m2.start_height(), 1);

        // Corrupt file should have been quarantined.
        let quarantined: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.file_name()
                    .to_string_lossy()
                    .contains("finality_state.json.corrupt.")
            })
            .collect();
        assert_eq!(quarantined.len(), 1);
    }

    #[test]
    fn test_config_validation() {
        assert!(FinalityConfig::default().validate().is_ok());

        assert!(FinalityConfig { window_size: 0, ..Default::default() }
            .validate()
            .is_err());

        assert!(FinalityConfig {
            min_propose_ms: 1000,
            max_propose_ms: 500,
            ..Default::default()
        }
        .validate()
        .is_err());

        assert!(FinalityConfig {
            adaptation_strength: 1.5,
            ..Default::default()
        }
        .validate()
        .is_err());

        assert!(FinalityConfig {
            adaptation_strength: f64::NAN,
            ..Default::default()
        }
        .validate()
        .is_err());

        assert!(FinalityConfig {
            shrink_threshold_ms: 1000,
            grow_threshold_ms: 500,
            ..Default::default()
        }
        .validate()
        .is_err());

        assert!(FinalityConfig {
            fast_commits_before_shrink: 0,
            ..Default::default()
        }
        .validate()
        .is_err());

        assert!(FinalityConfig {
            min_samples_for_subsecond: 200,
            window_size: 100,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn test_manager_flush() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        let m = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        m.record_commit(100, 0, 1);
        assert!(m.flush().is_ok());
        assert_eq!(m.stats().total_finalized, 1);
    }

    #[test]
    fn test_flush_on_non_persistent_is_ok() {
        let cfg = test_config();
        let m = FinalityManager::new(1, cfg).unwrap();
        assert!(!m.is_persistent());
        assert!(m.flush().is_ok());
    }

    #[test]
    fn test_purity_decay() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        let initial = t.purity;
        for _ in 0..50 {
            t.record_commit(100, 0, &cfg);
        }
        assert!(t.purity < initial);
        assert!(t.entropy > 0.0);
    }

    #[test]
    fn test_p95_calculation() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        // window_size = 20: only last 20 samples survive.
        for i in 1..=100u64 {
            t.record_commit(i * 10, 0, &cfg);
        }
        // Last 20 samples: 810..=1000.
        let p95 = t.p95_finality_ms(&cfg);
        assert!((810..=1000).contains(&p95), "got {p95}");
    }

    #[test]
    fn test_sub_second_detection() {
        let cfg = test_config();
        let mut t = FinalityTracker::with_config(1, &cfg);
        for _ in 0..15 {
            t.record_commit(500, 0, &cfg);
        }
        assert!(t.is_sub_second(&cfg));

        for _ in 0..15 {
            t.record_commit(1200, 2, &cfg);
        }
        assert!(!t.is_sub_second(&cfg));
    }

    #[test]
    fn test_record_commit_does_not_block_on_slow_disk() {
        // Sanity: after record_commit, the lock is free for stats.
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        let m = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        m.record_commit(100, 0, 1);
        // If the lock were still held, this would deadlock.
        let _ = m.stats();
    }
}
