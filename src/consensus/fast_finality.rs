//! Sub‑second finality module for IONA — Quantum Adaptive Finality.
//!
//! # Quantum Finality Model
//!
//! Finality is modelled as a **quantum projective measurement** on the
//! consensus state. When 2/3+ validators precommit, the wavefunction
//! collapses to the |committed⟩ eigenstate.
//!
//! # Production Features
//! - Thread‑safe with `parking_lot::Mutex`
//! - Atomic writes with file locking (`flock`)
//! - Persistent state on disk
//! - Configurable adaptive parameters
//! - Comprehensive metrics and statistics
//! - Integration with consensus engine via hooks
//! - Quantum-inspired metrics (purity, entropy, coherence) that influence behavior

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
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Default rolling window size for finality statistics (coherence length).
pub const DEFAULT_WINDOW_SIZE: usize = 100;

/// Minimum propose timeout (ms) – quantum ground state.
pub const MIN_PROPOSE_MS: u64 = 50;

/// Minimum vote timeout (ms) – ground state.
pub const MIN_VOTE_MS: u64 = 30;

/// Maximum propose timeout (ms) – classical limit.
pub const MAX_PROPOSE_MS: u64 = 500;

/// Maximum vote timeout (ms) – classical limit.
pub const MAX_VOTE_MS: u64 = 300;

/// Default initial propose timeout (ms).
pub const DEFAULT_PROPOSE_MS: u64 = 150;

/// Default initial prevote/precommit timeout (ms).
pub const DEFAULT_VOTE_MS: u64 = 100;

/// Default adaptation strength (harmonic oscillator coupling).
pub const DEFAULT_ADAPTATION_STRENGTH: f64 = 0.1;

/// Default decoherence rate per commit recording.
pub const DEFAULT_COMMIT_DECOHERENCE_RATE: f64 = 0.0005;

/// Default minimum samples for sub‑second detection.
pub const MIN_SAMPLES_FOR_SUBSECOND: usize = 10;

/// Default P95 percentile.
pub const P95_PERCENTILE: f64 = 0.95;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default fast commits before shrink.
pub const DEFAULT_FAST_COMMITS_BEFORE_SHRINK: u64 = 5;

/// Default shrink threshold (ms).
pub const DEFAULT_SHRINK_THRESHOLD_MS: u64 = 500;

/// Default grow threshold (ms).
pub const DEFAULT_GROW_THRESHOLD_MS: u64 = 800;

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the finality module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityConfig {
    /// Size of the rolling window for finality times.
    pub window_size: usize,
    /// Minimum propose timeout (ms).
    pub min_propose_ms: u64,
    /// Maximum propose timeout (ms).
    pub max_propose_ms: u64,
    /// Minimum vote timeout (ms).
    pub min_vote_ms: u64,
    /// Maximum vote timeout (ms).
    pub max_vote_ms: u64,
    /// Initial propose timeout (ms).
    pub initial_propose_ms: u64,
    /// Initial vote timeout (ms).
    pub initial_vote_ms: u64,
    /// Number of consecutive single-round commits before shrinking.
    pub fast_commits_before_shrink: u64,
    /// Threshold (ms) below which timeouts shrink.
    pub shrink_threshold_ms: u64,
    /// Threshold (ms) above which timeouts grow.
    pub grow_threshold_ms: u64,
    /// Adaptation strength (0.0 – 1.0).
    pub adaptation_strength: f64,
    /// Decoherence rate per commit (0.0 – 1.0).
    pub decoherence_rate: f64,
    /// Minimum samples for sub‑second detection.
    pub min_samples_for_subsecond: usize,
    /// P95 percentile.
    pub p95_percentile: f64,
    /// Whether to persist state to disk.
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
        if !(0.0..=1.0).contains(&self.adaptation_strength) {
            return Err("adaptation_strength must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if self.min_samples_for_subsecond == 0 {
            return Err("min_samples_for_subsecond must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.p95_percentile) {
            return Err("p95_percentile must be between 0.0 and 1.0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Persistent State (versioned)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
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
        let mut tracker = FinalityTracker {
            recent_finality_ms: VecDeque::from(self.recent_finality_ms),
            window_size: self.window_size,
            consecutive_fast_commits: self.consecutive_fast_commits,
            total_finalized: self.total_finalized,
            best_finality_ms: self.best_finality_ms,
            worst_finality_ms: self.worst_finality_ms,
            adaptive_propose_ms: self.adaptive_propose_ms,
            adaptive_prevote_ms: self.adaptive_prevote_ms,
            adaptive_precommit_ms: self.adaptive_precommit_ms,
            start_height: self.start_height,
            purity: self.purity,
            entropy: self.entropy,
            adaptation_coherence: self.adaptation_coherence,
        };
        // Ensure window size matches config.
        tracker.window_size = self.window_size;
        while tracker.recent_finality_ms.len() > tracker.window_size {
            tracker.recent_finality_ms.pop_front();
        }
        tracker
    }
}

/// Current timestamp (Unix seconds).
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------------------------------------------------------------------------
// File I/O with locking and atomic writes
// -----------------------------------------------------------------------------

fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file: {}", e))?;
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let start = SystemTime::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed().unwrap_or_default() > timeout {
                    return Err(format!("lock timeout after {}s", LOCK_TIMEOUT_SECS));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), String> {
    file.unlock().map_err(|e| format!("unlock error: {}", e))
}

fn load_persistent_state(path: &Path) -> Result<Option<PersistentStateV1>, String> {
    if !path.exists() {
        return Ok(None);
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path).map_err(|e| format!("open error: {}", e))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)
        .map_err(|e| format!("parse error: {}", e))?;
    // Versioned deserialization.
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            ));
        }
        let st: PersistentStateV1 = serde_json::from_value(raw)
            .map_err(|e| format!("deserialize error: {}", e))?;
        Ok(Some(st))
    } else {
        // Legacy format: try to parse as tracker directly.
        // This is a best-effort fallback for compatibility.
        match serde_json::from_value::<FinalityTracker>(raw) {
            Ok(tracker) => {
                // Convert to V1.
                let st = PersistentStateV1::from_tracker(&tracker);
                Ok(Some(st))
            }
            Err(e) => Err(format!("legacy parse error: {}", e)),
        }
    }
}

fn save_persistent_state(path: &Path, tracker: &FinalityTracker) -> Result<(), String> {
    let st = PersistentStateV1::from_tracker(tracker);
    let json = serde_json::to_string_pretty(&st)
        .map_err(|e| format!("serialize error: {}", e))?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)
        .map_err(|e| format!("write temp error: {}", e))?;
    fs::rename(&temp_path, path)
        .map_err(|e| format!("rename error: {}", e))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Finality Tracker (Thread‑safe)
// -----------------------------------------------------------------------------

/// Tracks finality timing with quantum state properties.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalityTracker {
    /// Rolling window of recent finality times (measurement outcomes).
    pub recent_finality_ms: VecDeque<u64>,
    /// Maximum window size (Hilbert space dimension bound).
    pub window_size: usize,
    /// Number of consecutive single‑round commits (coherence indicator).
    pub consecutive_fast_commits: u64,
    /// Total blocks finalized (cumulative measurement count).
    pub total_finalized: u64,
    /// Best (lowest) finality time observed.
    pub best_finality_ms: u64,
    /// Worst (highest) finality time observed.
    pub worst_finality_ms: u64,
    /// Current adaptive propose timeout (oscillator frequency).
    pub adaptive_propose_ms: u64,
    /// Current adaptive prevote timeout.
    pub adaptive_prevote_ms: u64,
    /// Current adaptive precommit timeout.
    pub adaptive_precommit_ms: u64,
    /// Height at which finality tracking started.
    pub start_height: Height,
    /// Quantum purity γ = Tr(ρ²) of the finality state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    #[serde(default)]
    pub entropy: f64,
    /// Coherence of the adaptation oscillator.
    #[serde(default = "default_purity")]
    pub adaptation_coherence: f64,
}

fn default_purity() -> f64 {
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
    /// Create a new quantum tracker starting at the given height.
    #[must_use]
    pub fn new(start_height: Height) -> Self {
        Self {
            start_height,
            ..Default::default()
        }
    }

    /// Create a tracker with custom configuration.
    #[must_use]
    pub fn with_config(start_height: Height, config: &FinalityConfig) -> Self {
        Self {
            window_size: config.window_size,
            adaptive_propose_ms: config.initial_propose_ms,
            adaptive_prevote_ms: config.initial_vote_ms,
            adaptive_precommit_ms: config.initial_vote_ms,
            start_height,
            ..Default::default()
        }
    }

    /// Record a successful commit — projective measurement outcome.
    ///
    /// Each commit collapses the quantum state slightly.
    pub fn record_commit(&mut self, finality_ms: u64, round: u32, config: &FinalityConfig) {
        self.total_finalized = self.total_finalized.wrapping_add(1);

        // Track fast commits (coherence preservation)
        if round == 0 {
            self.consecutive_fast_commits = self.consecutive_fast_commits.wrapping_add(1);
        } else {
            self.consecutive_fast_commits = 0;
        }

        // Update classical statistics
        if finality_ms < self.best_finality_ms {
            self.best_finality_ms = finality_ms;
        }
        if finality_ms > self.worst_finality_ms {
            self.worst_finality_ms = finality_ms;
        }

        // Update rolling window (quantum memory)
        self.recent_finality_ms.push_back(finality_ms);
        while self.recent_finality_ms.len() > self.window_size {
            self.recent_finality_ms.pop_front();
        }

        // Apply measurement decoherence
        self.apply_decoherence(config);

        // Adapt timeouts (harmonic oscillator evolution)
        self.adapt_timeouts(config);
    }

    /// Apply decoherence from measurement.
    fn apply_decoherence(&mut self, config: &FinalityConfig) {
        let decay = (-config.decoherence_rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.adaptation_coherence = (self.adaptation_coherence * decay).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
    }

    /// Average finality time over the recent window (expectation value).
    #[must_use]
    pub fn average_finality_ms(&self) -> u64 {
        if self.recent_finality_ms.is_empty() {
            return 0;
        }
        let sum: u64 = self.recent_finality_ms.iter().sum();
        sum / self.recent_finality_ms.len() as u64
    }

    /// P95 finality time (95th percentile of measurement distribution).
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

    /// Whether we are consistently achieving sub‑second finality.
    #[must_use]
    pub fn is_sub_second(&self, config: &FinalityConfig) -> bool {
        self.recent_finality_ms.len() >= config.min_samples_for_subsecond
            && self.p95_finality_ms(config) < 1000
    }

    /// Adapt timeouts — quantum harmonic oscillator evolution.
    ///
    /// ```text
    /// τ(t+dt) = τ(t) × exp(±γ × dt)
    /// where γ = adaptation_strength × adaptation_coherence
    /// ```
    fn adapt_timeouts(&mut self, config: &FinalityConfig) {
        let avg = self.average_finality_ms();
        if avg == 0 {
            return;
        }

        let gamma = config.adaptation_strength * self.adaptation_coherence;

        if avg < config.shrink_threshold_ms
            && self.consecutive_fast_commits >= config.fast_commits_before_shrink
        {
            // Network is healthy: shrink timeouts toward minimum.
            let factor = (-gamma).exp();
            self.adaptive_propose_ms = ((self.adaptive_propose_ms as f64 * factor) as u64)
                .max(config.min_propose_ms);
            self.adaptive_prevote_ms = ((self.adaptive_prevote_ms as f64 * factor) as u64)
                .max(config.min_vote_ms);
            self.adaptive_precommit_ms = ((self.adaptive_precommit_ms as f64 * factor) as u64)
                .max(config.min_vote_ms);
            // Adaptation preserves coherence
            self.adaptation_coherence = (self.adaptation_coherence * 1.001).min(1.0);
        } else if avg > config.grow_threshold_ms || self.consecutive_fast_commits == 0 {
            // Network is stressed: grow timeouts toward maximum.
            let factor = gamma.exp();
            self.adaptive_propose_ms = ((self.adaptive_propose_ms as f64 * factor) as u64)
                .min(config.max_propose_ms);
            self.adaptive_prevote_ms = ((self.adaptive_prevote_ms as f64 * factor) as u64)
                .min(config.max_vote_ms);
            self.adaptive_precommit_ms = ((self.adaptive_precommit_ms as f64 * factor) as u64)
                .min(config.max_vote_ms);
            // Stress causes decoherence
            self.adaptation_coherence = (self.adaptation_coherence * 0.99).max(0.0);
        }
    }

    /// Get current adaptive timeouts.
    #[must_use]
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        (
            self.adaptive_propose_ms,
            self.adaptive_prevote_ms,
            self.adaptive_precommit_ms,
        )
    }

    /// Report quantum finality statistics.
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
// Statistics Structure
// -----------------------------------------------------------------------------

/// Quantum statistics snapshot from the finality tracker.
#[derive(Clone, Debug, Serialize, Deserialize)]
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
// Finality Certificate
// -----------------------------------------------------------------------------

/// A finality certificate that proves a block was finalized.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalityCertificate {
    pub commit: CommitCertificate,
    pub finality_ms: u64,
    pub finality_round: u32,
    pub propose_timestamp_ms: u64,
    pub finality_timestamp_ms: u64,
}

// -----------------------------------------------------------------------------
// Quantum Pipeline State
// -----------------------------------------------------------------------------

/// Pipeline state with quantum entanglement between prepare and commit phases.
#[derive(Clone, Debug)]
pub struct PipelineState {
    /// Pre‑computed proposal data for the next height.
    pub next_proposal_txs: Option<Vec<crate::types::Tx>>,
    /// Whether the pipeline is active (entanglement exists).
    pub active: bool,
    /// Height for which the pipeline is preparing.
    pub pipeline_height: Height,
    /// Entanglement fidelity with the current commit.
    pub entanglement_fidelity: f64,
    /// Number of times the pipeline has been used successfully.
    pub pipeline_hits: u64,
    /// Number of times the pipeline was cancelled.
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
    /// Begin pipelining: entangle next height preparation with current commit.
    pub fn begin_pipeline(&mut self, height: Height, txs: Vec<crate::types::Tx>) {
        self.active = true;
        self.pipeline_height = height;
        self.next_proposal_txs = Some(txs);
        self.entanglement_fidelity = 0.99; // High but not perfect
    }

    /// Consume pipelined transactions if they match the expected height.
    pub fn take_pipelined_txs(&mut self, height: Height) -> Option<Vec<crate::types::Tx>> {
        if self.active && self.pipeline_height == height {
            self.active = false;
            self.pipeline_hits = self.pipeline_hits.wrapping_add(1);
            self.entanglement_fidelity = 1.0;
            self.next_proposal_txs.take()
        } else {
            self.active = false;
            self.next_proposal_txs = None;
            self.pipeline_misses = self.pipeline_misses.wrapping_add(1);
            self.entanglement_fidelity *= 0.9;
            None
        }
    }

    /// Cancel the pipeline — decoherence event.
    pub fn cancel(&mut self) {
        self.active = false;
        self.next_proposal_txs = None;
        self.pipeline_misses = self.pipeline_misses.wrapping_add(1);
        self.entanglement_fidelity *= 0.8;
    }

    /// Get pipeline success rate.
    pub fn success_rate(&self) -> f64 {
        let total = self.pipeline_hits + self.pipeline_misses;
        if total == 0 {
            return 1.0;
        }
        self.pipeline_hits as f64 / total as f64
    }
}

// -----------------------------------------------------------------------------
// FinalityManager — Thread‑safe, persistent, configurable
// -----------------------------------------------------------------------------

/// Manages finality tracking with persistence and thread‑safety.
#[derive(Clone)]
pub struct FinalityManager {
    tracker: Arc<Mutex<FinalityTracker>>,
    pipeline: Arc<Mutex<PipelineState>>,
    config: Arc<FinalityConfig>,
    path: Option<PathBuf>,
    /// Counter for total commits recorded.
    commits_recorded: Arc<AtomicU64>,
}

impl FinalityManager {
    /// Create a new manager from configuration.
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

    /// Create with persistence to a file.
    pub fn with_persistence(
        data_dir: &str,
        start_height: Height,
        config: FinalityConfig,
    ) -> Result<Self, String> {
        config.validate()?;
        let path = PathBuf::from(data_dir).join("finality_state.json");
        let mut tracker = if path.exists() {
            match load_persistent_state(&path) {
                Ok(Some(st)) => {
                    let mut t = st.into_tracker();
                    // Ensure start_height matches (or use stored).
                    if t.start_height == 0 {
                        t.start_height = start_height;
                    }
                    t
                }
                Ok(None) => FinalityTracker::with_config(start_height, &config),
                Err(e) => {
                    warn!(error = %e, "failed to load finality state, starting fresh");
                    FinalityTracker::with_config(start_height, &config)
                }
            }
        } else {
            FinalityTracker::with_config(start_height, &config)
        };
        // Ensure window size matches config.
        tracker.window_size = config.window_size;
        while tracker.recent_finality_ms.len() > tracker.window_size {
            tracker.recent_finality_ms.pop_front();
        }
        let tracker = Arc::new(Mutex::new(tracker));
        let pipeline = Arc::new(Mutex::new(PipelineState::default()));

        let manager = Self {
            tracker,
            pipeline,
            config: Arc::new(config),
            path: Some(path),
            commits_recorded: Arc::new(AtomicU64::new(0)),
        };
        // Save initial state.
        if manager.config.persist_state {
            if let Some(p) = &manager.path {
                let t = manager.tracker.lock();
                if let Err(e) = save_persistent_state(p, &t) {
                    warn!(error = %e, "failed to save initial finality state");
                }
            }
        }
        Ok(manager)
    }

    /// Record a commit (projective measurement).
    pub fn record_commit(&self, finality_ms: u64, round: u32, height: Height) {
        let mut tracker = self.tracker.lock();
        tracker.record_commit(finality_ms, round, &self.config);
        self.commits_recorded.fetch_add(1, Ordering::Relaxed);

        // Persist if enabled.
        if self.config.persist_state {
            if let Some(path) = &self.path {
                if let Err(e) = save_persistent_state(path, &tracker) {
                    warn!(error = %e, "failed to save finality state");
                }
            }
        }
        debug!(
            height,
            round,
            finality_ms,
            avg = tracker.average_finality_ms(),
            purity = tracker.purity,
            "commit recorded"
        );
    }

    /// Get current statistics.
    pub fn stats(&self) -> FinalityStats {
        let tracker = self.tracker.lock();
        tracker.stats(&self.config)
    }

    /// Get current adaptive timeouts.
    pub fn adaptive_timeouts(&self) -> (u64, u64, u64) {
        let tracker = self.tracker.lock();
        tracker.adaptive_timeouts()
    }

    /// Get pipeline state.
    pub fn pipeline_state(&self) -> PipelineState {
        self.pipeline.lock().clone()
    }

    /// Begin pipelining for the next height.
    pub fn begin_pipeline(&self, height: Height, txs: Vec<crate::types::Tx>) {
        let mut pipeline = self.pipeline.lock();
        pipeline.begin_pipeline(height, txs);
        debug!(height, "pipeline started");
    }

    /// Consume pipelined transactions.
    pub fn take_pipelined_txs(&self, height: Height) -> Option<Vec<crate::types::Tx>> {
        let mut pipeline = self.pipeline.lock();
        let txs = pipeline.take_pipelined_txs(height);
        if txs.is_some() {
            debug!(height, "pipeline hit");
        } else {
            debug!(height, "pipeline miss");
        }
        txs
    }

    /// Cancel pipeline.
    pub fn cancel_pipeline(&self) {
        let mut pipeline = self.pipeline.lock();
        pipeline.cancel();
        debug!("pipeline cancelled");
    }

    /// Force save state to disk.
    pub fn flush(&self) -> Result<(), String> {
        if let Some(path) = &self.path {
            let tracker = self.tracker.lock();
            save_persistent_state(path, &tracker)?;
        }
        Ok(())
    }

    /// Total commits recorded.
    pub fn total_commits(&self) -> u64 {
        self.commits_recorded.load(Ordering::Relaxed)
    }

    /// Get configuration.
    pub fn config(&self) -> &FinalityConfig {
        &self.config
    }

    /// Get current purity.
    pub fn purity(&self) -> f64 {
        self.tracker.lock().purity
    }

    /// Get current entropy.
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
        let mut cfg = FinalityConfig::default();
        cfg.window_size = 20;
        cfg.fast_commits_before_shrink = 3;
        cfg.adaptation_strength = 0.1;
        cfg.decoherence_rate = 0.001;
        cfg
    }

    #[test]
    fn test_tracker_basic() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        for _ in 0..10 {
            tracker.record_commit(100, 0, &cfg);
        }
        assert_eq!(tracker.total_finalized, 10);
        assert_eq!(tracker.consecutive_fast_commits, 10);
        assert_eq!(tracker.average_finality_ms(), 100);
        assert!(tracker.is_sub_second(&cfg));
        assert!(tracker.purity < 1.0);
    }

    #[test]
    fn test_adaptation_down() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        for _ in 0..20 {
            tracker.record_commit(80, 0, &cfg);
        }
        assert!(tracker.adaptive_propose_ms < DEFAULT_PROPOSE_MS);
        assert!(tracker.adaptive_prevote_ms < DEFAULT_VOTE_MS);
    }

    #[test]
    fn test_adaptation_up() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        for _ in 0..10 {
            tracker.record_commit(900, 2, &cfg);
        }
        assert!(tracker.adaptive_propose_ms >= DEFAULT_PROPOSE_MS);
    }

    #[test]
    fn test_pipeline() {
        let mut ps = PipelineState::default();
        ps.begin_pipeline(5, vec![]);
        assert!(ps.active);
        assert_eq!(ps.pipeline_height, 5);
        assert!(ps.take_pipelined_txs(6).is_none());
        assert_eq!(ps.pipeline_misses, 1);
        ps.begin_pipeline(7, vec![]);
        assert!(ps.take_pipelined_txs(7).is_some());
        assert_eq!(ps.pipeline_hits, 1);
    }

    #[test]
    fn test_manager_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        let manager = FinalityManager::with_persistence(path, 1, cfg.clone()).unwrap();
        manager.record_commit(100, 0, 1);
        manager.record_commit(120, 0, 2);
        drop(manager);

        let manager2 = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        let stats = manager2.stats();
        assert_eq!(stats.total_finalized, 2);
        assert!(stats.average_finality_ms >= 100);
    }

    #[test]
    fn test_manager_adaptive_timeouts() {
        let cfg = test_config();
        let manager = FinalityManager::new(1, cfg).unwrap();
        let (p, v, pc) = manager.adaptive_timeouts();
        assert_eq!(p, DEFAULT_PROPOSE_MS);
        assert_eq!(v, DEFAULT_VOTE_MS);
        assert_eq!(pc, DEFAULT_VOTE_MS);

        // Simulate fast commits.
        for i in 0..20 {
            manager.record_commit(50 + i, 0, i + 1);
        }
        let (p2, v2, pc2) = manager.adaptive_timeouts();
        assert!(p2 < p);
        assert!(v2 < v);
        assert!(pc2 < pc);
    }

    #[test]
    fn test_manager_stats() {
        let cfg = test_config();
        let manager = FinalityManager::new(1, cfg).unwrap();
        for i in 0..15 {
            manager.record_commit(100 + i * 5, 0, i + 1);
        }
        let stats = manager.stats();
        assert!(stats.is_sub_second);
        assert!(stats.average_finality_ms < 1000);
        assert!(stats.purity > 0.0);
        assert!(stats.purity <= 1.0);
        assert!(stats.entropy >= 0.0);
    }

    #[test]
    fn test_manager_pipeline() {
        let cfg = test_config();
        let manager = FinalityManager::new(1, cfg).unwrap();
        let txs = vec![crate::types::Tx::default()];
        manager.begin_pipeline(5, txs.clone());
        let state = manager.pipeline_state();
        assert!(state.active);
        assert_eq!(state.pipeline_height, 5);

        let taken = manager.take_pipelined_txs(5);
        assert!(taken.is_some());
        assert_eq!(taken.unwrap().len(), 1);

        let state2 = manager.pipeline_state();
        assert!(!state2.active);
    }

    #[test]
    fn test_persistence_corruption_recovery() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        let manager = FinalityManager::with_persistence(path, 1, cfg.clone()).unwrap();
        manager.record_commit(100, 0, 1);
        drop(manager);

        // Corrupt the file.
        let file_path = dir.path().join("finality_state.json");
        fs::write(&file_path, "corrupted").unwrap();

        let manager2 = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        // Should start fresh but keep existing height.
        let stats = manager2.stats();
        assert_eq!(stats.total_finalized, 0); // fresh state
        assert_eq!(manager2.tracker.lock().start_height, 1);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = FinalityConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.window_size = 0;
        assert!(cfg.validate().is_err());

        cfg.window_size = 10;
        cfg.min_propose_ms = 1000;
        cfg.max_propose_ms = 500;
        assert!(cfg.validate().is_err());

        cfg.min_propose_ms = 50;
        cfg.max_propose_ms = 500;
        cfg.adaptation_strength = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_manager_flush() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();
        let manager = FinalityManager::with_persistence(path, 1, cfg).unwrap();
        manager.record_commit(100, 0, 1);
        assert!(manager.flush().is_ok());

        let stats = manager.stats();
        assert_eq!(stats.total_finalized, 1);
    }

    #[test]
    fn test_purity_decay() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        let initial = tracker.purity;
        for _ in 0..50 {
            tracker.record_commit(100, 0, &cfg);
        }
        assert!(tracker.purity < initial);
        assert!(tracker.entropy > 0.0);
    }

    #[test]
    fn test_p95_calculation() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        for i in 1..=100 {
            tracker.record_commit(i * 10, 0, &cfg);
        }
        let p95 = tracker.p95_finality_ms(&cfg);
        assert!(p95 >= 940 && p95 <= 960);
    }

    #[test]
    fn test_sub_second_detection() {
        let cfg = test_config();
        let mut tracker = FinalityTracker::with_config(1, &cfg);
        for _ in 0..15 {
            tracker.record_commit(500, 0, &cfg);
        }
        assert!(tracker.is_sub_second(&cfg));

        // Introduce slow commits.
        for _ in 0..15 {
            tracker.record_commit(1200, 2, &cfg);
        }
        assert!(!tracker.is_sub_second(&cfg));
    }
}
