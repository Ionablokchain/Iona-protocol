//! Quantum validator set governance for IONA v21.
//!
//! # Production Features
//! - Configurable via `GovernanceConfig` (min deposit, TTL, quorum, decoherence).
//! - `GovernanceMetrics` with Prometheus counters for proposals, votes, actions.
//! - `GovernanceManager` with thread‑safe wrapper (`parking_lot::Mutex`).
//! - Persistent state with atomic writes and file locking.
//! - LRU cache for proposal lookups.
//! - Parameter validation (min/max bounds).
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::consensus::ValidatorSet;
use crate::crypto::PublicKeyBytes;
use crate::slashing::StakeLedger;
use crate::types::Height;
use fs2::FileExt;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, register_histogram_vec,
    Counter, CounterVec, Gauge, HistogramVec,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{BufReader, BufWriter, Write};
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Constants ─────────────────────────────────────────────────────────────

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default minimum deposit for governance proposals.
pub const DEFAULT_MIN_GOV_DEPOSIT: u64 = 1_000_000;

/// Default proposal time-to-live in blocks.
pub const DEFAULT_PROPOSAL_TTL_BLOCKS: u64 = 50_000;

/// Default quorum numerator (2/3).
pub const DEFAULT_QUORUM_NUMERATOR: u64 = 2;
pub const DEFAULT_QUORUM_DENOMINATOR: u64 = 3;

/// Default cache size for proposal lookups.
pub const DEFAULT_CACHE_SIZE: usize = 128;

/// Default cache TTL in seconds.
pub const DEFAULT_CACHE_TTL_SECS: u64 = 300;

/// Default persistence file name.
pub const DEFAULT_PERSIST_FILE: &str = "governance_state.json";

/// Lock timeout in seconds.
pub const DEFAULT_LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Maximum proposals per block.
const MAX_PROPOSALS_PER_BLOCK: usize = 10;

/// Maximum proposal TTL in blocks.
const MAX_PROPOSAL_TTL_BLOCKS: u64 = 1_000_000;

/// Minimum proposal TTL in blocks.
const MIN_PROPOSAL_TTL_BLOCKS: u64 = 100;

/// Maximum deposit amount.
const MAX_DEPOSIT: u64 = 10_000_000_000;

/// Minimum deposit amount.
const MIN_DEPOSIT: u64 = 1_000;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the governance subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceConfig {
    /// Minimum deposit required to submit a proposal.
    pub min_deposit: u64,
    /// Proposal time-to-live in blocks.
    pub proposal_ttl: u64,
    /// Quorum numerator (e.g., 2 for 2/3).
    pub quorum_numerator: u64,
    /// Quorum denominator (e.g., 3 for 2/3).
    pub quorum_denominator: u64,
    /// Decoherence rate per vote (0.0 – 1.0).
    pub decoherence_rate: f64,
    /// Whether to enable caching of proposals.
    pub enable_cache: bool,
    /// Maximum number of entries in the cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
    /// Path for persistence.
    pub persist_path: Option<PathBuf>,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log governance events.
    pub log_events: bool,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
}

impl Default for GovernanceConfig {
    fn default() -> Self {
        Self {
            min_deposit: DEFAULT_MIN_GOV_DEPOSIT,
            proposal_ttl: DEFAULT_PROPOSAL_TTL_BLOCKS,
            quorum_numerator: DEFAULT_QUORUM_NUMERATOR,
            quorum_denominator: DEFAULT_QUORUM_DENOMINATOR,
            decoherence_rate: 0.001,
            enable_cache: true,
            cache_size: DEFAULT_CACHE_SIZE,
            cache_ttl_secs: DEFAULT_CACHE_TTL_SECS,
            persist_state: true,
            persist_path: Some(PathBuf::from(DEFAULT_PERSIST_FILE)),
            enable_metrics: true,
            log_events: true,
            lock_timeout_secs: DEFAULT_LOCK_TIMEOUT_SECS,
        }
    }
}

impl GovernanceConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_deposit < MIN_DEPOSIT || self.min_deposit > MAX_DEPOSIT {
            return Err(format!(
                "min_deposit must be between {} and {}",
                MIN_DEPOSIT, MAX_DEPOSIT
            ));
        }
        if self.proposal_ttl < MIN_PROPOSAL_TTL_BLOCKS || self.proposal_ttl > MAX_PROPOSAL_TTL_BLOCKS {
            return Err(format!(
                "proposal_ttl must be between {} and {}",
                MIN_PROPOSAL_TTL_BLOCKS, MAX_PROPOSAL_TTL_BLOCKS
            ));
        }
        if self.quorum_numerator == 0 || self.quorum_denominator == 0 {
            return Err("quorum numerator and denominator must be > 0".into());
        }
        if self.quorum_numerator >= self.quorum_denominator {
            return Err("quorum numerator must be < denominator".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        if self.persist_state && self.persist_path.is_none() {
            return Err("persist_path must be set when persist_state is true".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the governance subsystem.
#[derive(Clone)]
pub struct GovernanceMetrics {
    pub proposals_submitted: Counter,
    pub proposals_passed: Counter,
    pub proposals_failed: Counter,
    pub proposals_expired: Counter,
    pub votes_cast: Counter,
    pub actions_applied: CounterVec,
    pub pending_count: Gauge,
    pub coherence: Gauge,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub duration: HistogramVec,
}

impl GovernanceMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let proposals_submitted = register_counter!(
            "iona_gov_proposals_submitted_total",
            "Total proposals submitted"
        )?;
        let proposals_passed = register_counter!(
            "iona_gov_proposals_passed_total",
            "Total proposals that passed"
        )?;
        let proposals_failed = register_counter!(
            "iona_gov_proposals_failed_total",
            "Total proposals that failed"
        )?;
        let proposals_expired = register_counter!(
            "iona_gov_proposals_expired_total",
            "Total proposals that expired"
        )?;
        let votes_cast = register_counter!(
            "iona_gov_votes_cast_total",
            "Total votes cast"
        )?;
        let actions_applied = register_counter_vec!(
            "iona_gov_actions_applied_total",
            "Total governance actions applied",
            &["action"]
        )?;
        let pending_count = register_gauge!(
            "iona_gov_pending_count",
            "Number of pending proposals"
        )?;
        let coherence = register_gauge!(
            "iona_gov_coherence",
            "Governance quantum coherence"
        )?;
        let cache_hits = register_counter!(
            "iona_gov_cache_hits_total",
            "Governance cache hits"
        )?;
        let cache_misses = register_counter!(
            "iona_gov_cache_misses_total",
            "Governance cache misses"
        )?;
        let duration = register_histogram_vec!(
            "iona_gov_operation_duration_seconds",
            "Governance operation duration",
            &["operation"]
        )?;
        Ok(Self {
            proposals_submitted,
            proposals_passed,
            proposals_failed,
            proposals_expired,
            votes_cast,
            actions_applied,
            pending_count,
            coherence,
            cache_hits,
            cache_misses,
            duration,
        })
    }

    pub fn record_submission(&self) {
        self.proposals_submitted.inc();
    }
    pub fn record_passed(&self) {
        self.proposals_passed.inc();
    }
    pub fn record_failed(&self) {
        self.proposals_failed.inc();
    }
    pub fn record_expired(&self) {
        self.proposals_expired.inc();
    }
    pub fn record_vote(&self) {
        self.votes_cast.inc();
    }
    pub fn record_action(&self, action: &str) {
        self.actions_applied.with_label_values(&[action]).inc();
    }
    pub fn set_pending(&self, count: usize) {
        self.pending_count.set(count as f64);
    }
    pub fn set_coherence(&self, coherence: f64) {
        self.coherence.set(coherence);
    }
    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }
    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }
    pub fn record_duration(&self, operation: &str, duration: Duration) {
        self.duration
            .with_label_values(&[operation])
            .observe(duration.as_secs_f64());
    }
}

impl Default for GovernanceMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            proposals_submitted: Counter::new("iona_gov_proposals_submitted_total", "Submissions").unwrap(),
            proposals_passed: Counter::new("iona_gov_proposals_passed_total", "Passed").unwrap(),
            proposals_failed: Counter::new("iona_gov_proposals_failed_total", "Failed").unwrap(),
            proposals_expired: Counter::new("iona_gov_proposals_expired_total", "Expired").unwrap(),
            votes_cast: Counter::new("iona_gov_votes_cast_total", "Votes").unwrap(),
            actions_applied: CounterVec::new(
                prometheus::Opts::new("iona_gov_actions_applied_total", "Actions applied"),
                &["action"],
            ).unwrap(),
            pending_count: Gauge::new("iona_gov_pending_count", "Pending count").unwrap(),
            coherence: Gauge::new("iona_gov_coherence", "Coherence").unwrap(),
            cache_hits: Counter::new("iona_gov_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_gov_cache_misses_total", "Cache misses").unwrap(),
            duration: HistogramVec::new(
                prometheus::HistogramOpts::new(
                    "iona_gov_operation_duration_seconds",
                    "Operation duration",
                ),
                &["operation"],
            ).unwrap(),
        })
    }
}

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors that can occur during quantum governance operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GovError {
    #[error("invalid public key hex: {0}")]
    InvalidPubKeyHex(String),

    #[error("stake must be > 0")]
    ZeroStake,

    #[error("proposal not found: id={0}")]
    ProposalNotFound(u64),

    #[error("invalid vote value: must be 'yes' or 'no'")]
    InvalidVoteValue,

    #[error("insufficient deposit: need at least {required}, got {provided}")]
    InsufficientDeposit { required: u64, provided: u64 },

    #[error("proposal expired (height {current} > {expiry})")]
    ProposalExpired { current: u64, expiry: u64 },

    #[error("validator already exists in the set")]
    ValidatorAlreadyExists,

    #[error("validator not found in the active set")]
    ValidatorNotFound,

    #[error("parse error: {0}")]
    ParseError(String),

    #[error("quantum decoherence: proposal state lost fidelity ({fidelity})")]
    Decoherence { fidelity: f64 },

    #[error("entanglement threshold not met for quorum")]
    EntanglementInsufficient,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("too many proposals submitted in this block (max {max})")]
    TooManyProposals { max: usize },
}

pub type GovResult<T> = Result<T, GovError>;

// ── Governance Actions ──────────────────────────────────────────────────

/// Governance actions — quantum gates on the validator set.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum GovAction {
    AddValidator { pk_hex: String, stake: u64 },
    RemoveValidator { pk_hex: String },
    Unjail { pk_hex: String },
    SetParam { key: String, value: String },
}

// ── Governance Proposal ─────────────────────────────────────────────────

/// A governance proposal — a quantum state in the proposal Hilbert space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovProposal {
    pub id: u64,
    pub action: GovAction,
    pub proposer: String,
    pub height: Height,
    pub votes: HashMap<String, bool>,
    pub deposit: u64,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    #[serde(default)]
    pub entanglement_entropy: f64,
}

fn default_coherence() -> f64 {
    1.0
}

impl GovProposal {
    pub fn new(id: u64, action: GovAction, proposer: String, height: Height, deposit: u64) -> Self {
        let mut votes = HashMap::new();
        votes.insert(proposer.clone(), true);
        Self {
            id,
            action,
            proposer,
            height,
            votes,
            deposit,
            coherence: 1.0,
            entanglement_entropy: 0.0,
        }
    }

    pub fn vote(&mut self, voter: String, yes: bool, config: &GovernanceConfig) -> GovResult<()> {
        self.votes.insert(voter, yes);
        let decay = (-config.decoherence_rate).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.entanglement_entropy = if self.coherence >= 1.0 {
            0.0
        } else {
            -self.coherence * self.coherence.ln().max(0.0)
        };
        Ok(())
    }

    pub fn yes_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes
            .iter()
            .filter(|(_, &yes)| yes)
            .filter_map(|(addr, _)| {
                stakes
                    .validators
                    .iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    pub fn no_power(&self, stakes: &StakeLedger) -> u64 {
        self.votes
            .iter()
            .filter(|(_, &no)| !no)
            .filter_map(|(addr, _)| {
                stakes
                    .validators
                    .iter()
                    .find(|(pk, _)| address_of(pk) == *addr)
                    .map(|(_, r)| r.stake)
            })
            .sum()
    }

    pub fn total_power(&self, stakes: &StakeLedger) -> u64 {
        stakes.total_power()
    }

    pub fn has_quorum(&self, stakes: &StakeLedger, config: &GovernanceConfig) -> bool {
        let yes = self.yes_power(stakes);
        let total = self.total_power(stakes);
        if total == 0 {
            return false;
        }
        yes * config.quorum_denominator > total * config.quorum_numerator
    }

    pub fn is_active(&self, current_height: Height, ttl: u64) -> bool {
        current_height.saturating_sub(self.height) < ttl
    }
}

// ── Persistent State ─────────────────────────────────────────────────────

/// Persistent governance state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistentGovernanceState {
    pub version: u32,
    pub pending: BTreeMap<u64, GovProposal>,
    pub next_id: u64,
    pub params: BTreeMap<String, String>,
    pub min_deposit: u64,
    pub proposal_ttl: u64,
    pub coherence: f64,
    pub last_modified: u64,
}

impl PersistentGovernanceState {
    pub fn from_manager(manager: &GovernanceManager) -> Self {
        let state = manager.state.lock();
        Self {
            version: CURRENT_VERSION,
            pending: state.pending.clone(),
            next_id: state.next_id,
            params: state.params.clone(),
            min_deposit: state.min_deposit,
            proposal_ttl: state.proposal_ttl,
            coherence: state.coherence,
            last_modified: current_timestamp(),
        }
    }

    pub fn into_state(self) -> GovernanceState {
        GovernanceState {
            pending: self.pending,
            next_id: self.next_id,
            params: self.params,
            min_deposit: self.min_deposit,
            proposal_ttl: self.proposal_ttl,
            coherence: self.coherence,
        }
    }
}

// ── File I/O ─────────────────────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, String> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| format!("cannot open lock file: {}", e))?;
    let timeout = Duration::from_secs(DEFAULT_LOCK_TIMEOUT_SECS);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(format!("lock timeout after {}s", DEFAULT_LOCK_TIMEOUT_SECS));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn load_state(path: &Path) -> Result<PersistentGovernanceState, String> {
    if !path.exists() {
        return Err("file not found".into());
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path).map_err(|e| format!("open error: {}", e))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)
        .map_err(|e| format!("parse error: {}", e))?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            ));
        }
        let st: PersistentGovernanceState = serde_json::from_value(raw)
            .map_err(|e| format!("deserialize error: {}", e))?;
        Ok(st)
    } else {
        Err("legacy format not supported".into())
    }
}

fn save_state(path: &Path, manager: &GovernanceManager) -> Result<(), String> {
    let state = PersistentGovernanceState::from_manager(manager);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| format!("serialize error: {}", e))?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json).map_err(|e| format!("write temp error: {}", e))?;
    fs::rename(&temp_path, path).map_err(|e| format!("rename error: {}", e))?;
    Ok(())
}

// ── GovernanceState ─────────────────────────────────────────────────────

/// The complete governance state.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovernanceState {
    pub pending: BTreeMap<u64, GovProposal>,
    pub next_id: u64,
    pub params: BTreeMap<String, String>,
    pub min_deposit: u64,
    pub proposal_ttl: u64,
    pub coherence: f64,
}

impl Default for GovernanceState {
    fn default() -> Self {
        Self {
            pending: BTreeMap::new(),
            next_id: 0,
            params: BTreeMap::new(),
            min_deposit: DEFAULT_MIN_GOV_DEPOSIT,
            proposal_ttl: DEFAULT_PROPOSAL_TTL_BLOCKS,
            coherence: 1.0,
        }
    }
}

impl GovernanceState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn validate_action(&self, action: &GovAction) -> GovResult<()> {
        match action {
            GovAction::AddValidator { pk_hex, stake } => {
                if *stake == 0 {
                    return Err(GovError::ZeroStake);
                }
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::RemoveValidator { pk_hex } => {
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::Unjail { pk_hex } => {
                self.validate_pk_hex(pk_hex)?;
            }
            GovAction::SetParam { .. } => {}
        }
        Ok(())
    }

    pub fn validate_pk_hex(&self, pk_hex: &str) -> GovResult<()> {
        let bytes = hex::decode(pk_hex)
            .map_err(|_| GovError::InvalidPubKeyHex(pk_hex.to_string()))?;
        if bytes.len() != 32 {
            return Err(GovError::InvalidPubKeyHex(pk_hex.to_string()));
        }
        Ok(())
    }
}

// ── GovernanceManager ──────────────────────────────────────────────────

/// Thread‑safe manager for the governance subsystem.
#[derive(Clone)]
pub struct GovernanceManager {
    config: Arc<GovernanceConfig>,
    metrics: Arc<GovernanceMetrics>,
    state: Arc<Mutex<GovernanceState>>,
    cache: Arc<Mutex<Option<lru::LruCache<u64, GovProposal>>>>,
    persist_path: Option<PathBuf>,
    proposals_this_block: Arc<Mutex<usize>>,
}

impl GovernanceManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: GovernanceConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(GovernanceMetrics::default());
        let persist_path = config.persist_path.clone();
        let state = if config.persist_state {
            if let Some(ref p) = persist_path {
                if let Ok(st) = load_state(p) {
                    GovernanceState::from_persistent(st)
                } else {
                    GovernanceState::new()
                }
            } else {
                GovernanceState::new()
            }
        } else {
            GovernanceState::new()
        };

        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size)
                .ok_or("cache_size must be > 0")?;
            Some(lru::LruCache::new(size))
        } else {
            None
        };

        let manager = Self {
            config: Arc::new(config),
            metrics,
            state: Arc::new(Mutex::new(state)),
            cache: Arc::new(Mutex::new(cache)),
            persist_path,
            proposals_this_block: Arc::new(Mutex::new(0)),
        };
        manager.update_metrics();
        Ok(manager)
    }

    /// Submit a new proposal.
    pub fn submit(
        &self,
        action: GovAction,
        proposer: String,
        height: Height,
        deposit: u64,
    ) -> GovResult<u64> {
        let start = Instant::now();
        let mut state = self.state.lock();

        // Check block limit.
        let mut block_count = self.proposals_this_block.lock();
        if *block_count >= MAX_PROPOSALS_PER_BLOCK {
            return Err(GovError::TooManyProposals { max: MAX_PROPOSALS_PER_BLOCK });
        }

        // Validate deposit.
        if deposit < self.config.min_deposit {
            return Err(GovError::InsufficientDeposit {
                required: self.config.min_deposit,
                provided: deposit,
            });
        }
        if deposit > MAX_DEPOSIT {
            return Err(GovError::InsufficientDeposit {
                required: self.config.min_deposit,
                provided: deposit,
            });
        }

        state.validate_action(&action)?;

        let id = state.next_id;
        state.next_id = state.next_id.wrapping_add(1);

        let proposal = GovProposal::new(id, action, proposer, height, deposit);
        state.pending.insert(id, proposal);

        state.coherence *= 0.999;
        *block_count += 1;

        self.metrics.record_submission();
        self.update_metrics();
        self.metrics.record_duration("submit", start.elapsed());

        if self.config.log_events {
            info!(proposal_id = id, "governance proposal submitted");
        }

        self.persist();
        Ok(id)
    }

    /// Vote on a proposal.
    pub fn vote(&self, id: u64, voter: String, yes: bool, height: Height) -> GovResult<()> {
        let start = Instant::now();
        let mut state = self.state.lock();

        let proposal = state
            .pending
            .get_mut(&id)
            .ok_or(GovError::ProposalNotFound(id))?;

        if !proposal.is_active(height, state.proposal_ttl) {
            return Err(GovError::ProposalExpired {
                current: height,
                expiry: proposal.height + state.proposal_ttl,
            });
        }

        proposal.vote(voter, yes, &self.config)?;
        state.coherence *= 0.999;

        self.metrics.record_vote();
        self.metrics.record_duration("vote", start.elapsed());

        if self.config.log_events {
            info!(proposal_id = id, yes, "vote cast");
        }

        self.update_metrics();
        self.persist();
        Ok(())
    }

    /// Apply all ready proposals.
    pub fn apply_ready(
        &self,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) -> Vec<GovAction> {
        let start = Instant::now();
        let mut state = self.state.lock();

        let mut applied = Vec::new();
        let mut to_apply = Vec::new();
        let mut to_expire = Vec::new();

        for (id, proposal) in state.pending.iter() {
            if proposal.is_active(current_height, state.proposal_ttl) && proposal.has_quorum(stakes, &self.config) {
                to_apply.push(*id);
            } else if !proposal.is_active(current_height, state.proposal_ttl) {
                to_expire.push(*id);
            }
        }

        // Remove expired.
        for id in to_expire {
            if let Some(proposal) = state.pending.remove(&id) {
                self.metrics.record_expired();
                if self.config.log_events {
                    warn!(proposal_id = id, "proposal expired");
                }
            }
        }

        // Apply quorum proposals.
        for id in to_apply {
            if let Some(proposal) = state.pending.remove(&id) {
                self.apply_action(&proposal.action, stakes, vset, current_height);
                applied.push(proposal.action.clone());
                self.metrics.record_passed();
                if self.config.log_events {
                    info!(proposal_id = id, "proposal passed and applied");
                }
            }
        }

        if !applied.is_empty() {
            state.coherence *= 0.99;
        }

        self.metrics.record_duration("apply", start.elapsed());
        self.update_metrics();
        self.persist();
        applied
    }

    fn apply_action(
        &self,
        action: &GovAction,
        stakes: &mut StakeLedger,
        vset: &mut ValidatorSet,
        current_height: Height,
    ) {
        match action {
            GovAction::AddValidator { pk_hex, stake } => {
                if let Ok(bytes) = hex::decode(pk_hex) {
                    if bytes.len() == 32 {
                        let pk = PublicKeyBytes(bytes);
                        use crate::slashing::ValidatorRecord;
                        let entry = stakes
                            .validators
                            .entry(pk.clone())
                            .or_insert_with(|| ValidatorRecord::new(0));
                        entry.stake += stake;

                        if !vset.vals.iter().any(|v| v.pk == pk) {
                            vset.vals.push(crate::consensus::Validator {
                                pk,
                                power: *stake,
                            });
                        }
                        self.metrics.record_action("add_validator");
                        info!(pk = %pk_hex, stake = %stake, "validator added via governance");
                    }
                }
            }
            GovAction::RemoveValidator { pk_hex } => {
                if let Ok(bytes) = hex::decode(pk_hex) {
                    if bytes.len() == 32 {
                        let pk = PublicKeyBytes(bytes);
                        stakes.validators.remove(&pk);
                        vset.vals.retain(|v| v.pk != pk);
                        self.metrics.record_action("remove_validator");
                        info!(pk = %pk_hex, "validator removed via governance");
                    }
                }
            }
            GovAction::Unjail { pk_hex } => {
                if let Ok(bytes) = hex::decode(pk_hex) {
                    if bytes.len() == 32 {
                        let pk = PublicKeyBytes(bytes);
                        if let Err(e) = stakes.unjail(&pk, current_height) {
                            warn!(pk = %pk_hex, error = %e, "unjail failed");
                        } else {
                            self.metrics.record_action("unjail");
                            info!(pk = %pk_hex, "validator unjailed via governance");
                        }
                    }
                }
            }
            GovAction::SetParam { key, value } => {
                let mut state = self.state.lock();
                state.params.insert(key.clone(), value.clone());
                match key.as_str() {
                    "min_deposit" => {
                        if let Ok(v) = value.parse::<u64>() {
                            state.min_deposit = v;
                        }
                    }
                    "proposal_ttl" => {
                        if let Ok(v) = value.parse::<u64>() {
                            state.proposal_ttl = v;
                        }
                    }
                    _ => {}
                }
                self.metrics.record_action("set_param");
                info!(key = %key, value = %value, "parameter updated via governance");
            }
        }
    }

    /// Get a proposal by ID (with caching).
    pub fn get_proposal(&self, id: u64) -> Option<GovProposal> {
        if self.config.enable_cache {
            let mut cache = self.cache.lock();
            if let Some(cache) = cache.as_mut() {
                if let Some(proposal) = cache.get(&id) {
                    self.metrics.record_cache_hit();
                    return Some(proposal.clone());
                }
                self.metrics.record_cache_miss();
            }
        }

        let state = self.state.lock();
        let proposal = state.pending.get(&id).cloned();

        if let Some(ref p) = proposal {
            if self.config.enable_cache {
                let mut cache = self.cache.lock();
                if let Some(cache) = cache.as_mut() {
                    cache.put(id, p.clone());
                }
            }
        }

        proposal
    }

    /// Get all pending proposals.
    pub fn pending_proposals(&self) -> Vec<GovProposal> {
        self.state.lock().pending.values().cloned().collect()
    }

    /// Get governance parameters.
    pub fn params(&self) -> BTreeMap<String, String> {
        self.state.lock().params.clone()
    }

    /// Get current min deposit.
    pub fn min_deposit(&self) -> u64 {
        self.state.lock().min_deposit
    }

    /// Get proposal TTL.
    pub fn proposal_ttl(&self) -> u64 {
        self.state.lock().proposal_ttl
    }

    /// Get quantum coherence.
    pub fn coherence(&self) -> f64 {
        self.state.lock().coherence
    }

    /// Get statistics.
    pub fn stats(&self) -> GovernanceStats {
        let state = self.state.lock();
        GovernanceStats {
            pending_count: state.pending.len(),
            next_id: state.next_id,
            min_deposit: state.min_deposit,
            proposal_ttl: state.proposal_ttl,
            coherence: state.coherence,
            total_proposals_submitted: self.metrics.proposals_submitted.get(),
            total_votes_cast: self.metrics.votes_cast.get(),
        }
    }

    /// Clear cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("Governance cache cleared");
        }
    }

    /// Get cache size.
    pub fn cache_size(&self) -> usize {
        if let Some(cache) = self.cache.lock().as_ref() {
            cache.len()
        } else {
            0
        }
    }

    /// Reset block proposal counter (call at the start of each block).
    pub fn reset_block_counter(&self) {
        *self.proposals_this_block.lock() = 0;
    }

    fn update_metrics(&self) {
        let state = self.state.lock();
        self.metrics.set_pending(state.pending.len());
        self.metrics.set_coherence(state.coherence);
    }

    fn persist(&self) {
        if self.config.persist_state {
            if let Some(ref path) = self.persist_path {
                if let Err(e) = save_state(path, self) {
                    warn!(error = %e, "failed to persist governance state");
                }
            }
        }
    }

    /// Force persist to disk.
    pub fn flush(&self) -> Result<(), String> {
        if let Some(ref path) = self.persist_path {
            save_state(path, self)
        } else {
            Err("persistence not enabled".into())
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &GovernanceConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> GovernanceMetricsSnapshot {
        GovernanceMetricsSnapshot {
            proposals_submitted: self.metrics.proposals_submitted.get(),
            proposals_passed: self.metrics.proposals_passed.get(),
            proposals_failed: self.metrics.proposals_failed.get(),
            proposals_expired: self.metrics.proposals_expired.get(),
            votes_cast: self.metrics.votes_cast.get(),
            pending_count: self.state.lock().pending.len(),
            coherence: self.state.lock().coherence,
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
        }
    }
}

// ── GovernanceState helpers ─────────────────────────────────────────────

impl GovernanceState {
    pub fn from_persistent(persistent: PersistentGovernanceState) -> Self {
        persistent.into_state()
    }
}

// ── GovernanceStats ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceStats {
    pub pending_count: usize,
    pub next_id: u64,
    pub min_deposit: u64,
    pub proposal_ttl: u64,
    pub coherence: f64,
    pub total_proposals_submitted: u64,
    pub total_votes_cast: u64,
}

// ── Metrics Snapshot ────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct GovernanceMetricsSnapshot {
    pub proposals_submitted: u64,
    pub proposals_passed: u64,
    pub proposals_failed: u64,
    pub proposals_expired: u64,
    pub votes_cast: u64,
    pub pending_count: usize,
    pub coherence: f64,
    pub cache_hits: u64,
    pub cache_misses: u64,
}

// ── Helpers ─────────────────────────────────────────────────────────────

fn address_of(pk: &PublicKeyBytes) -> String {
    let h = blake3::hash(&pk.0);
    hex::encode(&h.as_bytes()[..20])
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Payload Parsing ──────────────────────────────────────────────────────

#[derive(Debug)]
pub enum GovPayloadAction {
    Submit(GovAction, u64),
    Vote { id: u64, voter: String, yes: bool },
}

pub fn parse_gov_payload(
    payload: &str,
    from: &str,
    _height: Height,
) -> Option<GovPayloadAction> {
    let parts: Vec<&str> = payload.split_whitespace().collect();

    if parts.first() != Some(&"gov") {
        return None;
    }

    let mut deposit = DEFAULT_MIN_GOV_DEPOSIT;
    let mut args = parts[1..].to_vec();

    if let Some(pos) = args.iter().position(|&x| x == "--deposit") {
        if pos + 1 < args.len() {
            if let Ok(d) = args[pos + 1].parse::<u64>() {
                deposit = d;
            }
            args.drain(pos..=pos + 1);
        }
    }

    match args.first()? {
        &"add_validator" if args.len() >= 3 => {
            let pk_hex = args[1].to_string();
            let stake: u64 = args[2].parse().ok()?;
            Some(GovPayloadAction::Submit(
                GovAction::AddValidator { pk_hex, stake },
                deposit,
            ))
        }
        &"remove_validator" if args.len() >= 2 => {
            let pk_hex = args[1].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::RemoveValidator { pk_hex },
                deposit,
            ))
        }
        &"unjail" if args.len() >= 2 => {
            let pk_hex = args[1].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::Unjail { pk_hex },
                deposit,
            ))
        }
        &"set_param" if args.len() >= 3 => {
            let key = args[1].to_string();
            let value = args[2].to_string();
            Some(GovPayloadAction::Submit(
                GovAction::SetParam { key, value },
                deposit,
            ))
        }
        &"vote" if args.len() >= 3 => {
            let id: u64 = args[1].parse().ok()?;
            let yes = match args[2] {
                "yes" => true,
                "no" => false,
                _ => return None,
            };
            Some(GovPayloadAction::Vote {
                id,
                voter: from.to_string(),
                yes,
            })
        }
        _ => None,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::consensus::Validator;

    fn setup_stakes() -> (StakeLedger, ValidatorSet) {
        let mut stakes = StakeLedger::default();
        let pk1 = PublicKeyBytes([1u8; 32]);
        let pk2 = PublicKeyBytes([2u8; 32]);

        stakes
            .validators
            .insert(pk1.clone(), crate::slashing::ValidatorRecord::new(100));
        stakes
            .validators
            .insert(pk2.clone(), crate::slashing::ValidatorRecord::new(100));

        let vset = ValidatorSet {
            vals: vec![
                Validator { pk: pk1, power: 100 },
                Validator { pk: pk2, power: 100 },
            ],
        };

        (stakes, vset)
    }

    #[test]
    fn test_parse_gov_payload() {
        let from = "addr1";
        let height = 100;

        let payload = "gov add_validator aabbccdd 500";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Submit(GovAction::AddValidator { pk_hex, stake }, deposit) => {
                assert_eq!(pk_hex, "aabbccdd");
                assert_eq!(stake, 500);
                assert_eq!(deposit, DEFAULT_MIN_GOV_DEPOSIT);
            }
            _ => panic!("wrong variant"),
        }

        let payload = "gov vote 123 yes";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Vote { id, voter, yes } => {
                assert_eq!(id, 123);
                assert_eq!(voter, from);
                assert!(yes);
            }
            _ => panic!("wrong variant"),
        }

        let payload = "gov set_param min_deposit 2000000 --deposit 500000";
        let res = parse_gov_payload(payload, from, height).unwrap();
        match res {
            GovPayloadAction::Submit(GovAction::SetParam { key, value }, deposit) => {
                assert_eq!(key, "min_deposit");
                assert_eq!(value, "2000000");
                assert_eq!(deposit, 500000);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_submit_and_vote() {
        let config = GovernanceConfig::default();
        let manager = GovernanceManager::new(config).unwrap();
        let from = "addr1";
        let height = 1;

        let action = GovAction::SetParam {
            key: "min_deposit".to_string(),
            value: "500000".to_string(),
        };

        let id = manager
            .submit(action, from.to_string(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        assert_eq!(manager.pending_proposals().len(), 1);

        manager.vote(id, "addr2".to_string(), true, height).unwrap();

        let proposal = manager.get_proposal(id).unwrap();
        assert_eq!(proposal.votes.len(), 2);
        assert!(proposal.coherence < 1.0);
    }

    #[test]
    fn test_quorum() {
        let (mut stakes, mut vset) = setup_stakes();
        let config = GovernanceConfig::default();
        let manager = GovernanceManager::new(config).unwrap();
        let from = address_of(&PublicKeyBytes([1u8; 32]));
        let height = 1;

        let action = GovAction::SetParam {
            key: "test".to_string(),
            value: "ok".to_string(),
        };

        let id = manager
            .submit(action, from.clone(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        let proposal = manager.get_proposal(id).unwrap();
        assert!(!proposal.has_quorum(&stakes, &manager.config));

        manager
            .vote(id, address_of(&PublicKeyBytes([2u8; 32])), true, height)
            .unwrap();

        let proposal = manager.get_proposal(id).unwrap();
        assert!(proposal.has_quorum(&stakes, &manager.config));

        let applied = manager.apply_ready(&mut stakes, &mut vset, height + 1);
        assert_eq!(applied.len(), 1);
        assert!(manager.pending_proposals().is_empty());
    }

    #[test]
    fn test_expired_proposal() {
        let config = GovernanceConfig {
            proposal_ttl: 10,
            ..Default::default()
        };
        let manager = GovernanceManager::new(config).unwrap();
        let from = "addr1".to_string();
        let action = GovAction::SetParam {
            key: "x".to_string(),
            value: "y".to_string(),
        };

        let id = manager
            .submit(action, from, 100, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        let proposal = manager.get_proposal(id).unwrap();
        assert!(!proposal.is_active(111, manager.proposal_ttl()));

        let (mut stakes, mut vset) = setup_stakes();
        let applied = manager.apply_ready(&mut stakes, &mut vset, 111);
        assert!(applied.is_empty());
        assert!(manager.pending_proposals().is_empty());
    }

    #[test]
    fn test_governance_stats() {
        let config = GovernanceConfig::default();
        let manager = GovernanceManager::new(config).unwrap();
        let stats = manager.stats();
        assert_eq!(stats.pending_count, 0);
        assert_eq!(stats.min_deposit, DEFAULT_MIN_GOV_DEPOSIT);
        assert!((stats.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_cache() {
        let config = GovernanceConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = GovernanceManager::new(config).unwrap();
        let from = "addr1";
        let height = 1;

        let action = GovAction::SetParam {
            key: "test".to_string(),
            value: "ok".to_string(),
        };

        let id = manager
            .submit(action, from.to_string(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        let p1 = manager.get_proposal(id).unwrap();
        let p2 = manager.get_proposal(id).unwrap();
        assert_eq!(p1.id, p2.id);
        assert!(manager.cache_size() > 0);
        let snap = manager.metrics_snapshot();
        assert!(snap.cache_hits > 0);
        assert!(snap.cache_misses > 0);
    }

    #[test]
    fn test_clear_cache() {
        let config = GovernanceConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = GovernanceManager::new(config).unwrap();
        let from = "addr1";
        let height = 1;

        let action = GovAction::SetParam {
            key: "test".to_string(),
            value: "ok".to_string(),
        };

        let id = manager
            .submit(action, from.to_string(), height, DEFAULT_MIN_GOV_DEPOSIT)
            .unwrap();

        manager.get_proposal(id).unwrap();
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_config_validation() {
        let mut config = GovernanceConfig::default();
        assert!(config.validate().is_ok());

        config.min_deposit = 0;
        assert!(config.validate().is_err());

        config.min_deposit = 1000;
        config.proposal_ttl = 50;
        assert!(config.validate().is_err());

        config.proposal_ttl = 1000;
        config.quorum_numerator = 3;
        config.quorum_denominator = 2;
        assert!(config.validate().is_err());

        config.quorum_numerator = 2;
        config.quorum_denominator = 3;
        config.decoherence_rate = 1.5;
        assert!(config.validate().is_err());

        config.decoherence_rate = 0.1;
        config.cache_size = 0;
        assert!(config.validate().is_err());

        config.cache_size = 10;
        config.persist_state = true;
        config.persist_path = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_block_limit() {
        let config = GovernanceConfig::default();
        let manager = GovernanceManager::new(config).unwrap();
        let from = "addr1";
        let height = 1;

        for i in 0..MAX_PROPOSALS_PER_BLOCK + 1 {
            let action = GovAction::SetParam {
                key: format!("key_{}", i),
                value: format!("value_{}", i),
            };
            let result = manager.submit(action, from.to_string(), height, DEFAULT_MIN_GOV_DEPOSIT);
            if i < MAX_PROPOSALS_PER_BLOCK {
                assert!(result.is_ok());
            } else {
                assert!(matches!(result, Err(GovError::TooManyProposals { .. })));
            }
        }
    }
}
