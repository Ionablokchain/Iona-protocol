//! Quantum consensus message types and signing for IONA — Production-Grade.
//!
//! # Model
//!
//! Each consensus message (`Proposal`, `Vote`) is a discrete struct with a
//! deterministic binary signing format. The "quantum" naming
//! (`purity`, `entanglement_fidelity`) is a **decorative scoreboard** exposed
//! for observability only — see the module-level invariants below.
//!
//! # Invariants (must hold or the network forks / misbehaves)
//!
//! 1. **Domain separation.** Each `(message kind, value/nil)` pair has a
//!    unique 4-byte domain tag. A prevote-nil and precommit-nil for the
//!    same `(height, round)` **must not** produce identical sign bytes.
//! 2. **Determinism.** `proposal_sign_bytes` and `vote_sign_bytes` are pure
//!    functions of their arguments. Same inputs ⇒ same bytes.
//! 3. **Bounded memory.** Per-message-size and stats-window limits are
//!    enforced so a long-running node cannot be OOM'd by relayed traffic.
//! 4. **Durability (optional).** When persistence is enabled, every write is
//!    an fsync'd atomic rename; a crash never leaves a torn file.
//! 5. **Purity is informational.** `purity` and `entanglement_fidelity`
//!    never gate acceptance of a message.
//!
//! # Wire format note
//!
//! Wire size is computed via `serde_json::to_vec(value).len()`. This is the
//! same JSON the network serializes, so the check is exact (not an estimate)
//! and does not require a `bincode` dependency.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, warn};

// -----------------------------------------------------------------------------
// Domain tags
// -----------------------------------------------------------------------------

/// Domain tag for proposals: `"PROP"`.
const DOMAIN_PROPOSAL: [u8; 4] = *b"PROP";

/// Domain tag for prevote with a block value: `"VTPY"`.
const DOMAIN_PREVOTE: [u8; 4] = *b"VTPY";

/// Domain tag for precommit with a block value: `"VTCX"`.
const DOMAIN_PRECOMMIT: [u8; 4] = *b"VTCX";

/// Domain tag for a **nil** prevote.
///
/// **Invariant**: this must differ from [`DOMAIN_NIL_PRECOMMIT`]. Using a
/// shared `"VNIL"` tag would make a nil prevote and a nil precommit for the
/// same `(height, round)` produce identical sign bytes, allowing a signature
/// on one to be replayed as the other.
const DOMAIN_NIL_PREVOTE: [u8; 4] = *b"VNPY";

/// Domain tag for a **nil** precommit. See [`DOMAIN_NIL_PREVOTE`].
const DOMAIN_NIL_PRECOMMIT: [u8; 4] = *b"VNCX";

// -----------------------------------------------------------------------------
// Layout constants
// -----------------------------------------------------------------------------

const FLAG_PRESENT: u8 = 0x01;
const FLAG_ABSENT: u8 = 0x00;
const BLOCK_ID_LEN: usize = 32;
const DOMAIN_LEN: usize = 4;
const HEIGHT_LEN: usize = 8;
const ROUND_LEN: usize = 4;
const FLAG_LEN: usize = 1;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB
const DEFAULT_DECOHERENCE_RATE: f64 = 0.00001;
const DEFAULT_STATS_WINDOW: usize = 100;
const MAX_ALLOWED_STATS_WINDOW: usize = 10_000;
const LOCK_TIMEOUT: Duration = Duration::from_secs(10);
const TEMP_SUFFIX: &str = ".tmp";
const LOCK_SUFFIX: &str = ".lock";
const CURRENT_VERSION: u32 = 1;

/// Configuration for consensus messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MessageConfig {
    /// Maximum serialized message size in bytes.
    pub max_message_size: usize,
    /// Informational purity threshold — a message below this emits a
    /// `warn!` but is **not** rejected.
    pub min_purity: f64,
    /// Informational entanglement-fidelity threshold — see `min_purity`.
    pub min_entanglement_fidelity: f64,
    /// Informational signature-fidelity threshold (currently unused; kept
    /// for forward compatibility with a future partial-signature scheme).
    pub signature_fidelity_threshold: f64,
    /// Decoherence rate applied per message construction.
    pub decoherence_rate: f64,
    /// Whether `flush_stats` writes to disk. Note: this module does **not**
    /// auto-flush; callers must invoke [`MessageFactory::flush_stats`].
    pub persist_stats: bool,
    /// Maximum number of samples retained in the rolling stats window.
    ///
    /// Bounds `purity_samples` and `entanglement_samples` so a long-running
    /// node cannot be OOM'd by relayed traffic.
    pub stats_window_size: usize,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            min_purity: 0.5,
            min_entanglement_fidelity: 0.5,
            signature_fidelity_threshold: 0.999,
            decoherence_rate: DEFAULT_DECOHERENCE_RATE,
            persist_stats: true,
            stats_window_size: DEFAULT_STATS_WINDOW,
        }
    }
}

impl MessageConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_message_size == 0 {
            return Err("max_message_size must be > 0".into());
        }
        if !self.min_purity.is_finite() || !(0.0..=1.0).contains(&self.min_purity) {
            return Err("min_purity must be a finite value in [0.0, 1.0]".into());
        }
        if !self.min_entanglement_fidelity.is_finite()
            || !(0.0..=1.0).contains(&self.min_entanglement_fidelity)
        {
            return Err(
                "min_entanglement_fidelity must be a finite value in [0.0, 1.0]".into(),
            );
        }
        if !self.signature_fidelity_threshold.is_finite()
            || !(0.0..=1.0).contains(&self.signature_fidelity_threshold)
        {
            return Err(
                "signature_fidelity_threshold must be a finite value in [0.0, 1.0]".into(),
            );
        }
        if !self.decoherence_rate.is_finite()
            || !(0.0..=1.0).contains(&self.decoherence_rate)
        {
            return Err("decoherence_rate must be a finite value in [0.0, 1.0]".into());
        }
        if self.stats_window_size == 0 {
            return Err("stats_window_size must be > 0".into());
        }
        if self.stats_window_size > MAX_ALLOWED_STATS_WINDOW {
            return Err(format!(
                "stats_window_size must be <= {} (got {})",
                MAX_ALLOWED_STATS_WINDOW, self.stats_window_size
            ));
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during message handling.
#[derive(Debug, Error)]
pub enum MessageError {
    #[error("invalid proposal: {0}")]
    InvalidProposal(String),

    #[error("invalid vote: {0}")]
    InvalidVote(String),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("message size {size} exceeds maximum {max}")]
    MessageTooLarge { size: usize, max: usize },

    #[error("height mismatch: expected {expected}, got {actual}")]
    HeightMismatch { expected: Height, actual: Height },

    #[error("round mismatch: expected {expected}, got {actual}")]
    RoundMismatch { expected: Round, actual: Round },

    #[error("proposer mismatch: expected {expected}, got {actual}")]
    ProposerMismatch { expected: String, actual: String },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("configuration error: {0}")]
    Config(String),
}

pub type MessageResult<T> = Result<T, MessageError>;

// -----------------------------------------------------------------------------
// Vote type
// -----------------------------------------------------------------------------

/// Vote type — distinguishes prevote from precommit.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType {
    Prevote,
    Precommit,
}

impl VoteType {
    /// Domain tag for a **value-bearing** vote of this type.
    #[must_use]
    pub fn domain_tag(&self) -> [u8; 4] {
        match self {
            VoteType::Prevote => DOMAIN_PREVOTE,
            VoteType::Precommit => DOMAIN_PRECOMMIT,
        }
    }

    /// Domain tag for a **nil** vote of this type.
    #[must_use]
    pub fn nil_domain_tag(&self) -> [u8; 4] {
        match self {
            VoteType::Prevote => DOMAIN_NIL_PREVOTE,
            VoteType::Precommit => DOMAIN_NIL_PRECOMMIT,
        }
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

/// Rolling statistics for consensus messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct MessageStats {
    pub proposals_sent: u64,
    pub proposals_received: u64,
    pub prevotes_sent: u64,
    pub prevotes_received: u64,
    pub precommits_sent: u64,
    pub precommits_received: u64,
    pub nil_votes: u64,
    pub signature_failures: u64,
    /// Recent purity samples (bounded by `MessageConfig::stats_window_size`).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub purity_samples: Vec<f64>,
    /// Recent entanglement-fidelity samples (bounded similarly).
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub entanglement_samples: Vec<f64>,
}

impl MessageStats {
    /// Average purity over the retained window. `1.0` if empty.
    #[must_use]
    pub fn avg_purity(&self) -> f64 {
        if self.purity_samples.is_empty() {
            return 1.0;
        }
        self.purity_samples.iter().sum::<f64>() / self.purity_samples.len() as f64
    }

    /// Average entanglement fidelity over the retained window. `1.0` if empty.
    #[must_use]
    pub fn avg_entanglement_fidelity(&self) -> f64 {
        if self.entanglement_samples.is_empty() {
            return 1.0;
        }
        self.entanglement_samples.iter().sum::<f64>() / self.entanglement_samples.len() as f64
    }

    #[must_use]
    pub fn total_received(&self) -> u64 {
        self.proposals_received + self.prevotes_received + self.precommits_received
    }

    #[must_use]
    pub fn total_sent(&self) -> u64 {
        self.proposals_sent + self.prevotes_sent + self.precommits_sent
    }

    #[must_use]
    pub fn total_votes(&self) -> u64 {
        self.prevotes_sent
            + self.precommits_sent
            + self.prevotes_received
            + self.precommits_received
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct StatsStateV1 {
    version: u32,
    #[serde(flatten)]
    stats: MessageStats,
    last_modified: u64,
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Atomic, durable persistence
// -----------------------------------------------------------------------------

fn lock_path_for(path: &Path) -> PathBuf {
    path.with_extension(LOCK_SUFFIX)
}

fn temp_path_for(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(TEMP_SUFFIX);
    PathBuf::from(s)
}

fn acquire_lock(path: &Path) -> MessageResult<File> {
    let lock_path = lock_path_for(path);
    let file = OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&lock_path)
        .map_err(|e| MessageError::LockFailed(format!("open {}: {e}", lock_path.display())))?;

    let deadline = Instant::now() + LOCK_TIMEOUT;
    let mut delay = Duration::from_millis(1);
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(MessageError::LockFailed(format!(
                        "timeout on {} after {:?}",
                        lock_path.display(),
                        LOCK_TIMEOUT
                    )));
                }
                std::thread::sleep(delay);
                delay = (delay * 2).min(Duration::from_millis(100));
            }
            Err(e) => {
                return Err(MessageError::LockFailed(format!(
                    "lock error on {}: {e}",
                    lock_path.display()
                )));
            }
        }
    }
}

/// Write `bytes` atomically and durably: write temp + fsync + rename + fsync
/// parent dir (Unix).
fn atomic_write_durable(path: &Path, bytes: &[u8]) -> MessageResult<()> {
    let temp_path = temp_path_for(path);

    {
        let f = File::create(&temp_path)?;
        let mut w = BufWriter::new(f);
        if let Err(e) = w.write_all(bytes) {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }
        if let Err(e) = w.flush() {
            let _ = fs::remove_file(&temp_path);
            return Err(e.into());
        }
        let f = w.into_inner().map_err(|e| {
            MessageError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        })?;
        f.sync_all()?;
    }

    fs::rename(&temp_path, path).map_err(|e| {
        let _ = fs::remove_file(&temp_path);
        MessageError::Io(e)
    })?;

    #[cfg(unix)]
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }
    Ok(())
}

fn load_stats(path: &Path) -> MessageResult<MessageStats> {
    if !path.exists() {
        return Ok(MessageStats::default());
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;

    match raw.get("version").and_then(|v| v.as_u64()) {
        Some(v) if v == CURRENT_VERSION as u64 => {
            let st: StatsStateV1 = serde_json::from_value(raw)?;
            Ok(st.stats)
        }
        Some(v) => Err(MessageError::Config(format!(
            "unsupported stats version: {v} (expected {CURRENT_VERSION})"
        ))),
        None => {
            // Legacy: bare MessageStats without an envelope.
            let stats: MessageStats = serde_json::from_value(raw)?;
            Ok(stats)
        }
    }
}

fn save_stats(path: &Path, stats: &MessageStats) -> MessageResult<()> {
    let _lock = acquire_lock(path)?;
    let st = StatsStateV1 {
        version: CURRENT_VERSION,
        stats: stats.clone(),
        last_modified: current_timestamp(),
    };
    let json = serde_json::to_vec_pretty(&st)?;
    atomic_write_durable(path, &json)
}

// -----------------------------------------------------------------------------
// Sign bytes
// -----------------------------------------------------------------------------

/// Compute the sign bytes for a proposal.
///
/// # Invariants
///
/// - Pure function of arguments.
/// - Prefix `PROP` distinguishes proposals from votes.
#[must_use]
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + BLOCK_ID_LEN + FLAG_LEN + ROUND_LEN,
    );
    out.extend_from_slice(&DOMAIN_PROPOSAL);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    out.extend_from_slice(&block_id.0);
    match pol_round {
        None => out.push(FLAG_ABSENT),
        Some(r) => {
            out.push(FLAG_PRESENT);
            out.extend_from_slice(&r.to_le_bytes());
        }
    }
    out
}

/// Compute the sign bytes for a vote.
///
/// # Invariants
///
/// - **Domain separation**: `(Prevote, None)` and `(Precommit, None)` produce
///   *different* prefixes (`VNPY` vs `VNCX`). Using a shared tag would allow
///   replay of a nil prevote as a nil precommit.
/// - Pure function of arguments.
#[must_use]
pub fn vote_sign_bytes(
    vote_type: VoteType,
    height: Height,
    round: Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let domain = match block_id {
        Some(_) => vote_type.domain_tag(),
        None => vote_type.nil_domain_tag(),
    };
    let mut out =
        Vec::with_capacity(DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + FLAG_LEN + BLOCK_ID_LEN);
    out.extend_from_slice(&domain);
    out.extend_from_slice(&height.to_le_bytes());
    out.extend_from_slice(&round.to_le_bytes());
    match block_id {
        Some(id) => {
            out.push(FLAG_PRESENT);
            out.extend_from_slice(&id.0);
        }
        None => {
            out.push(FLAG_ABSENT);
            out.extend_from_slice(&[0u8; BLOCK_ID_LEN]);
        }
    }
    out
}

/// Fraction of byte positions that match between two sign-byte sequences.
///
/// Diagnostic only — never used for security decisions.
#[must_use]
pub fn sign_bytes_fidelity(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / len as f64
}

/// Serialize `value` to JSON and return the byte length.
fn wire_size<T: Serialize>(value: &T) -> MessageResult<usize> {
    Ok(serde_json::to_vec(value)?.len())
}

// -----------------------------------------------------------------------------
// Proposal
// -----------------------------------------------------------------------------

/// Proposal message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub proposer: PublicKeyBytes,
    pub block_id: Hash32,
    pub block: Option<Block>,
    pub pol_round: Option<Round>,
    pub signature: SignatureBytes,
    /// Informational purity. Never gates acceptance.
    #[serde(default = "default_one")]
    pub purity: f64,
    /// Informational entanglement fidelity. Never gates acceptance.
    #[serde(default = "default_one")]
    pub entanglement_fidelity: f64,
}

fn default_one() -> f64 {
    1.0
}

impl Proposal {
    /// Deterministic sign bytes (excludes signature and quantum fields).
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }

    /// Apply decoherence from a construction/relay step.
    ///
    /// Purity decays toward 0; the value is clamped to `[0, 1]`.
    pub fn apply_decoherence(&mut self, rate: f64) {
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }

    /// Validate the proposal.
    ///
    /// Enforces the wire-size limit and rejects zero block IDs. Purity and
    /// entanglement are **informational** — a message below the configured
    /// threshold is accepted but a `warn!` is emitted. This is intentional:
    /// gating on a decaying scalar would reject every relayed message after
    /// enough hops.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        let size = wire_size(self)?;
        if size > config.max_message_size {
            return Err(MessageError::MessageTooLarge {
                size,
                max: config.max_message_size,
            });
        }
        if self.block_id.0 == [0u8; 32] {
            return Err(MessageError::InvalidProposal(
                "block_id cannot be all-zero".into(),
            ));
        }
        if self.purity < config.min_purity {
            warn!(
                height = self.height,
                round = self.round,
                purity = self.purity,
                threshold = config.min_purity,
                "proposal purity below informational threshold"
            );
        }
        if self.entanglement_fidelity < config.min_entanglement_fidelity {
            warn!(
                height = self.height,
                round = self.round,
                fidelity = self.entanglement_fidelity,
                threshold = config.min_entanglement_fidelity,
                "proposal entanglement below informational threshold"
            );
        }
        Ok(())
    }

    /// Create a proposal with default (pure) quantum properties.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        height: Height,
        round: Round,
        proposer: PublicKeyBytes,
        block_id: Hash32,
        block: Option<Block>,
        pol_round: Option<Round>,
        signature: SignatureBytes,
    ) -> Self {
        Self {
            height,
            round,
            proposer,
            block_id,
            block,
            pol_round,
            signature,
            purity: 1.0,
            entanglement_fidelity: 1.0,
        }
    }

    /// Whether this proposal targets `block_id`.
    #[must_use]
    pub fn matches_block(&self, block_id: &Hash32) -> bool {
        self.block_id == *block_id
    }
}

// -----------------------------------------------------------------------------
// Vote
// -----------------------------------------------------------------------------

/// Vote message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: Height,
    pub round: Round,
    pub voter: PublicKeyBytes,
    pub block_id: Option<Hash32>,
    pub signature: SignatureBytes,
    /// Informational purity. Never gates acceptance.
    #[serde(default = "default_one")]
    pub purity: f64,
    /// Informational entanglement fidelity. Never gates acceptance.
    #[serde(default = "default_one")]
    pub entanglement_fidelity: f64,
}

impl Vote {
    /// Deterministic sign bytes (excludes signature and quantum fields).
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }

    /// Whether this is a nil vote (no block).
    #[must_use]
    pub fn is_nil(&self) -> bool {
        self.block_id.is_none()
    }

    /// Apply decoherence from a construction/relay step.
    pub fn apply_decoherence(&mut self, rate: f64) {
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }

    /// Validate the vote.
    ///
    /// Enforces the wire-size limit and rejects a non-nil vote carrying an
    /// all-zero block id. Purity is informational (see [`Proposal::validate`]).
    ///
    /// Note: the `Some(_)`/`None` shape of `block_id` **is** the nil/non-nil
    /// distinction. No separate check is needed (or possible) beyond that.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        let size = wire_size(self)?;
        if size > config.max_message_size {
            return Err(MessageError::MessageTooLarge {
                size,
                max: config.max_message_size,
            });
        }
        if let Some(id) = &self.block_id {
            if id.0 == [0u8; 32] {
                return Err(MessageError::InvalidVote(
                    "non-nil vote has all-zero block_id".into(),
                ));
            }
        }
        if self.purity < config.min_purity {
            warn!(
                vote_type = ?self.vote_type,
                height = self.height,
                round = self.round,
                purity = self.purity,
                "vote purity below informational threshold"
            );
        }
        if self.entanglement_fidelity < config.min_entanglement_fidelity {
            warn!(
                vote_type = ?self.vote_type,
                height = self.height,
                round = self.round,
                fidelity = self.entanglement_fidelity,
                "vote entanglement below informational threshold"
            );
        }
        Ok(())
    }

    /// Create a vote with default (pure) quantum properties.
    #[must_use]
    pub fn new(
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        block_id: Option<Hash32>,
        signature: SignatureBytes,
    ) -> Self {
        Self {
            vote_type,
            height,
            round,
            voter,
            block_id,
            signature,
            purity: 1.0,
            entanglement_fidelity: 1.0,
        }
    }

    /// Create a nil vote.
    #[must_use]
    pub fn nil_vote(
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        signature: SignatureBytes,
    ) -> Self {
        Self::new(vote_type, height, round, voter, None, signature)
    }

    /// Create a vote for a specific block.
    #[must_use]
    pub fn block_vote(
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        block_id: Hash32,
        signature: SignatureBytes,
    ) -> Self {
        Self::new(vote_type, height, round, voter, Some(block_id), signature)
    }

    /// Whether this vote targets `block_id`.
    #[must_use]
    pub fn matches_block(&self, block_id: &Hash32) -> bool {
        self.block_id.as_ref() == Some(block_id)
    }
}

// -----------------------------------------------------------------------------
// ConsensusMsg
// -----------------------------------------------------------------------------

/// Top-level consensus message.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

impl ConsensusMsg {
    /// Apply decoherence to the payload if applicable.
    pub fn apply_decoherence(&mut self, rate: f64) {
        match self {
            ConsensusMsg::Proposal(p) => p.apply_decoherence(rate),
            ConsensusMsg::Vote(v) => v.apply_decoherence(rate),
            ConsensusMsg::Evidence(_) => {}
        }
    }

    #[must_use]
    pub fn height(&self) -> Option<Height> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.height),
            ConsensusMsg::Vote(v) => Some(v.height),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    #[must_use]
    pub fn round(&self) -> Option<Round> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.round),
            ConsensusMsg::Vote(v) => Some(v.round),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Stable identifier for metrics and logs.
    #[must_use]
    pub fn msg_type(&self) -> &'static str {
        match self {
            ConsensusMsg::Proposal(_) => "Proposal",
            ConsensusMsg::Vote(v) => {
                if v.is_nil() {
                    "NilVote"
                } else {
                    match v.vote_type {
                        VoteType::Prevote => "Prevote",
                        VoteType::Precommit => "Precommit",
                    }
                }
            }
            ConsensusMsg::Evidence(_) => "Evidence",
        }
    }

    /// Validate the message.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        match self {
            ConsensusMsg::Proposal(p) => p.validate(config),
            ConsensusMsg::Vote(v) => v.validate(config),
            ConsensusMsg::Evidence(_) => Ok(()), // Evidence has its own validation.
        }
    }
}

// -----------------------------------------------------------------------------
// Statistics container
// -----------------------------------------------------------------------------

#[derive(Debug)]
struct StatsInner {
    stats: MessageStats,
    /// Whether the in-memory stats differ from disk.
    dirty: bool,
    window: usize,
}

/// Thread-safe statistics container with a bounded rolling window.
#[derive(Debug, Clone)]
struct AtomicMessageStats {
    inner: Arc<Mutex<StatsInner>>,
}

impl AtomicMessageStats {
    fn new(window: usize, initial: MessageStats) -> Self {
        Self {
            inner: Arc::new(Mutex::new(StatsInner {
                stats: initial,
                dirty: false,
                window,
            })),
        }
    }

    fn push_sample(stats: &mut MessageStats, window: usize, purity: f64, entanglement: f64) {
        stats.purity_samples.push(purity);
        stats.entanglement_samples.push(entanglement);
        // Bound both vectors to `window` entries.
        while stats.purity_samples.len() > window {
            stats.purity_samples.remove(0);
        }
        while stats.entanglement_samples.len() > window {
            stats.entanglement_samples.remove(0);
        }
    }

    fn record_proposal_sent(&self) {
        let mut g = self.inner.lock();
        g.stats.proposals_sent = g.stats.proposals_sent.saturating_add(1);
        g.dirty = true;
    }

    fn record_proposal_received(&self, purity: f64, entanglement: f64) {
        let mut g = self.inner.lock();
        g.stats.proposals_received = g.stats.proposals_received.saturating_add(1);
        let window = g.window;
        let stats = &mut g.stats;
        Self::push_sample(stats, window, purity, entanglement);
        g.dirty = true;
    }

    fn record_vote_sent(&self, vote_type: VoteType) {
        let mut g = self.inner.lock();
        match vote_type {
            VoteType::Prevote => {
                g.stats.prevotes_sent = g.stats.prevotes_sent.saturating_add(1)
            }
            VoteType::Precommit => {
                g.stats.precommits_sent = g.stats.precommits_sent.saturating_add(1)
            }
        }
        g.dirty = true;
    }

    fn record_vote_received(&self, vote_type: VoteType, purity: f64, entanglement: f64) {
        let mut g = self.inner.lock();
        match vote_type {
            VoteType::Prevote => {
                g.stats.prevotes_received = g.stats.prevotes_received.saturating_add(1)
            }
            VoteType::Precommit => {
                g.stats.precommits_received = g.stats.precommits_received.saturating_add(1)
            }
        }
        let window = g.window;
        let stats = &mut g.stats;
        Self::push_sample(stats, window, purity, entanglement);
        g.dirty = true;
    }

    fn record_nil_vote(&self) {
        let mut g = self.inner.lock();
        g.stats.nil_votes = g.stats.nil_votes.saturating_add(1);
        g.dirty = true;
    }

    fn record_signature_failure(&self) {
        let mut g = self.inner.lock();
        g.stats.signature_failures = g.stats.signature_failures.saturating_add(1);
        g.dirty = true;
    }

    fn snapshot(&self) -> (MessageStats, bool) {
        let g = self.inner.lock();
        (g.stats.clone(), g.dirty)
    }

    fn mark_clean(&self) {
        let mut g = self.inner.lock();
        g.dirty = false;
    }

    fn reset(&self) {
        let mut g = self.inner.lock();
        g.stats = MessageStats::default();
        g.dirty = true;
    }
}

// -----------------------------------------------------------------------------
// Message factory
// -----------------------------------------------------------------------------

/// Factory for constructing consensus messages with consistent properties.
///
/// # Persistence
///
/// When constructed via [`MessageFactory::with_persistence`], the factory
/// holds a path to a JSON stats file. Persistence is **explicit**: call
/// [`MessageFactory::flush_stats`] periodically (e.g. from a background
/// task). The factory deliberately does **not** auto-flush per record,
/// because that would produce one disk write per consensus message.
#[derive(Clone)]
pub struct MessageFactory {
    config: Arc<MessageConfig>,
    stats: Arc<AtomicMessageStats>,
    stats_path: Option<PathBuf>,
    /// Total flushes performed (diagnostic).
    flushes: Arc<AtomicU64>,
}

impl MessageFactory {
    /// Create a non-persistent factory.
    ///
    /// Returns `Err(MessageError::Config)` if the config fails validation.
    pub fn new(config: MessageConfig) -> MessageResult<Self> {
        config.validate().map_err(MessageError::Config)?;
        let window = config.stats_window_size;
        Ok(Self {
            config: Arc::new(config),
            stats: Arc::new(AtomicMessageStats::new(window, MessageStats::default())),
            stats_path: None,
            flushes: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Create a factory that persists stats to
    /// `<data_dir>/message_stats.json`.
    ///
    /// Loads existing stats if the file exists. Corrupt files are left in
    /// place — callers who need to distinguish "no file" from "broken file"
    /// should call [`load_stats`] directly (private) or restore from backup.
    pub fn with_persistence(
        data_dir: &str,
        config: MessageConfig,
    ) -> MessageResult<Self> {
        config.validate().map_err(MessageError::Config)?;
        let path = PathBuf::from(data_dir).join("message_stats.json");
        let initial = if path.exists() {
            load_stats(&path)?
        } else {
            MessageStats::default()
        };
        let window = config.stats_window_size;
        Ok(Self {
            config: Arc::new(config),
            stats: Arc::new(AtomicMessageStats::new(window, initial)),
            stats_path: Some(path),
            flushes: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Construct a proposal with initial decoherence applied.
    #[allow(clippy::too_many_arguments)]
    pub fn new_proposal(
        &self,
        height: Height,
        round: Round,
        proposer: PublicKeyBytes,
        block_id: Hash32,
        block: Option<Block>,
        pol_round: Option<Round>,
        signature: SignatureBytes,
    ) -> Proposal {
        let mut p = Proposal::new(height, round, proposer, block_id, block, pol_round, signature);
        p.apply_decoherence(self.config.decoherence_rate);
        self.stats.record_proposal_sent();
        debug!(height, round, "proposal constructed");
        p
    }

    /// Construct a vote with initial decoherence applied.
    pub fn new_vote(
        &self,
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        block_id: Option<Hash32>,
        signature: SignatureBytes,
    ) -> Vote {
        let mut v = Vote::new(vote_type, height, round, voter, block_id, signature);
        v.apply_decoherence(self.config.decoherence_rate);
        self.stats.record_vote_sent(vote_type);
        if v.is_nil() {
            self.stats.record_nil_vote();
        }
        debug!(?vote_type, height, round, "vote constructed");
        v
    }

    pub fn register_proposal_received(&self, proposal: &Proposal) {
        self.stats
            .record_proposal_received(proposal.purity, proposal.entanglement_fidelity);
    }

    pub fn register_vote_received(&self, vote: &Vote) {
        self.stats
            .record_vote_received(vote.vote_type, vote.purity, vote.entanglement_fidelity);
        if vote.is_nil() {
            self.stats.record_nil_vote();
        }
    }

    pub fn register_signature_failure(&self) {
        self.stats.record_signature_failure();
    }

    /// Snapshot of the current statistics.
    #[must_use]
    pub fn stats(&self) -> MessageStats {
        let (s, _) = self.stats.snapshot();
        s
    }

    /// Persist stats to disk if a path is configured.
    ///
    /// Idempotent. Callers should invoke this periodically; the factory does
    /// **not** flush per record.
    ///
    /// If the in-memory stats have not been modified since the last
    /// successful flush, this returns early without touching the disk.
    /// Use [`force_flush_stats`](Self::force_flush_stats) to bypass.
    pub fn flush_stats(&self) -> MessageResult<()> {
        let Some(path) = &self.stats_path else {
            return Ok(());
        };
        let (stats, dirty) = self.stats.snapshot();
        if !dirty {
            return Ok(());
        }
        save_stats(path, &stats)?;
        self.stats.mark_clean();
        self.flushes.fetch_add(1, Ordering::Relaxed);
        debug!(path = %path.display(), "message stats flushed");
        Ok(())
    }

    /// Force a stats flush even if nothing is marked dirty.
    pub fn force_flush_stats(&self) -> MessageResult<()> {
        let Some(path) = &self.stats_path else {
            return Ok(());
        };
        let (stats, _) = self.stats.snapshot();
        save_stats(path, &stats)?;
        self.stats.mark_clean();
        self.flushes.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Number of successful flushes performed via this handle.
    #[must_use]
    pub fn flush_count(&self) -> u64 {
        self.flushes.load(Ordering::Relaxed)
    }

    /// Reset in-memory statistics.
    pub fn reset_stats(&self) {
        self.stats.reset();
    }

    #[must_use]
    pub fn config(&self) -> &MessageConfig {
        &self.config
    }

    /// Whether this factory persists to disk.
    #[must_use]
    pub fn is_persistent(&self) -> bool {
        self.stats_path.is_some()
    }

    /// Path to the persistence file, if any.
    #[must_use]
    pub fn path(&self) -> Option<&Path> {
        self.stats_path.as_deref()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> MessageConfig {
        MessageConfig {
            min_purity: 0.1,
            min_entanglement_fidelity: 0.1,
            persist_stats: true,
            ..Default::default()
        }
    }

    fn test_proposal() -> Proposal {
        Proposal {
            height: 1,
            round: 0,
            proposer: PublicKeyBytes(vec![0; 32]),
            block_id: Hash32([0xAA; 32]),
            block: None,
            pol_round: None,
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        }
    }

    fn test_vote() -> Vote {
        Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: PublicKeyBytes(vec![0; 32]),
            block_id: Some(Hash32([0xBB; 32])),
            signature: SignatureBytes(vec![]),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        }
    }

    // ── Sign bytes ──────────────────────────────────────────────────────

    #[test]
    fn proposal_sign_bytes_deterministic() {
        let block_id = Hash32([0xAA; 32]);
        let a = proposal_sign_bytes(42, 7, &block_id, Some(5));
        let b = proposal_sign_bytes(42, 7, &block_id, Some(5));
        assert_eq!(a, b);
    }

    #[test]
    fn vote_sign_bytes_deterministic() {
        let block_id = Some(Hash32([0xBB; 32]));
        let a = vote_sign_bytes(VoteType::Prevote, 100, 3, &block_id);
        let b = vote_sign_bytes(VoteType::Prevote, 100, 3, &block_id);
        assert_eq!(a, b);
    }

    #[test]
    fn nil_vote_different_domain() {
        let nil_sig = vote_sign_bytes(VoteType::Prevote, 100, 3, &None);
        let block_sig =
            vote_sign_bytes(VoteType::Prevote, 100, 3, &Some(Hash32([0xCC; 32])));
        assert_ne!(nil_sig, block_sig);
    }

    #[test]
    fn nil_prevote_and_nil_precommit_have_different_domains() {
        // Regression: the previous implementation shared a `"VNIL"` domain
        // tag between nil prevotes and nil precommits, so a signature on one
        // was a valid signature on the other for the same (height, round).
        let nil_prevote = vote_sign_bytes(VoteType::Prevote, 42, 1, &None);
        let nil_precommit = vote_sign_bytes(VoteType::Precommit, 42, 1, &None);
        assert_ne!(
            nil_prevote, nil_precommit,
            "nil prevote and nil precommit must produce different sign bytes"
        );
        // Domain prefixes must differ:
        assert_ne!(&nil_prevote[..4], &nil_precommit[..4]);
    }

    #[test]
    fn proposal_and_vote_domains_differ() {
        let prop = proposal_sign_bytes(1, 0, &Hash32([0x11; 32]), None);
        let vote = vote_sign_bytes(VoteType::Prevote, 1, 0, &Some(Hash32([0x11; 32])));
        assert_ne!(&prop[..4], &vote[..4]);
    }

    #[test]
    fn sign_bytes_fidelity_identity() {
        let bytes = proposal_sign_bytes(1, 0, &Hash32([0xFF; 32]), None);
        assert!((sign_bytes_fidelity(&bytes, &bytes) - 1.0).abs() < 1e-10);
    }

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn proposal_validate_ok() {
        let config = test_config();
        let p = test_proposal();
        assert!(p.validate(&config).is_ok());
    }

    #[test]
    fn proposal_validate_rejects_low_purity_as_informational_only() {
        // Regression: previously low purity failed validation. Now it is
        // informational only — the message is accepted.
        let config = test_config();
        let mut p = test_proposal();
        p.purity = 0.0;
        p.entanglement_fidelity = 0.0;
        assert!(p.validate(&config).is_ok());
    }

    #[test]
    fn proposal_validate_rejects_zero_block_id() {
        let config = test_config();
        let mut p = test_proposal();
        p.block_id = Hash32([0u8; 32]);
        assert!(matches!(
            p.validate(&config),
            Err(MessageError::InvalidProposal(_))
        ));
    }

    #[test]
    fn proposal_validate_rejects_oversize() {
        let mut config = test_config();
        config.max_message_size = 10; // absurdly small
        let p = test_proposal();
        assert!(matches!(
            p.validate(&config),
            Err(MessageError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn vote_validate_ok() {
        let config = test_config();
        let v = test_vote();
        assert!(v.validate(&config).is_ok());
    }

    #[test]
    fn vote_validate_rejects_zero_block_id_on_non_nil() {
        let config = test_config();
        let mut v = test_vote();
        v.block_id = Some(Hash32([0u8; 32]));
        assert!(matches!(
            v.validate(&config),
            Err(MessageError::InvalidVote(_))
        ));
    }

    #[test]
    fn nil_vote_validates() {
        let config = test_config();
        let v = Vote::nil_vote(
            VoteType::Prevote,
            1,
            0,
            PublicKeyBytes(vec![0; 32]),
            SignatureBytes(vec![]),
        );
        assert!(v.validate(&config).is_ok());
        assert!(v.is_nil());
    }

    #[test]
    fn vote_is_nil_consistent_with_block_id() {
        let v = test_vote();
        assert_eq!(v.is_nil(), v.block_id.is_none());
        let nil = Vote::nil_vote(
            VoteType::Prevote,
            1,
            0,
            PublicKeyBytes(vec![0; 32]),
            SignatureBytes(vec![]),
        );
        assert_eq!(nil.is_nil(), nil.block_id.is_none());
    }

    // ── Stats ───────────────────────────────────────────────────────────

    #[test]
    fn stats_totals() {
        let stats = MessageStats {
            proposals_sent: 5,
            proposals_received: 3,
            prevotes_sent: 10,
            prevotes_received: 8,
            precommits_sent: 7,
            precommits_received: 6,
            nil_votes: 2,
            signature_failures: 1,
            purity_samples: vec![1.0, 0.9],
            entanglement_samples: vec![1.0, 0.8],
        };
        assert_eq!(stats.total_received(), 17);
        assert_eq!(stats.total_sent(), 22);
        assert_eq!(stats.total_votes(), 31);
        assert!((stats.avg_purity() - 0.95).abs() < 1e-10);
    }

    #[test]
    fn stats_samples_are_bounded() {
        // Regression: previously `purity_samples` grew without bound,
        // leaking memory on a long-running node.
        let config = MessageConfig {
            stats_window_size: 5,
            ..test_config()
        };
        let factory = MessageFactory::new(config).unwrap();
        for _ in 0..100 {
            factory.register_proposal_received(&test_proposal());
        }
        let stats = factory.stats();
        assert_eq!(stats.purity_samples.len(), 5);
        assert_eq!(stats.entanglement_samples.len(), 5);
    }

    #[test]
    fn factory_stats_records() {
        let factory = MessageFactory::new(test_config()).unwrap();
        factory.register_proposal_received(&test_proposal());
        let stats = factory.stats();
        assert_eq!(stats.proposals_received, 1);
        assert!((stats.avg_purity() - 1.0).abs() < 1e-10);
    }

    // ── Persistence ─────────────────────────────────────────────────────

    #[test]
    fn persistence_roundtrip() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let config = test_config();
        {
            let factory = MessageFactory::with_persistence(path, config.clone()).unwrap();
            factory.register_proposal_received(&test_proposal());
            factory.flush_stats().unwrap();
            assert_eq!(factory.flush_count(), 1);
        }

        let factory2 = MessageFactory::with_persistence(path, config).unwrap();
        assert_eq!(factory2.stats().proposals_received, 1);
    }

    #[test]
    fn flush_is_idempotent_and_skips_when_clean() {
        // Regression: previously `flush_stats` was called on every record.
        // Now it early-returns if nothing is dirty.
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let factory = MessageFactory::with_persistence(path, test_config()).unwrap();

        factory.register_proposal_received(&test_proposal());
        factory.flush_stats().unwrap();
        assert_eq!(factory.flush_count(), 1);

        // Second flush with no intervening records → no-op (no counter bump).
        factory.flush_stats().unwrap();
        assert_eq!(factory.flush_count(), 1);

        // force_flush bypasses the clean check.
        factory.force_flush_stats().unwrap();
        assert_eq!(factory.flush_count(), 2);
    }

    #[test]
    fn flush_on_non_persistent_is_noop() {
        let factory = MessageFactory::new(test_config()).unwrap();
        assert!(!factory.is_persistent());
        factory.register_proposal_received(&test_proposal());
        factory.flush_stats().unwrap();
        assert_eq!(factory.flush_count(), 0);
    }

    // ── ConsensusMsg ────────────────────────────────────────────────────

    #[test]
    fn consensus_msg_validate() {
        let config = test_config();
        let msg = ConsensusMsg::Proposal(test_proposal());
        assert!(msg.validate(&config).is_ok());

        let mut bad_p = test_proposal();
        bad_p.block_id = Hash32([0u8; 32]);
        let bad_msg = ConsensusMsg::Proposal(bad_p);
        assert!(bad_msg.validate(&config).is_err());
    }

    #[test]
    fn consensus_msg_height_round() {
        let msg = ConsensusMsg::Proposal(test_proposal());
        assert_eq!(msg.height(), Some(1));
        assert_eq!(msg.round(), Some(0));
    }

    #[test]
    fn consensus_msg_type_names() {
        assert_eq!(
            ConsensusMsg::Proposal(test_proposal()).msg_type(),
            "Proposal"
        );
        assert_eq!(ConsensusMsg::Vote(test_vote()).msg_type(), "Prevote");
        let nil = Vote::nil_vote(
            VoteType::Precommit,
            1,
            0,
            PublicKeyBytes(vec![0; 32]),
            SignatureBytes(vec![]),
        );
        assert_eq!(ConsensusMsg::Vote(nil).msg_type(), "NilVote");
    }

    // ── Config ──────────────────────────────────────────────────────────

    #[test]
    fn config_validation() {
        assert!(MessageConfig::default().validate().is_ok());

        assert!(MessageConfig { max_message_size: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(MessageConfig { min_purity: 1.5, ..Default::default() }
            .validate()
            .is_err());
        assert!(MessageConfig { min_purity: f64::NAN, ..Default::default() }
            .validate()
            .is_err());
        assert!(MessageConfig { min_entanglement_fidelity: -1.0, ..Default::default() }
            .validate()
            .is_err());
        assert!(MessageConfig { stats_window_size: 0, ..Default::default() }
            .validate()
            .is_err());
        assert!(MessageConfig {
            stats_window_size: MAX_ALLOWED_STATS_WINDOW + 1,
            ..Default::default()
        }
        .validate()
        .is_err());
    }

    #[test]
    fn factory_new_rejects_invalid_config() {
        let cfg = MessageConfig { max_message_size: 0, ..Default::default() };
        assert!(matches!(
            MessageFactory::new(cfg),
            Err(MessageError::Config(_))
        ));
    }
}
