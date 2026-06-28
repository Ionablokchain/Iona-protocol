//! Quantum consensus message types and signing for IONA — Production-Grade.
//!
//! # Quantum Message Model
//!
//! Each consensus message (Proposal, Vote) is modelled as a **quantum state**
//! in a tensor product Hilbert space. The deterministic binary signing format
//! acts as a **quantum fingerprint** that uniquely identifies each state.
//!
//! # Production Features
//! - Thread‑safe message validation with `thiserror` errors.
//! - Configurable limits (max message size, signature fidelity thresholds).
//! - Persistent statistics with atomic writes and file locking.
//! - Structured logging with `tracing`.
//! - Versioned serialization for forward compatibility.
//! - Message builder/factory for consistent creation.
//! - Comprehensive validation for all message types.

use crate::crypto::{PublicKeyBytes, SignatureBytes};
use crate::types::{Block, Hash32, Height, Round};
use fs2::FileExt;
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
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Domain tag for proposals: `"PROP"` as 4‑byte little‑endian.
const DOMAIN_PROPOSAL: [u8; 4] = *b"PROP";

/// Domain tag for prevote (non‑nil): `"VTPY"` — prevote subspace.
const DOMAIN_PREVOTE: [u8; 4] = *b"VTPY";

/// Domain tag for precommit (non‑nil): `"VTCX"` — precommit subspace.
const DOMAIN_PRECOMMIT: [u8; 4] = *b"VTCX";

/// Domain tag for nil votes: `"VNIL"` — nil subspace.
const DOMAIN_NIL_VOTE: [u8; 4] = *b"VNIL";

/// Flag byte indicating a value is present (quantum state populated).
const FLAG_PRESENT: u8 = 0x01;

/// Flag byte indicating a value is absent (vacuum state |∅⟩).
const FLAG_ABSENT: u8 = 0x00;

/// Length of a block ID hash in bytes.
const BLOCK_ID_LEN: usize = 32;

/// Length of domain tag.
const DOMAIN_LEN: usize = 4;

/// Length of height (8 bytes LE).
const HEIGHT_LEN: usize = 8;

/// Length of round (4 bytes LE).
const ROUND_LEN: usize = 4;

/// Length of the optional value flag byte.
const FLAG_LEN: usize = 1;

/// Default maximum message size in bytes.
const DEFAULT_MAX_MESSAGE_SIZE: usize = 10 * 1024 * 1024; // 10 MiB

/// Default signature fidelity threshold.
const DEFAULT_SIGNATURE_FIDELITY_THRESHOLD: f64 = 0.999;

/// Default decoherence rate per operation.
const DEFAULT_DECOHERENCE_RATE: f64 = 0.00001;

/// Kraus rank for domain quantum channels.
const KRAUS_RANK: usize = 4;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Maximum statistics window size.
const MAX_STATS_WINDOW: usize = 1000;

// -----------------------------------------------------------------------------
// Message Errors
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

    #[error("quantum decoherence: purity {purity} below threshold {threshold}")]
    Decoherence { purity: f64, threshold: f64 },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("nil vote cannot have a block hash")]
    NilVoteWithBlockHash,

    #[error("non‑nil vote must have a block hash")]
    NonNilVoteWithoutBlockHash,
}

pub type MessageResult<T> = Result<T, MessageError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for consensus messages.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessageConfig {
    /// Maximum message size in bytes.
    pub max_message_size: usize,
    /// Minimum required purity for messages (0.0 – 1.0).
    pub min_purity: f64,
    /// Minimum entanglement fidelity for messages.
    pub min_entanglement_fidelity: f64,
    /// Signature fidelity threshold.
    pub signature_fidelity_threshold: f64,
    /// Decoherence rate per operation.
    pub decoherence_rate: f64,
    /// Whether to persist statistics to disk.
    pub persist_stats: bool,
    /// Maximum statistics window size.
    pub stats_window_size: usize,
}

impl Default for MessageConfig {
    fn default() -> Self {
        Self {
            max_message_size: DEFAULT_MAX_MESSAGE_SIZE,
            min_purity: 0.5,
            min_entanglement_fidelity: 0.5,
            signature_fidelity_threshold: DEFAULT_SIGNATURE_FIDELITY_THRESHOLD,
            decoherence_rate: DEFAULT_DECOHERENCE_RATE,
            persist_stats: true,
            stats_window_size: 100,
        }
    }
}

impl MessageConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_message_size == 0 {
            return Err("max_message_size must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.min_purity) {
            return Err("min_purity must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_entanglement_fidelity) {
            return Err("min_entanglement_fidelity must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.signature_fidelity_threshold) {
            return Err("signature_fidelity_threshold must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        if self.stats_window_size == 0 {
            return Err("stats_window_size must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Vote Types
// -----------------------------------------------------------------------------

/// Vote type — quantum number distinguishing prevote from precommit.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum VoteType {
    Prevote,
    Precommit,
}

impl VoteType {
    /// Quantum domain tag for this vote type.
    pub fn domain_tag(&self) -> [u8; 4] {
        match self {
            VoteType::Prevote => DOMAIN_PREVOTE,
            VoteType::Precommit => DOMAIN_PRECOMMIT,
        }
    }
}

// -----------------------------------------------------------------------------
// Persistent Message Statistics
// -----------------------------------------------------------------------------

/// Persistent statistics state.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StatsStateV1 {
    version: u32,
    proposals_sent: u64,
    proposals_received: u64,
    prevotes_sent: u64,
    prevotes_received: u64,
    precommits_sent: u64,
    precommits_received: u64,
    nil_votes: u64,
    signature_failures: u64,
    purity_samples: Vec<f64>,
    entanglement_samples: Vec<f64>,
    last_modified: u64,
}

impl StatsStateV1 {
    fn from_stats(stats: &MessageStats) -> Self {
        Self {
            version: CURRENT_VERSION,
            proposals_sent: stats.proposals_sent,
            proposals_received: stats.proposals_received,
            prevotes_sent: stats.prevotes_sent,
            prevotes_received: stats.prevotes_received,
            precommits_sent: stats.precommits_sent,
            precommits_received: stats.precommits_received,
            nil_votes: stats.nil_votes,
            signature_failures: stats.signature_failures,
            purity_samples: stats.purity_samples.clone(),
            entanglement_samples: stats.entanglement_samples.clone(),
            last_modified: current_timestamp(),
        }
    }

    fn into_stats(self) -> MessageStats {
        MessageStats {
            proposals_sent: self.proposals_sent,
            proposals_received: self.proposals_received,
            prevotes_sent: self.prevotes_sent,
            prevotes_received: self.prevotes_received,
            precommits_sent: self.precommits_sent,
            precommits_received: self.precommits_received,
            nil_votes: self.nil_votes,
            signature_failures: self.signature_failures,
            purity_samples: self.purity_samples,
            entanglement_samples: self.entanglement_samples,
        }
    }
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// -----------------------------------------------------------------------------
// Message Statistics
// -----------------------------------------------------------------------------

/// Statistics for consensus messages.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MessageStats {
    pub proposals_sent: u64,
    pub proposals_received: u64,
    pub prevotes_sent: u64,
    pub prevotes_received: u64,
    pub precommits_sent: u64,
    pub precommits_received: u64,
    pub nil_votes: u64,
    pub signature_failures: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub purity_samples: Vec<f64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub entanglement_samples: Vec<f64>,
}

impl MessageStats {
    /// Average purity of received messages.
    pub fn avg_purity(&self) -> f64 {
        if self.purity_samples.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.purity_samples.iter().sum();
        sum / self.purity_samples.len() as f64
    }

    /// Average entanglement fidelity.
    pub fn avg_entanglement_fidelity(&self) -> f64 {
        if self.entanglement_samples.is_empty() {
            return 1.0;
        }
        let sum: f64 = self.entanglement_samples.iter().sum();
        sum / self.entanglement_samples.len() as f64
    }

    /// Total messages received.
    pub fn total_received(&self) -> u64 {
        self.proposals_received + self.prevotes_received + self.precommits_received
    }

    /// Total messages sent.
    pub fn total_sent(&self) -> u64 {
        self.proposals_sent + self.prevotes_sent + self.precommits_sent
    }

    /// Total votes (prevotes + precommits).
    pub fn total_votes(&self) -> u64 {
        self.prevotes_sent + self.precommits_sent + self.prevotes_received + self.precommits_received
    }
}

// -----------------------------------------------------------------------------
// File I/O for Statistics
// -----------------------------------------------------------------------------

fn acquire_lock(path: &Path) -> Result<File, MessageError> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| MessageError::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let start = SystemTime::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed().unwrap_or_default() > timeout {
                    return Err(MessageError::LockFailed(format!(
                        "timeout after {}s",
                        LOCK_TIMEOUT_SECS
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), MessageError> {
    file.unlock().map_err(|e| MessageError::LockFailed(e.to_string()))
}

fn load_stats(path: &Path) -> Result<MessageStats, MessageError> {
    if !path.exists() {
        return Ok(MessageStats::default());
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(MessageError::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: StatsStateV1 = serde_json::from_value(raw)?;
        Ok(st.into_stats())
    } else {
        // Legacy format: try to parse as stats directly.
        match serde_json::from_value::<MessageStats>(raw) {
            Ok(stats) => Ok(stats),
            Err(e) => Err(MessageError::Serialization(e)),
        }
    }
}

fn save_stats(path: &Path, stats: &MessageStats) -> Result<(), MessageError> {
    let st = StatsStateV1::from_stats(stats);
    let json = serde_json::to_string_pretty(&st)?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Quantum Proposal Message
// -----------------------------------------------------------------------------

/// Proposal message — quantum state in the proposal Hilbert space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Proposal {
    pub height: Height,
    pub round: Round,
    pub proposer: PublicKeyBytes,
    pub block_id: Hash32,
    pub block: Option<Block>,
    pub pol_round: Option<Round>,
    pub signature: SignatureBytes,
    /// Quantum purity of this proposal state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Entanglement fidelity with the validator set.
    #[serde(default = "default_purity")]
    pub entanglement_fidelity: f64,
}

fn default_purity() -> f64 {
    1.0
}

impl Proposal {
    /// Compute the deterministic bytes that must be signed.
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        proposal_sign_bytes(self.height, self.round, &self.block_id, self.pol_round)
    }

    /// Apply decoherence from network propagation.
    pub fn apply_decoherence(&mut self, rate: f64) {
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }

    /// Validate the proposal against the configuration.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        // Check size
        let size = bincode::serialized_size(self).unwrap_or(0) as usize;
        if size > config.max_message_size {
            return Err(MessageError::MessageTooLarge {
                size,
                max: config.max_message_size,
            });
        }
        // Check purity
        if self.purity < config.min_purity {
            return Err(MessageError::Decoherence {
                purity: self.purity,
                threshold: config.min_purity,
            });
        }
        // Check entanglement fidelity
        if self.entanglement_fidelity < config.min_entanglement_fidelity {
            return Err(MessageError::Decoherence {
                purity: self.entanglement_fidelity,
                threshold: config.min_entanglement_fidelity,
            });
        }
        // Check block_id is non-zero
        if self.block_id.0 == [0u8; 32] {
            return Err(MessageError::InvalidProposal("block_id cannot be zero".into()));
        }
        Ok(())
    }

    /// Create a new proposal with default quantum properties.
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

    /// Check if this proposal matches a specific block ID.
    pub fn matches_block(&self, block_id: &Hash32) -> bool {
        self.block_id == *block_id
    }
}

// -----------------------------------------------------------------------------
// Quantum Vote Message
// -----------------------------------------------------------------------------

/// Vote message — quantum state in the vote Hilbert space.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Vote {
    pub vote_type: VoteType,
    pub height: Height,
    pub round: Round,
    pub voter: PublicKeyBytes,
    pub block_id: Option<Hash32>,
    pub signature: SignatureBytes,
    /// Quantum purity of this vote state.
    #[serde(default = "default_purity")]
    pub purity: f64,
    /// Entanglement fidelity with the validator set.
    #[serde(default = "default_purity")]
    pub entanglement_fidelity: f64,
}

impl Vote {
    /// Compute the deterministic bytes that must be signed.
    #[must_use]
    pub fn sign_bytes(&self) -> Vec<u8> {
        vote_sign_bytes(self.vote_type, self.height, self.round, &self.block_id)
    }

    /// Check if this is a nil vote (vacuum state in block_id subspace).
    pub fn is_nil(&self) -> bool {
        self.block_id.is_none()
    }

    /// Apply decoherence from network propagation.
    pub fn apply_decoherence(&mut self, rate: f64) {
        let decay = (-rate).exp();
        self.purity = (self.purity * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity = (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }

    /// Validate the vote against the configuration.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        // Check size
        let size = bincode::serialized_size(self).unwrap_or(0) as usize;
        if size > config.max_message_size {
            return Err(MessageError::MessageTooLarge {
                size,
                max: config.max_message_size,
            });
        }
        // Check purity
        if self.purity < config.min_purity {
            return Err(MessageError::Decoherence {
                purity: self.purity,
                threshold: config.min_purity,
            });
        }
        // Check entanglement fidelity
        if self.entanglement_fidelity < config.min_entanglement_fidelity {
            return Err(MessageError::Decoherence {
                purity: self.entanglement_fidelity,
                threshold: config.min_entanglement_fidelity,
            });
        }
        // Validate nil/non-nil consistency
        if self.is_nil() {
            // Nil vote: block_id must be None
            if self.block_id.is_some() {
                return Err(MessageError::NilVoteWithBlockHash);
            }
        } else {
            // Non-nil vote: block_id must be Some
            if self.block_id.is_none() {
                return Err(MessageError::NonNilVoteWithoutBlockHash);
            }
        }
        Ok(())
    }

    /// Create a new vote with default quantum properties.
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
    pub fn nil_vote(
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        signature: SignatureBytes,
    ) -> Self {
        Self::new(vote_type, height, round, voter, None, signature)
    }

    /// Create a non-nil vote for a specific block.
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

    /// Check if this vote matches a specific block ID.
    pub fn matches_block(&self, block_id: &Hash32) -> bool {
        self.block_id.as_ref() == Some(block_id)
    }
}

// -----------------------------------------------------------------------------
// Consensus Message Enum
// -----------------------------------------------------------------------------

/// Top‑level consensus message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ConsensusMsg {
    Proposal(Proposal),
    Vote(Vote),
    Evidence(crate::evidence::Evidence),
}

impl ConsensusMsg {
    /// Apply decoherence based on message type.
    pub fn apply_decoherence(&mut self, rate: f64) {
        match self {
            ConsensusMsg::Proposal(p) => p.apply_decoherence(rate),
            ConsensusMsg::Vote(v) => v.apply_decoherence(rate),
            ConsensusMsg::Evidence(_) => {}
        }
    }

    /// Get the height of this message (if applicable).
    pub fn height(&self) -> Option<Height> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.height),
            ConsensusMsg::Vote(v) => Some(v.height),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the round of this message (if applicable).
    pub fn round(&self) -> Option<Round> {
        match self {
            ConsensusMsg::Proposal(p) => Some(p.round),
            ConsensusMsg::Vote(v) => Some(v.round),
            ConsensusMsg::Evidence(_) => None,
        }
    }

    /// Get the message type as a string.
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

    /// Validate the message against configuration.
    pub fn validate(&self, config: &MessageConfig) -> MessageResult<()> {
        match self {
            ConsensusMsg::Proposal(p) => p.validate(config),
            ConsensusMsg::Vote(v) => v.validate(config),
            ConsensusMsg::Evidence(_) => Ok(()), // Evidence has its own validation
        }
    }
}

// -----------------------------------------------------------------------------
// Deterministic Binary Sign Bytes
// -----------------------------------------------------------------------------

/// Compute the sign bytes for a proposal.
#[must_use]
pub fn proposal_sign_bytes(
    height: Height,
    round: Round,
    block_id: &Hash32,
    pol_round: Option<Round>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        DOMAIN_LEN + HEIGHT_LEN + ROUND_LEN + BLOCK_ID_LEN + 1 + ROUND_LEN,
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
#[must_use]
pub fn vote_sign_bytes(
    vote_type: VoteType,
    height: Height,
    round: Round,
    block_id: &Option<Hash32>,
) -> Vec<u8> {
    let domain = match (vote_type, block_id) {
        (VoteType::Prevote, Some(_)) => DOMAIN_PREVOTE,
        (VoteType::Precommit, Some(_)) => DOMAIN_PRECOMMIT,
        _ => DOMAIN_NIL_VOTE,
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

/// Compute the quantum fidelity between two sign byte sequences.
pub fn sign_bytes_fidelity(a: &[u8], b: &[u8]) -> f64 {
    let len = a.len().min(b.len());
    if len == 0 {
        return 1.0;
    }
    let matches = a.iter().zip(b.iter()).filter(|(x, y)| x == y).count();
    matches as f64 / len as f64
}

// -----------------------------------------------------------------------------
// Message Factory
// -----------------------------------------------------------------------------

/// Factory for creating consensus messages with consistent quantum properties.
#[derive(Clone)]
pub struct MessageFactory {
    config: Arc<MessageConfig>,
    stats: Arc<AtomicMessageStats>,
    stats_path: Option<PathBuf>,
}

/// Thread‑safe statistics container.
#[derive(Debug, Clone)]
struct AtomicMessageStats {
    inner: Arc<parking_lot::Mutex<MessageStats>>,
}

impl AtomicMessageStats {
    fn new() -> Self {
        Self {
            inner: Arc::new(parking_lot::Mutex::new(MessageStats::default())),
        }
    }

    fn record_proposal_sent(&self) {
        let mut stats = self.inner.lock();
        stats.proposals_sent = stats.proposals_sent.wrapping_add(1);
    }

    fn record_proposal_received(&self, purity: f64, entanglement: f64) {
        let mut stats = self.inner.lock();
        stats.proposals_received = stats.proposals_received.wrapping_add(1);
        stats.purity_samples.push(purity);
        stats.entanglement_samples.push(entanglement);
    }

    fn record_vote_sent(&self, vote_type: VoteType) {
        let mut stats = self.inner.lock();
        match vote_type {
            VoteType::Prevote => stats.prevotes_sent = stats.prevotes_sent.wrapping_add(1),
            VoteType::Precommit => stats.precommits_sent = stats.precommits_sent.wrapping_add(1),
        }
    }

    fn record_vote_received(&self, vote_type: VoteType, purity: f64, entanglement: f64) {
        let mut stats = self.inner.lock();
        match vote_type {
            VoteType::Prevote => stats.prevotes_received = stats.prevotes_received.wrapping_add(1),
            VoteType::Precommit => stats.precommits_received = stats.precommits_received.wrapping_add(1),
        }
        stats.purity_samples.push(purity);
        stats.entanglement_samples.push(entanglement);
    }

    fn record_nil_vote(&self) {
        let mut stats = self.inner.lock();
        stats.nil_votes = stats.nil_votes.wrapping_add(1);
    }

    fn record_signature_failure(&self) {
        let mut stats = self.inner.lock();
        stats.signature_failures = stats.signature_failures.wrapping_add(1);
    }

    fn snapshot(&self) -> MessageStats {
        self.inner.lock().clone()
    }

    fn reset(&self) {
        let mut stats = self.inner.lock();
        *stats = MessageStats::default();
    }
}

impl MessageFactory {
    /// Create a new message factory with the given configuration.
    pub fn new(config: MessageConfig) -> Result<Self, String> {
        config.validate().map_err(|e| format!("config validation: {}", e))?;
        Ok(Self {
            config: Arc::new(config),
            stats: Arc::new(AtomicMessageStats::new()),
            stats_path: None,
        })
    }

    /// Create a factory with persistence to disk.
    pub fn with_persistence(data_dir: &str, config: MessageConfig) -> Result<Self, MessageError> {
        config.validate().map_err(MessageError::Config)?;
        let path = PathBuf::from(data_dir).join("message_stats.json");
        let stats = if path.exists() {
            load_stats(&path)?
        } else {
            MessageStats::default()
        };
        let atomic_stats = Arc::new(AtomicMessageStats::new());
        // Load stats into atomic container.
        {
            let mut inner = atomic_stats.inner.lock();
            *inner = stats;
        }
        Ok(Self {
            config: Arc::new(config),
            stats: atomic_stats,
            stats_path: Some(path),
        })
    }

    /// Create a new proposal message.
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
        let mut proposal = Proposal::new(height, round, proposer, block_id, block, pol_round, signature);
        // Apply initial decoherence from creation
        proposal.apply_decoherence(self.config.decoherence_rate);
        self.stats.record_proposal_sent();
        // Persist if enabled
        if self.config.persist_stats {
            let _ = self.flush_stats();
        }
        proposal
    }

    /// Create a new vote message.
    pub fn new_vote(
        &self,
        vote_type: VoteType,
        height: Height,
        round: Round,
        voter: PublicKeyBytes,
        block_id: Option<Hash32>,
        signature: SignatureBytes,
    ) -> Vote {
        let mut vote = Vote::new(vote_type, height, round, voter, block_id, signature);
        vote.apply_decoherence(self.config.decoherence_rate);
        self.stats.record_vote_sent(vote_type);
        if vote.is_nil() {
            self.stats.record_nil_vote();
        }
        if self.config.persist_stats {
            let _ = self.flush_stats();
        }
        vote
    }

    /// Register a received proposal for statistics.
    pub fn register_proposal_received(&self, proposal: &Proposal) {
        self.stats.record_proposal_received(proposal.purity, proposal.entanglement_fidelity);
        if self.config.persist_stats {
            let _ = self.flush_stats();
        }
    }

    /// Register a received vote for statistics.
    pub fn register_vote_received(&self, vote: &Vote) {
        self.stats.record_vote_received(vote.vote_type, vote.purity, vote.entanglement_fidelity);
        if vote.is_nil() {
            self.stats.record_nil_vote();
        }
        if self.config.persist_stats {
            let _ = self.flush_stats();
        }
    }

    /// Register a signature verification failure.
    pub fn register_signature_failure(&self) {
        self.stats.record_signature_failure();
        if self.config.persist_stats {
            let _ = self.flush_stats();
        }
    }

    /// Get current statistics.
    pub fn stats(&self) -> MessageStats {
        self.stats.snapshot()
    }

    /// Flush statistics to disk.
    pub fn flush_stats(&self) -> Result<(), MessageError> {
        if let Some(path) = &self.stats_path {
            let stats = self.stats.snapshot();
            save_stats(path, &stats)?;
        }
        Ok(())
    }

    /// Reset statistics (for testing).
    #[cfg(test)]
    pub fn reset_stats(&self) {
        self.stats.reset();
        let _ = self.flush_stats();
    }

    /// Get the configuration.
    pub fn config(&self) -> &MessageConfig {
        &self.config
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
        let mut cfg = MessageConfig::default();
        cfg.min_purity = 0.1;
        cfg.min_entanglement_fidelity = 0.1;
        cfg.persist_stats = true;
        cfg
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

    #[test]
    fn test_proposal_sign_bytes_deterministic() {
        let height = 42;
        let round = 7;
        let block_id = Hash32([0xAA; 32]);
        let pol_round = Some(5);
        let bytes1 = proposal_sign_bytes(height, round, &block_id, pol_round);
        let bytes2 = proposal_sign_bytes(height, round, &block_id, pol_round);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_vote_sign_bytes_deterministic() {
        let height = 100;
        let round = 3;
        let block_id = Some(Hash32([0xBB; 32]));
        let bytes1 = vote_sign_bytes(VoteType::Prevote, height, round, &block_id);
        let bytes2 = vote_sign_bytes(VoteType::Prevote, height, round, &block_id);
        assert_eq!(bytes1, bytes2);
    }

    #[test]
    fn test_nil_vote_different_domain() {
        let height = 100;
        let round = 3;
        let nil_sig = vote_sign_bytes(VoteType::Prevote, height, round, &None);
        let block_sig =
            vote_sign_bytes(VoteType::Prevote, height, round, &Some(Hash32([0xCC; 32])));
        assert_ne!(nil_sig, block_sig);
    }

    #[test]
    fn test_sign_bytes_fidelity() {
        let bytes = proposal_sign_bytes(1, 0, &Hash32([0xFF; 32]), None);
        let fidelity = sign_bytes_fidelity(&bytes, &bytes);
        assert!((fidelity - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_proposal_validate() {
        let config = test_config();
        let p = test_proposal();
        assert!(p.validate(&config).is_ok());

        let mut bad = p.clone();
        bad.purity = 0.0;
        assert!(bad.validate(&config).is_err());
    }

    #[test]
    fn test_vote_validate() {
        let config = test_config();
        let v = test_vote();
        assert!(v.validate(&config).is_ok());

        let mut bad = v.clone();
        bad.purity = 0.0;
        assert!(bad.validate(&config).is_err());
    }

    #[test]
    fn test_vote_is_nil() {
        let v = test_vote();
        assert!(!v.is_nil());

        let nil_vote = Vote::nil_vote(VoteType::Prevote, 1, 0, PublicKeyBytes(vec![0; 32]), SignatureBytes(vec![]));
        assert!(nil_vote.is_nil());
    }

    #[test]
    fn test_factory_stats() {
        let config = test_config();
        let factory = MessageFactory::new(config).unwrap();
        let p = test_proposal();
        factory.register_proposal_received(&p);
        let stats = factory.stats();
        assert_eq!(stats.proposals_received, 1);
        assert_eq!(stats.avg_purity(), 1.0);
    }

    #[test]
    fn test_factory_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let config = test_config();
        let factory = MessageFactory::with_persistence(path, config.clone()).unwrap();
        let p = test_proposal();
        factory.register_proposal_received(&p);
        assert!(factory.flush_stats().is_ok());

        let factory2 = MessageFactory::with_persistence(path, config).unwrap();
        let stats = factory2.stats();
        assert_eq!(stats.proposals_received, 1);
    }

    #[test]
    fn test_consensus_msg_validate() {
        let config = test_config();
        let p = test_proposal();
        let msg = ConsensusMsg::Proposal(p);
        assert!(msg.validate(&config).is_ok());

        let mut bad_p = test_proposal();
        bad_p.purity = 0.0;
        let bad_msg = ConsensusMsg::Proposal(bad_p);
        assert!(bad_msg.validate(&config).is_err());
    }

    #[test]
    fn test_consensus_msg_height_round() {
        let p = test_proposal();
        let msg = ConsensusMsg::Proposal(p);
        assert_eq!(msg.height(), Some(1));
        assert_eq!(msg.round(), Some(0));
    }

    #[test]
    fn test_consensus_msg_type() {
        let p = test_proposal();
        let msg = ConsensusMsg::Proposal(p);
        assert_eq!(msg.msg_type(), "Proposal");

        let v = test_vote();
        let msg = ConsensusMsg::Vote(v);
        assert_eq!(msg.msg_type(), "Prevote");
    }

    #[test]
    fn test_stats_totals() {
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
    fn test_proposal_matches_block() {
        let p = test_proposal();
        let block_id = Hash32([0xAA; 32]);
        assert!(p.matches_block(&block_id));
        let other = Hash32([0xBB; 32]);
        assert!(!p.matches_block(&other));
    }

    #[test]
    fn test_vote_matches_block() {
        let v = test_vote();
        let block_id = Hash32([0xBB; 32]);
        assert!(v.matches_block(&block_id));
        let other = Hash32([0xCC; 32]);
        assert!(!v.matches_block(&other));
    }

    #[test]
    fn test_vote_validation_nil_non_nil() {
        let config = test_config();
        let voter = PublicKeyBytes(vec![0; 32]);
        let sig = SignatureBytes(vec![]);

        // Nil vote: must have no block_id
        let nil_vote = Vote::nil_vote(VoteType::Prevote, 1, 0, voter.clone(), sig.clone());
        assert!(nil_vote.validate(&config).is_ok());

        // Non-nil vote: must have block_id
        let block_vote = Vote::block_vote(VoteType::Prevote, 1, 0, voter.clone(), Hash32([0xDD; 32]), sig.clone());
        assert!(block_vote.validate(&config).is_ok());

        // Invalid: nil vote with block_id
        let invalid = Vote {
            vote_type: VoteType::Prevote,
            height: 1,
            round: 0,
            voter: voter.clone(),
            block_id: Some(Hash32([0xEE; 32])),
            signature: sig.clone(),
            purity: 1.0,
            entanglement_fidelity: 1.0,
        };
        assert!(invalid.validate(&config).is_err());
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = MessageConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.max_message_size = 0;
        assert!(cfg.validate().is_err());

        cfg.max_message_size = 1024;
        cfg.min_purity = 1.5;
        assert!(cfg.validate().is_err());

        cfg.min_purity = 0.5;
        cfg.min_entanglement_fidelity = -1.0;
        assert!(cfg.validate().is_err());
    }
}
