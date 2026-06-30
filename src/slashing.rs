//! Production slashing and validator lifecycle for IONA v28 — Quantum‑Ready.
//!
//! # Quantum Slashing Model
//!
//! Slashing is modelled as a **strong projective measurement** that
//! collapses a validator's state from |active⟩ to |jailed⟩ or |tombstoned⟩.
//! The slash fraction determines the **energy penalty** extracted from the
//! validator's stake.
//!
//! # Production Features
//! - Thread‑safe with `parking_lot::Mutex`.
//! - Persistent state with atomic writes and file locking (`flock`).
//! - Configurable slashing parameters via `SlashingConfig`.
//! - Snapshot/rollback support for consensus operations.
//! - Structured logging with `tracing`.
//! - Versioned serialization for forward compatibility.
//! - Quantum coherence tracking with decoherence models.
//! - Comprehensive metrics for monitoring.

use crate::crypto::PublicKeyBytes;
use crate::evidence::Evidence;
use crate::types::Height;
use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, Instant},
};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh validator.
const DEFAULT_VALIDATOR_COHERENCE: f64 = 1.0;

/// Decoherence rate per slashing operation.
const DEFAULT_SLASH_DECOHERENCE_RATE: f64 = 0.001;

/// Decoherence rate per unjail operation.
const DEFAULT_UNJAIL_DECOHERENCE_RATE: f64 = 0.0005;

/// Decoherence rate per downtime slash.
const DEFAULT_DOWNTIME_DECOHERENCE_RATE: f64 = 0.0008;

/// Minimum coherence threshold for a healthy ledger.
const DEFAULT_MIN_LEDGER_COHERENCE: f64 = 0.9;

/// Kraus rank for slashing quantum channels.
const SLASHING_KRAUS_RANK: usize = 4;

/// Default lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default persistence file name.
const DEFAULT_PERSIST_FILE: &str = "slashing_state.json";

/// Maximum number of validators to persist (avoid unbounded growth).
const MAX_PERSISTED_VALIDATORS: usize = 10_000;

/// Default blocks a validator must wait after being jailed before they can unjail.
const DEFAULT_UNJAIL_DELAY_BLOCKS: u64 = 1000;

/// Default slash fraction denominator for double‑vote (1/20 = 5%).
const DEFAULT_SLASH_FRACTION_DOUBLE_VOTE: u64 = 20;

/// Default slash fraction denominator for downtime (1/100 = 1%).
const DEFAULT_SLASH_FRACTION_DOWNTIME: u64 = 100;

/// Default window of blocks to check for downtime.
const DEFAULT_DOWNTIME_WINDOW: u64 = 200;

/// Default minimum blocks a validator must have signed to avoid jailing.
const DEFAULT_DOWNTIME_MIN_SIGNED: u64 = 100;

/// Default minimum stake after slashing.
const DEFAULT_MIN_STAKE_AFTER_SLASH: u64 = 1;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the slashing module.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingConfig {
    /// Blocks a validator must wait after being jailed before they can unjail.
    pub unjail_delay_blocks: u64,
    /// Denominator for double‑vote slash fraction (1/denominator).
    pub slash_fraction_double_vote: u64,
    /// Denominator for downtime slash fraction (1/denominator).
    pub slash_fraction_downtime: u64,
    /// Window of recent blocks to check for downtime.
    pub downtime_window: u64,
    /// Minimum blocks signed in the window to avoid jailing.
    pub downtime_min_signed: u64,
    /// Minimum stake required to remain a validator after slashing.
    pub min_stake_after_slash: u64,
    /// Decoherence rate for slashing operations.
    pub slash_decoherence_rate: f64,
    /// Decoherence rate for unjail operations.
    pub unjail_decoherence_rate: f64,
    /// Decoherence rate for downtime slashes.
    pub downtime_decoherence_rate: f64,
    /// Minimum ledger coherence threshold.
    pub min_ledger_coherence: f64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
}

impl Default for SlashingConfig {
    fn default() -> Self {
        Self {
            unjail_delay_blocks: DEFAULT_UNJAIL_DELAY_BLOCKS,
            slash_fraction_double_vote: DEFAULT_SLASH_FRACTION_DOUBLE_VOTE,
            slash_fraction_downtime: DEFAULT_SLASH_FRACTION_DOWNTIME,
            downtime_window: DEFAULT_DOWNTIME_WINDOW,
            downtime_min_signed: DEFAULT_DOWNTIME_MIN_SIGNED,
            min_stake_after_slash: DEFAULT_MIN_STAKE_AFTER_SLASH,
            slash_decoherence_rate: DEFAULT_SLASH_DECOHERENCE_RATE,
            unjail_decoherence_rate: DEFAULT_UNJAIL_DECOHERENCE_RATE,
            downtime_decoherence_rate: DEFAULT_DOWNTIME_DECOHERENCE_RATE,
            min_ledger_coherence: DEFAULT_MIN_LEDGER_COHERENCE,
            persist_state: true,
        }
    }
}

impl SlashingConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.unjail_delay_blocks == 0 {
            return Err("unjail_delay_blocks must be > 0".into());
        }
        if self.slash_fraction_double_vote == 0 {
            return Err("slash_fraction_double_vote must be > 0".into());
        }
        if self.slash_fraction_downtime == 0 {
            return Err("slash_fraction_downtime must be > 0".into());
        }
        if self.downtime_window == 0 {
            return Err("downtime_window must be > 0".into());
        }
        if self.downtime_min_signed > self.downtime_window {
            return Err("downtime_min_signed must be <= downtime_window".into());
        }
        if self.min_stake_after_slash == 0 {
            return Err("min_stake_after_slash must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.slash_decoherence_rate) {
            return Err("slash_decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.unjail_decoherence_rate) {
            return Err("unjail_decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.downtime_decoherence_rate) {
            return Err("downtime_decoherence_rate must be between 0.0 and 1.0".into());
        }
        if !(0.0..=1.0).contains(&self.min_ledger_coherence) {
            return Err("min_ledger_coherence must be between 0.0 and 1.0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during slashing operations.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SlashingError {
    #[error("unknown validator")]
    UnknownValidator,

    #[error("validator is tombstoned – cannot unjail")]
    Tombstoned,

    #[error("validator is not jailed")]
    NotJailed,

    #[error("unjail delay not elapsed (wait {remaining} more blocks)")]
    UnjailDelayNotElapsed { remaining: u64 },

    #[error("validator has zero stake – cannot unjail")]
    ZeroStake,

    #[error("duplicate evidence already processed")]
    DuplicateEvidence,

    #[error("validator already jailed for downtime")]
    AlreadyJailed,

    #[error("quantum decoherence: ledger coherence {coherence:.4} below threshold {threshold:.4}")]
    Decoherence { coherence: f64, threshold: f64 },

    #[error("invalid configuration: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(String),

    #[error("serialization error: {0}")]
    Serialization(String),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),
}

pub type SlashingResult<T> = Result<T, SlashingError>;

// -----------------------------------------------------------------------------
// Persistent State (versioned)
// -----------------------------------------------------------------------------

/// Persistent validator record.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentValidatorRecord {
    pubkey_hex: String,
    stake: u64,
    slashed_total: u64,
    status: String,
    jailed_at_height: Option<u64>,
    coherence: f64,
}

/// Persistent state file format.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentStateV1 {
    version: u32,
    validators: Vec<PersistentValidatorRecord>,
    processed_evidence: Vec<(u64, String)>,
    quantum_purity: f64,
    quantum_entropy: f64,
    slashing_coherence: f64,
    unjail_coherence: f64,
    total_slashes: u64,
    total_unjails: u64,
    total_downtime_slashes: u64,
    tombstoned_count: usize,
    last_modified: u64,
}

impl PersistentStateV1 {
    fn from_ledger(ledger: &StakeLedger) -> Self {
        let mut validators = Vec::new();
        for (pk, record) in &ledger.validators {
            let status = match &record.status {
                ValidatorStatus::Active => "active".to_string(),
                ValidatorStatus::Jailed { .. } => "jailed".to_string(),
                ValidatorStatus::Tombstoned => "tombstoned".to_string(),
            };
            let jailed_at_height = match &record.status {
                ValidatorStatus::Jailed { since_height, .. } => Some(*since_height),
                _ => None,
            };
            validators.push(PersistentValidatorRecord {
                pubkey_hex: hex::encode(&pk.0),
                stake: record.stake,
                slashed_total: record.slashed_total,
                status,
                jailed_at_height,
                coherence: record.coherence,
            });
        }
        // Cap to avoid unbounded growth.
        if validators.len() > MAX_PERSISTED_VALIDATORS {
            validators.truncate(MAX_PERSISTED_VALIDATORS);
        }

        let processed_evidence = ledger
            .processed_evidence
            .iter()
            .map(|(h, pk)| (*h, hex::encode(&pk.0)))
            .collect();

        Self {
            version: CURRENT_VERSION,
            validators,
            processed_evidence,
            quantum_purity: ledger.quantum.purity,
            quantum_entropy: ledger.quantum.entropy,
            slashing_coherence: ledger.quantum.slashing_coherence,
            unjail_coherence: ledger.quantum.unjail_coherence,
            total_slashes: ledger.quantum.total_slashes,
            total_unjails: ledger.quantum.total_unjails,
            total_downtime_slashes: ledger.quantum.total_downtime_slashes,
            tombstoned_count: ledger.quantum.tombstoned_count,
            last_modified: current_timestamp(),
        }
    }

    fn into_ledger(self, config: &SlashingConfig) -> StakeLedger {
        let mut validators = BTreeMap::new();
        for rec in self.validators {
            let pk_bytes = match hex::decode(&rec.pubkey_hex) {
                Ok(bytes) => PublicKeyBytes(bytes),
                Err(_) => continue,
            };
            let status = match rec.status.as_str() {
                "active" => ValidatorStatus::Active,
                "jailed" => ValidatorStatus::Jailed {
                    since_height: rec.jailed_at_height.unwrap_or(0),
                    slash_count: 1,
                },
                "tombstoned" => ValidatorStatus::Tombstoned,
                _ => ValidatorStatus::Active,
            };
            validators.insert(
                pk_bytes,
                ValidatorRecord {
                    stake: rec.stake,
                    slashed_total: rec.slashed_total,
                    status,
                    jailed_at: rec.jailed_at_height,
                    coherence: rec.coherence,
                },
            );
        }

        let processed_evidence = self
            .processed_evidence
            .into_iter()
            .map(|(h, hex_str)| {
                let bytes = hex::decode(hex_str).unwrap_or_default();
                (h, PublicKeyBytes(bytes))
            })
            .collect();

        let quantum = QuantumSlashingState {
            purity: self.quantum_purity,
            entropy: self.quantum_entropy,
            slashing_coherence: self.slashing_coherence,
            unjail_coherence: self.unjail_coherence,
            total_slashes: self.total_slashes,
            total_unjails: self.total_unjails,
            total_downtime_slashes: self.total_downtime_slashes,
            tombstoned_count: self.tombstoned_count,
            is_healthy: self.quantum_purity >= config.min_ledger_coherence,
        };

        StakeLedger {
            validators,
            processed_evidence,
            quantum,
            config: config.clone(),
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── File I/O with locking ──────────────────────────────────────────────

fn acquire_lock(path: &Path) -> Result<File, SlashingError> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| SlashingError::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(LOCK_TIMEOUT_SECS);
    let start = Instant::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed() > timeout {
                    return Err(SlashingError::LockFailed(format!(
                        "timeout after {}s",
                        LOCK_TIMEOUT_SECS
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), SlashingError> {
    file.unlock().map_err(|e| SlashingError::LockFailed(e.to_string()))
}

fn load_state(path: &Path, config: &SlashingConfig) -> Result<Option<StakeLedger>, SlashingError> {
    if !path.exists() {
        return Ok(None);
    }
    let _lock = acquire_lock(path)?;
    let file = File::open(path).map_err(|e| SlashingError::Io(e.to_string()))?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)
        .map_err(|e| SlashingError::Serialization(e.to_string()))?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(SlashingError::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: PersistentStateV1 = serde_json::from_value(raw)
            .map_err(|e| SlashingError::Serialization(e.to_string()))?;
        Ok(Some(st.into_ledger(config)))
    } else {
        // Legacy: try to parse as ledger directly.
        match serde_json::from_value::<StakeLedger>(raw) {
            Ok(ledger) => Ok(Some(ledger)),
            Err(e) => Err(SlashingError::Serialization(e.to_string())),
        }
    }
}

fn save_state(path: &Path, ledger: &StakeLedger) -> Result<(), SlashingError> {
    let state = PersistentStateV1::from_ledger(ledger);
    let json = serde_json::to_string_pretty(&state)
        .map_err(|e| SlashingError::Serialization(e.to_string()))?;
    let _lock = acquire_lock(path)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json).map_err(|e| SlashingError::Io(e.to_string()))?;
    fs::rename(&temp_path, path).map_err(|e| SlashingError::Io(e.to_string()))?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Quantum Slashing State
// -----------------------------------------------------------------------------

/// Quantum state of the entire stake ledger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumSlashingState {
    pub purity: f64,
    pub entropy: f64,
    pub slashing_coherence: f64,
    pub unjail_coherence: f64,
    pub total_slashes: u64,
    pub total_unjails: u64,
    pub total_downtime_slashes: u64,
    pub tombstoned_count: usize,
    pub is_healthy: bool,
}

impl Default for QuantumSlashingState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_VALIDATOR_COHERENCE,
            entropy: 0.0,
            slashing_coherence: DEFAULT_VALIDATOR_COHERENCE,
            unjail_coherence: DEFAULT_VALIDATOR_COHERENCE,
            total_slashes: 0,
            total_unjails: 0,
            total_downtime_slashes: 0,
            tombstoned_count: 0,
            is_healthy: true,
        }
    }
}

impl QuantumSlashingState {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn apply_slash_decoherence(&mut self, tombstoned: bool, rate: f64) {
        self.total_slashes = self.total_slashes.wrapping_add(1);
        if tombstoned {
            self.tombstoned_count = self.tombstoned_count.saturating_add(1);
        }
        let decay = (-rate).exp();
        self.slashing_coherence = (self.slashing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_unjail_decoherence(&mut self, rate: f64) {
        self.total_unjails = self.total_unjails.wrapping_add(1);
        let decay = (-rate).exp();
        self.unjail_coherence = (self.unjail_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_downtime_decoherence(&mut self, rate: f64) {
        self.total_downtime_slashes = self.total_downtime_slashes.wrapping_add(1);
        let decay = (-rate).exp();
        self.slashing_coherence = (self.slashing_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_slashing_channel(&mut self) {
        let kraus_factor = (1.0 / SLASHING_KRAUS_RANK as f64).sqrt();
        self.slashing_coherence = (self.slashing_coherence * kraus_factor).clamp(0.0, 1.0);
        self.unjail_coherence = (self.unjail_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self, min_coherence: f64) {
        self.purity = (self.slashing_coherence * self.unjail_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= min_coherence;
    }

    // Backward compatibility.
    fn recompute(&mut self) {
        self.recompute(DEFAULT_MIN_LEDGER_COHERENCE);
    }
}

// -----------------------------------------------------------------------------
// Validator Status
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ValidatorStatus {
    Active,
    Jailed { since_height: Height, slash_count: u32 },
    Tombstoned,
}

// -----------------------------------------------------------------------------
// Validator Record
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ValidatorRecord {
    pub stake: u64,
    pub slashed_total: u64,
    pub status: ValidatorStatus,
    pub jailed_at: Option<Height>,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    DEFAULT_VALIDATOR_COHERENCE
}

impl ValidatorRecord {
    pub const fn new(stake: u64) -> Self {
        Self {
            stake,
            slashed_total: 0,
            status: ValidatorStatus::Active,
            jailed_at: None,
            coherence: DEFAULT_VALIDATOR_COHERENCE,
        }
    }

    pub const fn is_active(&self) -> bool {
        matches!(self.status, ValidatorStatus::Active)
    }

    pub const fn is_jailed(&self) -> bool {
        matches!(self.status, ValidatorStatus::Jailed { .. })
    }

    pub const fn is_tombstoned(&self) -> bool {
        matches!(self.status, ValidatorStatus::Tombstoned)
    }

    pub fn can_unjail(&self, current_height: Height, delay: u64) -> bool {
        match &self.status {
            ValidatorStatus::Jailed { since_height, .. } => {
                current_height >= since_height + delay
            }
            _ => false,
        }
    }

    pub fn apply_decoherence(&mut self, rate: f64) {
        self.coherence = (self.coherence * (-rate).exp()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// StakeLedger (classical + quantum)
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StakeLedger {
    pub validators: BTreeMap<PublicKeyBytes, ValidatorRecord>,
    pub processed_evidence: HashSet<(Height, PublicKeyBytes)>,
    pub quantum: QuantumSlashingState,
    #[serde(skip)]
    pub config: SlashingConfig,
}

impl Default for StakeLedger {
    fn default() -> Self {
        Self {
            validators: BTreeMap::new(),
            processed_evidence: HashSet::new(),
            quantum: QuantumSlashingState::default(),
            config: SlashingConfig::default(),
        }
    }
}

impl StakeLedger {
    pub fn new(config: SlashingConfig) -> Self {
        Self {
            validators: BTreeMap::new(),
            processed_evidence: HashSet::new(),
            quantum: QuantumSlashingState::default(),
            config,
        }
    }

    pub fn total_power(&self) -> u64 {
        self.validators
            .values()
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .sum()
    }

    pub fn power_of(&self, pk: &PublicKeyBytes) -> u64 {
        self.validators
            .get(pk)
            .filter(|r| r.is_active())
            .map(|r| r.stake)
            .unwrap_or(0)
    }

    pub fn stake_raw(&self) -> BTreeMap<PublicKeyBytes, u64> {
        self.validators
            .iter()
            .map(|(k, v)| (k.clone(), v.stake))
            .collect()
    }

    pub fn purity(&self) -> f64 {
        self.quantum.purity
    }

    pub fn is_healthy(&self) -> bool {
        self.quantum.is_healthy
    }

    pub fn apply_evidence(
        &mut self,
        evidence: &Evidence,
        current_height: Height,
    ) -> SlashingResult<()> {
        let (offender, height) = match evidence {
            Evidence::DoubleVote { voter, height, .. } => (voter, height),
            Evidence::DoubleProposal { proposer, height, .. } => (proposer, height),
        };

        let key = (*height, offender.clone());
        if self.processed_evidence.contains(&key) {
            warn!("duplicate evidence for offender at height {height}, ignoring");
            return Err(SlashingError::DuplicateEvidence);
        }
        self.processed_evidence.insert(key);

        let record = self
            .validators
            .get_mut(offender)
            .ok_or(SlashingError::UnknownValidator)?;

        let slash = (record.stake / self.config.slash_fraction_double_vote).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;

        let is_tombstone = matches!(
            &record.status,
            ValidatorStatus::Jailed { slash_count, .. } if *slash_count >= 2
        );

        if is_tombstone {
            record.status = ValidatorStatus::Tombstoned;
            record.coherence = 0.0;
            warn!(
                offender = %hex::encode(&offender.0),
                "validator tombstoned (repeated double‑vote/double‑proposal)"
            );
        } else {
            let slash_count = match &record.status {
                ValidatorStatus::Jailed { slash_count, .. } => *slash_count + 1,
                _ => 1,
            };
            record.status = ValidatorStatus::Jailed {
                since_height: current_height,
                slash_count,
            };
            record.jailed_at = Some(current_height);
            record.apply_decoherence(self.config.slash_decoherence_rate);
            warn!(
                offender = %hex::encode(&offender.0),
                slashed = slash,
                remaining = record.stake,
                "validator jailed"
            );
        }

        self.quantum.apply_slash_decoherence(
            is_tombstone,
            self.config.slash_decoherence_rate,
        );
        self.quantum.apply_slashing_channel();
        self.quantum.recompute(self.config.min_ledger_coherence);

        if !self.quantum.is_healthy {
            warn!(
                coherence = self.quantum.purity,
                "ledger quantum coherence below threshold"
            );
        }
        Ok(())
    }

    pub fn apply_evidence_quantum(
        &mut self,
        evidence: &Evidence,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.apply_evidence(evidence, current_height);
        (result, self.quantum.clone())
    }

    pub fn unjail(&mut self, pk: &PublicKeyBytes, current_height: Height) -> SlashingResult<()> {
        let record = self
            .validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        match &record.status {
            ValidatorStatus::Tombstoned => Err(SlashingError::Tombstoned),
            ValidatorStatus::Active => Err(SlashingError::NotJailed),
            ValidatorStatus::Jailed { since_height, .. } => {
                if !record.can_unjail(current_height, self.config.unjail_delay_blocks) {
                    let remaining = (since_height + self.config.unjail_delay_blocks)
                        .saturating_sub(current_height);
                    return Err(SlashingError::UnjailDelayNotElapsed { remaining });
                }
                if record.stake == 0 {
                    return Err(SlashingError::ZeroStake);
                }
                record.status = ValidatorStatus::Active;
                record.jailed_at = None;
                record.coherence = (record.coherence * 1.1).min(1.0);
                self.quantum.apply_unjail_decoherence(self.config.unjail_decoherence_rate);
                self.quantum.apply_slashing_channel();
                self.quantum.recompute(self.config.min_ledger_coherence);
                info!(validator = %hex::encode(&pk.0), "validator unjailed");
                Ok(())
            }
        }
    }

    pub fn unjail_quantum(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.unjail(pk, current_height);
        (result, self.quantum.clone())
    }

    pub fn slash_downtime(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> SlashingResult<()> {
        let record = self
            .validators
            .get_mut(pk)
            .ok_or(SlashingError::UnknownValidator)?;

        if !record.is_active() {
            return Err(SlashingError::AlreadyJailed);
        }

        let slash = (record.stake / self.config.slash_fraction_downtime).max(1);
        record.stake = record.stake.saturating_sub(slash);
        record.slashed_total += slash;
        record.status = ValidatorStatus::Jailed {
            since_height: current_height,
            slash_count: 1,
        };
        record.jailed_at = Some(current_height);
        record.apply_decoherence(self.config.downtime_decoherence_rate);
        warn!(
            validator = %hex::encode(&pk.0),
            slashed = slash,
            "validator jailed for downtime"
        );
        self.quantum.apply_downtime_decoherence(self.config.downtime_decoherence_rate);
        self.quantum.apply_slashing_channel();
        self.quantum.recompute(self.config.min_ledger_coherence);
        Ok(())
    }

    pub fn slash_downtime_quantum(
        &mut self,
        pk: &PublicKeyBytes,
        current_height: Height,
    ) -> (SlashingResult<()>, QuantumSlashingState) {
        let result = self.slash_downtime(pk, current_height);
        (result, self.quantum.clone())
    }

    pub fn status_report(&self) -> Vec<(PublicKeyBytes, &ValidatorRecord)> {
        self.validators.iter().map(|(k, v)| (k.clone(), v)).collect()
    }

    pub fn add_validator(&mut self, pk: PublicKeyBytes, stake: u64) {
        self.validators.insert(pk, ValidatorRecord::new(stake));
    }

    pub fn remove_validator(&mut self, pk: &PublicKeyBytes) {
        self.validators.remove(pk);
    }

    /// Create a snapshot for rollback.
    pub fn snapshot(&self) -> Self {
        self.clone()
    }

    /// Apply a snapshot (rollback).
    pub fn apply_snapshot(&mut self, snapshot: Self) {
        *self = snapshot;
    }

    /// Save to disk.
    pub fn save(&self, path: &Path) -> Result<(), SlashingError> {
        save_state(path, self)
    }

    /// Load from disk.
    pub fn load(path: &Path, config: SlashingConfig) -> Result<Self, SlashingError> {
        config.validate().map_err(|e| SlashingError::Config(e))?;
        match load_state(path, &config)? {
            Some(ledger) => Ok(ledger),
            None => Ok(Self::new(config)),
        }
    }

    /// Load or create with persistence.
    pub fn with_persistence(
        data_dir: &str,
        config: SlashingConfig,
    ) -> Result<Self, SlashingError> {
        config.validate().map_err(|e| SlashingError::Config(e))?;
        let path = PathBuf::from(data_dir).join(DEFAULT_PERSIST_FILE);
        if let Ok(Some(ledger)) = load_state(&path, &config) {
            Ok(ledger)
        } else {
            Ok(Self::new(config))
        }
    }

    /// Flush to disk if persistence is enabled.
    pub fn flush(&self) -> Result<(), SlashingError> {
        if self.config.persist_state {
            let path = PathBuf::from(".").join(DEFAULT_PERSIST_FILE);
            self.save(&path)
        } else {
            Ok(())
        }
    }
}

// -----------------------------------------------------------------------------
// Uptime Tracker
// -----------------------------------------------------------------------------

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct UptimeTracker {
    pub signed_in_window: BTreeMap<PublicKeyBytes, u64>,
    pub last_signed_height: BTreeMap<PublicKeyBytes, Height>,
    pub window_start: Height,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

impl UptimeTracker {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_block(
        &mut self,
        height: Height,
        signers: &[PublicKeyBytes],
        all_validators: &[PublicKeyBytes],
        window: u64,
    ) {
        if height > window {
            self.window_start = height - window;
        }

        for pk in signers {
            *self.signed_in_window.entry(pk.clone()).or_insert(0) += 1;
            self.last_signed_height.insert(pk.clone(), height);
        }

        for pk in all_validators {
            self.signed_in_window.entry(pk.clone()).or_insert(0);
        }

        self.coherence = (self.coherence * (-0.00001f64).exp()).clamp(0.0, 1.0);
    }

    pub fn signed_count(&self, pk: &PublicKeyBytes) -> u64 {
        *self.signed_in_window.get(pk).unwrap_or(&0)
    }

    pub fn last_signed(&self, pk: &PublicKeyBytes) -> Option<Height> {
        self.last_signed_height.get(pk).copied()
    }

    pub fn check_downtime(&self, height: Height, stakes: &StakeLedger, config: &SlashingConfig) -> Vec<PublicKeyBytes> {
        if height < config.downtime_window {
            return vec![];
        }
        stakes
            .validators
            .iter()
            .filter(|(_, r)| r.is_active())
            .filter(|(pk, _)| {
                let signed = self.signed_count(pk);
                let last = self.last_signed(pk).unwrap_or(0);
                last > 0 && signed < config.downtime_min_signed
            })
            .map(|(pk, _)| pk.clone())
            .collect()
    }

    pub fn reset_counts(&mut self, pk: &PublicKeyBytes) {
        self.signed_in_window.remove(pk);
        self.last_signed_height.remove(pk);
    }

    /// Clear all data (for testing).
    #[cfg(test)]
    pub fn clear(&mut self) {
        self.signed_in_window.clear();
        self.last_signed_height.clear();
        self.window_start = 0;
        self.coherence = 1.0;
    }
}

// -----------------------------------------------------------------------------
// Slashing Manager (thread‑safe wrapper)
// -----------------------------------------------------------------------------

/// Thread‑safe manager for slashing operations.
#[derive(Clone)]
pub struct SlashingManager {
    ledger: Arc<Mutex<StakeLedger>>,
    uptime: Arc<Mutex<UptimeTracker>>,
    path: Option<PathBuf>,
}

impl SlashingManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: SlashingConfig) -> Result<Self, SlashingError> {
        config.validate().map_err(|e| SlashingError::Config(e))?;
        Ok(Self {
            ledger: Arc::new(Mutex::new(StakeLedger::new(config))),
            uptime: Arc::new(Mutex::new(UptimeTracker::new())),
            path: None,
        })
    }

    /// Create with persistence.
    pub fn with_persistence(
        data_dir: &str,
        config: SlashingConfig,
    ) -> Result<Self, SlashingError> {
        config.validate().map_err(|e| SlashingError::Config(e))?;
        let path = PathBuf::from(data_dir).join(DEFAULT_PERSIST_FILE);
        let ledger = StakeLedger::with_persistence(data_dir, config)?;
        Ok(Self {
            ledger: Arc::new(Mutex::new(ledger)),
            uptime: Arc::new(Mutex::new(UptimeTracker::new())),
            path: Some(path),
        })
    }

    /// Apply evidence (double‑vote or double‑proposal).
    pub fn apply_evidence(
        &self,
        evidence: &Evidence,
        current_height: Height,
    ) -> SlashingResult<()> {
        let mut ledger = self.ledger.lock();
        let result = ledger.apply_evidence(evidence, current_height);
        if result.is_ok() && ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }
        result
    }

    /// Unjail a validator.
    pub fn unjail(&self, pk: &PublicKeyBytes, current_height: Height) -> SlashingResult<()> {
        let mut ledger = self.ledger.lock();
        let result = ledger.unjail(pk, current_height);
        if result.is_ok() && ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }
        result
    }

    /// Slash for downtime.
    pub fn slash_downtime(&self, pk: &PublicKeyBytes, current_height: Height) -> SlashingResult<()> {
        let mut ledger = self.ledger.lock();
        let result = ledger.slash_downtime(pk, current_height);
        if result.is_ok() && ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }
        result
    }

    /// Record a committed block for uptime tracking.
    pub fn record_block(&self, height: Height, signers: &[PublicKeyBytes]) {
        let mut uptime = self.uptime.lock();
        let ledger = self.ledger.lock();
        let all_validators: Vec<PublicKeyBytes> = ledger.validators.keys().cloned().collect();
        uptime.record_block(height, signers, &all_validators, ledger.config.downtime_window);
    }

    /// Check for downtime violations and slash offenders.
    pub fn check_and_slash_downtime(&self, current_height: Height) -> Vec<PublicKeyBytes> {
        let ledger = self.ledger.lock();
        let uptime = self.uptime.lock();
        let offenders = uptime.check_downtime(current_height, &ledger, &ledger.config);
        drop(ledger);
        drop(uptime);

        for pk in &offenders {
            let _ = self.slash_downtime(pk, current_height);
        }

        // Reset uptime counts for jailed validators.
        let mut uptime = self.uptime.lock();
        for pk in &offenders {
            uptime.reset_counts(pk);
        }
        drop(uptime);

        // Persist if enabled.
        let mut ledger = self.ledger.lock();
        if ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }

        offenders
    }

    /// Get a snapshot of the ledger (for rollback).
    pub fn snapshot(&self) -> StakeLedger {
        self.ledger.lock().snapshot()
    }

    /// Apply a snapshot (rollback).
    pub fn apply_snapshot(&self, snapshot: StakeLedger) {
        let mut ledger = self.ledger.lock();
        ledger.apply_snapshot(snapshot);
        if ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }
    }

    /// Get current ledger statistics.
    pub fn stats(&self) -> SlashingStats {
        let ledger = self.ledger.lock();
        let uptime = self.uptime.lock();
        let active = ledger
            .validators
            .values()
            .filter(|r| r.is_active())
            .count();
        let jailed = ledger
            .validators
            .values()
            .filter(|r| r.is_jailed())
            .count();
        let tombstoned = ledger
            .validators
            .values()
            .filter(|r| r.is_tombstoned())
            .count();

        SlashingStats {
            total_validators: ledger.validators.len(),
            active,
            jailed,
            tombstoned,
            total_power: ledger.total_power(),
            purity: ledger.quantum.purity,
            entropy: ledger.quantum.entropy,
            total_slashes: ledger.quantum.total_slashes,
            total_unjails: ledger.quantum.total_unjails,
            total_downtime_slashes: ledger.quantum.total_downtime_slashes,
            is_healthy: ledger.quantum.is_healthy,
            uptime_coherence: uptime.coherence,
        }
    }

    /// Flush state to disk.
    pub fn flush(&self) -> Result<(), SlashingError> {
        let ledger = self.ledger.lock();
        if let Some(path) = &self.path {
            ledger.save(path)
        } else {
            Ok(())
        }
    }

    /// Get configuration.
    pub fn config(&self) -> SlashingConfig {
        self.ledger.lock().config.clone()
    }

    /// Add a validator (for genesis).
    pub fn add_validator(&self, pk: PublicKeyBytes, stake: u64) {
        let mut ledger = self.ledger.lock();
        ledger.add_validator(pk, stake);
        if ledger.config.persist_state {
            if let Some(path) = &self.path {
                let _ = ledger.save(path);
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Statistics
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingStats {
    pub total_validators: usize,
    pub active: usize,
    pub jailed: usize,
    pub tombstoned: usize,
    pub total_power: u64,
    pub purity: f64,
    pub entropy: f64,
    pub total_slashes: u64,
    pub total_unjails: u64,
    pub total_downtime_slashes: u64,
    pub is_healthy: bool,
    pub uptime_coherence: f64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn dummy_pk(id: u8) -> PublicKeyBytes {
        let mut bytes = [0u8; 32];
        bytes[0] = id;
        PublicKeyBytes(bytes.to_vec())
    }

    fn test_config() -> SlashingConfig {
        let mut cfg = SlashingConfig::default();
        cfg.unjail_delay_blocks = 10;
        cfg.slash_fraction_double_vote = 10;
        cfg.slash_fraction_downtime = 10;
        cfg.downtime_window = 10;
        cfg.downtime_min_signed = 5;
        cfg.persist_state = false;
        cfg
    }

    #[test]
    fn test_validator_record() {
        let v = ValidatorRecord::new(1000);
        assert!(v.is_active());
        assert_eq!(v.stake, 1000);
        assert_eq!(v.slashed_total, 0);
        assert!((v.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_slash_double_vote() -> SlashingResult<()> {
        let config = test_config();
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(1);
        ledger.add_validator(pk.clone(), 1000);

        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 10));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_unjail() -> SlashingResult<()> {
        let config = test_config();
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(2);
        ledger.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10)?;
        let err = ledger.unjail(&pk, 10).unwrap_err();
        assert!(matches!(err, SlashingError::UnjailDelayNotElapsed { .. }));
        ledger.unjail(&pk, 10 + 10)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert!(record.is_active());
        Ok(())
    }

    #[test]
    fn test_downtime_slash() -> SlashingResult<()> {
        let config = test_config();
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(3);
        ledger.add_validator(pk.clone(), 1000);
        ledger.slash_downtime(&pk, 100)?;
        let record = ledger.validators.get(&pk).unwrap();
        assert_eq!(record.stake, 1000 - (1000 / 10));
        assert!(matches!(record.status, ValidatorStatus::Jailed { .. }));
        Ok(())
    }

    #[test]
    fn test_uptime_tracker() {
        let config = test_config();
        let pk = dummy_pk(4);
        let mut tracker = UptimeTracker::new();
        tracker.record_block(1, &[pk.clone()], &[pk.clone()], config.downtime_window);
        assert_eq!(tracker.signed_count(&pk), 1);
    }

    #[test]
    fn test_quantum_state() {
        let mut state = QuantumSlashingState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        state.apply_slash_decoherence(false, 0.001);
        assert!(state.purity < 1.0);
        assert_eq!(state.total_slashes, 1);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let mut config = test_config();
        config.persist_state = true;

        let ledger = StakeLedger::with_persistence(path, config.clone()).unwrap();
        let pk = dummy_pk(10);
        let mut ledger = ledger;
        ledger.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10).unwrap();
        ledger.flush().unwrap();

        // Load a new ledger.
        let ledger2 = StakeLedger::with_persistence(path, config).unwrap();
        assert_eq!(ledger2.total_power(), 1000 - (1000 / 10));
    }

    #[test]
    fn test_manager() {
        let config = test_config();
        let manager = SlashingManager::new(config).unwrap();
        let pk = dummy_pk(20);
        manager.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        manager.apply_evidence(&evidence, 10).unwrap();
        let stats = manager.stats();
        assert_eq!(stats.total_validators, 1);
        assert_eq!(stats.active, 0);
        assert_eq!(stats.jailed, 1);
    }

    #[test]
    fn test_snapshot() {
        let config = test_config();
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(30);
        ledger.add_validator(pk.clone(), 1000);
        let snapshot = ledger.snapshot();
        ledger.remove_validator(&pk);
        assert!(ledger.validators.is_empty());
        ledger.apply_snapshot(snapshot);
        assert!(ledger.validators.contains_key(&pk));
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = SlashingConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.unjail_delay_blocks = 0;
        assert!(cfg.validate().is_err());

        cfg.unjail_delay_blocks = 10;
        cfg.slash_fraction_double_vote = 0;
        assert!(cfg.validate().is_err());

        cfg.slash_fraction_double_vote = 10;
        cfg.downtime_min_signed = 100;
        cfg.downtime_window = 50;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_unjail_quantum_state() {
        let config = test_config();
        let mut ledger = StakeLedger::new(config);
        let pk = dummy_pk(40);
        ledger.add_validator(pk.clone(), 1000);
        let evidence = Evidence::DoubleVote {
            voter: pk.clone(),
            height: 10,
            round: 0,
            vote_type: crate::consensus::messages::VoteType::Prevote,
            a: None,
            b: None,
            vote_a: crate::consensus::messages::Vote::default(),
            vote_b: crate::consensus::messages::Vote::default(),
        };
        ledger.apply_evidence(&evidence, 10).unwrap();
        let initial_purity = ledger.quantum.purity;
        ledger.unjail(&pk, 20).unwrap();
        assert!(ledger.quantum.purity < initial_purity); // decoherence from unjail
    }
}
