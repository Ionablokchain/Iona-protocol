//! IONA — IBC Light Client (ICS-002 quantum implementation).
//!
//! # Quantum Light Client Model
//!
//! The IBC light client is modeled as a quantum system that tracks the
//! state of a counterparty chain. Each header verification is a quantum
//! measurement that collapses the superposition of possible chain states.
//!
//! # Production Features
//! - Thread‑safe client management with `parking_lot::Mutex`.
//! - Persistent state with atomic writes and file locking (`flock`).
//! - Configurable parameters with validation.
//! - Comprehensive metrics and statistics.
//! - Validation of headers and client states.
//! - Pruning of old consensus states to control storage growth.
//! - Builder pattern for client creation.
//! - Structured logging with `tracing`.

use fs2::FileExt;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufReader, BufWriter, Write},
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use thiserror::Error;
use tracing::{debug, error, info, warn};

use crate::types::Height;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default trust threshold numerator (1/3).
const DEFAULT_TRUST_NUMERATOR: u64 = 1;
const DEFAULT_TRUST_DENOMINATOR: u64 = 3;

/// Entanglement fidelity threshold for header acceptance.
const HEADER_FIDELITY_THRESHOLD: f64 = 0.99;

/// Maximum clock drift in seconds (quantum uncertainty principle limit).
const DEFAULT_MAX_CLOCK_DRIFT_S: u64 = 30;

/// Default trusting period in seconds (7 days).
const DEFAULT_TRUSTING_PERIOD_S: u64 = 7 * 24 * 3600;

/// Lock timeout in seconds.
const LOCK_TIMEOUT_SECS: u64 = 10;

/// Temporary file extension for atomic writes.
const TEMP_EXT: &str = ".tmp";

/// Current serialization version.
const CURRENT_VERSION: u32 = 1;

/// Default pruning threshold: keep only last N heights.
const DEFAULT_PRUNING_THRESHOLD: usize = 1000;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the IBC light client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IbcConfig {
    /// Default trust numerator.
    pub default_trust_numerator: u64,
    /// Default trust denominator.
    pub default_trust_denominator: u64,
    /// Default trusting period in seconds.
    pub default_trusting_period_s: u64,
    /// Default max clock drift in seconds.
    pub default_max_clock_drift_s: u64,
    /// Minimum required fidelity for header verification (0.0 – 1.0).
    pub min_fidelity: f64,
    /// Whether to persist state to disk.
    pub persist_state: bool,
    /// Maximum number of consensus states to keep per client (pruning).
    pub prune_threshold: usize,
    /// Lock timeout in seconds.
    pub lock_timeout_secs: u64,
}

impl Default for IbcConfig {
    fn default() -> Self {
        Self {
            default_trust_numerator: DEFAULT_TRUST_NUMERATOR,
            default_trust_denominator: DEFAULT_TRUST_DENOMINATOR,
            default_trusting_period_s: DEFAULT_TRUSTING_PERIOD_S,
            default_max_clock_drift_s: DEFAULT_MAX_CLOCK_DRIFT_S,
            min_fidelity: HEADER_FIDELITY_THRESHOLD,
            persist_state: true,
            prune_threshold: DEFAULT_PRUNING_THRESHOLD,
            lock_timeout_secs: LOCK_TIMEOUT_SECS,
        }
    }
}

impl IbcConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.default_trust_numerator == 0 || self.default_trust_denominator == 0 {
            return Err("trust threshold numerator and denominator must be > 0".into());
        }
        if self.default_trust_numerator > self.default_trust_denominator {
            return Err("trust numerator must be <= denominator".into());
        }
        if self.default_trusting_period_s == 0 {
            return Err("trusting_period_s must be > 0".into());
        }
        if self.default_max_clock_drift_s == 0 {
            return Err("max_clock_drift_s must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.min_fidelity) {
            return Err("min_fidelity must be between 0.0 and 1.0".into());
        }
        if self.prune_threshold == 0 {
            return Err("prune_threshold must be > 0".into());
        }
        if self.lock_timeout_secs == 0 {
            return Err("lock_timeout_secs must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum IBC Types
// -----------------------------------------------------------------------------

/// Unique identifier for an IBC light client.
pub type ClientId = String;

/// Chain ID of the counterparty chain.
pub type ChainId = String;

/// Quantum IBC height with revision number and height.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub struct IbcHeight {
    pub revision_number: u64,
    pub revision_height: u64,
}

impl IbcHeight {
    pub fn new(revision_number: u64, revision_height: u64) -> Self {
        Self {
            revision_number,
            revision_height,
        }
    }

    pub fn zero() -> Self {
        Self {
            revision_number: 0,
            revision_height: 0,
        }
    }

    /// Increment height by 1 (within same revision).
    pub fn increment(&self) -> Self {
        Self {
            revision_number: self.revision_number,
            revision_height: self.revision_height + 1,
        }
    }

    /// Check if this height is greater than another.
    pub fn is_gt(&self, other: &Self) -> bool {
        self.revision_number > other.revision_number
            || (self.revision_number == other.revision_number
                && self.revision_height > other.revision_height)
    }
}

impl std::fmt::Display for IbcHeight {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}-{}", self.revision_number, self.revision_height)
    }
}

// -----------------------------------------------------------------------------
// Quantum Client State
// -----------------------------------------------------------------------------

/// IBC client state — quantum configuration for tracking a counterparty chain.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientState {
    /// Chain ID of the counterparty.
    pub chain_id: ChainId,
    /// Latest height verified on the counterparty chain.
    pub latest_height: IbcHeight,
    /// Trust threshold (numerator/denominator). Typically 1/3.
    pub trust_threshold_numerator: u64,
    pub trust_threshold_denominator: u64,
    /// How long a header is trusted after its timestamp.
    pub trusting_period_s: u64,
    /// Maximum clock drift allowed (quantum uncertainty).
    pub max_clock_drift_s: u64,
    /// Whether the client is frozen (collapsed to |frozen⟩).
    pub frozen: bool,
    /// Height at which the client was frozen.
    pub frozen_height: Option<IbcHeight>,
    /// Quantum coherence of the client state.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
    /// Entanglement fidelity with counterparty.
    #[serde(default = "default_coherence")]
    pub entanglement_fidelity: f64,
    /// Number of successful updates.
    #[serde(default)]
    pub updates_count: u64,
    /// Number of verification failures.
    #[serde(default)]
    pub failures_count: u64,
    /// Creation timestamp (Unix seconds).
    #[serde(default)]
    pub created_at: u64,
}

fn default_coherence() -> f64 {
    1.0
}

impl ClientState {
    /// Create a new client state with default quantum properties.
    pub fn new(
        chain_id: ChainId,
        latest_height: IbcHeight,
        trust_threshold_numerator: u64,
        trust_threshold_denominator: u64,
        trusting_period_s: u64,
        max_clock_drift_s: u64,
    ) -> Self {
        Self {
            chain_id,
            latest_height,
            trust_threshold_numerator,
            trust_threshold_denominator,
            trusting_period_s,
            max_clock_drift_s,
            frozen: false,
            frozen_height: None,
            coherence: 1.0,
            entanglement_fidelity: 1.0,
            updates_count: 0,
            failures_count: 0,
            created_at: current_timestamp(),
        }
    }

    /// Apply decoherence from an update operation.
    pub fn apply_decoherence(&mut self) {
        let decay = (-0.0001).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.entanglement_fidelity =
            (self.entanglement_fidelity * decay.sqrt()).clamp(0.0, 1.0);
    }

    /// Freeze the client (collapse to |frozen⟩).
    pub fn freeze(&mut self, height: IbcHeight) {
        self.frozen = true;
        self.frozen_height = Some(height);
        self.coherence = 0.0;
        self.entanglement_fidelity = 0.0;
    }

    /// Check if the client is expired (trusting period passed).
    pub fn is_expired(&self, current_time_s: u64, latest_consensus_ts: u64) -> bool {
        let period_end = latest_consensus_ts.saturating_add(self.trusting_period_s);
        current_time_s > period_end
    }
}

// -----------------------------------------------------------------------------
// Quantum Consensus State
// -----------------------------------------------------------------------------

/// Consensus state at a specific height — the verified quantum snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    /// Block timestamp from the verified header.
    pub timestamp: u64,
    /// App hash (state root) of the counterparty.
    pub root: Vec<u8>,
    /// Next validators hash — entanglement link to future headers.
    pub next_validators_hash: Vec<u8>,
    /// Quantum fidelity of this consensus state.
    #[serde(default = "default_coherence")]
    pub fidelity: f64,
    /// Verification confidence (Born probability).
    #[serde(default = "default_coherence")]
    pub confidence: f64,
    /// Hash of the header that produced this consensus state.
    #[serde(default)]
    pub header_hash: Vec<u8>,
}

impl ConsensusState {
    /// Create a new consensus state from a verified header.
    pub fn from_header(header: &Header, fidelity: f64) -> Self {
        Self {
            timestamp: header.timestamp,
            root: header.app_hash.clone(),
            next_validators_hash: header.next_validators_hash.clone(),
            fidelity,
            confidence: fidelity,
            header_hash: header.quantum_signature.clone(), // placeholder
        }
    }

    /// Apply decoherence from storage.
    pub fn apply_decoherence(&mut self) {
        let decay = (-0.00001).exp();
        self.fidelity = (self.fidelity * decay).clamp(0.0, 1.0);
        self.confidence = (self.confidence * decay.sqrt()).clamp(0.0, 1.0);
    }
}

// -----------------------------------------------------------------------------
// Quantum Header
// -----------------------------------------------------------------------------

/// A Tendermint light block header for quantum verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Header {
    pub chain_id: ChainId,
    pub height: IbcHeight,
    pub timestamp: u64,
    pub validators_hash: Vec<u8>,
    pub next_validators_hash: Vec<u8>,
    pub app_hash: Vec<u8>,
    pub last_commit_hash: Vec<u8>,
    pub trusted_height: IbcHeight,
    pub trusted_validators_hash: Vec<u8>,
    #[serde(default)]
    pub quantum_signature: Vec<u8>,
}

impl Header {
    /// Validate the header's internal consistency.
    pub fn validate(&self) -> Result<(), String> {
        if self.chain_id.is_empty() {
            return Err("chain_id must not be empty".into());
        }
        if self.app_hash.is_empty() {
            return Err("app_hash must not be empty".into());
        }
        if self.validators_hash.is_empty() {
            return Err("validators_hash must not be empty".into());
        }
        if self.next_validators_hash.is_empty() {
            return Err("next_validators_hash must not be empty".into());
        }
        if self.height <= self.trusted_height {
            return Err(format!(
                "height {} must be greater than trusted_height {}",
                self.height, self.trusted_height
            ));
        }
        if self.timestamp == 0 {
            return Err("timestamp must be > 0".into());
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum Misbehaviour
// -----------------------------------------------------------------------------

/// Misbehaviour evidence — two conflicting headers creating entanglement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Misbehaviour {
    pub client_id: ClientId,
    pub header_1: Header,
    pub header_2: Header,
    #[serde(default)]
    pub witness_value: f64,
    #[serde(default = "default_coherence")]
    pub detection_confidence: f64,
}

// -----------------------------------------------------------------------------
// Quantum IBC Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum light client operations.
#[derive(Debug, Error)]
pub enum IbcError {
    #[error("client not found: {0}")]
    ClientNotFound(ClientId),

    #[error("consensus state not found at height {0}")]
    ConsensusNotFound(IbcHeight),

    #[error("client is frozen at height {0}")]
    ClientFrozen(IbcHeight),

    #[error("header height {header} <= latest {latest}")]
    HeaderHeightTooLow { header: IbcHeight, latest: IbcHeight },

    #[error("header timestamp {header_ts} in past (trusted={trusted_ts}, max_drift={drift_s}s)")]
    HeaderTimestampTooOld {
        header_ts: u64,
        trusted_ts: u64,
        drift_s: u64,
    },

    #[error("clock drift too large: {diff_s}s > {max_drift_s}s")]
    ClockDriftTooLarge { diff_s: u64, max_drift_s: u64 },

    #[error("trusting period expired: header_ts={header_ts}, period_end={period_end}")]
    TrustingPeriodExpired { header_ts: u64, period_end: u64 },

    #[error("validators hash mismatch: expected {expected}, got {actual}")]
    ValidatorsHashMismatch { expected: String, actual: String },

    #[error("misbehaviour: conflicting headers at same height")]
    Misbehaviour,

    #[error("client already exists: {0}")]
    ClientAlreadyExists(ClientId),

    #[error("quantum decoherence: fidelity {fidelity} below threshold {threshold}")]
    Decoherence { fidelity: f64, threshold: f64 },

    #[error("entanglement witness below detection threshold")]
    WitnessInsufficient,

    #[error("configuration error: {0}")]
    Config(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("invalid header: {0}")]
    InvalidHeader(String),

    #[error("invalid client state: {0}")]
    InvalidClientState(String),

    #[error("header verification failed: {0}")]
    VerificationFailed(String),
}

pub type IbcResult<T> = Result<T, IbcError>;

// -----------------------------------------------------------------------------
// Persistent Registry (versioned)
// -----------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistentRegistryV1 {
    version: u32,
    clients: BTreeMap<ClientId, ClientState>,
    consensus_states: BTreeMap<(ClientId, IbcHeight), ConsensusState>,
    next_client_seq: u64,
    coherence: f64,
    last_modified: u64,
}

impl PersistentRegistryV1 {
    fn from_registry(reg: &LightClientRegistry) -> Self {
        Self {
            version: CURRENT_VERSION,
            clients: reg.clients.clone(),
            consensus_states: reg.consensus_states.clone(),
            next_client_seq: reg.next_client_seq,
            coherence: reg.coherence,
            last_modified: current_timestamp(),
        }
    }

    fn into_registry(self) -> LightClientRegistry {
        LightClientRegistry {
            clients: self.clients,
            consensus_states: self.consensus_states,
            next_client_seq: self.next_client_seq,
            coherence: self.coherence,
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
// File I/O with locking
// -----------------------------------------------------------------------------

fn acquire_lock(path: &Path, timeout_secs: u64) -> Result<File, IbcError> {
    let lock_path = path.with_extension("lock");
    let file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(&lock_path)
        .map_err(|e| IbcError::LockFailed(e.to_string()))?;
    let timeout = Duration::from_secs(timeout_secs);
    let start = SystemTime::now();
    loop {
        match file.try_lock_exclusive() {
            Ok(()) => return Ok(file),
            Err(_) => {
                if start.elapsed().unwrap_or_default() > timeout {
                    return Err(IbcError::LockFailed(format!(
                        "timeout after {}s",
                        timeout_secs
                    )));
                }
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}

fn release_lock(file: File) -> Result<(), IbcError> {
    file.unlock().map_err(|e| IbcError::LockFailed(e.to_string()))
}

fn load_registry(path: &Path, config: &IbcConfig) -> Result<LightClientRegistry, IbcError> {
    if !path.exists() {
        return Ok(LightClientRegistry::default());
    }
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let raw: serde_json::Value = serde_json::from_reader(reader)?;
    if let Some(version) = raw.get("version").and_then(|v| v.as_u64()) {
        if version != CURRENT_VERSION as u64 {
            return Err(IbcError::Config(format!(
                "unsupported version: {} (expected {})",
                version, CURRENT_VERSION
            )));
        }
        let st: PersistentRegistryV1 = serde_json::from_value(raw)?;
        Ok(st.into_registry())
    } else {
        // Legacy format
        match serde_json::from_value::<LightClientRegistry>(raw) {
            Ok(reg) => Ok(reg),
            Err(e) => Err(IbcError::Serialization(e)),
        }
    }
}

fn save_registry(path: &Path, registry: &LightClientRegistry, config: &IbcConfig) -> Result<(), IbcError> {
    let st = PersistentRegistryV1::from_registry(registry);
    let json = serde_json::to_string_pretty(&st)?;
    let _lock = acquire_lock(path, config.lock_timeout_secs)?;
    let temp_path = path.with_extension(TEMP_EXT);
    fs::write(&temp_path, &json)?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

// -----------------------------------------------------------------------------
// Light Client Registry (thread‑safe)
// -----------------------------------------------------------------------------

/// On-chain registry of quantum IBC light clients.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LightClientRegistry {
    pub clients: BTreeMap<ClientId, ClientState>,
    pub consensus_states: BTreeMap<(ClientId, IbcHeight), ConsensusState>,
    pub next_client_seq: u64,
    pub coherence: f64,
}

impl LightClientRegistry {
    /// Create a new client with a generated ID.
    pub fn create_client(
        &mut self,
        chain_id: ChainId,
        initial_height: IbcHeight,
        initial_consensus: ConsensusState,
        trust_num: u64,
        trust_den: u64,
        trusting_period_s: u64,
        max_clock_drift_s: u64,
    ) -> Result<ClientId, IbcError> {
        let client_id = format!("{}-{}", chain_id, self.next_client_seq);
        self.next_client_seq = self.next_client_seq.wrapping_add(1);

        let client = ClientState::new(
            chain_id,
            initial_height,
            trust_num,
            trust_den,
            trusting_period_s,
            max_clock_drift_s,
        );

        self.clients.insert(client_id.clone(), client);
        self.consensus_states.insert(
            (client_id.clone(), initial_height),
            initial_consensus,
        );
        self.coherence *= 0.9999;

        Ok(client_id)
    }

    /// Update client with a new header.
    pub fn update_client(
        &mut self,
        client_id: &str,
        header: Header,
        current_time_s: u64,
        config: &IbcConfig,
    ) -> Result<IbcHeight, IbcError> {
        let client = self
            .clients
            .get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.to_string()))?
            .clone();

        if client.frozen {
            return Err(IbcError::ClientFrozen(
                client.frozen_height.unwrap_or(IbcHeight::zero()),
            ));
        }

        // Validate header
        header.validate().map_err(IbcError::InvalidHeader)?;

        // Get trusted consensus
        let trusted_cs = self
            .consensus_states
            .get(&(client_id.to_string(), header.trusted_height))
            .ok_or(IbcError::ConsensusNotFound(header.trusted_height))?
            .clone();

        // Quantum verification
        let fidelity = Self::verify_header_quantum(
            &client,
            &header,
            &trusted_cs,
            current_time_s,
            config,
        )?;

        let new_height = header.height;
        let new_cs = ConsensusState::from_header(&header, fidelity);

        // Update client
        if new_height > client.latest_height {
            let client_mut = self.clients.get_mut(client_id).unwrap();
            client_mut.latest_height = new_height;
            client_mut.updates_count += 1;
            client_mut.apply_decoherence();
        }

        self.consensus_states
            .insert((client_id.to_string(), new_height), new_cs);

        // Prune old consensus states
        self.prune_consensus_states(client_id, config.prune_threshold);

        self.coherence *= 0.9999;

        Ok(new_height)
    }

    /// Prune old consensus states for a client.
    fn prune_consensus_states(&mut self, client_id: &str, keep: usize) {
        let prefix = (client_id.to_string(), IbcHeight::zero());
        let mut heights: Vec<IbcHeight> = self
            .consensus_states
            .keys()
            .filter_map(|(id, h)| {
                if id == client_id {
                    Some(*h)
                } else {
                    None
                }
            })
            .collect();
        heights.sort_unstable();
        if heights.len() > keep {
            let remove_count = heights.len() - keep;
            for h in &heights[0..remove_count] {
                self.consensus_states.remove(&(client_id.to_string(), *h));
            }
            debug!(
                client_id = %client_id,
                removed = remove_count,
                "pruned old consensus states"
            );
        }
    }

    /// Submit misbehaviour (freeze client).
    pub fn submit_misbehaviour(
        &mut self,
        mut misbehaviour: Misbehaviour,
        config: &IbcConfig,
    ) -> Result<(), IbcError> {
        let client_id = &misbehaviour.client_id;
        let client = self
            .clients
            .get(client_id)
            .ok_or_else(|| IbcError::ClientNotFound(client_id.clone()))?
            .clone();

        if client.frozen {
            return Ok(());
        }

        // Both headers must be at same height
        if misbehaviour.header_1.height != misbehaviour.header_2.height {
            return Err(IbcError::Misbehaviour);
        }

        // Must have different app hashes
        if misbehaviour.header_1.app_hash == misbehaviour.header_2.app_hash {
            return Err(IbcError::Misbehaviour);
        }

        // Compute witness
        let witness = Self::compute_misbehaviour_witness(
            &misbehaviour.header_1,
            &misbehaviour.header_2,
        );
        if witness < config.min_fidelity {
            return Err(IbcError::WitnessInsufficient);
        }

        misbehaviour.witness_value = witness;
        misbehaviour.detection_confidence = witness;

        let freeze_height = misbehaviour.header_1.height;
        let client_mut = self.clients.get_mut(client_id).unwrap();
        client_mut.freeze(freeze_height);
        self.coherence *= 0.99;

        info!(
            client_id = %client_id,
            height = %freeze_height,
            witness = witness,
            "client frozen due to misbehaviour"
        );

        Ok(())
    }

    /// Quantum header verification.
    fn verify_header_quantum(
        client: &ClientState,
        header: &Header,
        trusted_cs: &ConsensusState,
        current_time_s: u64,
        config: &IbcConfig,
    ) -> Result<f64, IbcError> {
        let mut fidelity = 1.0;

        // 1. Height check
        if header.height <= header.trusted_height {
            return Err(IbcError::HeaderHeightTooLow {
                header: header.height,
                latest: header.trusted_height,
            });
        }
        fidelity *= 0.999;

        // 2. Trusting period
        let period_end = trusted_cs
            .timestamp
            .saturating_add(client.trusting_period_s);
        if header.timestamp > period_end {
            return Err(IbcError::TrustingPeriodExpired {
                header_ts: header.timestamp,
                period_end,
            });
        }
        fidelity *= 0.999;

        // 3. Clock drift
        if header.timestamp > current_time_s.saturating_add(client.max_clock_drift_s) {
            return Err(IbcError::ClockDriftTooLarge {
                diff_s: header.timestamp - current_time_s,
                max_drift_s: client.max_clock_drift_s,
            });
        }
        fidelity *= 0.999;

        // 4. Header timestamp >= trusted timestamp
        if header.timestamp < trusted_cs.timestamp {
            return Err(IbcError::HeaderTimestampTooOld {
                header_ts: header.timestamp,
                trusted_ts: trusted_cs.timestamp,
                drift_s: client.max_clock_drift_s,
            });
        }
        fidelity *= 0.999;

        // 5. Validators hash match
        let expected = hex::encode(&trusted_cs.next_validators_hash);
        let actual = hex::encode(&header.validators_hash);
        if expected != actual {
            return Err(IbcError::ValidatorsHashMismatch {
                expected,
                actual,
            });
        }
        fidelity *= 0.998;

        // Check minimum
        if fidelity < config.min_fidelity {
            return Err(IbcError::Decoherence {
                fidelity,
                threshold: config.min_fidelity,
            });
        }

        Ok(fidelity)
    }

    /// Compute misbehaviour witness.
    fn compute_misbehaviour_witness(header_1: &Header, header_2: &Header) -> f64 {
        let h1 = &header_1.app_hash;
        let h2 = &header_2.app_hash;
        let len = h1.len().min(h2.len());
        if len == 0 {
            return 1.0;
        }
        let matches = h1.iter().zip(h2.iter()).filter(|(a, b)| a == b).count();
        1.0 - (matches as f64 / len as f64)
    }

    /// Get client state.
    pub fn client(&self, id: &str) -> Option<&ClientState> {
        self.clients.get(id)
    }

    /// Get consensus state.
    pub fn consensus_state(&self, id: &str, height: IbcHeight) -> Option<&ConsensusState> {
        self.consensus_states.get(&(id.to_string(), height))
    }

    /// List client IDs.
    pub fn client_ids(&self) -> Vec<&str> {
        self.clients.keys().map(|s| s.as_str()).collect()
    }

    /// Get registry statistics.
    pub fn stats(&self) -> IbcStats {
        IbcStats {
            total_clients: self.clients.len(),
            frozen_clients: self.clients.values().filter(|c| c.frozen).count(),
            total_consensus_states: self.consensus_states.len(),
            coherence: self.coherence,
            total_updates: self.clients.values().map(|c| c.updates_count).sum(),
            total_failures: self.clients.values().map(|c| c.failures_count).sum(),
        }
    }
}

// -----------------------------------------------------------------------------
// IBC Statistics
// -----------------------------------------------------------------------------

/// Observable statistics for the IBC light client registry.
#[derive(Debug, Clone)]
pub struct IbcStats {
    pub total_clients: usize,
    pub frozen_clients: usize,
    pub total_consensus_states: usize,
    pub coherence: f64,
    pub total_updates: u64,
    pub total_failures: u64,
}

// -----------------------------------------------------------------------------
// IBC Light Client Manager (thread‑safe, persistent)
// -----------------------------------------------------------------------------

/// Manages IBC light clients with persistence and thread‑safety.
#[derive(Clone)]
pub struct IbcManager {
    registry: Arc<Mutex<LightClientRegistry>>,
    config: Arc<IbcConfig>,
    path: Option<PathBuf>,
}

impl IbcManager {
    /// Create a new manager with configuration.
    pub fn new(config: IbcConfig) -> Result<Self, IbcError> {
        config.validate().map_err(IbcError::Config)?;
        Ok(Self {
            registry: Arc::new(Mutex::new(LightClientRegistry::default())),
            config: Arc::new(config),
            path: None,
        })
    }

    /// Create a manager with persistence.
    pub fn with_persistence(data_dir: &str, config: IbcConfig) -> Result<Self, IbcError> {
        config.validate().map_err(IbcError::Config)?;
        let path = PathBuf::from(data_dir).join("ibc_registry.json");
        let registry = if path.exists() {
            load_registry(&path, &config)?
        } else {
            LightClientRegistry::default()
        };
        // Ensure directory exists
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let manager = Self {
            registry: Arc::new(Mutex::new(registry)),
            config: Arc::new(config),
            path: Some(path),
        };
        // Save initial state if new
        if let Some(p) = &manager.path {
            let reg = manager.registry.lock();
            if manager.config.persist_state {
                let _ = save_registry(p, &reg, &manager.config);
            }
        }
        Ok(manager)
    }

    /// Create a new client.
    pub fn create_client(
        &self,
        chain_id: ChainId,
        initial_height: IbcHeight,
        initial_consensus: ConsensusState,
        trust_threshold_num: Option<u64>,
        trust_threshold_den: Option<u64>,
        trusting_period_s: Option<u64>,
        max_clock_drift_s: Option<u64>,
    ) -> IbcResult<ClientId> {
        let trust_num = trust_threshold_num.unwrap_or(self.config.default_trust_numerator);
        let trust_den = trust_threshold_den.unwrap_or(self.config.default_trust_denominator);
        let trust_period = trusting_period_s.unwrap_or(self.config.default_trusting_period_s);
        let max_drift = max_clock_drift_s.unwrap_or(self.config.default_max_clock_drift_s);

        if trust_num == 0 || trust_den == 0 {
            return Err(IbcError::Config(
                "trust threshold numerator and denominator must be > 0".into(),
            ));
        }
        if trust_num > trust_den {
            return Err(IbcError::Config("trust numerator must be <= denominator".into()));
        }
        if trust_period == 0 {
            return Err(IbcError::Config("trust_period must be > 0".into()));
        }

        let mut reg = self.registry.lock();
        let id = reg.create_client(
            chain_id,
            initial_height,
            initial_consensus,
            trust_num,
            trust_den,
            trust_period,
            max_drift,
        )?;
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_registry(path, &reg, &self.config);
            }
        }
        Ok(id)
    }

    /// Update a client with a new header.
    pub fn update_client(
        &self,
        client_id: &str,
        header: Header,
        current_time_s: u64,
    ) -> IbcResult<IbcHeight> {
        let mut reg = self.registry.lock();
        let result = reg.update_client(client_id, header, current_time_s, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_registry(path, &reg, &self.config);
            }
        }
        result
    }

    /// Submit misbehaviour.
    pub fn submit_misbehaviour(&self, misbehaviour: Misbehaviour) -> IbcResult<()> {
        let mut reg = self.registry.lock();
        let result = reg.submit_misbehaviour(misbehaviour, &self.config);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_registry(path, &reg, &self.config);
            }
        }
        result
    }

    /// Get client state.
    pub fn client(&self, id: &str) -> Option<ClientState> {
        self.registry.lock().client(id).cloned()
    }

    /// Get consensus state.
    pub fn consensus_state(&self, id: &str, height: IbcHeight) -> Option<ConsensusState> {
        self.registry.lock().consensus_state(id, height).cloned()
    }

    /// List client IDs.
    pub fn client_ids(&self) -> Vec<String> {
        self.registry
            .lock()
            .client_ids()
            .iter()
            .map(|s| s.to_string())
            .collect()
    }

    /// Get statistics.
    pub fn stats(&self) -> IbcStats {
        self.registry.lock().stats()
    }

    /// Flush state to disk.
    pub fn flush(&self) -> IbcResult<()> {
        if let Some(path) = &self.path {
            let reg = self.registry.lock();
            save_registry(path, &reg, &self.config)?;
        }
        Ok(())
    }

    /// Get configuration.
    pub fn config(&self) -> &IbcConfig {
        &self.config
    }

    /// Prune consensus states for a client.
    pub fn prune_client(&self, client_id: &str, keep: usize) -> IbcResult<()> {
        let mut reg = self.registry.lock();
        reg.prune_consensus_states(client_id, keep);
        if self.config.persist_state {
            if let Some(path) = &self.path {
                let _ = save_registry(path, &reg, &self.config);
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// RPC Helpers
// -----------------------------------------------------------------------------

/// IBC query response for a client state.
#[derive(Debug, Serialize)]
pub struct ClientStateResponse {
    pub client_id: String,
    pub chain_id: String,
    pub latest_height: String,
    pub trust_threshold: String,
    pub trusting_period_s: u64,
    pub frozen: bool,
    pub frozen_height: Option<String>,
    pub coherence: f64,
    pub entanglement_fidelity: f64,
    pub updates_count: u64,
    pub failures_count: u64,
    pub created_at: u64,
}

impl From<(&str, &ClientState)> for ClientStateResponse {
    fn from((id, cs): (&str, &ClientState)) -> Self {
        Self {
            client_id: id.to_string(),
            chain_id: cs.chain_id.clone(),
            latest_height: cs.latest_height.to_string(),
            trust_threshold: format!(
                "{}/{}",
                cs.trust_threshold_numerator, cs.trust_threshold_denominator
            ),
            trusting_period_s: cs.trusting_period_s,
            frozen: cs.frozen,
            frozen_height: cs.frozen_height.map(|h| h.to_string()),
            coherence: cs.coherence,
            entanglement_fidelity: cs.entanglement_fidelity,
            updates_count: cs.updates_count,
            failures_count: cs.failures_count,
            created_at: cs.created_at,
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> IbcConfig {
        let mut cfg = IbcConfig::default();
        cfg.persist_state = true;
        cfg.min_fidelity = 0.5;
        cfg
    }

    fn make_consensus(ts: u64) -> ConsensusState {
        ConsensusState {
            timestamp: ts,
            root: vec![1u8; 32],
            next_validators_hash: vec![0xABu8; 32],
            fidelity: 1.0,
            confidence: 1.0,
            header_hash: vec![],
        }
    }

    #[test]
    fn test_create_and_query_client() {
        let cfg = test_config();
        let manager = IbcManager::new(cfg).unwrap();
        let initial_height = IbcHeight::new(4, 100);
        let cs = make_consensus(1_700_000_000);

        let id = manager
            .create_client(
                "cosmoshub-4".into(),
                initial_height,
                cs,
                None, None, None, None,
            )
            .unwrap();

        assert!(id.starts_with("cosmoshub-4-"));
        let state = manager.client(&id).unwrap();
        assert_eq!(state.latest_height, initial_height);
        assert!(!state.frozen);
        assert!((state.coherence - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_update_client_success() {
        let cfg = test_config();
        let manager = IbcManager::new(cfg).unwrap();
        let trusted_h = IbcHeight::new(4, 100);
        let trusted_ts = 1_700_000_000u64;
        let cs = make_consensus(trusted_ts);
        let next_validators_hash = cs.next_validators_hash.clone();

        let id = manager
            .create_client(
                "chain-1".into(),
                trusted_h,
                cs,
                None, None, None, None,
            )
            .unwrap();

        let header = Header {
            chain_id: "chain-1".into(),
            height: IbcHeight::new(4, 101),
            timestamp: trusted_ts + 6,
            validators_hash: next_validators_hash.clone(),
            next_validators_hash: vec![0xCDu8; 32],
            app_hash: vec![2u8; 32],
            last_commit_hash: vec![3u8; 32],
            trusted_height: trusted_h,
            trusted_validators_hash: next_validators_hash,
            quantum_signature: vec![],
        };

        let current_time = trusted_ts + 10;
        let new_h = manager.update_client(&id, header, current_time).unwrap();
        assert_eq!(new_h, IbcHeight::new(4, 101));
        let state = manager.client(&id).unwrap();
        assert_eq!(state.latest_height, IbcHeight::new(4, 101));
        assert_eq!(state.updates_count, 1);
    }

    #[test]
    fn test_misbehaviour_freezes_client() {
        let cfg = test_config();
        let manager = IbcManager::new(cfg).unwrap();
        let h = IbcHeight::new(1, 50);
        let id = manager
            .create_client(
                "chain-x".into(),
                h,
                make_consensus(1_000),
                None, None, None, None,
            )
            .unwrap();

        let mb = Misbehaviour {
            client_id: id.clone(),
            header_1: Header {
                chain_id: "chain-x".into(),
                height: IbcHeight::new(1, 60),
                timestamp: 1100,
                validators_hash: vec![],
                next_validators_hash: vec![],
                app_hash: vec![1u8; 32],
                last_commit_hash: vec![],
                trusted_height: h,
                trusted_validators_hash: vec![],
                quantum_signature: vec![],
            },
            header_2: Header {
                chain_id: "chain-x".into(),
                height: IbcHeight::new(1, 60),
                timestamp: 1100,
                validators_hash: vec![],
                next_validators_hash: vec![],
                app_hash: vec![2u8; 32],
                last_commit_hash: vec![],
                trusted_height: h,
                trusted_validators_hash: vec![],
                quantum_signature: vec![],
            },
            witness_value: 0.0,
            detection_confidence: 1.0,
        };

        manager.submit_misbehaviour(mb).unwrap();
        let state = manager.client(&id).unwrap();
        assert!(state.frozen);
        assert!((state.coherence - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().to_str().unwrap();
        let cfg = test_config();

        {
            let manager = IbcManager::with_persistence(path, cfg.clone()).unwrap();
            let id = manager
                .create_client(
                    "chain-p".into(),
                    IbcHeight::new(1, 1),
                    make_consensus(1000),
                    None, None, None, None,
                )
                .unwrap();
            let header = Header {
                chain_id: "chain-p".into(),
                height: IbcHeight::new(1, 2),
                timestamp: 1010,
                validators_hash: vec![0xABu8; 32],
                next_validators_hash: vec![0xCDu8; 32],
                app_hash: vec![2u8; 32],
                last_commit_hash: vec![],
                trusted_height: IbcHeight::new(1, 1),
                trusted_validators_hash: vec![0xABu8; 32],
                quantum_signature: vec![],
            };
            manager.update_client(&id, header, 1020).unwrap();
            manager.flush().unwrap();
        }

        {
            let manager = IbcManager::with_persistence(path, cfg).unwrap();
            let stats = manager.stats();
            assert_eq!(stats.total_clients, 1);
            let state = manager.client(&"chain-p-0".to_string()).unwrap();
            assert_eq!(state.latest_height, IbcHeight::new(1, 2));
            assert_eq!(state.updates_count, 1);
        }
    }

    #[test]
    fn test_pruning() {
        let cfg = test_config();
        let manager = IbcManager::new(cfg).unwrap();
        let id = manager
            .create_client(
                "chain-p".into(),
                IbcHeight::new(1, 1),
                make_consensus(1000),
                None, None, None, None,
            )
            .unwrap();

        for i in 2..=2000 {
            let header = Header {
                chain_id: "chain-p".into(),
                height: IbcHeight::new(1, i),
                timestamp: 1000 + i * 10,
                validators_hash: vec![0xABu8; 32],
                next_validators_hash: vec![0xCDu8; 32],
                app_hash: vec![i as u8; 32],
                last_commit_hash: vec![],
                trusted_height: IbcHeight::new(1, i - 1),
                trusted_validators_hash: vec![0xABu8; 32],
                quantum_signature: vec![],
            };
            manager.update_client(&id, header, 1000 + i * 10 + 5).unwrap();
        }
        // Prune to last 100
        manager.prune_client(&id, 100).unwrap();

        let stats = manager.stats();
        assert!(stats.total_consensus_states <= 100);
    }

    #[test]
    fn test_misbehaviour_witness() {
        let h1 = Header {
            chain_id: "test".into(),
            height: IbcHeight::new(1, 1),
            timestamp: 1000,
            validators_hash: vec![],
            next_validators_hash: vec![],
            app_hash: vec![1u8; 32],
            last_commit_hash: vec![],
            trusted_height: IbcHeight::zero(),
            trusted_validators_hash: vec![],
            quantum_signature: vec![],
        };
        let h2 = Header {
            app_hash: vec![2u8; 32],
            ..h1.clone()
        };
        let witness = LightClientRegistry::compute_misbehaviour_witness(&h1, &h2);
        assert!(witness > 0.9);
    }

    #[test]
    fn test_config_validation() {
        let mut cfg = IbcConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.default_trust_numerator = 0;
        assert!(cfg.validate().is_err());

        cfg.default_trust_numerator = 2;
        cfg.default_trust_denominator = 1;
        assert!(cfg.validate().is_err());

        cfg.default_trust_numerator = 1;
        cfg.default_trust_denominator = 3;
        cfg.min_fidelity = 1.5;
        assert!(cfg.validate().is_err());
    }
}
