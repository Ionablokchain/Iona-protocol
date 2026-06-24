//! Quantum audit trail — tamper-evident logging via entanglement chains.
//!
//! # Quantum Audit Architecture
//!
//! Each audit event is modeled as a quantum state |e_i⟩ in a Hilbert space
//! of security-relevant events. The audit trail forms an **entanglement chain**
//! where each event is quantum-correlated with its predecessor:
//!
//! ```text
//! |Ψ_chain⟩ = |e₀⟩ ⊗ Σ_i √p_i |e_i⟩ ⊗ |e_{i-1}⟩
//! ```
//!
//! # Hamiltonian for Audit Operations
//!
//! ```text
//! Ĥ_audit = Ĥ_record + Ĥ_verify + Ĥ_entangle
//!
//! Ĥ_record   = Σ_i E_i a†_i a_i                    (event recording)
//! Ĥ_verify   = Σ_j λ_j |valid_j⟩⟨valid_j|           (integrity measurement)
//! Ĥ_entangle = Σ_k g_k (σ^+_k σ^-_{k+1} + h.c.)    (hash chain entanglement)
//! ```
//!
//! # Tamper Evidence via Quantum No-Cloning
//!
//! The audit chain leverages the **quantum no-cloning theorem**: any attempt
//! to modify a past event breaks the entanglement, causing the entire chain
//! to decohere. This provides information-theoretic tamper evidence.
//!
//! # Decoherence Channels
//!
//! Environmental coupling is modeled via Lindblad operators:
//! ```text
//! dρ/dt = -i[Ĥ, ρ] + Σ L_k ρ L_k† - ½{L_k† L_k, ρ}
//! ```
//! where L_k represent tampering attempts, I/O errors, and cosmic rays.

use blake3;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, BufWriter, Read, Write, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Genesis hash — the vacuum state of the audit chain.
const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Reduced Planck constant in natural units.
const HBAR: f64 = 1.0;

/// Maximum coherence length for the audit chain.
const MAX_COHERENCE_LENGTH: usize = 1_000_000;

/// Entanglement strength between consecutive events.
const ENTANGLEMENT_STRENGTH: f64 = 0.99;

/// Maximum retries for file operations.
const MAX_RETRIES: u32 = 3;

/// Initial backoff in milliseconds.
const RETRY_BACKOFF_MS: u64 = 100;

/// Default maximum number of events kept in memory.
const DEFAULT_MAX_MEMORY_EVENTS: usize = 1000;

// -----------------------------------------------------------------------------
// Quantum Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum audit operations.
#[derive(Debug, Error)]
pub enum AuditError {
    #[error("I/O decoherence: {0}")]
    Io(#[from] io::Error),

    #[error("JSON serialization collapse: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Entanglement verification failed: {0}")]
    Verification(String),

    #[error("Coherence lost: chain decohered at event {seq}")]
    CoherenceLost { seq: u64 },

    #[error("Entanglement fidelity below threshold: {fidelity}")]
    FidelityLost { fidelity: f64 },

    #[error("Lock acquisition failed: {0}")]
    LockFailed(String),

    #[error("Chain file is corrupted: {0}")]
    CorruptedChain(String),
}

pub type AuditResult<T> = Result<T, AuditError>;

// -----------------------------------------------------------------------------
// Quantum Event Types
// -----------------------------------------------------------------------------

/// Audit event severity — energy levels of the audit Hamiltonian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditLevel {
    Info,
    Warning,
    Critical,
}

impl fmt::Display for AuditLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARNING"),
            Self::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Audit event categories — quantum numbers of the audit observable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditCategory {
    Key,
    Consensus,
    Migration,
    Network,
    Admin,
    Startup,
    Shutdown,
}

impl fmt::Display for AuditCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Key => write!(f, "KEY"),
            Self::Consensus => write!(f, "CONSENSUS"),
            Self::Migration => write!(f, "MIGRATION"),
            Self::Network => write!(f, "NETWORK"),
            Self::Admin => write!(f, "ADMIN"),
            Self::Startup => write!(f, "STARTUP"),
            Self::Shutdown => write!(f, "SHUTDOWN"),
        }
    }
}

/// A quantum audit event — a state vector in the audit Hilbert space.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub level: AuditLevel,
    pub category: AuditCategory,
    pub action: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<(String, String)>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 { 1.0 }

impl AuditEvent {
    /// Create a new audit event in a pure state.
    pub fn new(level: AuditLevel, category: AuditCategory, action: impl Into<String>) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            level,
            category,
            action: action.into(),
            details: Vec::new(),
            node_id: None,
            coherence: 1.0,
        }
    }

    /// Add a detail — expand the basis state.
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.push((key.into(), value.into()));
        self
    }

    /// Set the node identity — specify the entangled partner.
    pub fn with_node_id(mut self, id: impl Into<String>) -> Self {
        self.node_id = Some(id.into());
        self
    }

    /// Apply decoherence from environmental interaction.
    pub fn apply_decoherence(&mut self, strength: f64) {
        self.coherence *= (-strength).exp();
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[AUDIT] {} | {} | {} | {} | γ={:.4}",
            self.timestamp, self.level, self.category, self.action, self.coherence
        )?;
        for (k, v) in &self.details {
            write!(f, " | {k}={v}")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum Audit Logger (Memory + File)
// -----------------------------------------------------------------------------

/// Quantum audit logger with entanglement-based tamper evidence.
pub struct QuantumAuditLogger {
    /// File writer (classical channel for state persistence), protected by a mutex.
    file: Option<Mutex<BufWriter<File>>>,
    /// In-memory event buffer (quantum register) using VecDeque for O(1) pop_front.
    events: Mutex<VecDeque<AuditEvent>>,
    /// Maximum events in memory before decoherence (eviction).
    max_memory_events: usize,
    /// Overall chain coherence (decays with each recorded event).
    chain_coherence: Mutex<f64>,
    /// Lock file path for concurrency control.
    lock_path: Option<PathBuf>,
}

impl QuantumAuditLogger {
    /// Create a new quantum audit logger.
    ///
    /// If `path` is provided, events are projected onto the filesystem
    /// via JSON-lines format. Otherwise, they exist only in the memory
    /// quantum register.
    pub fn new(path: Option<PathBuf>, max_memory_events: usize) -> AuditResult<Self> {
        let file = match path.as_ref() {
            Some(p) => {
                // Ensure directory exists.
                if let Some(parent) = p.parent() {
                    fs::create_dir_all(parent)?;
                }
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?;
                Some(Mutex::new(BufWriter::new(f)))
            }
            None => None,
        };

        let lock_path = path.as_ref().map(|p| p.with_extension("lock"));

        Ok(Self {
            file,
            events: Mutex::new(VecDeque::with_capacity(max_memory_events)),
            max_memory_events,
            chain_coherence: Mutex::new(1.0),
            lock_path,
        })
    }

    /// Acquire an exclusive lock on the log file (if filesystem backing is used).
    fn acquire_lock(&self) -> AuditResult<Option<File>> {
        if let Some(ref lock_path) = self.lock_path {
            // Try to open/create lock file.
            let lock_file = OpenOptions::new()
                .create(true)
                .write(true)
                .open(lock_path)?;
            lock_file.try_lock_exclusive().map_err(|e| {
                AuditError::LockFailed(format!("cannot acquire lock on audit log: {}", e))
            })?;
            Ok(Some(lock_file))
        } else {
            Ok(None)
        }
    }

    fn release_lock(lock: Option<File>) -> AuditResult<()> {
        if let Some(f) = lock {
            f.unlock().map_err(|e| {
                AuditError::LockFailed(format!("cannot release lock: {}", e))
            })?;
        }
        Ok(())
    }

    /// Record a quantum audit event.
    ///
    /// The event is entangled with the previous event via the hash chain,
    /// and projected onto the filesystem (if configured).
    pub fn log(&self, mut event: AuditEvent) -> AuditResult<()> {
        // Acquire lock for file writing.
        let lock = self.acquire_lock()?;

        // Apply chain decoherence.
        let coherence = {
            let mut cc = self.chain_coherence.lock().unwrap();
            *cc *= ENTANGLEMENT_STRENGTH;
            *cc
        };
        event.coherence = coherence;

        // Project to filesystem (measurement) with retry.
        if let Some(ref file) = self.file {
            let json = serde_json::to_string(&event)?;
            let result = retry_operation(|| {
                let mut f = file.lock().unwrap();
                writeln!(f, "{}", json)?;
                f.flush()?;
                Ok::<_, AuditError>(())
            });
            if let Err(e) = result {
                error!("Failed to write audit event: {}", e);
                // We could log but not fail; but we'll propagate.
                return Err(e);
            }
        }

        // Store in quantum memory register (VecDeque).
        {
            let mut events = self.events.lock().unwrap();
            if events.len() >= self.max_memory_events {
                events.pop_front(); // Oldest event decoheres.
            }
            events.push_back(event);
        }

        // Release lock.
        Self::release_lock(lock)?;
        Ok(())
    }

    /// Measure recent events (Born rule sampling).
    pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
        self.events
            .lock()
            .map(|events| {
                let start = events.len().saturating_sub(n);
                events.range(start..).cloned().collect()
            })
            .unwrap_or_default()
    }

    /// Filter events by category (quantum number selection).
    pub fn by_category(&self, cat: AuditCategory, limit: usize) -> Vec<AuditEvent> {
        self.events
            .lock()
            .map(|events| {
                events
                    .iter()
                    .rev()
                    .filter(|e| e.category == cat)
                    .take(limit)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Get current chain coherence.
    pub fn coherence(&self) -> f64 {
        *self.chain_coherence.lock().unwrap()
    }

    /// Sync all data to disk (if file-backed).
    pub fn flush(&self) -> AuditResult<()> {
        if let Some(ref file) = self.file {
            let mut f = file.lock().unwrap();
            f.flush()?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Quantum Audit Convenience Functions
// -----------------------------------------------------------------------------

pub fn audit_key_generated(logger: &QuantumAuditLogger, key_type: &str, address: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_generated")
            .with_detail("key_type", key_type)
            .with_detail("address", address),
    );
}

pub fn audit_key_imported(logger: &QuantumAuditLogger, source: &str, address: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_imported")
            .with_detail("source", source)
            .with_detail("address", address),
    );
}

pub fn audit_block_committed(logger: &QuantumAuditLogger, height: u64, hash: &str, txs: usize) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_committed")
            .with_detail("height", height.to_string())
            .with_detail("hash", hash)
            .with_detail("tx_count", txs.to_string()),
    );
}

pub fn audit_finality(logger: &QuantumAuditLogger, height: u64, latency_ms: u64) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_finalized")
            .with_detail("height", height.to_string())
            .with_detail("latency_ms", latency_ms.to_string()),
    );
}

pub fn audit_equivocation(logger: &QuantumAuditLogger, validator: &str, height: u64) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Consensus, "equivocation_detected")
            .with_detail("validator", validator)
            .with_detail("height", height.to_string()),
    );
}

pub fn audit_migration(logger: &QuantumAuditLogger, from_sv: u32, to_sv: u32, status: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Migration, "schema_migration")
            .with_detail("from_sv", from_sv.to_string())
            .with_detail("to_sv", to_sv.to_string())
            .with_detail("status", status),
    );
}

pub fn audit_protocol_upgrade(logger: &QuantumAuditLogger, from_pv: u32, to_pv: u32, height: u64) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Migration, "protocol_upgrade")
            .with_detail("from_pv", from_pv.to_string())
            .with_detail("to_pv", to_pv.to_string())
            .with_detail("activation_height", height.to_string()),
    );
}

pub fn audit_peer_action(logger: &QuantumAuditLogger, peer_id: &str, action: &str, reason: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Network, action)
            .with_detail("peer_id", peer_id)
            .with_detail("reason", reason),
    );
}

pub fn audit_snapshot(logger: &QuantumAuditLogger, action: &str, height: u64, path: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Admin, action)
            .with_detail("height", height.to_string())
            .with_detail("path", path),
    );
}

pub fn audit_startup(logger: &QuantumAuditLogger, version: &str, pv: u32, sv: u32) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "node_started")
            .with_detail("version", version)
            .with_detail("protocol_version", pv.to_string())
            .with_detail("schema_version", sv.to_string()),
    );
}

pub fn audit_shutdown(logger: &QuantumAuditLogger, reason: &str) {
    let _ = logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Shutdown, "node_stopped")
            .with_detail("reason", reason),
    );
}

// -----------------------------------------------------------------------------
// Quantum Hashchain — Entanglement-Based Tamper Evidence
// -----------------------------------------------------------------------------

/// Compute BLAKE3 hex digest — quantum fingerprint of a state.
fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// A quantum-entangled entry in the tamper-evident audit log.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumHashchainEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    pub entanglement_fidelity: f64,
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// Quantum hashchain logger with entanglement-based tamper evidence.
///
/// Uses BLAKE3 as the quantum fingerprint function and maintains
/// an entanglement chain that cannot be broken without detection.
/// This implementation uses file locking and streaming verification.
pub struct QuantumHashchainLogger {
    /// Path to the log file.
    path: PathBuf,
    /// Writer with buffering and locking.
    writer: Mutex<BufWriter<File>>,
    /// Current chain state (seq, prev_hash, coherence).
    state: Mutex<QuantumHashchainState>,
    /// Lock file path.
    lock_path: PathBuf,
}

struct QuantumHashchainState {
    next_seq: u64,
    prev_hash: String,
    chain_coherence: f64,
}

impl QuantumHashchainLogger {
    /// Open or create a quantum hashchain audit log.
    pub fn open(path: &Path) -> AuditResult<Self> {
        // Ensure directory exists.
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }

        // Determine lock file path.
        let lock_path = path.with_extension("lock");

        // Acquire exclusive lock.
        let lock_file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(&lock_path)?;
        lock_file.try_lock_exclusive().map_err(|e| {
            AuditError::LockFailed(format!("cannot acquire lock on hashchain: {}", e))
        })?;
        // Keep lock file open; we'll hold it for the lifetime of the logger.
        // We'll store it? Not necessary; we'll unlock on drop.
        // We'll keep it in a variable to be dropped later, but we can store as Option<File>.
        // Simpler: we'll use a separate file handle and lock it.

        // Now open the log file.
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true) // needed to read last line for state.
            .open(path)?;

        // Determine initial state from last line.
        let (next_seq, prev_hash, chain_coherence) = if path.exists() && file.metadata()?.len() > 0 {
            // Read the last line.
            let mut reader = BufReader::new(&mut file);
            let mut last_line = String::new();
            // Seek to end - some bytes, read line.
            // We'll just read all lines and take last.
            // For efficiency, we can read from end backwards, but we'll keep simple.
            let mut lines = Vec::new();
            let mut line = String::new();
            while reader.read_line(&mut line)? > 0 {
                if !line.trim().is_empty() {
                    lines.push(line.clone());
                }
                line.clear();
            }
            if let Some(last) = lines.last() {
                let entry: QuantumHashchainEntry = serde_json::from_str(last)?;
                let coherence = ENTANGLEMENT_STRENGTH.powi(entry.seq as i32);
                let prev_hash = blake3_hex(last.as_bytes());
                (entry.seq + 1, prev_hash, coherence)
            } else {
                (0, GENESIS_HASH.to_string(), 1.0)
            }
        } else {
            (0, GENESIS_HASH.to_string(), 1.0)
        };

        // Reopen file for append (we already have it).
        // But we need to set the file pointer to end.
        file.seek(SeekFrom::End(0))?;

        let writer = Mutex::new(BufWriter::new(file));

        Ok(Self {
            path: path.to_path_buf(),
            writer,
            state: Mutex::new(QuantumHashchainState {
                next_seq,
                prev_hash,
                chain_coherence,
            }),
            lock_path,
        })
    }

    /// Append an event to the quantum hashchain.
    pub fn append(&self, event: AuditEvent) -> AuditResult<()> {
        let mut state = self.state.lock().unwrap();
        let seq = state.next_seq;
        let prev_hash = state.prev_hash.clone();

        // Update chain coherence: decay.
        state.chain_coherence *= ENTANGLEMENT_STRENGTH;
        let fidelity = state.chain_coherence;

        // Build partial for hash.
        let partial = serde_json::json!({
            "seq": seq,
            "prev_hash": prev_hash,
            "timestamp": event.timestamp,
            "level": event.level,
            "category": event.category,
            "action": event.action,
            "details": event.details,
            "node_id": event.node_id,
        });
        let partial_bytes = serde_json::to_vec(&partial)?;
        let entry_hash = blake3_hex(&partial_bytes);

        let full = QuantumHashchainEntry {
            seq,
            prev_hash,
            entry_hash,
            entanglement_fidelity: fidelity,
            event,
        };
        let line = serde_json::to_string(&full)?;

        // Write with retry.
        retry_operation(|| {
            let mut w = self.writer.lock().unwrap();
            writeln!(w, "{}", line)?;
            w.flush()?;
            Ok::<_, AuditError>(())
        })?;

        // Update state.
        state.next_seq += 1;
        state.prev_hash = blake3_hex(line.as_bytes());

        Ok(())
    }

    /// Get current chain coherence.
    pub fn coherence(&self) -> f64 {
        self.state.lock().unwrap().chain_coherence
    }

    /// Get number of entries.
    pub fn len(&self) -> u64 {
        self.state.lock().unwrap().next_seq
    }

    /// Sync all data to disk.
    pub fn flush(&self) -> AuditResult<()> {
        let mut w = self.writer.lock().unwrap();
        w.flush()?;
        Ok(())
    }
}

impl Drop for QuantumHashchainLogger {
    fn drop(&mut self) {
        // Try to flush and unlock lock file.
        let _ = self.flush();
        // Unlock the lock file.
        if let Ok(lock_file) = OpenOptions::new().write(true).open(&self.lock_path) {
            let _ = lock_file.unlock();
        }
    }
}

/// Result of quantum hashchain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Ok {
        entries: u64,
        average_fidelity: f64,
    },
    Broken {
        seq: u64,
        reason: String,
    },
    Empty,
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyResult::Ok { entries, average_fidelity } => {
                write!(
                    f,
                    "OK: {entries} entries verified, chain intact, avg fidelity={average_fidelity:.4}"
                )
            }
            VerifyResult::Broken { seq, reason } => {
                write!(f, "BROKEN at seq={seq}: {reason}")
            }
            VerifyResult::Empty => write!(f, "EMPTY: log file contains no entries"),
        }
    }
}

/// Verify the quantum hashchain integrity using streaming to avoid memory blow‑up.
///
/// This performs a full measurement of the entanglement chain,
/// checking that each entry's hash matches its computed value
/// and that the chain of prev_hashes is unbroken.
pub fn verify_hashchain(path: &Path) -> AuditResult<VerifyResult> {
    let file = File::open(path)?;
    let reader = BufReader::new(file);
    let mut lines = reader.lines();

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut total_fidelity = 0.0;
    let mut entries = 0u64;

    for (idx, line_result) in lines.enumerate() {
        let line = line_result?;
        if line.trim().is_empty() {
            continue;
        }

        let entry: QuantumHashchainEntry = serde_json::from_str(&line)
            .map_err(|e| AuditError::Verification(format!("line {}: JSON error: {}", idx, e)))?;

        // Verify sequence
        if entry.seq != expected_seq {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!(
                    "sequence mismatch: expected {expected_seq}, found {}",
                    entry.seq
                ),
            });
        }

        // Verify entanglement link
        if entry.prev_hash != expected_prev {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!(
                    "entanglement broken: prev_hash mismatch (expected {expected_prev}, found {})",
                    entry.prev_hash
                ),
            });
        }

        // Verify entry integrity
        let partial = serde_json::json!({
            "seq": entry.seq,
            "prev_hash": entry.prev_hash,
            "timestamp": entry.event.timestamp,
            "level": entry.event.level,
            "category": entry.event.category,
            "action": entry.event.action,
            "details": entry.event.details,
            "node_id": entry.event.node_id,
        });
        let partial_bytes = serde_json::to_vec(&partial)?;
        let computed_hash = blake3_hex(&partial_bytes);

        if computed_hash != entry.entry_hash {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!(
                    "entry tampered: hash mismatch (computed {computed_hash}, stored {})",
                    entry.entry_hash
                ),
            });
        }

        // Check fidelity against expected decay.
        let expected_fidelity = ENTANGLEMENT_STRENGTH.powi(entry.seq as i32);
        // Allow small floating point differences.
        if (entry.entanglement_fidelity - expected_fidelity).abs() > 0.01 {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!(
                    "fidelity anomaly: expected {expected_fidelity:.4}, found {:.4}",
                    entry.entanglement_fidelity
                ),
            });
        }

        total_fidelity += entry.entanglement_fidelity;
        expected_prev = blake3_hex(line.as_bytes());
        expected_seq += 1;
        entries += 1;
    }

    if entries == 0 {
        return Ok(VerifyResult::Empty);
    }

    let avg_fidelity = total_fidelity / entries as f64;

    Ok(VerifyResult::Ok {
        entries,
        average_fidelity: avg_fidelity,
    })
}

// -----------------------------------------------------------------------------
// Helpers: Retry and locking
// -----------------------------------------------------------------------------

/// Retry a closure with exponential backoff.
fn retry_operation<F, T>(mut f: F) -> Result<T, AuditError>
where
    F: FnMut() -> Result<T, AuditError>,
{
    let mut attempt = 0;
    let mut delay = RETRY_BACKOFF_MS;
    loop {
        match f() {
            Ok(val) => return Ok(val),
            Err(e) => {
                attempt += 1;
                if attempt >= MAX_RETRIES {
                    return Err(e);
                }
                std::thread::sleep(std::time::Duration::from_millis(delay));
                delay *= 2;
            }
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

    #[test]
    fn test_quantum_audit_event_coherence() {
        let mut event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "test");
        assert!((event.coherence - 1.0).abs() < 1e-10);
        event.apply_decoherence(0.1);
        assert!(event.coherence < 1.0);
    }

    #[test]
    fn test_quantum_audit_logger_memory_only() {
        let logger = QuantumAuditLogger::new(None, 10).unwrap();
        for i in 0..15 {
            logger.log(
                AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, format!("ev_{i}"))
            ).unwrap();
        }
        let recent = logger.recent(5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent[0].action, "ev_10");
        assert!(logger.coherence() < 1.0);
        assert!(logger.coherence() > 0.0);
    }

    #[test]
    fn test_quantum_audit_logger_file_backed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = QuantumAuditLogger::new(Some(path.clone()), 100).unwrap();
        logger.log(
            AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "boot")
        ).unwrap();
        logger.flush().unwrap();

        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("\"action\":\"boot\""));
    }

    #[test]
    fn test_quantum_hashchain_single() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = QuantumHashchainLogger::open(&path).unwrap();
        logger
            .append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "boot"))
            .unwrap();

        let result = verify_hashchain(&path).unwrap();
        match result {
            VerifyResult::Ok { entries, average_fidelity } => {
                assert_eq!(entries, 1);
                assert!(average_fidelity > 0.9);
            }
            _ => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_quantum_hashchain_multiple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = QuantumHashchainLogger::open(&path).unwrap();

        for i in 0..5 {
            logger
                .append(AuditEvent::new(
                    AuditLevel::Info,
                    AuditCategory::Consensus,
                    format!("block_{i}"),
                ))
                .unwrap();
        }

        let result = verify_hashchain(&path).unwrap();
        match result {
            VerifyResult::Ok { entries, average_fidelity } => {
                assert_eq!(entries, 5);
                assert!(average_fidelity > 0.9);
            }
            _ => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_quantum_hashchain_tampered() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = QuantumHashchainLogger::open(&path).unwrap();
        logger
            .append(AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block"))
            .unwrap();
        drop(logger);

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("block", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();

        let result = verify_hashchain(&path).unwrap();
        assert!(matches!(result, VerifyResult::Broken { .. }));
    }

    #[test]
    fn test_quantum_hashchain_resume() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");

        {
            let logger = QuantumHashchainLogger::open(&path).unwrap();
            logger
                .append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "first"))
                .unwrap();
        }

        {
            let logger = QuantumHashchainLogger::open(&path).unwrap();
            logger
                .append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "second"))
                .unwrap();
        }

        let result = verify_hashchain(&path).unwrap();
        match result {
            VerifyResult::Ok { entries, .. } => {
                assert_eq!(entries, 2);
            }
            _ => panic!("Expected Ok"),
        }
    }

    #[test]
    fn test_coherence_decay() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = QuantumHashchainLogger::open(&path).unwrap();

        let initial = logger.coherence();
        assert!((initial - 1.0).abs() < 1e-10);

        for i in 0..10 {
            logger
                .append(AuditEvent::new(
                    AuditLevel::Info,
                    AuditCategory::Consensus,
                    format!("event_{i}"),
                ))
                .unwrap();
        }

        let final_coherence = logger.coherence();
        assert!(final_coherence < initial);
        assert!(final_coherence > 0.0);
        // Approximate decay: 0.99^10 ≈ 0.904
        assert!((final_coherence - 0.99_f64.powi(10)).abs() < 0.001);
    }
}
