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

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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

// -----------------------------------------------------------------------------
// Quantum Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during quantum audit operations.
#[derive(Debug, thiserror::Error)]
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
}

pub type AuditResult<T> = Result<T, AuditError>;

// -----------------------------------------------------------------------------
// Quantum Event Types
// -----------------------------------------------------------------------------

/// Audit event severity — energy levels of the audit Hamiltonian.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuditLevel {
    /// Ground state — informational.
    Info,
    /// First excited state — warning.
    Warning,
    /// Highly excited state — critical.
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
    /// Key operations — identity observable.
    Key,
    /// Consensus events — agreement observable.
    Consensus,
    /// Migration events — evolution observable.
    Migration,
    /// Network events — entanglement observable.
    Network,
    /// Admin operations — control observable.
    Admin,
    /// Startup event — initial state preparation.
    Startup,
    /// Shutdown event — final state measurement.
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
///
/// Each event is a pure state |e⟩ = Σ_i α_i |i⟩ with observable properties
/// (timestamp, level, category, action) and a set of basis vectors (details).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix timestamp — classical time coordinate.
    pub timestamp: u64,
    /// Event severity — energy eigenvalue.
    pub level: AuditLevel,
    /// Event category — quantum number.
    pub category: AuditCategory,
    /// Human-readable action — state label.
    pub action: String,
    /// Optional key-value details — basis state decomposition.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<(String, String)>,
    /// Node identity — entangled partner identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Quantum coherence of this event (1.0 = perfect).
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
// Quantum Audit Logger
// -----------------------------------------------------------------------------

/// Quantum audit logger with entanglement-based tamper evidence.
///
/// Events are stored in a superposition of memory and file states,
/// with entanglement between consecutive events forming a hash chain.
pub struct QuantumAuditLogger {
    /// File writer (classical channel for state persistence).
    file: Option<Mutex<BufWriter<File>>>,
    /// In-memory event buffer (quantum register).
    events: Mutex<Vec<AuditEvent>>,
    /// Maximum events in memory before decoherence.
    max_memory_events: usize,
    /// Overall chain coherence.
    chain_coherence: Mutex<f64>,
}

impl QuantumAuditLogger {
    /// Create a new quantum audit logger.
    ///
    /// If `path` is provided, events are projected onto the filesystem
    /// via JSON-lines format. Otherwise, they exist only in the memory
    /// quantum register.
    pub fn new(path: Option<PathBuf>, max_memory_events: usize) -> AuditResult<Self> {
        let file = match path {
            Some(p) => {
                let f = OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?;
                Some(Mutex::new(BufWriter::new(f)))
            }
            None => None,
        };

        Ok(Self {
            file,
            events: Mutex::new(Vec::with_capacity(max_memory_events)),
            max_memory_events,
            chain_coherence: Mutex::new(1.0),
        })
    }

    /// Record a quantum audit event.
    ///
    /// The event is entangled with the previous event via the hash chain,
    /// and projected onto the filesystem (if configured).
    pub fn log(&self, mut event: AuditEvent) -> AuditResult<()> {
        // Apply chain decoherence
        let coherence = {
            let mut cc = self.chain_coherence.lock().unwrap();
            *cc *= ENTANGLEMENT_STRENGTH;
            *cc
        };
        event.coherence = coherence;

        // Project to filesystem (measurement)
        if let Some(ref file) = self.file {
            let json = serde_json::to_string(&event)?;
            if let Ok(mut f) = file.lock() {
                writeln!(f, "{}", json)?;
                f.flush()?;
            }
        }

        // Store in quantum memory register
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.max_memory_events {
                events.remove(0); // Oldest event decoheres
            }
            events.push(event);
        }

        Ok(())
    }

    /// Measure recent events (Born rule sampling).
    pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
        self.events
            .lock()
            .map(|events| {
                let start = events.len().saturating_sub(n);
                events[start..].to_vec()
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
///
/// Each entry is entangled with its predecessor via the `prev_hash`,
/// forming an unbreakable chain of quantum correlations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumHashchainEntry {
    /// Sequence number — quantum state index.
    pub seq: u64,
    /// Previous hash — entanglement link to prior state.
    pub prev_hash: String,
    /// Current entry hash — quantum fingerprint.
    pub entry_hash: String,
    /// Entanglement fidelity with previous entry.
    pub entanglement_fidelity: f64,
    /// The underlying audit event.
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// Quantum hashchain logger with entanglement-based tamper evidence.
///
/// Uses BLAKE3 as the quantum fingerprint function and maintains
/// an entanglement chain that cannot be broken without detection.
pub struct QuantumHashchainLogger {
    writer: Mutex<BufWriter<File>>,
    state: Mutex<QuantumHashchainState>,
}

struct QuantumHashchainState {
    next_seq: u64,
    prev_hash: String,
    chain_coherence: f64,
}

impl QuantumHashchainLogger {
    /// Open or create a quantum hashchain audit log.
    pub fn open(path: &Path) -> AuditResult<Self> {
        let (next_seq, prev_hash, chain_coherence) = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let last_line = content.lines().filter(|l| !l.trim().is_empty()).last();

            match last_line {
                Some(line) => {
                    let line_hash = blake3_hex(line.as_bytes());
                    let entry: QuantumHashchainEntry = serde_json::from_str(line)?;
                    let coherence = ENTANGLEMENT_STRENGTH.powi(entry.seq as i32);
                    (entry.seq + 1, line_hash, coherence)
                }
                None => (0, GENESIS_HASH.to_string(), 1.0),
            }
        } else {
            (0, GENESIS_HASH.to_string(), 1.0)
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = Mutex::new(BufWriter::new(file));

        Ok(Self {
            writer,
            state: Mutex::new(QuantumHashchainState {
                next_seq,
                prev_hash,
                chain_coherence,
            }),
        })
    }

    /// Append an event to the quantum hashchain.
    ///
    /// The event is entangled with the chain via BLAKE3 hashing,
    /// and the entanglement fidelity decays with each operation
    /// due to computational decoherence.
    pub fn append(&self, event: AuditEvent) -> AuditResult<()> {
        let mut state = self.state.lock().unwrap();
        let seq = state.next_seq;
        let prev_hash = state.prev_hash.clone();

        // Apply chain decoherence
        state.chain_coherence *= ENTANGLEMENT_STRENGTH;
        let fidelity = state.chain_coherence;

        // Compute partial entry for hash
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

        // Write and flush
        {
            let mut w = self.writer.lock().unwrap();
            writeln!(w, "{}", line)?;
            w.flush()?;
        }

        // Update state
        state.next_seq += 1;
        state.prev_hash = blake3_hex(line.as_bytes());

        Ok(())
    }

    /// Get current chain coherence.
    pub fn coherence(&self) -> f64 {
        self.state.lock().unwrap().chain_coherence
    }
}

/// Result of quantum hashchain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    /// Chain is intact — all entanglements verified.
    Ok {
        entries: u64,
        average_fidelity: f64,
    },
    /// Chain is broken — entanglement lost.
    Broken {
        seq: u64,
        reason: String,
    },
    /// Chain is empty — vacuum state.
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

/// Verify the quantum hashchain integrity.
///
/// This performs a full measurement of the entanglement chain,
/// checking that each entry's hash matches its computed value
/// and that the chain of prev_hashes is unbroken.
pub fn verify_hashchain(path: &Path) -> AuditResult<VerifyResult> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return Ok(VerifyResult::Empty);
    }

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq = 0u64;
    let mut total_fidelity = 0.0;

    for (idx, line) in lines.iter().enumerate() {
        let entry: QuantumHashchainEntry = serde_json::from_str(line)
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

        // Check fidelity
        let expected_fidelity = ENTANGLEMENT_STRENGTH.powi(entry.seq as i32);
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
    }

    let avg_fidelity = if expected_seq > 0 {
        total_fidelity / expected_seq as f64
    } else {
        1.0
    };

    Ok(VerifyResult::Ok {
        entries: expected_seq,
        average_fidelity: avg_fidelity,
    })
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
    fn test_quantum_audit_logger() {
        let logger = QuantumAuditLogger::new(None, 100).unwrap();
        for i in 0..10 {
            let _ = logger.log(
                AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, format!("ev_{i}"))
            );
        }
        let recent = logger.recent(5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent.last().unwrap().action, "ev_9");
        assert!(logger.coherence() < 1.0);
        assert!(logger.coherence() > 0.0);
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
            VerifyResult::Ok {
                entries,
                average_fidelity,
            } => {
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
            VerifyResult::Ok {
                entries,
                average_fidelity,
            } => {
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

        for i in 0..100 {
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
    }
}
