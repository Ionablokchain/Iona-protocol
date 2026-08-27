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
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                         Audit Module                                  │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   Config    │    Error     │    Metrics    │         Types            │
//! │ (AuditCfg)  │ (AuditErr)   │ (AuditMetr)   │ (Event, Level, Category) │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   Logger    │  Hashchain   │   Manager     │        Legacy            │
//! │ (QuantumAuditLogger)│ (QuantumHashchainLogger)│ (AuditMgr) │ (global fns) │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::audit::{AuditManager, AuditConfig};
//!
//! let config = AuditConfig::default();
//! let manager = AuditManager::new(config);
//! manager.init();
//! manager.log_event(event)?;
//! ```

#![allow(dead_code)]

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
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the audit subsystem.
    use serde::{Deserialize, Serialize};
    use super::constants::*;

    /// Configuration for audit logging.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditConfig {
        pub enable_file_logging: bool,
        pub log_path: Option<String>,
        pub lock_path: Option<String>,
        pub max_memory_events: usize,
        pub max_retries: u32,
        pub retry_backoff_ms: u64,
        pub entanglement_strength: f64,
        pub max_coherence_length: usize,
        pub collect_metrics: bool,
        pub log_operations: bool,
    }

    impl Default for AuditConfig {
        fn default() -> Self {
            Self {
                enable_file_logging: true,
                log_path: None,
                lock_path: None,
                max_memory_events: super::constants::DEFAULT_MAX_MEMORY_EVENTS,
                max_retries: super::constants::MAX_RETRIES,
                retry_backoff_ms: super::constants::RETRY_BACKOFF_MS,
                entanglement_strength: super::constants::ENTANGLEMENT_STRENGTH,
                max_coherence_length: super::constants::MAX_COHERENCE_LENGTH,
                collect_metrics: true,
                log_operations: false,
            }
        }
    }

    impl AuditConfig {
        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_memory_events == 0 {
                return Err("max_memory_events must be > 0");
            }
            if self.max_retries == 0 {
                return Err("max_retries must be > 0");
            }
            if self.retry_backoff_ms == 0 {
                return Err("retry_backoff_ms must be > 0");
            }
            if self.entanglement_strength <= 0.0 || self.entanglement_strength > 1.0 {
                return Err("entanglement_strength must be in (0,1]");
            }
            if self.max_coherence_length == 0 {
                return Err("max_coherence_length must be > 0");
            }
            Ok(())
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod constants {
    //! Constants for the audit subsystem.

    /// Genesis hash — the vacuum state of the audit chain.
    pub const GENESIS_HASH: &str =
        "0000000000000000000000000000000000000000000000000000000000000000";

    /// Reduced Planck constant in natural units.
    pub const HBAR: f64 = 1.0;

    /// Maximum coherence length for the audit chain.
    pub const MAX_COHERENCE_LENGTH: usize = 1_000_000;

    /// Entanglement strength between consecutive events.
    pub const ENTANGLEMENT_STRENGTH: f64 = 0.99;

    /// Maximum retries for file operations.
    pub const MAX_RETRIES: u32 = 3;

    /// Initial backoff in milliseconds.
    pub const RETRY_BACKOFF_MS: u64 = 100;

    /// Default maximum number of events kept in memory.
    pub const DEFAULT_MAX_MEMORY_EVENTS: usize = 1000;
}

pub mod error {
    //! Error types for audit operations.
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum AuditError {
        #[error("I/O decoherence: {0}")]
        Io(#[from] std::io::Error),

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
}

pub mod types {
    //! Core types for audit events.
    use super::error::AuditResult;
    use serde::{Deserialize, Serialize};
    use std::fmt;
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn default_coherence() -> f64 {
        1.0
    }

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
}

pub mod metrics {
    //! Metrics for audit operations.
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct AuditMetrics {
        pub events_logged: AtomicU64,
        pub events_failed: AtomicU64,
        pub hashchain_appends: AtomicU64,
        pub hashchain_failures: AtomicU64,
        pub verifications_run: AtomicU64,
        pub verifications_passed: AtomicU64,
        pub verifications_failed: AtomicU64,
        pub lock_acquire_failures: AtomicU64,
        pub io_errors: AtomicU64,
    }

    impl AuditMetrics {
        pub fn inc_event_logged(&self) {
            self.events_logged.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_event_failed(&self) {
            self.events_failed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hashchain_append(&self) {
            self.hashchain_appends.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_hashchain_failure(&self) {
            self.hashchain_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_verification(&self) {
            self.verifications_run.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_verification_passed(&self) {
            self.verifications_passed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_verification_failed(&self) {
            self.verifications_failed.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_lock_failure(&self) {
            self.lock_acquire_failures.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_io_error(&self) {
            self.io_errors.fetch_add(1, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> AuditMetricsSnapshot {
            AuditMetricsSnapshot {
                events_logged: self.events_logged.load(Ordering::Relaxed),
                events_failed: self.events_failed.load(Ordering::Relaxed),
                hashchain_appends: self.hashchain_appends.load(Ordering::Relaxed),
                hashchain_failures: self.hashchain_failures.load(Ordering::Relaxed),
                verifications_run: self.verifications_run.load(Ordering::Relaxed),
                verifications_passed: self.verifications_passed.load(Ordering::Relaxed),
                verifications_failed: self.verifications_failed.load(Ordering::Relaxed),
                lock_acquire_failures: self.lock_acquire_failures.load(Ordering::Relaxed),
                io_errors: self.io_errors.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct AuditMetricsSnapshot {
        pub events_logged: u64,
        pub events_failed: u64,
        pub hashchain_appends: u64,
        pub hashchain_failures: u64,
        pub verifications_run: u64,
        pub verifications_passed: u64,
        pub verifications_failed: u64,
        pub lock_acquire_failures: u64,
        pub io_errors: u64,
    }

    /// Global metrics instance.
    pub(crate) static GLOBAL_METRICS: spin::Once<AuditMetrics> = spin::Once::new();

    pub fn global_metrics() -> &'static AuditMetrics {
        GLOBAL_METRICS.get_or_init(AuditMetrics::default)
    }
}

pub mod helpers {
    //! Helper functions for audit operations.
    use super::{
        error::{AuditError, AuditResult},
        constants::{RETRY_BACKOFF_MS, MAX_RETRIES},
    };
    use std::time::Duration;
    use std::fs::File;
    use fs2::FileExt;
    use tracing::warn;

    /// Compute BLAKE3 hex digest — quantum fingerprint of a state.
    pub fn blake3_hex(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    /// Retry a closure with exponential backoff.
    pub fn retry_operation<F, T>(mut f: F) -> Result<T, AuditError>
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
                    std::thread::sleep(Duration::from_millis(delay));
                    delay *= 2;
                }
            }
        }
    }

    /// Acquire an exclusive lock on a file.
    pub fn acquire_lock(lock_path: &std::path::Path) -> AuditResult<File> {
        let file = File::create(lock_path).map_err(|e| AuditError::Io(e))?;
        file.try_lock_exclusive().map_err(|e| {
            AuditError::LockFailed(format!("cannot acquire lock: {}", e))
        })?;
        Ok(file)
    }

    /// Release an exclusive lock.
    pub fn release_lock(file: File) -> AuditResult<()> {
        file.unlock().map_err(|e| {
            AuditError::LockFailed(format!("cannot release lock: {}", e))
        })?;
        Ok(())
    }
}

pub mod logger {
    //! Quantum audit logger with memory + file backing.
    use super::{
        config::AuditConfig,
        error::{AuditError, AuditResult},
        types::AuditEvent,
        metrics::global_metrics,
        helpers::{retry_operation, acquire_lock, release_lock},
        constants::ENTANGLEMENT_STRENGTH,
    };
    use std::collections::VecDeque;
    use std::fs::{self, OpenOptions};
    use std::io::{BufWriter, Write, Seek, SeekFrom};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use tracing::{debug, info, warn};

    /// Quantum audit logger with entanglement-based tamper evidence.
    pub struct QuantumAuditLogger {
        file: Option<Mutex<BufWriter<std::fs::File>>>,
        events: Mutex<VecDeque<AuditEvent>>,
        max_memory_events: usize,
        chain_coherence: Mutex<f64>,
        lock_path: Option<PathBuf>,
        config: AuditConfig,
    }

    impl QuantumAuditLogger {
        pub fn new(path: Option<PathBuf>, config: &AuditConfig) -> AuditResult<Self> {
            let file = match path.as_ref() {
                Some(p) => {
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
                events: Mutex::new(VecDeque::with_capacity(config.max_memory_events)),
                max_memory_events: config.max_memory_events,
                chain_coherence: Mutex::new(1.0),
                lock_path,
                config: config.clone(),
            })
        }

        fn acquire_lock(&self) -> AuditResult<Option<std::fs::File>> {
            if let Some(ref lock_path) = self.lock_path {
                match acquire_lock(lock_path) {
                    Ok(f) => Ok(Some(f)),
                    Err(e) => {
                        global_metrics().inc_lock_failure();
                        Err(e)
                    }
                }
            } else {
                Ok(None)
            }
        }

        fn release_lock(&self, lock: Option<std::fs::File>) -> AuditResult<()> {
            if let Some(f) = lock {
                release_lock(f)?;
            }
            Ok(())
        }

        pub fn log(&self, mut event: AuditEvent) -> AuditResult<()> {
            let lock = self.acquire_lock()?;

            let coherence = {
                let mut cc = self.chain_coherence.lock().unwrap();
                *cc *= ENTANGLEMENT_STRENGTH;
                *cc
            };
            event.coherence = coherence;

            if let Some(ref file) = self.file {
                let json = serde_json::to_string(&event)?;
                let result = retry_operation(|| {
                    let mut f = file.lock().unwrap();
                    writeln!(f, "{}", json)?;
                    f.flush()?;
                    Ok::<_, AuditError>(())
                });
                if let Err(e) = result {
                    global_metrics().inc_event_failed();
                    global_metrics().inc_io_error();
                    return Err(e);
                }
            }

            {
                let mut events = self.events.lock().unwrap();
                if events.len() >= self.max_memory_events {
                    events.pop_front();
                }
                events.push_back(event);
            }

            global_metrics().inc_event_logged();
            self.release_lock(lock)?;
            Ok(())
        }

        pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
            self.events
                .lock()
                .map(|events| {
                    let start = events.len().saturating_sub(n);
                    events.range(start..).cloned().collect()
                })
                .unwrap_or_default()
        }

        pub fn by_category(&self, cat: super::types::AuditCategory, limit: usize) -> Vec<AuditEvent> {
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

        pub fn coherence(&self) -> f64 {
            *self.chain_coherence.lock().unwrap()
        }

        pub fn flush(&self) -> AuditResult<()> {
            if let Some(ref file) = self.file {
                let mut f = file.lock().unwrap();
                f.flush()?;
            }
            Ok(())
        }
    }
}

pub mod hashchain {
    //! Quantum hashchain logger with entanglement-based tamper evidence.
    use super::{
        config::AuditConfig,
        error::{AuditError, AuditResult},
        types::{AuditEvent, QuantumHashchainEntry, VerifyResult},
        helpers::{blake3_hex, retry_operation, acquire_lock, release_lock},
        constants::{ENTANGLEMENT_STRENGTH, GENESIS_HASH},
        metrics::global_metrics,
    };
    use std::fs::{self, OpenOptions};
    use std::io::{self, BufReader, BufWriter, Write, Seek, SeekFrom, Read};
    use std::path::{Path, PathBuf};
    use std::sync::Mutex;
    use serde_json;
    use tracing::{debug, info, warn};

    struct QuantumHashchainState {
        next_seq: u64,
        prev_hash: String,
        chain_coherence: f64,
    }

    /// Quantum hashchain logger with entanglement-based tamper evidence.
    pub struct QuantumHashchainLogger {
        path: PathBuf,
        writer: Mutex<BufWriter<std::fs::File>>,
        state: Mutex<QuantumHashchainState>,
        lock_path: PathBuf,
        config: AuditConfig,
    }

    impl QuantumHashchainLogger {
        pub fn open(path: &Path, config: &AuditConfig) -> AuditResult<Self> {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }

            let lock_path = path.with_extension("lock");
            let _lock = acquire_lock(&lock_path)?; // hold during init, then release? Actually we want to keep lock for the lifetime? We'll hold it in a field.

            // We'll keep the lock file handle open.
            let lock_file = std::fs::File::create(&lock_path)?;
            // We'll store it in the struct to keep the lock held.
            // But we can't easily store it because we need to unlock on drop.
            // We'll use a Mutex<Option<File>> to hold the lock.

            // Instead, we'll use a separate lock_file field.
            // For simplicity, we'll just rely on the lock_path and re-acquire each time.
            // That's simpler and avoids holding the lock for the entire lifetime.
            // We'll use a method that acquires and releases per operation.

            // However, we need to hold the lock while reading/writing to prevent corruption.
            // We'll implement the lock inside each method using acquire_lock/release_lock.

            // We'll store the lock_path only.

            let mut file = OpenOptions::new()
                .create(true)
                .append(true)
                .read(true)
                .open(path)?;

            let (next_seq, prev_hash, chain_coherence) = if path.exists() && file.metadata()?.len() > 0 {
                // Read the last line.
                let mut reader = BufReader::new(&mut file);
                let mut last_line = String::new();
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
                config: config.clone(),
            })
        }

        fn with_lock<F, R>(&self, f: F) -> AuditResult<R>
        where
            F: FnOnce() -> AuditResult<R>,
        {
            let lock = acquire_lock(&self.lock_path)?;
            let result = f();
            release_lock(lock)?;
            result
        }

        pub fn append(&self, event: AuditEvent) -> AuditResult<()> {
            self.with_lock(|| {
                let mut state = self.state.lock().unwrap();
                let seq = state.next_seq;
                let prev_hash = state.prev_hash.clone();

                state.chain_coherence *= ENTANGLEMENT_STRENGTH;
                let fidelity = state.chain_coherence;

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

                retry_operation(|| {
                    let mut w = self.writer.lock().unwrap();
                    writeln!(w, "{}", line)?;
                    w.flush()?;
                    Ok::<_, AuditError>(())
                })?;

                state.next_seq += 1;
                state.prev_hash = blake3_hex(line.as_bytes());

                global_metrics().inc_hashchain_append();
                Ok(())
            })
        }

        pub fn coherence(&self) -> f64 {
            self.state.lock().unwrap().chain_coherence
        }

        pub fn len(&self) -> u64 {
            self.state.lock().unwrap().next_seq
        }

        pub fn flush(&self) -> AuditResult<()> {
            let mut w = self.writer.lock().unwrap();
            w.flush()?;
            Ok(())
        }
    }

    /// Verify the quantum hashchain integrity.
    pub fn verify_hashchain(path: &Path) -> AuditResult<VerifyResult> {
        global_metrics().inc_verification();
        let file = std::fs::File::open(path)?;
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

            if entry.seq != expected_seq {
                global_metrics().inc_verification_failed();
                return Ok(VerifyResult::Broken {
                    seq: entry.seq,
                    reason: format!(
                        "sequence mismatch: expected {expected_seq}, found {}",
                        entry.seq
                    ),
                });
            }

            if entry.prev_hash != expected_prev {
                global_metrics().inc_verification_failed();
                return Ok(VerifyResult::Broken {
                    seq: entry.seq,
                    reason: format!(
                        "entanglement broken: prev_hash mismatch (expected {expected_prev}, found {})",
                        entry.prev_hash
                    ),
                });
            }

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
                global_metrics().inc_verification_failed();
                return Ok(VerifyResult::Broken {
                    seq: entry.seq,
                    reason: format!(
                        "entry tampered: hash mismatch (computed {computed_hash}, stored {})",
                        entry.entry_hash
                    ),
                });
            }

            let expected_fidelity = ENTANGLEMENT_STRENGTH.powi(entry.seq as i32);
            if (entry.entanglement_fidelity - expected_fidelity).abs() > 0.01 {
                global_metrics().inc_verification_failed();
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
            global_metrics().inc_verification_passed();
            return Ok(VerifyResult::Empty);
        }

        let avg_fidelity = total_fidelity / entries as f64;
        global_metrics().inc_verification_passed();
        Ok(VerifyResult::Ok {
            entries,
            average_fidelity: avg_fidelity,
        })
    }
}

pub mod manager {
    //! Centralised manager for audit operations.
    use super::{
        config::AuditConfig,
        error::{AuditError, AuditResult},
        types::{AuditEvent, AuditLevel, AuditCategory, VerifyResult},
        logger::QuantumAuditLogger,
        hashchain::{QuantumHashchainLogger, verify_hashchain},
        metrics::{AuditMetrics, global_metrics},
    };
    use std::path::{Path, PathBuf};
    use tracing::{debug, info};

    /// Centralised manager for the audit subsystem.
    pub struct AuditManager {
        config: AuditConfig,
        logger: QuantumAuditLogger,
        hashchain: Option<QuantumHashchainLogger>,
        initialised: bool,
    }

    impl AuditManager {
        pub fn new(config: AuditConfig) -> Self {
            config.validate().expect("invalid AuditConfig");
            // Create logger.
            let log_path = config.log_path.as_ref().map(|p| PathBuf::from(p));
            let logger = QuantumAuditLogger::new(log_path, &config)
                .expect("failed to create audit logger");

            let hashchain = if config.enable_file_logging {
                if let Some(ref path) = config.log_path {
                    let hash_path = Path::new(path).with_extension("hashchain");
                    Some(QuantumHashchainLogger::open(&hash_path, &config)
                        .expect("failed to open hashchain logger"))
                } else {
                    None
                }
            } else {
                None
            };

            Self {
                config,
                logger,
                hashchain,
                initialised: false,
            }
        }

        pub fn default() -> Self {
            Self::new(AuditConfig::default())
        }

        pub fn config(&self) -> &AuditConfig {
            &self.config
        }

        pub fn init(&mut self) {
            self.initialised = true;
            info!("audit manager initialised");
        }

        pub fn is_initialised(&self) -> bool {
            self.initialised
        }

        /// Log an audit event.
        pub fn log_event(&self, event: AuditEvent) -> AuditResult<()> {
            if !self.initialised {
                debug!("audit manager not initialised; logging event anyway");
            }
            self.logger.log(event.clone())?;
            if let Some(ref hc) = self.hashchain {
                hc.append(event)?;
            }
            Ok(())
        }

        /// Log a convenience event (helper wrappers).
        pub fn log_key_generated(&self, key_type: &str, address: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_generated")
                .with_detail("key_type", key_type)
                .with_detail("address", address);
            self.log_event(event)
        }

        pub fn log_key_imported(&self, source: &str, address: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_imported")
                .with_detail("source", source)
                .with_detail("address", address);
            self.log_event(event)
        }

        pub fn log_block_committed(&self, height: u64, hash: &str, txs: usize) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_committed")
                .with_detail("height", height.to_string())
                .with_detail("hash", hash)
                .with_detail("tx_count", txs.to_string());
            self.log_event(event)
        }

        pub fn log_finality(&self, height: u64, latency_ms: u64) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_finalized")
                .with_detail("height", height.to_string())
                .with_detail("latency_ms", latency_ms.to_string());
            self.log_event(event)
        }

        pub fn log_equivocation(&self, validator: &str, height: u64) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Critical, AuditCategory::Consensus, "equivocation_detected")
                .with_detail("validator", validator)
                .with_detail("height", height.to_string());
            self.log_event(event)
        }

        pub fn log_migration(&self, from_sv: u32, to_sv: u32, status: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Warning, AuditCategory::Migration, "schema_migration")
                .with_detail("from_sv", from_sv.to_string())
                .with_detail("to_sv", to_sv.to_string())
                .with_detail("status", status);
            self.log_event(event)
        }

        pub fn log_protocol_upgrade(&self, from_pv: u32, to_pv: u32, height: u64) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Critical, AuditCategory::Migration, "protocol_upgrade")
                .with_detail("from_pv", from_pv.to_string())
                .with_detail("to_pv", to_pv.to_string())
                .with_detail("activation_height", height.to_string());
            self.log_event(event)
        }

        pub fn log_peer_action(&self, peer_id: &str, action: &str, reason: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Warning, AuditCategory::Network, action)
                .with_detail("peer_id", peer_id)
                .with_detail("reason", reason);
            self.log_event(event)
        }

        pub fn log_snapshot(&self, action: &str, height: u64, path: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Admin, action)
                .with_detail("height", height.to_string())
                .with_detail("path", path);
            self.log_event(event)
        }

        pub fn log_startup(&self, version: &str, pv: u32, sv: u32) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "node_started")
                .with_detail("version", version)
                .with_detail("protocol_version", pv.to_string())
                .with_detail("schema_version", sv.to_string());
            self.log_event(event)
        }

        pub fn log_shutdown(&self, reason: &str) -> AuditResult<()> {
            let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Shutdown, "node_stopped")
                .with_detail("reason", reason);
            self.log_event(event)
        }

        /// Get recent events.
        pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
            self.logger.recent(n)
        }

        /// Get events by category.
        pub fn by_category(&self, cat: AuditCategory, limit: usize) -> Vec<AuditEvent> {
            self.logger.by_category(cat, limit)
        }

        /// Get current coherence.
        pub fn coherence(&self) -> f64 {
            self.logger.coherence()
        }

        /// Flush logs to disk.
        pub fn flush(&self) -> AuditResult<()> {
            self.logger.flush()?;
            if let Some(ref hc) = self.hashchain {
                hc.flush()?;
            }
            Ok(())
        }

        /// Verify hashchain integrity.
        pub fn verify_hashchain(&self) -> AuditResult<VerifyResult> {
            if let Some(ref hc) = self.hashchain {
                // We need the path; we can store it in the manager.
                // For simplicity, we'll use the log path to derive hashchain path.
                if let Some(ref log_path) = self.config.log_path {
                    let hash_path = Path::new(log_path).with_extension("hashchain");
                    return super::hashchain::verify_hashchain(&hash_path);
                }
            }
            Ok(VerifyResult::Empty)
        }

        pub fn metrics_snapshot(&self) -> super::metrics::AuditMetricsSnapshot {
            global_metrics().snapshot()
        }

        pub fn reset_metrics(&self) {
            // Not supported; global metrics can't be reset easily.
            tracing::warn!("resetting audit metrics not supported in this version");
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::AuditConfig;
pub use error::{AuditError, AuditResult};
pub use types::{AuditEvent, AuditLevel, AuditCategory, QuantumHashchainEntry, VerifyResult};
pub use logger::QuantumAuditLogger;
pub use hashchain::QuantumHashchainLogger;
pub use manager::AuditManager;
pub use hashchain::verify_hashchain;

// Re-export constants for backward compatibility.
pub use constants::*;

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

use spin::Once;

static GLOBAL_MANAGER: Once<AuditManager> = Once::new();

fn global_manager() -> &'static AuditManager {
    GLOBAL_MANAGER.get_or_init(|| {
        let mut mgr = AuditManager::new(AuditConfig::default());
        mgr.init();
        mgr
    })
}

/// Record a quantum audit event (legacy).
pub fn log_event(event: AuditEvent) -> AuditResult<()> {
    global_manager().log_event(event)
}

/// Legacy convenience functions.
pub fn audit_key_generated(key_type: &str, address: &str) {
    let _ = global_manager().log_key_generated(key_type, address);
}

pub fn audit_key_imported(source: &str, address: &str) {
    let _ = global_manager().log_key_imported(source, address);
}

pub fn audit_block_committed(height: u64, hash: &str, txs: usize) {
    let _ = global_manager().log_block_committed(height, hash, txs);
}

pub fn audit_finality(height: u64, latency_ms: u64) {
    let _ = global_manager().log_finality(height, latency_ms);
}

pub fn audit_equivocation(validator: &str, height: u64) {
    let _ = global_manager().log_equivocation(validator, height);
}

pub fn audit_migration(from_sv: u32, to_sv: u32, status: &str) {
    let _ = global_manager().log_migration(from_sv, to_sv, status);
}

pub fn audit_protocol_upgrade(from_pv: u32, to_pv: u32, height: u64) {
    let _ = global_manager().log_protocol_upgrade(from_pv, to_pv, height);
}

pub fn audit_peer_action(peer_id: &str, action: &str, reason: &str) {
    let _ = global_manager().log_peer_action(peer_id, action, reason);
}

pub fn audit_snapshot(action: &str, height: u64, path: &str) {
    let _ = global_manager().log_snapshot(action, height, path);
}

pub fn audit_startup(version: &str, pv: u32, sv: u32) {
    let _ = global_manager().log_startup(version, pv, sv);
}

pub fn audit_shutdown(reason: &str) {
    let _ = global_manager().log_shutdown(reason);
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_event_coherence() {
        let mut event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "test");
        assert!((event.coherence - 1.0).abs() < 1e-10);
        event.apply_decoherence(0.1);
        assert!(event.coherence < 1.0);
    }

    #[test]
    fn test_audit_logger_memory_only() {
        let config = AuditConfig {
            enable_file_logging: false,
            ..Default::default()
        };
        let logger = QuantumAuditLogger::new(None, &config).unwrap();
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
    fn test_audit_logger_file_backed() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let config = AuditConfig {
            enable_file_logging: true,
            log_path: Some(path.to_str().unwrap().to_string()),
            ..Default::default()
        };
        let logger = QuantumAuditLogger::new(Some(path.clone()), &config).unwrap();
        logger.log(
            AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "boot")
        ).unwrap();
        logger.flush().unwrap();

        let content = std::fs::read_to_string(path).unwrap();
        assert!(content.contains("\"action\":\"boot\""));
    }

    #[test]
    fn test_hashchain_single() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let config = AuditConfig::default();
        let hc = QuantumHashchainLogger::open(&path, &config).unwrap();
        hc.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "boot")).unwrap();

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
    fn test_hashchain_multiple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let config = AuditConfig::default();
        let hc = QuantumHashchainLogger::open(&path, &config).unwrap();

        for i in 0..5 {
            hc.append(
                AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, format!("block_{i}"))
            ).unwrap();
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
    fn test_hashchain_tampered() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let config = AuditConfig::default();
        let hc = QuantumHashchainLogger::open(&path, &config).unwrap();
        hc.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block")).unwrap();
        drop(hc);

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("block", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();

        let result = verify_hashchain(&path).unwrap();
        assert!(matches!(result, VerifyResult::Broken { .. }));
    }

    #[test]
    fn test_manager() {
        let mut mgr = AuditManager::default();
        mgr.init();
        mgr.log_startup("0.6.0", 1, 1).unwrap();
        let recent = mgr.recent(10);
        assert!(!recent.is_empty());
        assert_eq!(recent[0].action, "node_started");
    }
}
