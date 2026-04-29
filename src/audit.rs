//! Audit trail logging for critical node operations.
//!
//! All security-sensitive actions are logged as structured JSON events to both
//! the tracing subsystem and an optional dedicated audit log file.
//!
//! Event categories:
//! - KEY: key generation, import, export, rotation
//! - CONSENSUS: block production, finality, equivocation
//! - MIGRATION: schema/protocol upgrades
//! - NETWORK: peer bans, quarantine, rate limit violations
//! - ADMIN: config changes, manual overrides, snapshot operations

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{self, Write, BufWriter};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during audit logging or hashchain verification.
#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("JSON serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    #[error("Hashchain verification failed: {0}")]
    Verification(String),
}

pub type AuditResult<T> = Result<T, AuditError>;

// -----------------------------------------------------------------------------
// Event types
// -----------------------------------------------------------------------------

/// Audit event severity levels.
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

/// Audit event categories.
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

/// A structured audit event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    /// Unix timestamp (seconds)
    pub timestamp: u64,
    /// Event severity
    pub level: AuditLevel,
    /// Event category
    pub category: AuditCategory,
    /// Human-readable action description
    pub action: String,
    /// Optional key-value details
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub details: Vec<(String, String)>,
    /// Node identity (validator address or node ID)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
}

impl AuditEvent {
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
        }
    }

    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.push((key.into(), value.into()));
        self
    }

    pub fn with_node_id(mut self, id: impl Into<String>) -> Self {
        self.node_id = Some(id.into());
        self
    }
}

impl fmt::Display for AuditEvent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "[AUDIT] {} | {} | {} | {}",
            self.timestamp, self.level, self.category, self.action
        )?;
        for (k, v) in &self.details {
            write!(f, " | {k}={v}")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Basic audit logger (file + memory ring buffer)
// -----------------------------------------------------------------------------

/// Audit logger that writes to a file and/or tracing.
pub struct AuditLogger {
    file: Option<Mutex<BufWriter<File>>>,
    events: Mutex<Vec<AuditEvent>>,
    max_memory_events: usize,
}

impl AuditLogger {
    /// Create a new audit logger. If `path` is Some, events are appended to
    /// the specified file in JSON-lines format.
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
        })
    }

    /// Log an audit event.
    pub fn log(&self, event: AuditEvent) {
        // Write to file if configured
        if let Some(ref file) = self.file {
            if let Ok(json) = serde_json::to_string(&event) {
                if let Ok(mut f) = file.lock() {
                    let _ = writeln!(f, "{json}");
                    let _ = f.flush();
                }
            }
        }

        // Store in memory buffer (capped ring)
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.max_memory_events {
                events.remove(0);
            }
            events.push(event);
        }
    }

    /// Get recent audit events (last N).
    pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
        self.events.lock().map(|events| {
            let start = events.len().saturating_sub(n);
            events[start..].to_vec()
        }).unwrap_or_default()
    }

    /// Get events by category (most recent first, up to `limit`).
    pub fn by_category(&self, cat: AuditCategory, limit: usize) -> Vec<AuditEvent> {
        self.events.lock().map(|events| {
            events.iter()
                .rev()
                .filter(|e| e.category == cat)
                .take(limit)
                .cloned()
                .collect()
        }).unwrap_or_default()
    }
}

// -----------------------------------------------------------------------------
// Convenience audit macros/functions
// -----------------------------------------------------------------------------

pub fn audit_key_generated(logger: &AuditLogger, key_type: &str, address: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_generated")
            .with_detail("key_type", key_type)
            .with_detail("address", address),
    );
}

pub fn audit_key_imported(logger: &AuditLogger, source: &str, address: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_imported")
            .with_detail("source", source)
            .with_detail("address", address),
    );
}

pub fn audit_block_committed(logger: &AuditLogger, height: u64, hash: &str, txs: usize) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_committed")
            .with_detail("height", height.to_string())
            .with_detail("hash", hash)
            .with_detail("tx_count", txs.to_string()),
    );
}

pub fn audit_finality(logger: &AuditLogger, height: u64, latency_ms: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_finalized")
            .with_detail("height", height.to_string())
            .with_detail("latency_ms", latency_ms.to_string()),
    );
}

pub fn audit_equivocation(logger: &AuditLogger, validator: &str, height: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Consensus, "equivocation_detected")
            .with_detail("validator", validator)
            .with_detail("height", height.to_string()),
    );
}

pub fn audit_migration(logger: &AuditLogger, from_sv: u32, to_sv: u32, status: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Migration, "schema_migration")
            .with_detail("from_sv", from_sv.to_string())
            .with_detail("to_sv", to_sv.to_string())
            .with_detail("status", status),
    );
}

pub fn audit_protocol_upgrade(logger: &AuditLogger, from_pv: u32, to_pv: u32, height: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Migration, "protocol_upgrade")
            .with_detail("from_pv", from_pv.to_string())
            .with_detail("to_pv", to_pv.to_string())
            .with_detail("activation_height", height.to_string()),
    );
}

pub fn audit_peer_action(logger: &AuditLogger, peer_id: &str, action: &str, reason: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Network, action)
            .with_detail("peer_id", peer_id)
            .with_detail("reason", reason),
    );
}

pub fn audit_snapshot(logger: &AuditLogger, action: &str, height: u64, path: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Admin, action)
            .with_detail("height", height.to_string())
            .with_detail("path", path),
    );
}

pub fn audit_startup(logger: &AuditLogger, version: &str, pv: u32, sv: u32) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "node_started")
            .with_detail("version", version)
            .with_detail("protocol_version", pv.to_string())
            .with_detail("schema_version", sv.to_string()),
    );
}

pub fn audit_shutdown(logger: &AuditLogger, reason: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Shutdown, "node_stopped")
            .with_detail("reason", reason),
    );
}

// -----------------------------------------------------------------------------
// Tamper-evident hashchain audit log
// -----------------------------------------------------------------------------

const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Compute BLAKE3 hex digest.
fn blake3_hex(data: &[u8]) -> String {
    blake3::hash(data).to_hex().to_string()
}

/// A single entry in the tamper-evident audit log file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashchainEntry {
    pub seq: u64,
    pub prev_hash: String,
    pub entry_hash: String,
    #[serde(flatten)]
    pub event: AuditEvent,
}

/// Tamper-evident audit logger using a forward hash chain.
pub struct HashchainLogger {
    writer: Mutex<BufWriter<File>>,
    state: Mutex<HashchainState>,
}

struct HashchainState {
    next_seq: u64,
    prev_hash: String,
}

impl HashchainLogger {
    /// Open or create a hashchain audit log file.
    pub fn open(path: &Path) -> AuditResult<Self> {
        let (next_seq, prev_hash) = if path.exists() {
            let content = std::fs::read_to_string(path)?;
            let last_line = content.lines().filter(|l| !l.trim().is_empty()).last();
            match last_line {
                Some(line) => {
                    let line_hash = blake3_hex(line.as_bytes());
                    let entry: HashchainEntry = serde_json::from_str(line)?;
                    (entry.seq + 1, line_hash)
                }
                None => (0, GENESIS_HASH.to_string()),
            }
        } else {
            (0, GENESIS_HASH.to_string())
        };

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        let writer = Mutex::new(BufWriter::new(file));

        Ok(Self {
            writer,
            state: Mutex::new(HashchainState { next_seq, prev_hash }),
        })
    }

    /// Append an audit event to the hashchain log.
    pub fn append(&self, event: AuditEvent) -> AuditResult<()> {
        let mut state = self.state.lock().unwrap();
        let seq = state.next_seq;
        let prev_hash = state.prev_hash.clone();

        // Partial entry (without entry_hash) for computing hash
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

        let full = HashchainEntry {
            seq,
            prev_hash,
            entry_hash,
            event,
        };
        let line = serde_json::to_string(&full)?;

        // Write and flush
        {
            let mut w = self.writer.lock().unwrap();
            writeln!(w, "{}", line)?;
            w.flush()?;
        }

        // Update state for next entry
        state.next_seq += 1;
        state.prev_hash = blake3_hex(line.as_bytes());
        Ok(())
    }
}

/// Result of hashchain verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyResult {
    Ok { entries: u64 },
    Broken { seq: u64, reason: String },
    Empty,
}

impl fmt::Display for VerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VerifyResult::Ok { entries } => write!(f, "OK: {entries} entries verified, chain intact"),
            VerifyResult::Broken { seq, reason } => write!(f, "BROKEN at seq={seq}: {reason}"),
            VerifyResult::Empty => write!(f, "EMPTY: log file contains no entries"),
        }
    }
}

/// Verify the tamper-evident hashchain in an audit log file.
pub fn verify_hashchain(path: &Path) -> AuditResult<VerifyResult> {
    let content = std::fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().filter(|l| !l.trim().is_empty()).collect();

    if lines.is_empty() {
        return Ok(VerifyResult::Empty);
    }

    let mut expected_prev = GENESIS_HASH.to_string();
    let mut expected_seq = 0u64;

    for (idx, line) in lines.iter().enumerate() {
        let entry: HashchainEntry = serde_json::from_str(line)
            .map_err(|e| AuditError::Verification(format!("line {}: JSON error: {}", idx, e)))?;

        if entry.seq != expected_seq {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!("expected seq={expected_seq}, found {}", entry.seq),
            });
        }

        if entry.prev_hash != expected_prev {
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!("prev_hash mismatch: expected {expected_prev}, found {}", entry.prev_hash),
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
            return Ok(VerifyResult::Broken {
                seq: entry.seq,
                reason: format!("entry_hash mismatch: computed {computed_hash}, stored {}", entry.entry_hash),
            });
        }

        expected_prev = blake3_hex(line.as_bytes());
        expected_seq += 1;
    }

    Ok(VerifyResult::Ok { entries: expected_seq })
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_audit_event() {
        let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "test")
            .with_detail("k", "v")
            .with_node_id("n1");
        assert_eq!(event.level, AuditLevel::Info);
        assert_eq!(event.details.len(), 1);
        assert_eq!(event.node_id, Some("n1".to_string()));
    }

    #[test]
    fn test_audit_logger_memory() {
        let logger = AuditLogger::new(None, 100).unwrap();
        for i in 0..10 {
            logger.log(AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, format!("ev_{i}")));
        }
        let recent = logger.recent(5);
        assert_eq!(recent.len(), 5);
        assert_eq!(recent.last().unwrap().action, "ev_9");
    }

    #[test]
    fn test_audit_logger_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::new(Some(path.clone()), 1000).unwrap();
        audit_startup(&logger, "1.0", 1, 2);
        audit_block_committed(&logger, 100, "0xabc", 5);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        let ev: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(ev.action, "node_started");
    }

    #[test]
    fn test_hashchain_single() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = HashchainLogger::open(&path).unwrap();
        logger.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "boot")).unwrap();
        let result = verify_hashchain(&path).unwrap();
        assert_eq!(result, VerifyResult::Ok { entries: 1 });
    }

    #[test]
    fn test_hashchain_multiple() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = HashchainLogger::open(&path).unwrap();
        for i in 0..5 {
            logger.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, format!("block_{i}"))).unwrap();
        }
        let result = verify_hashchain(&path).unwrap();
        assert_eq!(result, VerifyResult::Ok { entries: 5 });
    }

    #[test]
    fn test_hashchain_tampered() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        let logger = HashchainLogger::open(&path).unwrap();
        logger.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block")).unwrap();
        drop(logger);

        let content = std::fs::read_to_string(&path).unwrap();
        let tampered = content.replace("block", "TAMPERED");
        std::fs::write(&path, tampered).unwrap();

        let result = verify_hashchain(&path).unwrap();
        assert!(matches!(result, VerifyResult::Broken { .. }));
    }

    #[test]
    fn test_hashchain_resume() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("chain.log");
        {
            let logger = HashchainLogger::open(&path).unwrap();
            logger.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "first")).unwrap();
        }
        {
            let logger = HashchainLogger::open(&path).unwrap();
            logger.append(AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "second")).unwrap();
        }
        let result = verify_hashchain(&path).unwrap();
        assert_eq!(result, VerifyResult::Ok { entries: 2 });
    }
}
