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
//! - STARTUP / SHUTDOWN: node lifecycle events

use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{error, info, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the audit logger.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditConfig {
    /// Path to the audit log file. If None, file logging is disabled.
    pub file_path: Option<PathBuf>,
    /// Maximum size of the audit log file in bytes before rotation (0 = unlimited).
    pub max_file_size_bytes: u64,
    /// Number of rotated log files to keep.
    pub rotate_count: usize,
    /// Maximum number of events to keep in memory (for `recent()` queries).
    pub max_memory_events: usize,
    /// Whether to also emit audit events via `tracing`.
    pub emit_to_tracing: bool,
    /// File permissions (Unix only) as an octal string, e.g., "600".
    pub file_mode: Option<String>,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            file_path: None,
            max_file_size_bytes: 100 * 1024 * 1024, // 100 MiB
            rotate_count: 5,
            max_memory_events: 10_000,
            emit_to_tracing: true,
            file_mode: Some("600".into()),
        }
    }
}

// -----------------------------------------------------------------------------
// Audit Types
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
    /// Unix timestamp (seconds) – millisecond precision stored as float.
    pub timestamp: f64,
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
    /// Create a new event with the current timestamp (with millisecond precision).
    pub fn new(level: AuditLevel, category: AuditCategory, action: impl Into<String>) -> Self {
        let now = SystemTime::now();
        let timestamp = now
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            timestamp,
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
            "[AUDIT] {:.3} | {} | {} | {}",
            self.timestamp, self.level, self.category, self.action
        )?;
        for (k, v) in &self.details {
            write!(f, " | {k}={v}")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Audit Logger
// -----------------------------------------------------------------------------

/// Audit logger that writes to a file (with rotation) and/or tracing.
pub struct AuditLogger {
    config: AuditConfig,
    file_writer: Option<Mutex<BufWriter<File>>>,
    current_size: Arc<AtomicUsize>,
    events: Mutex<Vec<AuditEvent>>,
    _drop_guard: Option<Box<dyn Drop>>,
}

impl AuditLogger {
    /// Create a new audit logger based on the configuration.
    pub fn new(config: AuditConfig) -> std::io::Result<Self> {
        let file_writer = if let Some(ref path) = config.file_path {
            let file = Self::open_log_file(path, &config)?;
            let writer = BufWriter::new(file);
            Some(Mutex::new(writer))
        } else {
            None
        };

        let current_size = if let Some(ref path) = config.file_path {
            let size = Self::get_file_size(path).unwrap_or(0);
            Arc::new(AtomicUsize::new(size as usize))
        } else {
            Arc::new(AtomicUsize::new(0))
        };

        Ok(Self {
            config,
            file_writer,
            current_size,
            events: Mutex::new(Vec::with_capacity(config.max_memory_events)),
            _drop_guard: None,
        })
    }

    /// Open the audit log file with the appropriate permissions.
    fn open_log_file(path: &Path, config: &AuditConfig) -> std::io::Result<File> {
        let mut opts = OpenOptions::new();
        opts.create(true).append(true);
        #[cfg(unix)]
        {
            if let Some(mode_str) = &config.file_mode {
                if let Ok(mode) = u32::from_str_radix(mode_str, 8) {
                    use std::os::unix::fs::OpenOptionsExt;
                    opts.mode(mode);
                }
            }
        }
        opts.open(path)
    }

    /// Get file size (for rotation).
    fn get_file_size(path: &Path) -> std::io::Result<u64> {
        Ok(path.metadata()?.len())
    }

    /// Rotate the log file if it exceeds max size.
    fn rotate_if_needed(&self) {
        let max_size = self.config.max_file_size_bytes;
        if max_size == 0 {
            return;
        }
        let current = self.current_size.load(Ordering::Relaxed) as u64;
        if current < max_size {
            return;
        }

        // Perform rotation (needs exclusive lock on file_writer)
        if let Some(writer_lock) = &self.file_writer {
            if let Ok(mut writer) = writer_lock.try_lock() {
                // Flush and close the current file
                let _ = writer.flush();

                // Get the path from the config
                if let Some(path) = &self.config.file_path {
                    // Rotate existing files: .1, .2, ...
                    for i in (1..self.config.rotate_count).rev() {
                        let src = path.with_extension(format!("{}.{}", path.extension().unwrap_or_default().to_str().unwrap_or("log"), i));
                        let dst = path.with_extension(format!("{}.{}", path.extension().unwrap_or_default().to_str().unwrap_or("log"), i + 1));
                        let _ = std::fs::rename(src, dst);
                    }
                    let old = path.with_extension("log.1");
                    let _ = std::fs::rename(path, old);

                    // Reopen the file
                    match Self::open_log_file(path, &self.config) {
                        Ok(file) => {
                            *writer = BufWriter::new(file);
                            self.current_size.store(0, Ordering::Relaxed);
                        }
                        Err(e) => {
                            error!("Failed to rotate audit log: {}", e);
                        }
                    }
                }
            }
        }
    }

    /// Write a JSON event to the file (if enabled).
    fn write_event_to_file(&self, event: &AuditEvent) {
        let json = match serde_json::to_string(event) {
            Ok(j) => j,
            Err(e) => {
                error!("Failed to serialize audit event: {}", e);
                return;
            }
        };

        if let Some(writer_lock) = &self.file_writer {
            if let Ok(mut writer) = writer_lock.lock() {
                if let Err(e) = writeln!(writer, "{}", json) {
                    error!("Failed to write audit event to file: {}", e);
                } else {
                    let len = json.len();
                    self.current_size.fetch_add(len, Ordering::Relaxed);
                    let _ = writer.flush();
                    // Check rotation after write
                    self.rotate_if_needed();
                }
            }
        }
    }

    /// Log an audit event.
    pub fn log(&self, event: AuditEvent) {
        // Emit via tracing if configured
        if self.config.emit_to_tracing {
            let msg = format!("{}", event);
            match event.level {
                AuditLevel::Info => info!("{}", msg),
                AuditLevel::Warning => warn!("{}", msg),
                AuditLevel::Critical => error!("{}", msg),
            }
        }

        // Write to file
        self.write_event_to_file(&event);

        // Store in memory buffer
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= self.config.max_memory_events {
                // Remove oldest
                let to_remove = events.len() - self.config.max_memory_events + 1;
                events.drain(0..to_remove);
            }
            events.push(event);
        }
    }

    /// Get recent audit events (last N).
    pub fn recent(&self, n: usize) -> Vec<AuditEvent> {
        if let Ok(events) = self.events.lock() {
            let start = events.len().saturating_sub(n);
            events[start..].to_vec()
        } else {
            Vec::new()
        }
    }

    /// Get events by category (most recent first).
    pub fn by_category(&self, cat: AuditCategory, limit: usize) -> Vec<AuditEvent> {
        if let Ok(events) = self.events.lock() {
            events
                .iter()
                .rev()
                .filter(|e| e.category == cat)
                .take(limit)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Flush any pending writes to disk.
    pub fn flush(&self) {
        if let Some(writer_lock) = &self.file_writer {
            if let Ok(mut writer) = writer_lock.lock() {
                let _ = writer.flush();
            }
        }
    }
}

impl Drop for AuditLogger {
    fn drop(&mut self) {
        self.flush();
    }
}

// -----------------------------------------------------------------------------
// Convenience audit functions
// -----------------------------------------------------------------------------

/// Log a key generation event.
pub fn audit_key_generated(logger: &AuditLogger, key_type: &str, address: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_generated")
            .with_detail("key_type", key_type)
            .with_detail("address", address),
    );
}

/// Log a key import event.
pub fn audit_key_imported(logger: &AuditLogger, source: &str, address: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "key_imported")
            .with_detail("source", source)
            .with_detail("address", address),
    );
}

/// Log a block committed event.
pub fn audit_block_committed(logger: &AuditLogger, height: u64, hash: &str, txs: usize) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_committed")
            .with_detail("height", height.to_string())
            .with_detail("hash", hash)
            .with_detail("tx_count", txs.to_string()),
    );
}

/// Log a finality event.
pub fn audit_finality(logger: &AuditLogger, height: u64, latency_ms: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Consensus, "block_finalized")
            .with_detail("height", height.to_string())
            .with_detail("latency_ms", latency_ms.to_string()),
    );
}

/// Log an equivocation (double-sign) detection.
pub fn audit_equivocation(logger: &AuditLogger, validator: &str, height: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Consensus, "equivocation_detected")
            .with_detail("validator", validator)
            .with_detail("height", height.to_string()),
    );
}

/// Log a schema migration event.
pub fn audit_migration(logger: &AuditLogger, from_sv: u32, to_sv: u32, status: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Migration, "schema_migration")
            .with_detail("from_sv", from_sv.to_string())
            .with_detail("to_sv", to_sv.to_string())
            .with_detail("status", status),
    );
}

/// Log a protocol upgrade activation.
pub fn audit_protocol_upgrade(logger: &AuditLogger, from_pv: u32, to_pv: u32, height: u64) {
    logger.log(
        AuditEvent::new(AuditLevel::Critical, AuditCategory::Migration, "protocol_upgrade")
            .with_detail("from_pv", from_pv.to_string())
            .with_detail("to_pv", to_pv.to_string())
            .with_detail("activation_height", height.to_string()),
    );
}

/// Log a peer ban/quarantine event.
pub fn audit_peer_action(logger: &AuditLogger, peer_id: &str, action: &str, reason: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Warning, AuditCategory::Network, action)
            .with_detail("peer_id", peer_id)
            .with_detail("reason", reason),
    );
}

/// Log a snapshot operation.
pub fn audit_snapshot(logger: &AuditLogger, action: &str, height: u64, path: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Admin, action)
            .with_detail("height", height.to_string())
            .with_detail("path", path),
    );
}

/// Log node startup.
pub fn audit_startup(logger: &AuditLogger, version: &str, pv: u32, sv: u32) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Startup, "node_started")
            .with_detail("version", version)
            .with_detail("protocol_version", pv.to_string())
            .with_detail("schema_version", sv.to_string()),
    );
}

/// Log node shutdown.
pub fn audit_shutdown(logger: &AuditLogger, reason: &str) {
    logger.log(
        AuditEvent::new(AuditLevel::Info, AuditCategory::Shutdown, "node_stopped")
            .with_detail("reason", reason),
    );
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_config() -> AuditConfig {
        AuditConfig {
            file_path: None,
            max_file_size_bytes: 0,
            rotate_count: 3,
            max_memory_events: 10,
            emit_to_tracing: false,
            file_mode: None,
        }
    }

    #[test]
    fn test_audit_event_creation() {
        let event = AuditEvent::new(AuditLevel::Info, AuditCategory::Key, "test_action")
            .with_detail("key", "value")
            .with_node_id("node_1");

        assert_eq!(event.level, AuditLevel::Info);
        assert_eq!(event.category, AuditCategory::Key);
        assert_eq!(event.action, "test_action");
        assert_eq!(event.details.len(), 1);
        assert_eq!(event.node_id.as_deref(), Some("node_1"));
    }

    #[test]
    fn test_audit_event_display() {
        let event = AuditEvent::new(AuditLevel::Critical, AuditCategory::Consensus, "equivocation")
            .with_detail("validator", "abc123");
        let s = format!("{}", event);
        assert!(s.contains("CRITICAL"));
        assert!(s.contains("CONSENSUS"));
        assert!(s.contains("equivocation"));
        assert!(s.contains("validator=abc123"));
    }

    #[test]
    fn test_audit_event_serialization() {
        let event = AuditEvent::new(AuditLevel::Warning, AuditCategory::Migration, "migrate")
            .with_detail("from", "3")
            .with_detail("to", "4");
        let json = serde_json::to_string(&event).unwrap();
        let parsed: AuditEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.action, "migrate");
        assert_eq!(parsed.details.len(), 2);
    }

    #[test]
    fn test_audit_logger_memory() {
        let config = AuditConfig {
            max_memory_events: 5,
            ..test_config()
        };
        let logger = AuditLogger::new(config).unwrap();
        for i in 0..10 {
            logger.log(AuditEvent::new(
                AuditLevel::Info,
                AuditCategory::Consensus,
                format!("block_{i}"),
            ));
        }
        let recent = logger.recent(10);
        // Should have only last 5 events
        assert_eq!(recent.len(), 5);
        assert_eq!(recent.last().unwrap().action, "block_9");
    }

    #[test]
    fn test_audit_logger_file() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let config = AuditConfig {
            file_path: Some(path.clone()),
            max_file_size_bytes: 1024, // small for rotation test
            rotate_count: 2,
            ..test_config()
        };
        let logger = AuditLogger::new(config).unwrap();

        audit_startup(&logger, "27.0.0", 1, 4);
        audit_block_committed(&logger, 1, "abc123", 5);

        // Force flush
        logger.flush();

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify JSON parsing
        let event: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event.action, "node_started");
    }

    #[test]
    fn test_audit_by_category() {
        let logger = AuditLogger::new(test_config()).unwrap();
        audit_startup(&logger, "27.0.0", 1, 4);
        audit_block_committed(&logger, 1, "abc", 5);
        audit_block_committed(&logger, 2, "def", 3);
        audit_peer_action(&logger, "peer1", "quarantine", "rate_limit");

        let consensus = logger.by_category(AuditCategory::Consensus, 10);
        assert_eq!(consensus.len(), 2);

        let network = logger.by_category(AuditCategory::Network, 10);
        assert_eq!(network.len(), 1);
    }

    #[test]
    fn test_log_rotation() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let config = AuditConfig {
            file_path: Some(path.clone()),
            max_file_size_bytes: 100, // very small
            rotate_count: 2,
            ..test_config()
        };
        let logger = AuditLogger::new(config).unwrap();

        // Write events until rotation happens
        for i in 0..50 {
            audit_block_committed(&logger, i, &format!("hash_{i}"), 1);
        }

        logger.flush();

        // Check that rotated files exist
        let rotated = path.with_extension("log.1");
        assert!(rotated.exists() || !path.exists() /* rotated away */);
    }
}
