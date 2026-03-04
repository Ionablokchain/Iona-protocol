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
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            timestamp: ts,
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

/// Audit logger that writes to a file and/or tracing.
pub struct AuditLogger {
    file: Option<Mutex<std::fs::File>>,
    events: Mutex<Vec<AuditEvent>>,
}

impl AuditLogger {
    /// Create a new audit logger. If `path` is Some, events are appended to
    /// the specified file in JSON-lines format.
    pub fn new(path: Option<PathBuf>) -> std::io::Result<Self> {
        let file = match path {
            Some(p) => {
                let f = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(p)?;
                Some(Mutex::new(f))
            }
            None => None,
        };
        Ok(Self {
            file,
            events: Mutex::new(Vec::new()),
        })
    }

    /// Log an audit event.
    pub fn log(&self, event: AuditEvent) {
        // Write to file if configured
        if let Some(ref file) = self.file {
            if let Ok(json) = serde_json::to_string(&event) {
                if let Ok(mut f) = file.lock() {
                    let _ = writeln!(f, "{}", json);
                    let _ = f.flush();
                }
            }
        }

        // Store in memory buffer (capped)
        if let Ok(mut events) = self.events.lock() {
            if events.len() >= 10_000 {
                events.drain(..1000); // keep last 9000
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

    /// Get events by category.
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
}

// ── Convenience functions for common audit events ───────────────────────

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

#[cfg(test)]
mod tests {
    use super::*;

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
        let logger = AuditLogger::new(None).unwrap();
        for i in 0..100 {
            logger.log(AuditEvent::new(
                AuditLevel::Info,
                AuditCategory::Consensus,
                format!("block_{i}"),
            ));
        }
        let recent = logger.recent(10);
        assert_eq!(recent.len(), 10);
        assert_eq!(recent.last().unwrap().action, "block_99");
    }

    #[test]
    fn test_audit_logger_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        let logger = AuditLogger::new(Some(path.clone())).unwrap();

        audit_startup(&logger, "27.0.0", 1, 4);
        audit_block_committed(&logger, 1, "abc123", 5);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        // Verify JSON parsing
        let event: AuditEvent = serde_json::from_str(lines[0]).unwrap();
        assert_eq!(event.action, "node_started");
    }

    #[test]
    fn test_audit_by_category() {
        let logger = AuditLogger::new(None).unwrap();
        audit_startup(&logger, "27.0.0", 1, 4);
        audit_block_committed(&logger, 1, "abc", 5);
        audit_block_committed(&logger, 2, "def", 3);
        audit_peer_action(&logger, "peer1", "quarantine", "rate_limit");

        let consensus = logger.by_category(AuditCategory::Consensus, 10);
        assert_eq!(consensus.len(), 2);

        let network = logger.by_category(AuditCategory::Network, 10);
        assert_eq!(network.len(), 1);
    }
}
