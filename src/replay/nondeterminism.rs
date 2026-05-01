//! Nondeterministic input logging.
//!
//! Tracks and logs every source of nondeterminism that could cause state
//! divergence between nodes.  In a deterministic blockchain, the *only*
//! valid source of nondeterminism is the block itself (proposer choice,
//! tx ordering).  Everything else must be either:
//!
//! - Derived deterministically from the block/state
//! - Logged and auditable
//!
//! # Nondeterminism Sources
//!
//! | Source         | Risk  | Mitigation                              |
//! |----------------|-------|-----------------------------------------|
//! | System clock   | HIGH  | Use block.timestamp, never wall clock    |
//! | RNG            | HIGH  | Use deterministic seed from block hash   |
//! | HashMap order  | HIGH  | Use BTreeMap exclusively                 |
//! | Float ops      | MED   | Avoid floats; use integer arithmetic     |
//! | Thread sched   | MED   | Single-threaded state transitions        |
//! | External I/O   | LOW   | No external calls during execution       |
//! | Compiler opts  | LOW   | Pinned toolchain + --locked              |
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::replay::nondeterminism::{NdLogger, NdLoggerBuilder};
//!
//! let logger = NdLoggerBuilder::new()
//!     .with_file("nondet.log")
//!     .build()?;
//! logger.set_height(100);
//! logger.log_timestamp(wall_time, block_time);
//! let report = logger.report();
//! ```

use serde::{Deserialize, Serialize};
use std::fs::OpenOptions;
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during nondeterminism logging.
#[derive(Debug, Error)]
pub enum NdLoggerError {
    #[error("failed to open log file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write to log file: {source}")]
    WriteFile {
        #[source]
        source: std::io::Error,
    },
    #[error("serialization error: {source}")]
    Serialization {
        #[source]
        source: serde_json::Error,
    },
}

pub type NdLoggerResult<T> = Result<T, NdLoggerError>;

// -----------------------------------------------------------------------------
// Event types
// -----------------------------------------------------------------------------

/// Categories of nondeterministic inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NdSource {
    Timestamp,
    Rng,
    HashMapOrder,
    FloatOp,
    ThreadSchedule,
    ExternalIo,
    PlatformSpecific,
    Other(String),
}

impl std::fmt::Display for NdSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timestamp => write!(f, "TIMESTAMP"),
            Self::Rng => write!(f, "RNG"),
            Self::HashMapOrder => write!(f, "HASHMAP_ORDER"),
            Self::FloatOp => write!(f, "FLOAT_OP"),
            Self::ThreadSchedule => write!(f, "THREAD_SCHEDULE"),
            Self::ExternalIo => write!(f, "EXTERNAL_IO"),
            Self::PlatformSpecific => write!(f, "PLATFORM_SPECIFIC"),
            Self::Other(s) => write!(f, "OTHER({s})"),
        }
    }
}

/// Severity of a nondeterminism event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum NdSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for NdSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => write!(f, "INFO"),
            Self::Warning => write!(f, "WARN"),
            Self::Critical => write!(f, "CRIT"),
        }
    }
}

/// A single logged nondeterminism event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NdEvent {
    pub source: NdSource,
    pub severity: NdSeverity,
    pub height: u64,
    pub description: String,
    pub observed_value: String,
    pub deterministic_alternative: Option<String>,
    pub logged_at_ns: u64,
}

impl std::fmt::Display for NdEvent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "[{}] {} h={}: {} (observed={}",
            self.severity, self.source, self.height, self.description, self.observed_value
        )?;
        if let Some(alt) = &self.deterministic_alternative {
            write!(f, ", should_use={alt}")?;
        }
        write!(f, ")")
    }
}

// -----------------------------------------------------------------------------
// Logger with optional file output
// -----------------------------------------------------------------------------

/// Thread-safe nondeterminism logger.
pub struct NdLogger {
    events: Mutex<Vec<NdEvent>>,
    current_height: Mutex<u64>,
    enabled: bool,
    file_writer: Mutex<Option<BufWriter<std::fs::File>>>,
}

impl NdLogger {
    /// Create a new logger without file output.
    pub fn new(enabled: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            enabled,
            file_writer: Mutex::new(None),
        }
    }

    /// Create a logger that also writes to a file (JSON lines).
    pub fn with_file(enabled: bool, path: impl AsRef<Path>) -> NdLoggerResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path.as_ref())
            .map_err(|e| NdLoggerError::OpenFile {
                path: path.as_ref().to_path_buf(),
                source: e,
            })?;
        let writer = BufWriter::new(file);
        Ok(Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            enabled,
            file_writer: Mutex::new(Some(writer)),
        })
    }

    /// Set the current block height (called at start of block execution).
    pub fn set_height(&self, height: u64) {
        if let Ok(mut h) = self.current_height.lock() {
            *h = height;
        }
    }

    /// Internal log method.
    fn log_internal(
        &self,
        source: NdSource,
        severity: NdSeverity,
        description: String,
        observed: String,
        alternative: Option<String>,
    ) {
        if !self.enabled {
            return;
        }
        let height = self.current_height.lock().map(|h| *h).unwrap_or(0);
        let event = NdEvent {
            source,
            severity,
            height,
            description,
            observed_value: observed,
            deterministic_alternative: alternative,
            logged_at_ns: 0,
        };

        // Store in memory
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }

        // Write to file if configured
        if let Ok(mut writer) = self.file_writer.lock() {
            if let Some(w) = writer.as_mut() {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(w, "{json}");
                    let _ = w.flush();
                }
            }
        }
    }

    /// Log a timestamp usage.
    pub fn log_timestamp(&self, wall_clock_ms: u64, block_timestamp: u64) {
        self.log_internal(
            NdSource::Timestamp,
            NdSeverity::Critical,
            "wall clock used during execution".to_string(),
            format!("{wall_clock_ms}"),
            Some(format!("block.timestamp={block_timestamp}")),
        );
    }

    /// Log RNG usage.
    pub fn log_rng(&self, seed_source: &str, value: &str) {
        self.log_internal(
            NdSource::Rng,
            NdSeverity::Critical,
            format!("RNG used with seed source: {seed_source}"),
            value.to_string(),
            Some("use deterministic seed from block_hash".to_string()),
        );
    }

    /// Log HashMap iteration.
    pub fn log_hashmap_usage(&self, location: &str) {
        self.log_internal(
            NdSource::HashMapOrder,
            NdSeverity::Warning,
            format!("HashMap/HashSet used at {location}"),
            "unordered iteration".to_string(),
            Some("use BTreeMap/BTreeSet".to_string()),
        );
    }

    /// Log external I/O during execution.
    pub fn log_external_io(&self, description: &str) {
        self.log_internal(
            NdSource::ExternalIo,
            NdSeverity::Critical,
            description.to_string(),
            "external call".to_string(),
            Some("remove external I/O from state transition".to_string()),
        );
    }

    /// Log floating-point operation.
    pub fn log_float_op(&self, location: &str, value: &str) {
        self.log_internal(
            NdSource::FloatOp,
            NdSeverity::Warning,
            format!("float operation at {location}"),
            value.to_string(),
            Some("use integer/fixed-point arithmetic".to_string()),
        );
    }

    /// Log platform-specific behaviour.
    pub fn log_platform(&self, description: &str, observed: &str) {
        self.log_internal(
            NdSource::PlatformSpecific,
            NdSeverity::Info,
            description.to_string(),
            observed.to_string(),
            None,
        );
    }

    /// Get all logged events.
    pub fn events(&self) -> Vec<NdEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Get events filtered by severity.
    pub fn events_by_severity(&self, min_severity: NdSeverity) -> Vec<NdEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }

    /// Get events filtered by source.
    pub fn events_by_source(&self, source: &NdSource) -> Vec<NdEvent> {
        self.events()
            .into_iter()
            .filter(|e| &e.source == source)
            .collect()
    }

    /// Check if any critical nondeterminism was detected.
    pub fn has_critical(&self) -> bool {
        self.events()
            .iter()
            .any(|e| e.severity == NdSeverity::Critical)
    }

    /// Clear all events (memory only, file not truncated).
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }

    /// Generate a summary report.
    pub fn report(&self) -> NdReport {
        let events = self.events();
        let critical_count = events
            .iter()
            .filter(|e| e.severity == NdSeverity::Critical)
            .count();
        let warning_count = events
            .iter()
            .filter(|e| e.severity == NdSeverity::Warning)
            .count();
        let info_count = events
            .iter()
            .filter(|e| e.severity == NdSeverity::Info)
            .count();

        NdReport {
            total_events: events.len(),
            critical_count,
            warning_count,
            info_count,
            events,
            clean: critical_count == 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Builder
// -----------------------------------------------------------------------------

/// Builder for configuring an [`NdLogger`].
#[derive(Default)]
pub struct NdLoggerBuilder {
    enabled: bool,
    file_path: Option<PathBuf>,
}

impl NdLoggerBuilder {
    pub fn new() -> Self {
        Self {
            enabled: true,
            file_path: None,
        }
    }

    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    pub fn build(self) -> NdLoggerResult<NdLogger> {
        match self.file_path {
            Some(path) => NdLogger::with_file(self.enabled, path),
            None => Ok(NdLogger::new(self.enabled)),
        }
    }
}

// -----------------------------------------------------------------------------
// Summary report
// -----------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct NdReport {
    pub total_events: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub events: Vec<NdEvent>,
    pub clean: bool,
}

impl std::fmt::Display for NdReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Nondeterminism Report: {}",
            if self.clean { "CLEAN" } else { "ISSUES DETECTED" }
        )?;
        writeln!(
            f,
            "  total={}, critical={}, warning={}, info={}",
            self.total_events, self.critical_count, self.warning_count, self.info_count
        )?;
        for e in &self.events {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Static analysis helpers
// -----------------------------------------------------------------------------

pub const SAFE_PATTERNS: &[&str] = &[
    "BTreeMap",
    "BTreeSet",
    "Vec::sort",
    "deterministic_seed",
    "block.timestamp",
    "block.hash",
];

pub const DANGEROUS_PATTERNS: &[&str] = &[
    "HashMap",
    "HashSet",
    "SystemTime::now",
    "Instant::now",
    "thread_rng",
    "rand::random",
    "std::time",
    "f32",
    "f64",
];

pub fn check_code_snippet(code: &str) -> Vec<(String, NdSeverity)> {
    let mut findings = Vec::new();
    for &pattern in DANGEROUS_PATTERNS {
        if code.contains(pattern) {
            let severity = match pattern {
                "HashMap" | "HashSet" => NdSeverity::Warning,
                "SystemTime::now" | "Instant::now" | "thread_rng" | "rand::random" => {
                    NdSeverity::Critical
                }
                "f32" | "f64" => NdSeverity::Warning,
                _ => NdSeverity::Info,
            };
            findings.push((pattern.to_string(), severity));
        }
    }
    findings
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_logger_basic() {
        let logger = NdLogger::new(true);
        logger.set_height(100);
        logger.log_timestamp(1234567890, 1234567000);

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].height, 100);
        assert_eq!(events[0].source, NdSource::Timestamp);
        assert_eq!(events[0].severity, NdSeverity::Critical);
    }

    #[test]
    fn test_logger_disabled() {
        let logger = NdLogger::new(false);
        logger.log_timestamp(123, 456);
        assert!(logger.events().is_empty());
    }

    #[test]
    fn test_logger_with_file() -> NdLoggerResult<()> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let logger = NdLogger::with_file(true, &path)?;
        logger.set_height(42);
        logger.log_rng("thread_rng", "0xdead");

        // Read file content
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("RNG"));
        assert!(content.contains("0xdead"));
        Ok(())
    }

    #[test]
    fn test_builder() -> NdLoggerResult<()> {
        let file = NamedTempFile::new().unwrap();
        let logger = NdLoggerBuilder::new()
            .with_file(file.path())
            .build()?;
        logger.log_timestamp(1, 2);
        let events = logger.events();
        assert_eq!(events.len(), 1);
        Ok(())
    }

    #[test]
    fn test_filter_by_severity() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        logger.log_hashmap_usage("test");
        logger.log_platform("test", "x86");

        let critical = logger.events_by_severity(NdSeverity::Critical);
        assert_eq!(critical.len(), 1);
        let warnings = logger.events_by_severity(NdSeverity::Warning);
        assert_eq!(warnings.len(), 2);
    }

    #[test]
    fn test_has_critical() {
        let logger = NdLogger::new(true);
        assert!(!logger.has_critical());
        logger.log_hashmap_usage("test");
        assert!(!logger.has_critical());
        logger.log_timestamp(1, 2);
        assert!(logger.has_critical());
    }

    #[test]
    fn test_report() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        logger.log_hashmap_usage("test");
        let report = logger.report();
        assert_eq!(report.total_events, 2);
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.warning_count, 1);
        assert!(!report.clean);
    }

    #[test]
    fn test_check_code_snippet() {
        let code = "let map: HashMap<String, u64> = HashMap::new();";
        let findings = check_code_snippet(code);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].0, "HashMap");
        assert_eq!(findings[0].1, NdSeverity::Warning);
    }
}
