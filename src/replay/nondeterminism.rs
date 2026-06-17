//! Nondeterministic input logging.
//!
//! Tracks and logs every source of nondeterminism that could cause state
//! divergence between nodes. In a deterministic blockchain, the *only*
//! valid source of nondeterminism is the block itself (proposer choice,
//! transaction ordering). Everything else must be either:
//!
//! - Derived deterministically from the block or state
//! - Logged and auditable
//!
//! # Nondeterminism Sources
//!
//! | Source         | Risk  | Mitigation                              |
//! |----------------|-------|-----------------------------------------|
//! | System clock   | HIGH  | Use `block.timestamp`, never wall clock  |
//! | RNG            | HIGH  | Use deterministic seed from block hash   |
//! | HashMap order  | HIGH  | Use `BTreeMap` exclusively               |
//! | Float ops      | MED   | Avoid floats; use integer arithmetic     |
//! | Thread sched   | MED   | Single‑threaded state transitions        |
//! | External I/O   | LOW   | No external calls during execution       |
//! | Compiler opts  | LOW   | Pinned toolchain + `--locked`            |
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
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during nondeterminism logging.
#[derive(Debug, Error)]
pub enum NdLoggerError {
    /// Failed to open the log file for writing.
    #[error("failed to open log file {path}: {source}")]
    OpenFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    /// Failed to write an event to the log file.
    #[error("failed to write to log file: {source}")]
    WriteFile {
        #[source]
        source: std::io::Error,
    },
    /// Failed to serialise an event to JSON.
    #[error("serialization error: {source}")]
    Serialization {
        #[source]
        source: serde_json::Error,
    },
    /// The logger is disabled (no operations allowed).
    #[error("logger is disabled")]
    Disabled,
}

pub type NdLoggerResult<T> = Result<T, NdLoggerError>;

// -----------------------------------------------------------------------------
// Event types
// -----------------------------------------------------------------------------

/// Categories of nondeterministic inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum NdSource {
    /// System wall‑clock time.
    Timestamp,
    /// Random number generator.
    Rng,
    /// Unordered iteration over a hash map or hash set.
    HashMapOrder,
    /// Floating‑point arithmetic.
    FloatOp,
    /// Thread scheduling (e.g., sleeping, yielding).
    ThreadSchedule,
    /// External I/O (file, network).
    ExternalIo,
    /// Behaviour that varies by CPU, OS, or compiler.
    PlatformSpecific,
    /// Any other user‑defined source.
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
    /// Informational – not a direct cause of divergence but worth noting.
    Info,
    /// Warning – could cause divergence under certain conditions.
    Warning,
    /// Critical – definitely causes divergence in production.
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
    /// The source of nondeterminism.
    pub source: NdSource,
    /// Severity level.
    pub severity: NdSeverity,
    /// Block height at which this event occurred.
    pub height: u64,
    /// Human‑readable description.
    pub description: String,
    /// The observed nondeterministic value.
    pub observed_value: String,
    /// Suggested deterministic alternative (if known).
    pub deterministic_alternative: Option<String>,
    /// Timestamp when the event was logged (nanoseconds since boot, placeholder).
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

/// Thread‑safe nondeterminism logger.
///
/// Events are stored in memory and optionally written to a JSON‑lines file.
pub struct NdLogger {
    /// In‑memory event buffer.
    events: Mutex<Vec<NdEvent>>,
    /// Current block height (set before execution).
    current_height: Mutex<u64>,
    /// Whether logging is enabled.
    enabled: bool,
    /// Optional file writer for persistent logging.
    file_writer: Mutex<Option<BufWriter<std::fs::File>>>,
    /// Monotonic event counter for logged_at_ns.
    event_counter: Mutex<u64>,
}

impl NdLogger {
    /// Create a new logger without file output, enabled by default.
    #[must_use]
    pub fn new() -> Self {
        Self::with_enabled(true)
    }

    /// Create a logger with explicit enabled flag.
    #[must_use]
    pub fn with_enabled(enabled: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            enabled,
            file_writer: Mutex::new(None),
            event_counter: Mutex::new(0),
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
            event_counter: Mutex::new(0),
        })
    }

    /// Create a logger enabled by environment variable `IONA_ND_LOG=1`.
    #[must_use]
    pub fn from_env() -> Self {
        let enabled = std::env::var("IONA_ND_LOG")
            .map(|v| v == "1" || v == "true" || v == "yes")
            .unwrap_or(false);
        Self::with_enabled(enabled)
    }

    /// Set the current block height (call at the start of block execution).
    pub fn set_height(&self, height: u64) {
        if let Ok(mut h) = self.current_height.lock() {
            *h = height;
        }
    }

    /// Internal helper to log an event with a timestamp.
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
        let counter = self.event_counter.lock().map(|c| { let v = *c; *c += 1; v }).unwrap_or(0);
        // Use a monotonic counter as a timestamp substitute (actual clock could be non‑deterministic).
        // In production, you could use a real monotonic clock if available.
        let logged_at_ns = counter;

        let event = NdEvent {
            source,
            severity,
            height,
            description,
            observed_value: observed,
            deterministic_alternative: alternative,
            logged_at_ns,
        };

        // Store in memory.
        if let Ok(mut events) = self.events.lock() {
            events.push(event.clone());
        }

        // Write to file if configured.
        if let Ok(mut writer) = self.file_writer.lock() {
            if let Some(w) = writer.as_mut() {
                if let Ok(json) = serde_json::to_string(&event) {
                    let _ = writeln!(w, "{json}");
                    let _ = w.flush();
                }
            }
        }
    }

    /// Log a generic event.
    pub fn log_event(
        &self,
        source: NdSource,
        severity: NdSeverity,
        description: &str,
        observed: &str,
        alternative: Option<&str>,
    ) {
        self.log_internal(
            source,
            severity,
            description.to_string(),
            observed.to_string(),
            alternative.map(|s| s.to_string()),
        );
    }

    /// Log a timestamp usage (wall clock vs block timestamp).
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

    /// Log HashMap/HashSet iteration.
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

    /// Log floating‑point operation.
    pub fn log_float_op(&self, location: &str, value: &str) {
        self.log_internal(
            NdSource::FloatOp,
            NdSeverity::Warning,
            format!("float operation at {location}"),
            value.to_string(),
            Some("use integer/fixed‑point arithmetic".to_string()),
        );
    }

    /// Log platform‑specific behaviour (e.g., CPU‑dependent results).
    pub fn log_platform(&self, description: &str, observed: &str) {
        self.log_internal(
            NdSource::PlatformSpecific,
            NdSeverity::Info,
            description.to_string(),
            observed.to_string(),
            None,
        );
    }

    /// Log a custom event with explicit source and severity.
    pub fn log_custom(&self, source: NdSource, severity: NdSeverity, description: &str, observed: &str) {
        self.log_event(source, severity, description, observed, None);
    }

    /// Get all logged events.
    #[must_use]
    pub fn events(&self) -> Vec<NdEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }

    /// Get events filtered by minimum severity.
    #[must_use]
    pub fn events_by_severity(&self, min_severity: NdSeverity) -> Vec<NdEvent> {
        self.events()
            .into_iter()
            .filter(|e| e.severity >= min_severity)
            .collect()
    }

    /// Get events filtered by source.
    #[must_use]
    pub fn events_by_source(&self, source: &NdSource) -> Vec<NdEvent> {
        self.events()
            .into_iter()
            .filter(|e| &e.source == source)
            .collect()
    }

    /// Check if any critical nondeterminism events were logged.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.events()
            .iter()
            .any(|e| e.severity == NdSeverity::Critical)
    }

    /// Clear all events (in‑memory only; file is not truncated).
    pub fn clear(&self) {
        if let Ok(mut events) = self.events.lock() {
            events.clear();
        }
    }

    /// Generate a summary report.
    #[must_use]
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

    /// Dump in‑memory events to the configured file (if any).
    /// This is useful for flushing after a block is processed.
    pub fn flush(&self) -> NdLoggerResult<()> {
        if let Ok(mut writer) = self.file_writer.lock() {
            if let Some(w) = writer.as_mut() {
                w.flush().map_err(|e| NdLoggerError::WriteFile { source: e })?;
            }
        }
        Ok(())
    }
}

impl Default for NdLogger {
    fn default() -> Self {
        Self::new()
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
    from_env: bool,
}

impl NdLoggerBuilder {
    /// Create a new builder with default settings (enabled = true, no file).
    #[must_use]
    pub fn new() -> Self {
        Self {
            enabled: true,
            file_path: None,
            from_env: false,
        }
    }

    /// Set whether logging is enabled.
    #[must_use]
    pub fn with_enabled(mut self, enabled: bool) -> Self {
        self.enabled = enabled;
        self
    }

    /// Enable file output to the given path.
    #[must_use]
    pub fn with_file(mut self, path: impl Into<PathBuf>) -> Self {
        self.file_path = Some(path.into());
        self
    }

    /// Enable logging based on environment variable `IONA_ND_LOG=1`.
    #[must_use]
    pub fn from_env(mut self) -> Self {
        self.from_env = true;
        self
    }

    /// Build the logger.
    pub fn build(self) -> NdLoggerResult<NdLogger> {
        let enabled = if self.from_env {
            std::env::var("IONA_ND_LOG")
                .map(|v| v == "1" || v == "true" || v == "yes")
                .unwrap_or(false)
        } else {
            self.enabled
        };

        match self.file_path {
            Some(path) => NdLogger::with_file(enabled, path),
            None => Ok(NdLogger::with_enabled(enabled)),
        }
    }
}

// -----------------------------------------------------------------------------
// Summary report
// -----------------------------------------------------------------------------

/// Report summarising all logged nondeterminism events.
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

/// Patterns that are safe (deterministic).
pub const SAFE_PATTERNS: &[&str] = &[
    "BTreeMap",
    "BTreeSet",
    "Vec::sort",
    "deterministic_seed",
    "block.timestamp",
    "block.hash",
];

/// Patterns that are dangerous (nondeterministic) and should be avoided.
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

/// Statically check a code snippet for dangerous patterns.
///
/// Returns a list of `(pattern, severity)` for each dangerous pattern found.
#[must_use]
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
// Global singleton (optional)
// -----------------------------------------------------------------------------

static GLOBAL_LOGGER: once_cell::sync::OnceCell<NdLogger> = once_cell::sync::OnceCell::new();

/// Initialise the global logger. Must be called before use.
/// If not initialised, all logging calls will be no‑ops.
pub fn init_global(logger: NdLogger) {
    let _ = GLOBAL_LOGGER.set(logger);
}

/// Get a reference to the global logger, or `None` if not initialised.
#[must_use]
pub fn global_logger() -> Option<&'static NdLogger> {
    GLOBAL_LOGGER.get()
}

/// Convenience macro to log using the global logger if available.
/// Otherwise, does nothing.
#[macro_export]
macro_rules! nd_log {
    ($source:expr, $severity:expr, $desc:expr, $observed:expr) => {
        if let Some(logger) = $crate::replay::nondeterminism::global_logger() {
            logger.log_event($source, $severity, $desc, $observed, None);
        }
    };
    ($source:expr, $severity:expr, $desc:expr, $observed:expr, $alt:expr) => {
        if let Some(logger) = $crate::replay::nondeterminism::global_logger() {
            logger.log_event($source, $severity, $desc, $observed, Some($alt));
        }
    };
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
        let logger = NdLogger::new();
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
        let logger = NdLogger::with_enabled(false);
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
        let logger = NdLogger::new();
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
        let logger = NdLogger::new();
        assert!(!logger.has_critical());
        logger.log_hashmap_usage("test");
        assert!(!logger.has_critical());
        logger.log_timestamp(1, 2);
        assert!(logger.has_critical());
    }

    #[test]
    fn test_report() {
        let logger = NdLogger::new();
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

    #[test]
    fn test_log_event_generic() {
        let logger = NdLogger::new();
        logger.log_event(
            NdSource::Other("custom".to_string()),
            NdSeverity::Info,
            "test description",
            "observed value",
            Some("alternative"),
        );
        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, NdSource::Other("custom".to_string()));
    }

    #[test]
    fn test_flush() -> NdLoggerResult<()> {
        let file = NamedTempFile::new().unwrap();
        let path = file.path().to_path_buf();
        let logger = NdLogger::with_file(true, &path)?;
        logger.set_height(1);
        logger.log_timestamp(100, 200);
        logger.flush()?;
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(!content.is_empty());
        Ok(())
    }

    #[test]
    fn test_global_logger() {
        let logger = NdLogger::new();
        init_global(logger);
        assert!(global_logger().is_some());
        // Test macro
        nd_log!(NdSource::Rng, NdSeverity::Critical, "test", "123");
        let events = global_logger().unwrap().events();
        assert_eq!(events.len(), 1);
    }
}
