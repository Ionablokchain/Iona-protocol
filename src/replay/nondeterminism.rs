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

use std::sync::Mutex;

/// Categories of nondeterministic inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NdSource {
    /// System clock / wall time used during execution.
    Timestamp,
    /// Random number generation.
    Rng,
    /// HashMap or HashSet iteration order.
    HashMapOrder,
    /// Floating-point arithmetic.
    FloatOp,
    /// Thread scheduling / race condition.
    ThreadSchedule,
    /// External I/O (network, disk) during state transition.
    ExternalIo,
    /// Compiler or platform-specific behaviour.
    PlatformSpecific,
    /// Other / custom source.
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum NdSeverity {
    /// Informational: logged but not dangerous.
    Info,
    /// Warning: could cause issues under certain conditions.
    Warning,
    /// Critical: will cause state divergence if not handled.
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
#[derive(Debug, Clone)]
pub struct NdEvent {
    /// Source category.
    pub source: NdSource,
    /// Severity level.
    pub severity: NdSeverity,
    /// Block height at which this was detected (0 if outside block execution).
    pub height: u64,
    /// Human-readable description.
    pub description: String,
    /// The nondeterministic value that was observed.
    pub observed_value: String,
    /// What the deterministic alternative should be.
    pub deterministic_alternative: Option<String>,
    /// Timestamp when the event was logged (wall clock, for audit only).
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

/// Thread-safe nondeterminism logger.
///
/// Collects all nondeterminism events during block execution for later
/// audit and analysis.
pub struct NdLogger {
    events: Mutex<Vec<NdEvent>>,
    /// Current block height being executed.
    current_height: Mutex<u64>,
    /// Whether logging is enabled.
    enabled: bool,
}

impl NdLogger {
    /// Create a new logger.
    pub fn new(enabled: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            enabled,
        }
    }

    /// Set the current block height (called at start of block execution).
    pub fn set_height(&self, height: u64) {
        if let Ok(mut h) = self.current_height.lock() {
            *h = height;
        }
    }

    /// Log a nondeterminism event.
    pub fn log(
        &self,
        source: NdSource,
        severity: NdSeverity,
        description: &str,
        observed: &str,
        alternative: Option<&str>,
    ) {
        if !self.enabled {
            return;
        }

        let height = self.current_height.lock().map(|h| *h).unwrap_or(0);
        let event = NdEvent {
            source,
            severity,
            height,
            description: description.to_string(),
            observed_value: observed.to_string(),
            deterministic_alternative: alternative.map(|s| s.to_string()),
            logged_at_ns: 0, // Wall clock intentionally zeroed for determinism.
        };

        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }

    /// Log a timestamp usage.
    pub fn log_timestamp(&self, wall_clock_ms: u64, block_timestamp: u64) {
        self.log(
            NdSource::Timestamp,
            NdSeverity::Critical,
            "wall clock used during execution",
            &format!("{wall_clock_ms}"),
            Some(&format!("block.timestamp={block_timestamp}")),
        );
    }

    /// Log RNG usage.
    pub fn log_rng(&self, seed_source: &str, value: &str) {
        self.log(
            NdSource::Rng,
            NdSeverity::Critical,
            &format!("RNG used with seed source: {seed_source}"),
            value,
            Some("use deterministic seed from block_hash"),
        );
    }

    /// Log HashMap iteration.
    pub fn log_hashmap_usage(&self, location: &str) {
        self.log(
            NdSource::HashMapOrder,
            NdSeverity::Warning,
            &format!("HashMap/HashSet used at {location}"),
            "unordered iteration",
            Some("use BTreeMap/BTreeSet"),
        );
    }

    /// Log external I/O during execution.
    pub fn log_external_io(&self, description: &str) {
        self.log(
            NdSource::ExternalIo,
            NdSeverity::Critical,
            description,
            "external call",
            Some("remove external I/O from state transition"),
        );
    }

    /// Log floating-point operation.
    pub fn log_float_op(&self, location: &str, value: &str) {
        self.log(
            NdSource::FloatOp,
            NdSeverity::Warning,
            &format!("float operation at {location}"),
            value,
            Some("use integer/fixed-point arithmetic"),
        );
    }

    /// Log platform-specific behaviour.
    pub fn log_platform(&self, description: &str, observed: &str) {
        self.log(
            NdSource::PlatformSpecific,
            NdSeverity::Info,
            description,
            observed,
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

    /// Clear all events.
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

/// Summary report of nondeterminism events.
#[derive(Debug, Clone)]
pub struct NdReport {
    pub total_events: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub events: Vec<NdEvent>,
    /// True if no critical events were detected.
    pub clean: bool,
}

impl std::fmt::Display for NdReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Nondeterminism Report: {}",
            if self.clean {
                "CLEAN"
            } else {
                "ISSUES DETECTED"
            }
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

// ─── Static analysis helpers ────────────────────────────────────────────────

/// Known-safe patterns that don't introduce nondeterminism.
pub const SAFE_PATTERNS: &[&str] = &[
    "BTreeMap",
    "BTreeSet",
    "Vec::sort",
    "deterministic_seed",
    "block.timestamp",
    "block.hash",
];

/// Known-dangerous patterns.
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

/// Check a code snippet for dangerous patterns (simple static analysis).
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

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_logger_rng() {
        let logger = NdLogger::new(true);
        logger.set_height(50);
        logger.log_rng("thread_rng", "0xdeadbeef");

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, NdSource::Rng);
    }

    #[test]
    fn test_logger_hashmap() {
        let logger = NdLogger::new(true);
        logger.log_hashmap_usage("tx_pool.rs:42");

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, NdSource::HashMapOrder);
        assert_eq!(events[0].severity, NdSeverity::Warning);
    }

    #[test]
    fn test_logger_external_io() {
        let logger = NdLogger::new(true);
        logger.log_external_io("HTTP call to price oracle");

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, NdSource::ExternalIo);
        assert_eq!(events[0].severity, NdSeverity::Critical);
    }

    #[test]
    fn test_logger_float_op() {
        let logger = NdLogger::new(true);
        logger.log_float_op("reward_calc.rs:10", "0.1 + 0.2 = 0.30000000000000004");

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].source, NdSource::FloatOp);
    }

    #[test]
    fn test_logger_platform() {
        let logger = NdLogger::new(true);
        logger.log_platform("endianness check", "little-endian");

        let events = logger.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].severity, NdSeverity::Info);
    }

    #[test]
    fn test_filter_by_severity() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2); // Critical
        logger.log_hashmap_usage("test"); // Warning
        logger.log_platform("test", "x86"); // Info

        let critical = logger.events_by_severity(NdSeverity::Critical);
        assert_eq!(critical.len(), 1);

        let warnings = logger.events_by_severity(NdSeverity::Warning);
        assert_eq!(warnings.len(), 2); // Warning + Critical
    }

    #[test]
    fn test_filter_by_source() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        logger.log_rng("test", "val");
        logger.log_timestamp(3, 4);

        let ts = logger.events_by_source(&NdSource::Timestamp);
        assert_eq!(ts.len(), 2);
    }

    #[test]
    fn test_has_critical() {
        let logger = NdLogger::new(true);
        assert!(!logger.has_critical());

        logger.log_hashmap_usage("test"); // Warning, not critical.
        assert!(!logger.has_critical());

        logger.log_timestamp(1, 2); // Critical.
        assert!(logger.has_critical());
    }

    #[test]
    fn test_clear() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        assert_eq!(logger.events().len(), 1);
        logger.clear();
        assert!(logger.events().is_empty());
    }

    #[test]
    fn test_report() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        logger.log_hashmap_usage("test");
        logger.log_platform("arch", "x86");

        let report = logger.report();
        assert_eq!(report.total_events, 3);
        assert_eq!(report.critical_count, 1);
        assert_eq!(report.warning_count, 1);
        assert_eq!(report.info_count, 1);
        assert!(!report.clean);
    }

    #[test]
    fn test_report_clean() {
        let logger = NdLogger::new(true);
        logger.log_platform("arch", "x86"); // Only info.

        let report = logger.report();
        assert!(report.clean);
    }

    #[test]
    fn test_report_display() {
        let logger = NdLogger::new(true);
        logger.log_timestamp(1, 2);
        let report = logger.report();
        let s = format!("{report}");
        assert!(s.contains("Nondeterminism Report"));
        assert!(s.contains("ISSUES DETECTED"));
    }

    #[test]
    fn test_event_display() {
        let event = NdEvent {
            source: NdSource::Timestamp,
            severity: NdSeverity::Critical,
            height: 100,
            description: "wall clock used".into(),
            observed_value: "12345".into(),
            deterministic_alternative: Some("block.timestamp".into()),
            logged_at_ns: 0,
        };
        let s = format!("{event}");
        assert!(s.contains("TIMESTAMP"));
        assert!(s.contains("should_use=block.timestamp"));
    }

    #[test]
    fn test_nd_source_display() {
        assert_eq!(format!("{}", NdSource::Timestamp), "TIMESTAMP");
        assert_eq!(format!("{}", NdSource::Rng), "RNG");
        assert_eq!(
            format!("{}", NdSource::Other("custom".into())),
            "OTHER(custom)"
        );
    }

    #[test]
    fn test_check_code_snippet_safe() {
        let code = "let map: BTreeMap<String, u64> = BTreeMap::new();";
        let findings = check_code_snippet(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_check_code_snippet_dangerous() {
        let code = "let map: HashMap<String, u64> = HashMap::new(); let now = SystemTime::now();";
        let findings = check_code_snippet(code);
        assert!(findings.len() >= 2);
        assert!(findings.iter().any(|(p, _)| p == "HashMap"));
        assert!(findings.iter().any(|(p, _)| p == "SystemTime::now"));
    }

    #[test]
    fn test_multiple_heights() {
        let logger = NdLogger::new(true);

        logger.set_height(10);
        logger.log_timestamp(1, 2);

        logger.set_height(20);
        logger.log_rng("test", "val");

        let events = logger.events();
        assert_eq!(events[0].height, 10);
        assert_eq!(events[1].height, 20);
    }
}
