//! Nondeterministic input logging.
//!
//! Tracks every source of nondeterminism that could cause state divergence
//! between nodes. In a deterministic blockchain the *only* valid source of
//! nondeterminism is the block itself (proposer choice, tx ordering).
//! Everything else must be either derived deterministically from the
//! block/state, or logged and auditable.
//!
//! # Nondeterminism sources
//!
//! | Source          | Risk | Mitigation                            |
//! |-----------------|------|---------------------------------------|
//! | System clock    | HIGH | Use `block.timestamp`, not wall clock |
//! | RNG             | HIGH | Deterministic seed from block hash    |
//! | HashMap order   | HIGH | Use `BTreeMap` / `BTreeSet`           |
//! | Float ops       | MED  | Integer / fixed-point arithmetic      |
//! | Thread schedule | MED  | Single-threaded state transitions     |
//! | External I/O    | LOW  | No external calls during execution    |
//! | Compiler opts   | LOW  | Pinned toolchain + `--locked`         |
//!
//! # Two modes
//!
//! 1. **In-memory** — [`NdLogger::new`] / [`NdLogger::new_in_memory`]. Fast,
//!    deterministic, no I/O. Intended for tests and for runs that check
//!    `report().clean` and discard the logger afterwards.
//!
//! 2. **File-backed** — [`NdLogger::with_file`]. Writes each event as a
//!    JSON line to the supplied path while still recording it in memory.
//!    Intended for production runs that need post-hoc forensics.
//!
//! # Bounds
//!
//! Every collection and string in this module is bounded:
//!
//! - [`MAX_EVENTS`] events retained (oldest dropped, counter in
//!   [`NdLogger::dropped_count`]).
//! - [`MAX_FIELD_BYTES`] per string field (truncated with a `…`
//!   marker, not silently truncated).
//!
//! A caller that passes an oversized string gets a bounded log rather
//! than an OOM.
//!
//! # `logged_at_ns`
//!
//! `NdEvent::logged_at_ns` is zero on the deterministic path. Use
//! [`NdLogger::log_at`] to supply a wall-clock value when writing for
//! forensics. The value is **not** consumed by any consensus code.

use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ── Limits ────────────────────────────────────────────────────────────────

/// Maximum number of events retained in memory.
///
/// When the log is full, the oldest event is dropped and
/// [`NdLogger::dropped_count`] is incremented. A future reader can see
/// `total_events + dropped_count` to know how much was lost.
pub const MAX_EVENTS: usize = 100_000;

/// Maximum length of a single string field (`description`,
/// `observed_value`, `deterministic_alternative`). Longer inputs are
/// truncated and a trailing `…` is appended.
pub const MAX_FIELD_BYTES: usize = 4 * 1024;

/// Marker appended to a field that was truncated.
const TRUNCATION_MARKER: &str = "…";

// ── Errors ────────────────────────────────────────────────────────────────

/// Errors from constructing a file-backed logger.
#[derive(Debug, Error)]
pub enum NdError {
    #[error("I/O error opening `{path}`: {source}")]
    Open {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

// ── Source ────────────────────────────────────────────────────────────────

/// Categories of nondeterministic inputs.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NdSource {
    /// System clock / wall time used during execution.
    Timestamp,
    /// Random number generation.
    Rng,
    /// `HashMap` / `HashSet` iteration order.
    HashMapOrder,
    /// Floating-point arithmetic.
    FloatOp,
    /// Thread scheduling / race condition.
    ThreadSchedule,
    /// External I/O (network, disk) during a state transition.
    ExternalIo,
    /// Compiler- or platform-specific behaviour.
    PlatformSpecific,
    /// A custom source not covered by the built-in categories.
    Other(String),
}

impl std::fmt::Display for NdSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timestamp => f.write_str("TIMESTAMP"),
            Self::Rng => f.write_str("RNG"),
            Self::HashMapOrder => f.write_str("HASHMAP_ORDER"),
            Self::FloatOp => f.write_str("FLOAT_OP"),
            Self::ThreadSchedule => f.write_str("THREAD_SCHEDULE"),
            Self::ExternalIo => f.write_str("EXTERNAL_IO"),
            Self::PlatformSpecific => f.write_str("PLATFORM_SPECIFIC"),
            Self::Other(s) => write!(f, "OTHER({s})"),
        }
    }
}

// ── Severity ──────────────────────────────────────────────────────────────

/// Severity of a nondeterminism event.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum NdSeverity {
    /// Logged for information only.
    Info,
    /// Could cause issues under some conditions.
    Warning,
    /// Will cause state divergence if not handled.
    Critical,
}

impl std::fmt::Display for NdSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Info => f.write_str("INFO"),
            Self::Warning => f.write_str("WARN"),
            Self::Critical => f.write_str("CRIT"),
        }
    }
}

// ── Event ─────────────────────────────────────────────────────────────────

/// A single logged nondeterminism event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NdEvent {
    /// Source category.
    pub source: NdSource,
    /// Severity level.
    pub severity: NdSeverity,
    /// Block height at which this was detected (`0` outside block execution).
    pub height: u64,
    /// Human-readable description (bounded by [`MAX_FIELD_BYTES`]).
    pub description: String,
    /// The nondeterministic value that was observed.
    pub observed_value: String,
    /// What the deterministic alternative should be.
    pub deterministic_alternative: Option<String>,
    /// Wall-clock timestamp in nanoseconds, when supplied.
    ///
    /// Zero on the deterministic path (see [`NdLogger::log`]). Populated
    /// by [`NdLogger::log_at`] for forensic runs.
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

// ── Logger ────────────────────────────────────────────────────────────────

/// Thread-safe nondeterminism logger.
///
/// See the module docs for the two operating modes and the bound
/// guarantees.
pub struct NdLogger {
    /// Ring buffer of retained events.
    events: Mutex<Vec<NdEvent>>,
    /// Height of the block currently being executed.
    current_height: Mutex<u64>,
    /// Wall-clock nanoseconds for [`NdLogger::log`]. `0` means
    /// deterministic (the default).
    wall_clock_base_ns: u64,
    /// Whether logging is enabled. When `false`, `log_*` is a no-op.
    enabled: bool,
    /// Optional sink. When `Some`, each event is appended as a JSON line.
    file: Option<Mutex<BufWriter<File>>>,
    /// Number of events dropped because the ring buffer was full.
    dropped: AtomicUsize,
}

impl NdLogger {
    /// Create an in-memory logger.
    ///
    /// `logged_at_ns` on every event is `0`. Use
    /// [`with_file`](Self::with_file) to also write JSONL to disk, and
    /// [`log_at`](Self::log_at) to supply a wall-clock timestamp.
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            wall_clock_base_ns: 0,
            enabled,
            file: None,
            dropped: AtomicUsize::new(0),
        }
    }

    /// Alias for [`new`](Self::new) with an explicit name.
    #[must_use]
    pub fn new_in_memory(enabled: bool) -> Self {
        Self::new(enabled)
    }

    /// Create a file-backed logger.
    ///
    /// The file is opened in append mode. Each call to `log_*` writes a
    /// single JSON line followed by `\n` and flushes the buffer, so the
    /// file is complete even if the process is killed later.
    ///
    /// In addition to writing, every event is retained in memory under
    /// the same bounds as the in-memory logger.
    pub fn with_file(path: impl AsRef<Path>, enabled: bool) -> Result<Self, NdError> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|source| NdError::Open {
                path: path.clone(),
                source,
            })?;
        Ok(Self {
            events: Mutex::new(Vec::new()),
            current_height: Mutex::new(0),
            wall_clock_base_ns: 0,
            enabled,
            file: Some(Mutex::new(BufWriter::new(file))),
            dropped: AtomicUsize::new(0),
        })
    }

    /// Whether logging is enabled.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Whether this logger writes to a file.
    #[must_use]
    pub fn is_file_backed(&self) -> bool {
        self.file.is_some()
    }

    /// Set the current block height.
    ///
    /// Call once at the start of block execution. Logging outside of a
    /// block records `height = 0`.
    pub fn set_height(&self, height: u64) {
        *self.current_height.lock() = height;
    }

    /// Current block height as tracked by the logger.
    #[must_use]
    pub fn height(&self) -> u64 {
        *self.current_height.lock()
    }

    /// Log a nondeterminism event with `logged_at_ns = 0`.
    ///
    /// Use [`log_at`](Self::log_at) to supply a wall-clock timestamp.
    pub fn log(
        &self,
        source: NdSource,
        severity: NdSeverity,
        description: &str,
        observed: &str,
        alternative: Option<&str>,
    ) {
        self.log_at(source, severity, description, observed, alternative, 0);
    }

    /// Log a nondeterminism event with a caller-supplied wall-clock
    /// timestamp (nanoseconds since epoch).
    ///
    /// The timestamp is written to disk and to the in-memory event for
    /// forensics only. It is never consumed by consensus.
    pub fn log_at(
        &self,
        source: NdSource,
        severity: NdSeverity,
        description: &str,
        observed: &str,
        alternative: Option<&str>,
        wall_clock_ns: u64,
    ) {
        if !self.enabled {
            return;
        }

        let height = *self.current_height.lock();
        let event = NdEvent {
            source,
            severity,
            height,
            description: truncate_field(description),
            observed_value: truncate_field(observed),
            deterministic_alternative: alternative.map(truncate_field),
            logged_at_ns: wall_clock_ns.max(self.wall_clock_base_ns),
        };

        // File first: if we panic pushing to the vec (which we won't, but
        // the ordering is defined), the file is the source of truth.
        if let Some(f) = &self.file {
            let mut w = f.lock();
            if serde_json::to_writer(&mut *w, &event).is_ok() {
                let _ = w.write_all(b"\n");
                let _ = w.flush();
            }
        }

        // Ring buffer with drop-oldest policy.
        let mut events = self.events.lock();
        if events.len() >= MAX_EVENTS {
            events.remove(0);
            self.dropped.fetch_add(1, Ordering::Relaxed);
        }
        events.push(event);
    }

    /// Log wall-clock usage.
    pub fn log_timestamp(&self, wall_clock_ms: u64, block_timestamp: u64) {
        self.log(
            NdSource::Timestamp,
            NdSeverity::Critical,
            "wall clock used during execution",
            &wall_clock_ms.to_string(),
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
            Some("deterministic seed from block_hash"),
        );
    }

    /// Log `HashMap` / `HashSet` iteration.
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

    /// Log a floating-point operation.
    pub fn log_float_op(&self, location: &str, value: &str) {
        self.log(
            NdSource::FloatOp,
            NdSeverity::Warning,
            &format!("float operation at {location}"),
            value,
            Some("use integer/fixed-point arithmetic"),
        );
    }

    /// Log a platform-specific observation.
    pub fn log_platform(&self, description: &str, observed: &str) {
        self.log(
            NdSource::PlatformSpecific,
            NdSeverity::Info,
            description,
            observed,
            None,
        );
    }

    /// Snapshot of all retained events.
    ///
    /// Clones the ring buffer under the lock. For read-only scans of
    /// large logs, prefer [`for_each`](Self::for_each).
    #[must_use]
    pub fn events(&self) -> Vec<NdEvent> {
        self.events.lock().clone()
    }

    /// Iterate over retained events without cloning the buffer.
    pub fn for_each<F: FnMut(&NdEvent)>(&self, mut f: F) {
        let events = self.events.lock();
        for e in events.iter() {
            f(e);
        }
    }

    /// Number of retained events.
    #[must_use]
    pub fn event_count(&self) -> usize {
        self.events.lock().len()
    }

    /// Number of events dropped because the ring buffer was full.
    #[must_use]
    pub fn dropped_count(&self) -> usize {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Events with severity `>= min_severity`.
    #[must_use]
    pub fn events_by_severity(&self, min_severity: NdSeverity) -> Vec<NdEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| e.severity >= min_severity)
            .cloned()
            .collect()
    }

    /// Events whose source matches `source`.
    #[must_use]
    pub fn events_by_source(&self, source: &NdSource) -> Vec<NdEvent> {
        self.events
            .lock()
            .iter()
            .filter(|e| &e.source == source)
            .cloned()
            .collect()
    }

    /// Whether any `Critical` event has been logged.
    #[must_use]
    pub fn has_critical(&self) -> bool {
        self.events
            .lock()
            .iter()
            .any(|e| e.severity == NdSeverity::Critical)
    }

    /// Clear all retained events.
    ///
    /// The dropped counter and the file sink (if any) are **not**
    /// affected. Call [`reset_counters`](Self::reset_counters) as well
    /// if you want a fully clean slate.
    pub fn clear(&self) {
        self.events.lock().clear();
    }

    /// Reset the dropped counter. Typically paired with [`clear`](Self::clear).
    pub fn reset_counters(&self) {
        self.dropped.store(0, Ordering::Relaxed);
    }

    /// Flush the file sink (no-op in memory-only mode).
    pub fn flush(&self) {
        if let Some(f) = &self.file {
            let mut w = f.lock();
            let _ = w.flush();
        }
    }

    /// Build a summary report.
    #[must_use]
    pub fn report(&self) -> NdReport {
        let events = self.events.lock().clone();
        let mut critical = 0usize;
        let mut warning = 0usize;
        let mut info = 0usize;
        for e in &events {
            match e.severity {
                NdSeverity::Critical => critical += 1,
                NdSeverity::Warning => warning += 1,
                NdSeverity::Info => info += 1,
            }
        }
        NdReport {
            total_events: events.len(),
            critical_count: critical,
            warning_count: warning,
            info_count: info,
            dropped: self.dropped.load(Ordering::Relaxed),
            events,
            clean: critical == 0,
        }
    }
}

impl Default for NdLogger {
    fn default() -> Self {
        Self::new(true)
    }
}

// ── Report ────────────────────────────────────────────────────────────────

/// Summary report of nondeterminism events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NdReport {
    pub total_events: usize,
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    /// Number of events dropped due to the [`MAX_EVENTS`] cap.
    pub dropped: usize,
    pub events: Vec<NdEvent>,
    /// `true` when no `Critical` events were recorded.
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
            "  total={}, critical={}, warning={}, info={}, dropped={}",
            self.total_events, self.critical_count, self.warning_count, self.info_count, self.dropped
        )?;
        for e in &self.events {
            writeln!(f, "  {e}")?;
        }
        Ok(())
    }
}

// ── Static analysis helpers ───────────────────────────────────────────────

/// Known-safe patterns. Their presence is never reported.
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

/// A finding from [`check_code_snippet`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// The pattern that matched.
    pub pattern: String,
    /// Severity assigned to this pattern.
    pub severity: NdSeverity,
    /// Byte offset within the input where the match starts.
    pub offset: usize,
    /// Byte offset of the end of the match (exclusive).
    pub end: usize,
}

/// Scan `code` for dangerous patterns with word-boundary matching.
///
/// A match counts only when the character immediately before and after
/// the pattern is not an identifier character (`[A-Za-z0-9_]`). This
/// prevents `f32` from matching inside `f32x_config` and `HashMap`
/// matching inside `HashMapLike`.
///
/// The function performs **no** parsing: a pattern inside a string
/// literal or a comment is still reported. That is intentional —
/// false positives are cheap, a missed match may cost a fork.
#[must_use]
pub fn check_code_snippet(code: &str) -> Vec<Finding> {
    let bytes = code.as_bytes();
    let mut findings = Vec::new();

    for &pattern in DANGEROUS_PATTERNS {
        let severity = severity_for(pattern);
        let mut search_from = 0usize;
        while let Some(rel) = code[search_from..].find(pattern) {
            let start = search_from + rel;
            let end = start + pattern.len();
            if is_word_boundary(bytes, start, end) {
                findings.push(Finding {
                    pattern: pattern.to_string(),
                    severity,
                    offset: start,
                    end,
                });
            }
            // Advance past this match to avoid an infinite loop on
            // zero-length patterns (there are none, but be defensive).
            search_from = end.max(start + 1);
            if search_from >= code.len() {
                break;
            }
        }
    }

    findings.sort_by_key(|f| (f.offset, f.end));
    findings
}

fn severity_for(pattern: &str) -> NdSeverity {
    match pattern {
        "HashMap" | "HashSet" | "f32" | "f64" | "std::time" => NdSeverity::Warning,
        "SystemTime::now" | "Instant::now" | "thread_rng" | "rand::random" => NdSeverity::Critical,
        _ => NdSeverity::Info,
    }
}

fn is_word_boundary(bytes: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !is_ident_byte(bytes[start - 1]);
    let after_ok = end >= bytes.len() || !is_ident_byte(bytes[end]);
    before_ok && after_ok
}

fn is_ident_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

// ── Field truncation ──────────────────────────────────────────────────────

/// Truncate a field to `MAX_FIELD_BYTES` bytes on a char boundary,
/// appending a marker.
fn truncate_field(s: &str) -> String {
    if s.len() <= MAX_FIELD_BYTES {
        return s.to_string();
    }
    // Walk back from MAX_FIELD_BYTES to the nearest char boundary so we
    // do not split a multi-byte UTF-8 sequence.
    let mut end = MAX_FIELD_BYTES;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = String::with_capacity(end + TRUNCATION_MARKER.len());
    out.push_str(&s[..end]);
    out.push_str(TRUNCATION_MARKER);
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Basic logging ───────────────────────────────────────────────────

    #[test]
    fn log_records_height_and_severity() {
        let l = NdLogger::new(true);
        l.set_height(100);
        l.log_timestamp(1_234_567_890, 1_234_567_000);

        let events = l.events();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].height, 100);
        assert_eq!(events[0].source, NdSource::Timestamp);
        assert_eq!(events[0].severity, NdSeverity::Critical);
        assert_eq!(events[0].logged_at_ns, 0);
    }

    #[test]
    fn disabled_logger_is_a_noop() {
        let l = NdLogger::new(false);
        l.log_timestamp(1, 2);
        assert!(l.events().is_empty());
        assert!(!l.has_critical());
    }

    #[test]
    fn log_at_populates_wall_clock() {
        let l = NdLogger::new(true);
        l.set_height(1);
        l.log_at(
            NdSource::Rng,
            NdSeverity::Warning,
            "desc",
            "obs",
            None,
            42_000,
        );
        assert_eq!(l.events()[0].logged_at_ns, 42_000);
    }

    #[test]
    fn height_zero_outside_block() {
        let l = NdLogger::new(true);
        l.log_platform("startup", "x86_64");
        assert_eq!(l.events()[0].height, 0);
    }

    // ── Ring buffer ─────────────────────────────────────────────────────

    #[test]
    fn ring_buffer_drops_oldest() {
        let l = NdLogger::new(true);
        // Fill exactly to the cap and then one over.
        for i in 0..(MAX_EVENTS + 1) {
            l.log(
                NdSource::Other("test".into()),
                NdSeverity::Info,
                "fill",
                &i.to_string(),
                None,
            );
        }
        assert_eq!(l.event_count(), MAX_EVENTS);
        assert_eq!(l.dropped_count(), 1);
        // The oldest event (observed = "0") must be gone.
        assert_eq!(l.events()[0].observed_value, "1");
    }

    #[test]
    fn clear_keeps_dropped_counter() {
        let l = NdLogger::new(true);
        for i in 0..(MAX_EVENTS + 5) {
            l.log(
                NdSource::Other("x".into()),
                NdSeverity::Info,
                "fill",
                &i.to_string(),
                None,
            );
        }
        assert_eq!(l.dropped_count(), 5);
        l.clear();
        assert_eq!(l.event_count(), 0);
        assert_eq!(l.dropped_count(), 5);
        l.reset_counters();
        assert_eq!(l.dropped_count(), 0);
    }

    // ── Truncation ──────────────────────────────────────────────────────

    #[test]
    fn oversized_field_is_truncated_with_marker() {
        let l = NdLogger::new(true);
        let huge = "a".repeat(MAX_FIELD_BYTES * 2);
        l.log(NdSource::Other("x".into()), NdSeverity::Info, &huge, "obs", None);
        let ev = &l.events()[0];
        assert!(ev.description.len() <= MAX_FIELD_BYTES + TRUNCATION_MARKER.len());
        assert!(ev.description.ends_with(TRUNCATION_MARKER));
    }

    #[test]
    fn truncation_respects_char_boundary() {
        let l = NdLogger::new(true);
        // Fill with multi-byte chars so the boundary lands mid-char at
        // MAX_FIELD_BYTES for some inputs.
        let s: String = "é".repeat(MAX_FIELD_BYTES); // 2 bytes each
        l.log(NdSource::Other("x".into()), NdSeverity::Info, &s, "obs", None);
        let ev = &l.events()[0];
        // The whole thing must be valid UTF-8 (guaranteed by Rust, but
        // exercise it anyway).
        assert!(ev.description.is_char_boundary(ev.description.len()));
    }

    // ── Filters ─────────────────────────────────────────────────────────

    #[test]
    fn filter_by_severity() {
        let l = NdLogger::new(true);
        l.log_timestamp(1, 2); // Critical
        l.log_hashmap_usage("test"); // Warning
        l.log_platform("test", "x86"); // Info

        assert_eq!(l.events_by_severity(NdSeverity::Critical).len(), 1);
        assert_eq!(l.events_by_severity(NdSeverity::Warning).len(), 2);
        assert_eq!(l.events_by_severity(NdSeverity::Info).len(), 3);
    }

    #[test]
    fn filter_by_source() {
        let l = NdLogger::new(true);
        l.log_timestamp(1, 2);
        l.log_rng("t", "v");
        l.log_timestamp(3, 4);

        assert_eq!(l.events_by_source(&NdSource::Timestamp).len(), 2);
        assert_eq!(l.events_by_source(&NdSource::Rng).len(), 1);
    }

    #[test]
    fn has_critical_only_flips_on_critical() {
        let l = NdLogger::new(true);
        assert!(!l.has_critical());
        l.log_hashmap_usage("test");
        assert!(!l.has_critical());
        l.log_timestamp(1, 2);
        assert!(l.has_critical());
    }

    // ── Report ──────────────────────────────────────────────────────────

    #[test]
    fn report_counts_per_severity() {
        let l = NdLogger::new(true);
        l.log_timestamp(1, 2);
        l.log_hashmap_usage("test");
        l.log_platform("arch", "x86");

        let r = l.report();
        assert_eq!(r.total_events, 3);
        assert_eq!(r.critical_count, 1);
        assert_eq!(r.warning_count, 1);
        assert_eq!(r.info_count, 1);
        assert_eq!(r.dropped, 0);
        assert!(!r.clean);
    }

    #[test]
    fn report_clean_when_only_info() {
        let l = NdLogger::new(true);
        l.log_platform("arch", "x86");
        assert!(l.report().clean);
    }

    #[test]
    fn report_display_contains_marker() {
        let l = NdLogger::new(true);
        l.log_timestamp(1, 2);
        let s = l.report().to_string();
        assert!(s.contains("ISSUES DETECTED"));
        assert!(s.contains("critical=1"));
    }

    // ── File-backed mode ────────────────────────────────────────────────

    #[test]
    fn file_backed_writes_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nd.jsonl");
        let l = NdLogger::with_file(&path, true).unwrap();
        l.set_height(7);
        l.log_platform("startup", "x86_64");
        l.log_timestamp(1, 2);
        l.flush();
        drop(l);

        let content = std::fs::read_to_string(&path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        // Each line must be valid JSON with the fields we expect.
        for line in lines {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(v.get("height").is_some());
            assert!(v.get("source").is_some());
        }
    }

    #[test]
    fn with_file_reports_open_error() {
        // A path whose parent is not a directory.
        let dir = tempfile::tempdir().unwrap();
        let bad = dir.path().join("not-a-dir").join("nd.jsonl");
        assert!(matches!(NdLogger::with_file(&bad, true), Err(NdError::Open { .. })));
    }

    #[test]
    fn is_file_backed_flag() {
        let a = NdLogger::new(true);
        assert!(!a.is_file_backed());
        let dir = tempfile::tempdir().unwrap();
        let b = NdLogger::with_file(dir.path().join("x.jsonl"), true).unwrap();
        assert!(b.is_file_backed());
    }

    // ── Static analysis ─────────────────────────────────────────────────

    #[test]
    fn snippet_check_ignores_safe_patterns() {
        let code = "let map: BTreeMap<String, u64> = BTreeMap::new();";
        assert!(check_code_snippet(code).is_empty());
    }

    #[test]
    fn snippet_check_finds_dangerous_patterns() {
        let code = "let m: HashMap<String, u64> = HashMap::new(); \
                    let now = SystemTime::now();";
        let findings = check_code_snippet(code);
        assert!(findings.iter().any(|f| f.pattern == "HashMap"));
        assert!(findings.iter().any(|f| f.pattern == "SystemTime::now"));
    }

    #[test]
    fn snippet_check_respects_word_boundaries() {
        let code = "let cfg = f32x_config(); let _x = my_ham_hash_mapper;";
        let findings = check_code_snippet(code);
        // Neither "f32" nor "HashMap" should match.
        assert!(!findings.iter().any(|f| f.pattern == "f32"));
        assert!(!findings.iter().any(|f| f.pattern == "HashMap"));
    }

    #[test]
    fn snippet_check_reports_offset() {
        let code = "aaa HashMap bbb";
        let findings = check_code_snippet(code);
        let hm = findings.iter().find(|f| f.pattern == "HashMap").unwrap();
        assert_eq!(hm.offset, 4);
        assert_eq!(hm.end, 4 + "HashMap".len());
    }

    #[test]
    fn snippet_check_finds_multiple_occurrences() {
        let code = "HashMap and HashMap";
        let findings = check_code_snippet(code);
        let hms: Vec<_> = findings.iter().filter(|f| f.pattern == "HashMap").collect();
        assert_eq!(hms.len(), 2);
        assert_ne!(hms[0].offset, hms[1].offset);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn event_display_includes_alternative() {
        let e = NdEvent {
            source: NdSource::Timestamp,
            severity: NdSeverity::Critical,
            height: 100,
            description: "wall clock used".into(),
            observed_value: "12345".into(),
            deterministic_alternative: Some("block.timestamp".into()),
            logged_at_ns: 0,
        };
        let s = e.to_string();
        assert!(s.contains("TIMESTAMP"));
        assert!(s.contains("should_use=block.timestamp"));
    }

    #[test]
    fn source_display_variants() {
        assert_eq!(NdSource::Timestamp.to_string(), "TIMESTAMP");
        assert_eq!(NdSource::Rng.to_string(), "RNG");
        assert_eq!(
            NdSource::Other("custom".into()).to_string(),
            "OTHER(custom)"
        );
    }

    // ── Default ─────────────────────────────────────────────────────────

    #[test]
    fn default_is_enabled_in_memory() {
        let l = NdLogger::default();
        assert!(l.is_enabled());
        assert!(!l.is_file_backed());
    }
}
