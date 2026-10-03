//! SchemaVersion monotonicity enforcement — Quantum Migration Safety.
//!
//! # Quantum Monotonicity Model
//!
//! Schema version evolution is modelled as a **quantum walk** on a
//! one‑dimensional lattice where each node represents a schema version.
//! The monotonicity rules (SM‑1 … SM‑5) are **projectors** that constrain
//! the walk to the forward direction only.
//!
//! # Rules
//!
//! | ID   | Name                      | Quantum Interpretation                    |
//! |------|---------------------------|-------------------------------------------|
//! | SM-1 | Strictly increasing       | Π_forward = θ(v_new - v_old)              |
//! | SM-2 | No gaps                   | Path integral over contiguous steps       |
//! | SM-3 | Binary >= disk            | Energy ordering E_bin ≥ E_disk            |
//! | SM-4 | Checkpoint after step     | Projective measurement at each step       |
//! | SM-5 | Idempotent re‑run         | Π_idem = |current⟩⟨current|                |
//!
//! # Production Features
//! - Overflow-safe counters using `saturating_add`.
//! - Atomic checkpoint writes: temp + fsync + rename + parent-dir fsync.
//! - `Result`-based API for all operations.
//! - Prometheus metrics (optional) with atomic fallback.
//! - Full test coverage.
//!
//! # Example
//!
//! ```
//! use iona::storage::schema_monotonicity::{
//!     check_monotonicity, validate_migration_step, MonotonicityReport
//! };
//!
//! let report = check_monotonicity(current_sv, target_sv, Some(data_dir));
//! if !report.all_passed {
//!     eprintln!("{}", report);
//!     std::process::exit(1);
//! }
//!
//! validate_migration_step(from_sv, to_sv)?;
//! ```

use crate::storage::{SchemaMeta, CURRENT_SCHEMA_VERSION};
use prometheus::{register_counter, register_gauge, Counter, Gauge};
use serde::Serialize;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for monotonicity checks.
const DEFAULT_MONO_COHERENCE: f64 = 1.0;

/// Decoherence rate per check operation.
const CHECK_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per validation failure (stronger).
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum coherence threshold for valid state.
const MIN_MONO_COHERENCE: f64 = 0.99;

/// Kraus rank for monotonicity quantum channels.
const MONO_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors produced by monotonicity checks.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum MonotonicityError {
    #[error("SM-1 VIOLATION: schema version not strictly increasing: old={old}, new={new}")]
    NotIncreasing { old: u32, new: u32 },

    #[error("SM-2 VIOLATION: no migration found for SV {from} -> {to}")]
    Gap { from: u32, to: u32 },

    #[error("SM-3 VIOLATION: on-disk SV={disk} newer than binary SV={binary}; upgrade required")]
    BinaryTooOld { disk: u32, binary: u32 },

    #[error("SM-4 VIOLATION: schema.json missing at {path}")]
    CheckpointMissing { path: String },

    #[error("SM-4 VIOLATION: schema.json version={actual}, expected={expected}")]
    CheckpointMismatch { actual: u32, expected: u32 },

    #[error("SM-4 ERROR: cannot read/parse {path}: {reason}")]
    CheckpointReadError { path: String, reason: String },

    #[error("SM-5 VIOLATION: cannot downgrade from SV={current} to SV={target}")]
    Downgrade { current: u32, target: u32 },

    #[error("SM-2 VIOLATION: migration step must be +1: {from} -> {to}")]
    NotUnitStep { from: u32, to: u32 },
}

pub type MonotonicityResult<T> = Result<T, MonotonicityError>;

// -----------------------------------------------------------------------------
// Prometheus metrics
// -----------------------------------------------------------------------------

/// Prometheus counters/gauges for monotonicity checks.
#[derive(Clone)]
pub struct MonotonicityPrometheus {
    pub checks_total: Counter,
    pub passes_total: Counter,
    pub failures_total: Counter,
    pub current_sv: Gauge,
    pub target_sv: Gauge,
    pub purity: Gauge,
}

impl MonotonicityPrometheus {
    /// Register metrics with the global Prometheus registry.
    pub fn new() -> Result<Self, prometheus::Error> {
        Ok(Self {
            checks_total: register_counter!(
                "iona_schema_mono_checks_total",
                "Total monotonicity checks performed"
            )?,
            passes_total: register_counter!(
                "iona_schema_mono_passes_total",
                "Total monotonicity checks passed"
            )?,
            failures_total: register_counter!(
                "iona_schema_mono_failures_total",
                "Total monotonicity checks failed"
            )?,
            current_sv: register_gauge!(
                "iona_schema_mono_current_sv",
                "Current schema version being validated"
            )?,
            target_sv: register_gauge!(
                "iona_schema_mono_target_sv",
                "Target schema version being validated"
            )?,
            purity: register_gauge!(
                "iona_schema_mono_purity",
                "Quantum purity of the monotonicity state"
            )?,
        })
    }

    /// Create an unregistered instance (for tests or disabled metrics).
    pub fn new_unregistered() -> Self {
        Self {
            checks_total: Counter::new("iona_schema_mono_checks_total", "Checks").unwrap(),
            passes_total: Counter::new("iona_schema_mono_passes_total", "Passes").unwrap(),
            failures_total: Counter::new("iona_schema_mono_failures_total", "Failures").unwrap(),
            current_sv: Gauge::new("iona_schema_mono_current_sv", "Current").unwrap(),
            target_sv: Gauge::new("iona_schema_mono_target_sv", "Target").unwrap(),
            purity: Gauge::new("iona_schema_mono_purity", "Purity").unwrap(),
        }
    }
}

/// Metrics for monotonicity state.
#[derive(Debug, Clone)]
pub struct MonotonicityMetrics {
    pub checks: Arc<AtomicU64>,
    pub passes: Arc<AtomicU64>,
    pub failures: Arc<AtomicU64>,
    pub prometheus: Option<Arc<MonotonicityPrometheus>>,
}

impl Default for MonotonicityMetrics {
    fn default() -> Self {
        Self {
            checks: Arc::new(AtomicU64::new(0)),
            passes: Arc::new(AtomicU64::new(0)),
            failures: Arc::new(AtomicU64::new(0)),
            prometheus: None,
        }
    }
}

impl MonotonicityMetrics {
    pub fn new(enable_prometheus: bool) -> Result<Self, prometheus::Error> {
        let prometheus = if enable_prometheus {
            Some(Arc::new(MonotonicityPrometheus::new()?))
        } else {
            None
        };
        Ok(Self {
            prometheus,
            ..Default::default()
        })
    }

    fn record_check(&self) {
        self.checks.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.checks_total.inc();
        }
    }
    fn record_pass(&self) {
        self.passes.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.passes_total.inc();
        }
    }
    fn record_failure(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
        if let Some(p) = &self.prometheus {
            p.failures_total.inc();
        }
    }
    fn update_version_gauges(&self, current: u32, target: u32) {
        if let Some(p) = &self.prometheus {
            p.current_sv.set(current as f64);
            p.target_sv.set(target as f64);
        }
    }
    fn update_purity(&self, purity: f64) {
        if let Some(p) = &self.prometheus {
            p.purity.set(purity);
        }
    }
}

/// Snapshot of monotonicity metrics.
#[derive(Debug, Clone, Copy, Default)]
pub struct MonotonicityMetricsSnapshot {
    pub checks: u64,
    pub passes: u64,
    pub failures: u64,
}

impl MonotonicityMetrics {
    pub fn snapshot(&self) -> MonotonicityMetricsSnapshot {
        MonotonicityMetricsSnapshot {
            checks: self.checks.load(Ordering::Relaxed),
            passes: self.passes.load(Ordering::Relaxed),
            failures: self.failures.load(Ordering::Relaxed),
        }
    }
}

// -----------------------------------------------------------------------------
// Quantum Monotonicity State
// -----------------------------------------------------------------------------

/// Quantum state of the schema monotonicity system.
#[derive(Debug, Clone)]
pub struct QuantumMonotonicityState {
    pub purity: f64,
    pub entropy: f64,
    pub path_coherence: f64,
    pub total_checks: u64,
    pub checks_passed: u64,
    pub checks_failed: u64,
    pub current_version: u32,
    pub target_version: u32,
    pub is_valid: bool,
}

impl Default for QuantumMonotonicityState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_MONO_COHERENCE,
            entropy: 0.0,
            path_coherence: DEFAULT_MONO_COHERENCE,
            total_checks: 0,
            checks_passed: 0,
            checks_failed: 0,
            current_version: 0,
            target_version: 0,
            is_valid: true,
        }
    }
}

impl QuantumMonotonicityState {
    pub fn new(current_sv: u32, target_sv: u32) -> Self {
        Self {
            current_version: current_sv,
            target_version: target_sv,
            ..Default::default()
        }
    }

    pub fn record_pass(&mut self) {
        self.total_checks = self.total_checks.saturating_add(1);
        self.checks_passed = self.checks_passed.saturating_add(1);
        let decay = (-CHECK_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn record_failure(&mut self) {
        self.total_checks = self.total_checks.saturating_add(1);
        self.checks_failed = self.checks_failed.saturating_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    pub fn apply_mono_channel(&mut self) {
        let kraus_factor = (1.0 / MONO_KRAUS_RANK as f64).sqrt();
        self.path_coherence = (self.path_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.path_coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_MONO_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// SM-1: Strictly increasing
// -----------------------------------------------------------------------------

/// Verify that a proposed schema version bump is strictly increasing.
pub fn check_strictly_increasing(old_sv: u32, new_sv: u32) -> MonotonicityResult<()> {
    if new_sv <= old_sv {
        return Err(MonotonicityError::NotIncreasing {
            old: old_sv,
            new: new_sv,
        });
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_strictly_increasing_quantum(
    old_sv: u32,
    new_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> MonotonicityResult<()> {
    let result = check_strictly_increasing(old_sv, new_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

// -----------------------------------------------------------------------------
// SM-2: No gaps
// -----------------------------------------------------------------------------

/// Legacy maximum version handled by older code (v0 → v1, v1 → v2, v2 → v3).
const LEGACY_MAX_SV: u32 = 3;

/// Verify that the migration registry has no gaps between `from_sv` and `to_sv`.
pub fn check_no_gaps(from_sv: u32, to_sv: u32) -> MonotonicityResult<()> {
    if from_sv >= to_sv {
        return Ok(());
    }

    let migrations = &crate::storage::migrations::MIGRATIONS;

    for sv in from_sv..to_sv {
        if sv < LEGACY_MAX_SV {
            continue;
        }
        let has_migration = migrations.iter().any(|entry| entry.from_version == sv);
        if !has_migration {
            return Err(MonotonicityError::Gap {
                from: sv,
                to: sv.saturating_add(1),
            });
        }
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_no_gaps_quantum(
    from_sv: u32,
    to_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> MonotonicityResult<()> {
    let result = check_no_gaps(from_sv, to_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

// -----------------------------------------------------------------------------
// SM-3: Binary >= disk
// -----------------------------------------------------------------------------

/// Verify that this binary supports the on‑disk schema version.
pub fn check_binary_compat(disk_sv: u32) -> MonotonicityResult<()> {
    if disk_sv > CURRENT_SCHEMA_VERSION {
        return Err(MonotonicityError::BinaryTooOld {
            disk: disk_sv,
            binary: CURRENT_SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_binary_compat_quantum(
    disk_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> MonotonicityResult<()> {
    let result = check_binary_compat(disk_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

// -----------------------------------------------------------------------------
// SM-4: Checkpoint after step
// -----------------------------------------------------------------------------

/// Verify that a schema checkpoint file exists and contains the expected version.
pub fn check_checkpoint(data_dir: &str, expected_sv: u32) -> MonotonicityResult<()> {
    let path = Path::new(data_dir).join("schema.json");
    if !path.exists() {
        return Err(MonotonicityError::CheckpointMissing {
            path: path.display().to_string(),
        });
    }

    let content = fs::read_to_string(&path).map_err(|e| MonotonicityError::CheckpointReadError {
        path: path.display().to_string(),
        reason: e.to_string(),
    })?;
    let meta: SchemaMeta = serde_json::from_str(&content).map_err(|e| {
        MonotonicityError::CheckpointReadError {
            path: path.display().to_string(),
            reason: e.to_string(),
        }
    })?;

    if meta.version != expected_sv {
        return Err(MonotonicityError::CheckpointMismatch {
            actual: meta.version,
            expected: expected_sv,
        });
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_checkpoint_quantum(
    data_dir: &str,
    expected_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> MonotonicityResult<()> {
    let result = check_checkpoint(data_dir, expected_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

/// Create a checkpoint file after a successful migration step.
/// Writes atomically: temp + fsync + rename + parent-dir fsync.
pub fn create_checkpoint(data_dir: &str, meta: &SchemaMeta) -> io::Result<()> {
    let path = Path::new(data_dir).join("schema.json");
    let tmp_path = path.with_extension("tmp");

    let content = serde_json::to_string_pretty(meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    // Write to temp file with fsync.
    {
        let mut f = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)?;
        f.write_all(content.as_bytes())?;
        f.sync_all()?;
    }

    // Atomic rename.
    fs::rename(&tmp_path, &path)?;

    // fsync parent directory so the rename is durable.
    if let Some(parent) = path.parent() {
        if let Ok(dir) = File::open(parent) {
            let _ = dir.sync_all();
        }
    }

    debug!(version = meta.version, path = %path.display(), "checkpoint saved");
    Ok(())
}

// -----------------------------------------------------------------------------
// SM-5: Idempotent re‑run
// -----------------------------------------------------------------------------

/// Verify that running a migration at the current version is a no‑op.
pub fn check_idempotent(current_sv: u32, target_sv: u32) -> MonotonicityResult<bool> {
    if current_sv == target_sv {
        return Ok(true);
    }
    if current_sv > target_sv {
        return Err(MonotonicityError::Downgrade {
            current: current_sv,
            target: target_sv,
        });
    }
    Ok(false)
}

/// Version with quantum state tracking.
pub fn check_idempotent_quantum(
    current_sv: u32,
    target_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> MonotonicityResult<bool> {
    let result = check_idempotent(current_sv, target_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

// -----------------------------------------------------------------------------
// Monotonicity check structures
// -----------------------------------------------------------------------------

/// Result of a single monotonicity check.
#[derive(Debug, Clone, Serialize)]
pub struct MonotonicityCheck {
    pub id: String,
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Result of all schema monotonicity checks.
#[derive(Debug, Clone)]
pub struct MonotonicityReport {
    pub checks: Vec<MonotonicityCheck>,
    pub all_passed: bool,
    pub quantum_state: QuantumMonotonicityState,
}

impl std::fmt::Display for MonotonicityReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Schema Monotonicity: {}",
            if self.all_passed {
                "ALL PASSED"
            } else {
                "VIOLATIONS DETECTED"
            }
        )?;
        for c in &self.checks {
            let mark = if c.passed { "OK" } else { "FAIL" };
            writeln!(f, "  [{mark}] {}: {} — {}", c.id, c.name, c.detail)?;
        }
        writeln!(
            f,
            "  Quantum state: γ={:.6}, S={:.6}, valid={}",
            self.quantum_state.purity,
            self.quantum_state.entropy,
            self.quantum_state.is_valid
        )?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Aggregate check
// -----------------------------------------------------------------------------

/// Run all monotonicity checks for a proposed migration.
pub fn check_monotonicity(
    current_sv: u32,
    target_sv: u32,
    data_dir: Option<&str>,
) -> MonotonicityReport {
    check_monotonicity_with_metrics(current_sv, target_sv, data_dir, None)
}

/// Same as `check_monotonicity`, but with optional metrics recording.
pub fn check_monotonicity_with_metrics(
    current_sv: u32,
    target_sv: u32,
    data_dir: Option<&str>,
    metrics: Option<&MonotonicityMetrics>,
) -> MonotonicityReport {
    let mut state = QuantumMonotonicityState::new(current_sv, target_sv);
    if let Some(m) = metrics {
        m.update_version_gauges(current_sv, target_sv);
    }

    let mut checks = Vec::new();
    let mut record = |passed: bool, metrics: Option<&MonotonicityMetrics>| {
        if let Some(m) = metrics {
            m.record_check();
            if passed {
                m.record_pass();
            } else {
                m.record_failure();
            }
        }
    };

    // SM-1: Strictly increasing.
    if target_sv != current_sv {
        let r = check_strictly_increasing_quantum(current_sv, target_sv, &mut state);
        record(r.is_ok(), metrics);
        checks.push(MonotonicityCheck {
            id: "SM-1".into(),
            name: "Strictly increasing".into(),
            passed: r.is_ok(),
            detail: r
                .err()
                .map(|e| e.to_string())
                .unwrap_or_else(|| format!("SV {current_sv} -> {target_sv}: OK")),
        });
    } else {
        state.record_pass();
        record(true, metrics);
        checks.push(MonotonicityCheck {
            id: "SM-1".into(),
            name: "Strictly increasing".into(),
            passed: true,
            detail: "same version, no increase needed".into(),
        });
    }

    // SM-2: No gaps.
    let r = check_no_gaps_quantum(current_sv, target_sv, &mut state);
    record(r.is_ok(), metrics);
    checks.push(MonotonicityCheck {
        id: "SM-2".into(),
        name: "No gaps".into(),
        passed: r.is_ok(),
        detail: r.err().map(|e| e.to_string()).unwrap_or_else(|| {
            format!("migration path {current_sv}..{target_sv} contiguous")
        }),
    });

    // SM-3: Binary >= disk.
    let r = check_binary_compat_quantum(current_sv, &mut state);
    record(r.is_ok(), metrics);
    checks.push(MonotonicityCheck {
        id: "SM-3".into(),
        name: "Binary >= disk".into(),
        passed: r.is_ok(),
        detail: r.err().map(|e| e.to_string()).unwrap_or_else(|| {
            format!("binary SV={CURRENT_SCHEMA_VERSION} >= disk SV={current_sv}")
        }),
    });

    // SM-4: Checkpoint (if data_dir provided).
    if let Some(dir) = data_dir {
        let r = check_checkpoint_quantum(dir, current_sv, &mut state);
        record(r.is_ok(), metrics);
        checks.push(MonotonicityCheck {
            id: "SM-4".into(),
            name: "Checkpoint exists".into(),
            passed: r.is_ok(),
            detail: r.err().map(|e| e.to_string()).unwrap_or_else(|| {
                format!("schema.json at SV={current_sv}")
            }),
        });
    } else {
        state.record_pass();
        record(true, metrics);
        checks.push(MonotonicityCheck {
            id: "SM-4".into(),
            name: "Checkpoint exists".into(),
            passed: true,
            detail: "skipped (no data_dir provided)".into(),
        });
    }

    // SM-5: Idempotent.
    let r = check_idempotent_quantum(current_sv, target_sv, &mut state);
    record(r.is_ok(), metrics);
    checks.push(MonotonicityCheck {
        id: "SM-5".into(),
        name: "Idempotent re‑run".into(),
        passed: r.is_ok(),
        detail: match &r {
            Ok(true) => "already at target SV (no‑op)".into(),
            Ok(false) => format!("migration needed: SV {current_sv} -> {target_sv}"),
            Err(e) => e.to_string(),
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);
    if let Some(m) = metrics {
        m.update_purity(state.purity);
    }
    MonotonicityReport {
        checks,
        all_passed,
        quantum_state: state,
    }
}

/// Run monotonicity checks and return the quantum state separately.
pub fn check_monotonicity_quantum(
    current_sv: u32,
    target_sv: u32,
    data_dir: Option<&str>,
) -> (MonotonicityReport, QuantumMonotonicityState) {
    let report = check_monotonicity(current_sv, target_sv, data_dir);
    let qstate = report.quantum_state.clone();
    (report, qstate)
}

// -----------------------------------------------------------------------------
// Migration step validation
// -----------------------------------------------------------------------------

/// Validate a migration step: SM-1 (strictly increasing), SM-2 (+1 step size), SM-3 (binary >= disk).
pub fn validate_migration_step(from_sv: u32, to_sv: u32) -> MonotonicityResult<()> {
    check_strictly_increasing(from_sv, to_sv)?;

    if to_sv != from_sv.saturating_add(1) {
        return Err(MonotonicityError::NotUnitStep {
            from: from_sv,
            to: to_sv,
        });
    }

    check_binary_compat(from_sv)?;
    Ok(())
}

/// Validate a migration step with quantum state tracking.
pub fn validate_migration_step_quantum(
    from_sv: u32,
    to_sv: u32,
) -> (MonotonicityResult<()>, QuantumMonotonicityState) {
    let mut state = QuantumMonotonicityState::new(from_sv, to_sv);
    let result = validate_migration_step(from_sv, to_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    (result, state)
}

// -----------------------------------------------------------------------------
// Quantum fidelity
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two schema versions.
pub fn version_fidelity(v_a: u32, v_b: u32) -> f64 {
    if v_a == v_b { 1.0 } else { 0.0 }
}

// -----------------------------------------------------------------------------
// Helper: timestamp
// -----------------------------------------------------------------------------

/// Return the current Unix timestamp as a string (seconds since epoch).
pub fn current_timestamp() -> String {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    format!("[{}]", ts)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write_schema_meta(dir: &Path, version: u32) {
        let meta = SchemaMeta {
            version,
            migrated_at: None,
            migration_log: vec![],
        };
        let content = serde_json::to_string(&meta).unwrap();
        fs::write(dir.join("schema.json"), content).unwrap();
    }

    #[test]
    fn test_strictly_increasing_ok() {
        assert!(check_strictly_increasing(1, 2).is_ok());
        assert!(check_strictly_increasing(4, 5).is_ok());
    }

    #[test]
    fn test_strictly_increasing_violation() {
        assert!(check_strictly_increasing(2, 2).is_err());
        assert!(check_strictly_increasing(3, 1).is_err());
    }

    #[test]
    fn test_no_gaps_ok() {
        assert!(check_no_gaps(CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION).is_ok());
        assert!(check_no_gaps(3, 5).is_ok());
    }

    #[test]
    fn test_no_gaps_violation() {
        assert!(check_no_gaps(4, 10).is_err());
    }

    #[test]
    fn test_binary_compat_ok() {
        assert!(check_binary_compat(CURRENT_SCHEMA_VERSION).is_ok());
        assert!(check_binary_compat(1).is_ok());
    }

    #[test]
    fn test_binary_compat_violation() {
        assert!(check_binary_compat(CURRENT_SCHEMA_VERSION + 1).is_err());
        assert!(check_binary_compat(999).is_err());
    }

    #[test]
    fn test_checkpoint_missing() {
        let r = check_checkpoint("/tmp/nonexistent_iona_test_dir", 5);
        assert!(matches!(r, Err(MonotonicityError::CheckpointMissing { .. })));
    }

    #[test]
    fn test_checkpoint_with_temp_dir() {
        let dir = tempdir().unwrap();
        write_schema_meta(dir.path(), 5);
        assert!(check_checkpoint(dir.path().to_str().unwrap(), 5).is_ok());
    }

    #[test]
    fn test_checkpoint_wrong_version() {
        let dir = tempdir().unwrap();
        write_schema_meta(dir.path(), 3);
        let err = check_checkpoint(dir.path().to_str().unwrap(), 5).unwrap_err();
        assert!(matches!(
            err,
            MonotonicityError::CheckpointMismatch { actual: 3, expected: 5 }
        ));
    }

    #[test]
    fn test_create_checkpoint_atomic() {
        let dir = tempdir().unwrap();
        let data_dir = dir.path().to_str().unwrap();
        let meta = SchemaMeta {
            version: 5,
            migrated_at: None,
            migration_log: vec![],
        };
        create_checkpoint(data_dir, &meta).unwrap();
        let path = dir.path().join("schema.json");
        assert!(path.exists());
        let tmp = path.with_extension("tmp");
        assert!(!tmp.exists(), "temp file must be renamed away");
        let loaded: SchemaMeta = serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(loaded.version, 5);
    }

    #[test]
    fn test_idempotent_noop() {
        assert!(check_idempotent(5, 5).unwrap());
    }

    #[test]
    fn test_idempotent_needs_migration() {
        assert!(!check_idempotent(4, 5).unwrap());
    }

    #[test]
    fn test_idempotent_downgrade_rejected() {
        assert!(check_idempotent(5, 3).is_err());
    }

    #[test]
    fn test_monotonicity_report_all_pass() {
        let report = check_monotonicity(CURRENT_SCHEMA_VERSION, CURRENT_SCHEMA_VERSION, None);
        assert!(report.all_passed, "report: {report}");
    }

    #[test]
    fn test_monotonicity_report_display() {
        let report = check_monotonicity(4, 5, None);
        let s = format!("{report}");
        assert!(s.contains("Schema Monotonicity"));
        assert!(s.contains("Quantum state"));
    }

    #[test]
    fn test_validate_migration_step_ok() {
        assert!(validate_migration_step(4, 5).is_ok());
    }

    #[test]
    fn test_validate_migration_step_skip() {
        assert!(matches!(
            validate_migration_step(3, 5),
            Err(MonotonicityError::NotUnitStep { .. })
        ));
    }

    #[test]
    fn test_validate_migration_step_equal() {
        assert!(matches!(
            validate_migration_step(5, 5),
            Err(MonotonicityError::NotIncreasing { .. })
        ));
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts.starts_with('['));
        assert!(ts.ends_with(']'));
    }

    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumMonotonicityState::new(4, 5);
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
        assert_eq!(state.current_version, 4);
        assert_eq!(state.target_version, 5);
    }

    #[test]
    fn test_record_pass_decoheres() {
        let mut state = QuantumMonotonicityState::new(1, 2);
        let initial_purity = state.purity;
        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.checks_passed, 1);
    }

    #[test]
    fn test_record_failure_stronger_decoherence() {
        let mut state1 = QuantumMonotonicityState::new(1, 2);
        let mut state2 = QuantumMonotonicityState::new(1, 2);
        state1.record_pass();
        state2.record_failure();
        assert!(state2.purity < state1.purity);
        assert_eq!(state2.checks_failed, 1);
    }

    #[test]
    fn test_mono_channel() {
        let mut state = QuantumMonotonicityState::new(1, 2);
        let initial_coherence = state.path_coherence;
        state.apply_mono_channel();
        assert!(state.path_coherence < initial_coherence);
    }

    #[test]
    fn test_quantum_report_includes_state() {
        let report = check_monotonicity(4, 5, None);
        assert!(report.quantum_state.purity < 1.0);
        assert!(report.quantum_state.total_checks > 0);
    }

    #[test]
    fn test_check_monotonicity_quantum() {
        let (report, qstate) = check_monotonicity_quantum(4, 5, None);
        assert!(report.all_passed);
        assert!(qstate.total_checks > 0);
    }

    #[test]
    fn test_validate_migration_step_quantum() {
        let (result, state) = validate_migration_step_quantum(4, 5);
        assert!(result.is_ok());
        assert!(state.total_checks > 0);
        assert!(state.purity < 1.0);
    }

    #[test]
    fn test_version_fidelity() {
        assert!((version_fidelity(5, 5) - 1.0).abs() < 1e-10);
        assert!((version_fidelity(4, 5) - 0.0).abs() < 1e-10);
    }

    #[test]
    fn test_health_after_failures() {
        let mut state = QuantumMonotonicityState::new(1, 2);
        assert!(state.is_valid);
        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumMonotonicityState::new(1, 2);
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }

    #[test]
    fn test_prometheus_metrics_unregistered() {
        let p = MonotonicityPrometheus::new_unregistered();
        p.checks_total.inc();
        p.passes_total.inc_by(2);
        p.failures_total.inc();
        p.current_sv.set(4.0);
        p.target_sv.set(5.0);
        p.purity.set(0.95);
        assert_eq!(p.checks_total.get(), 1);
        assert_eq!(p.passes_total.get(), 2);
        assert_eq!(p.failures_total.get(), 1);
        assert_eq!(p.current_sv.get(), 4.0);
        assert_eq!(p.target_sv.get(), 5.0);
        assert_eq!(p.purity.get(), 0.95);
    }

    #[test]
    fn test_check_with_metrics_records() -> Result<(), prometheus::Error> {
        let metrics = MonotonicityMetrics::new(false)?;
        let _ = check_monotonicity_with_metrics(4, 5, None, Some(&metrics));
        let snap = metrics.snapshot();
        assert!(snap.checks > 0);
        assert!(snap.passes > 0);
        Ok(())
    }
}
