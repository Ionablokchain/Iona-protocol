//! SchemaVersion monotonicity enforcement — Quantum Migration Safety.
//!
//! # Quantum Monotonicity Model
//!
//! Schema version evolution is modelled as a **quantum walk** on a
//! one‑dimensional lattice where each node represents a schema version.
//! The monotonicity rules (SM‑1 … SM‑5) are **projectors** that constrain
//! the walk to the forward direction only.
//!
//! # Mathematical Formalism
//!
//! ## Version State
//! ```text
//! |SV⟩ = Σ_v α_v |v⟩,   Σ_v |α_v|² = 1
//! ```
//!
//! ## Hamiltonian for Migration
//! ```text
//! Ĥ_migrate = Ĥ_step + Ĥ_checkpoint + Ĥ_validate
//!
//! Ĥ_step      = Σ_s E_s (|s⟩⟨s+1| + h.c.)            (step operator)
//! Ĥ_checkpoint = Σ_c ω_c |c⟩⟨c|                       (persistence)
//! Ĥ_validate  = Σ_v λ_v |valid_v⟩⟨valid_v|            (projector)
//! ```
//!
//! ## Monotonicity as Quantum Constraint
//! ```text
//! Π_mono = Σ_{v_old < v_new} |v_new⟩⟨v_old|
//! ⟨SV| Π_mono |SV⟩ = 1   (must hold for all migrations)
//! ```
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
use serde::Serialize;
use std::fs;
use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};
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
// Quantum Monotonicity State
// -----------------------------------------------------------------------------

/// Quantum state of the schema monotonicity system.
///
/// Tracks the density matrix properties during migration validation,
/// providing observables for monitoring migration safety.
#[derive(Debug, Clone)]
pub struct QuantumMonotonicityState {
    /// Purity γ = Tr(ρ²) of the validation state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the migration path.
    pub path_coherence: f64,
    /// Number of checks performed.
    pub total_checks: u64,
    /// Number of checks passed.
    pub checks_passed: u64,
    /// Number of checks failed.
    pub checks_failed: u64,
    /// Current schema version.
    pub current_version: u32,
    /// Target schema version.
    pub target_version: u32,
    /// Whether the state is valid.
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
    /// Create a new quantum monotonicity state in the ground state |∅⟩.
    pub fn new(current_sv: u32, target_sv: u32) -> Self {
        Self {
            current_version: current_sv,
            target_version: target_sv,
            ..Default::default()
        }
    }

    /// Record a check that passed — minor decoherence.
    pub fn record_pass(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        self.checks_passed = self.checks_passed.wrapping_add(1);
        let decay = (-CHECK_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a check that failed — strong decoherence.
    pub fn record_failure(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        self.checks_failed = self.checks_failed.wrapping_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.path_coherence = (self.path_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for monotonicity operations.
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
///
/// # Quantum Interpretation
/// ```text
/// Π_forward = θ(v_new - v_old)
/// ```
#[must_use]
pub fn check_strictly_increasing(old_sv: u32, new_sv: u32) -> Result<(), String> {
    if new_sv <= old_sv {
        return Err(format!(
            "SM-1 VIOLATION: schema version not strictly increasing: \
             old={old_sv}, new={new_sv}"
        ));
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_strictly_increasing_quantum(
    old_sv: u32,
    new_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> Result<(), String> {
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
///
/// # Quantum Interpretation
/// ```text
/// Path integral over contiguous steps — no tunnelling allowed.
/// ```
#[must_use]
pub fn check_no_gaps(from_sv: u32, to_sv: u32) -> Result<(), String> {
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
            return Err(format!(
                "SM-2 VIOLATION: no migration found for SV {sv} -> {}",
                sv + 1
            ));
        }
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_no_gaps_quantum(
    from_sv: u32,
    to_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> Result<(), String> {
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
///
/// # Quantum Interpretation
/// ```text
/// Energy ordering: E_bin ≥ E_disk   (ground state cannot exceed binary)
/// ```
#[must_use]
pub fn check_binary_compat(disk_sv: u32) -> Result<(), String> {
    if disk_sv > CURRENT_SCHEMA_VERSION {
        return Err(format!(
            "SM-3 VIOLATION: on-disk SV={disk_sv} is newer than binary SV={CURRENT_SCHEMA_VERSION}; \
             upgrade the node binary"
        ));
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_binary_compat_quantum(
    disk_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> Result<(), String> {
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
///
/// # Quantum Interpretation
/// ```text
/// Projective measurement at each step: Π_c |SV⟩ = |c⟩⟨c|SV⟩
/// ```
#[must_use]
pub fn check_checkpoint(data_dir: &str, expected_sv: u32) -> Result<(), String> {
    let path = Path::new(data_dir).join("schema.json");
    if !path.exists() {
        return Err(format!(
            "SM-4 VIOLATION: schema.json does not exist at {}",
            path.display()
        ));
    }

    let content = fs::read_to_string(&path)
        .map_err(|e| format!("SM-4 ERROR: cannot read {}: {}", path.display(), e))?;
    let meta: SchemaMeta = serde_json::from_str(&content)
        .map_err(|e| format!("SM-4 ERROR: cannot parse {}: {}", path.display(), e))?;

    if meta.version != expected_sv {
        return Err(format!(
            "SM-4 VIOLATION: schema.json version={}, expected={expected_sv}",
            meta.version
        ));
    }
    Ok(())
}

/// Version with quantum state tracking.
pub fn check_checkpoint_quantum(
    data_dir: &str,
    expected_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> Result<(), String> {
    let result = check_checkpoint(data_dir, expected_sv);
    match &result {
        Ok(_) => state.record_pass(),
        Err(_) => state.record_failure(),
    }
    state.apply_mono_channel();
    result
}

/// Create a checkpoint file after a successful migration step.
/// Writes atomically (temporary file + rename).
pub fn create_checkpoint(data_dir: &str, meta: &SchemaMeta) -> io::Result<()> {
    let path = Path::new(data_dir).join("schema.json");
    let tmp_path = path.with_extension("tmp");

    let content = serde_json::to_string_pretty(meta)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    fs::write(&tmp_path, &content)?;
    fs::rename(&tmp_path, &path)?;

    debug!(version = meta.version, path = %path.display(), "checkpoint saved");
    Ok(())
}

// -----------------------------------------------------------------------------
// SM-5: Idempotent re‑run
// -----------------------------------------------------------------------------

/// Verify that running a migration at the current version is a no‑op.
///
/// # Quantum Interpretation
/// ```text
/// Π_idem = |current⟩⟨current|
/// Returns |current⟩ if already at target.
/// ```
#[must_use]
pub fn check_idempotent(current_sv: u32, target_sv: u32) -> Result<bool, String> {
    if current_sv == target_sv {
        return Ok(true);
    }
    if current_sv > target_sv {
        return Err(format!(
            "SM-5 VIOLATION: cannot downgrade from SV={current_sv} to SV={target_sv}"
        ));
    }
    Ok(false)
}

/// Version with quantum state tracking.
pub fn check_idempotent_quantum(
    current_sv: u32,
    target_sv: u32,
    state: &mut QuantumMonotonicityState,
) -> Result<bool, String> {
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
#[derive(Debug, Clone)]
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
    /// Quantum state after all checks.
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
///
/// # Arguments
/// * `current_sv` – Current schema version on disk.
/// * `target_sv` – Target schema version after migration.
/// * `data_dir` – Optional data directory (for checkpoint check).
///
/// # Returns
/// A `MonotonicityReport` summarising all checks with quantum state.
pub fn check_monotonicity(
    current_sv: u32,
    target_sv: u32,
    data_dir: Option<&str>,
) -> MonotonicityReport {
    let mut state = QuantumMonotonicityState::new(current_sv, target_sv);
    let mut checks = Vec::new();

    // SM-1: Strictly increasing (only if target != current).
    if target_sv != current_sv {
        let r = check_strictly_increasing_quantum(current_sv, target_sv, &mut state);
        checks.push(MonotonicityCheck {
            id: "SM-1".into(),
            name: "Strictly increasing".into(),
            passed: r.is_ok(),
            detail: r
                .err()
                .unwrap_or_else(|| format!("SV {current_sv} -> {target_sv}: OK")),
        });
    } else {
        state.record_pass();
        checks.push(MonotonicityCheck {
            id: "SM-1".into(),
            name: "Strictly increasing".into(),
            passed: true,
            detail: "same version, no increase needed".into(),
        });
    }

    // SM-2: No gaps.
    let r = check_no_gaps_quantum(current_sv, target_sv, &mut state);
    checks.push(MonotonicityCheck {
        id: "SM-2".into(),
        name: "No gaps".into(),
        passed: r.is_ok(),
        detail: r
            .err()
            .unwrap_or_else(|| format!("migration path {current_sv}..{target_sv} contiguous")),
    });

    // SM-3: Binary >= disk.
    let r = check_binary_compat_quantum(current_sv, &mut state);
    checks.push(MonotonicityCheck {
        id: "SM-3".into(),
        name: "Binary >= disk".into(),
        passed: r.is_ok(),
        detail: r.err().unwrap_or_else(|| {
            format!("binary SV={CURRENT_SCHEMA_VERSION} >= disk SV={current_sv}")
        }),
    });

    // SM-4: Checkpoint (if data_dir provided).
    if let Some(dir) = data_dir {
        let r = check_checkpoint_quantum(dir, current_sv, &mut state);
        checks.push(MonotonicityCheck {
            id: "SM-4".into(),
            name: "Checkpoint exists".into(),
            passed: r.is_ok(),
            detail: r
                .err()
                .unwrap_or_else(|| format!("schema.json at SV={current_sv}")),
        });
    } else {
        state.record_pass();
        checks.push(MonotonicityCheck {
            id: "SM-4".into(),
            name: "Checkpoint exists".into(),
            passed: true,
            detail: "skipped (no data_dir provided)".into(),
        });
    }

    // SM-5: Idempotent.
    let r = check_idempotent_quantum(current_sv, target_sv, &mut state);
    checks.push(MonotonicityCheck {
        id: "SM-5".into(),
        name: "Idempotent re‑run".into(),
        passed: r.is_ok(),
        detail: match &r {
            Ok(true) => "already at target SV (no‑op)".into(),
            Ok(false) => format!("migration needed: SV {current_sv} -> {target_sv}"),
            Err(e) => e.clone(),
        },
    });

    let all_passed = checks.iter().all(|c| c.passed);
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

/// Validate a migration step atomically: checks SM‑1, SM‑2 (step size), and SM‑3.
pub fn validate_migration_step(from_sv: u32, to_sv: u32) -> io::Result<()> {
    check_strictly_increasing(from_sv, to_sv)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if to_sv != from_sv + 1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("SM-2: migration step must be +1: {from_sv} -> {to_sv}"),
        ));
    }

    check_binary_compat(from_sv)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    Ok(())
}

/// Validate a migration step with quantum state tracking.
pub fn validate_migration_step_quantum(
    from_sv: u32,
    to_sv: u32,
) -> (io::Result<()>, QuantumMonotonicityState) {
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
// Quantum Fidelity
// -----------------------------------------------------------------------------

/// Compute the quantum fidelity between two schema versions.
///
/// ```text
/// F = |⟨v_a|v_b⟩|² = δ(v_a, v_b)
/// ```
pub fn version_fidelity(v_a: u32, v_b: u32) -> f64 {
    if v_a == v_b {
        1.0
    } else {
        0.0
    }
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

    // ── Classical Tests ──────────────────────────────────────────────
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
        assert!(r.is_err());
    }

    #[test]
    fn test_checkpoint_with_temp_dir() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("schema.json");
        let meta = SchemaMeta {
            version: 5,
            migrated_at: None,
            migration_log: vec![],
        };
        fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(check_checkpoint(dir.path().to_str().unwrap(), 5).is_ok());
    }

    #[test]
    fn test_checkpoint_wrong_version() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("schema.json");
        let meta = SchemaMeta {
            version: 3,
            migrated_at: None,
            migration_log: vec![],
        };
        fs::write(&path, serde_json::to_string(&meta).unwrap()).unwrap();
        assert!(check_checkpoint(dir.path().to_str().unwrap(), 5).is_err());
    }

    #[test]
    fn test_create_checkpoint() {
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
        let content = fs::read_to_string(&path).unwrap();
        let loaded: SchemaMeta = serde_json::from_str(&content).unwrap();
        assert_eq!(loaded.version, 5);
    }

    #[test]
    fn test_idempotent_noop() {
        assert_eq!(check_idempotent(5, 5).unwrap(), true);
    }

    #[test]
    fn test_idempotent_needs_migration() {
        assert_eq!(check_idempotent(4, 5).unwrap(), false);
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
        assert!(validate_migration_step(3, 5).is_err());
    }

    #[test]
    fn test_validate_migration_step_equal() {
        assert!(validate_migration_step(5, 5).is_err());
    }

    #[test]
    fn test_current_timestamp() {
        let ts = current_timestamp();
        assert!(ts.starts_with('['));
        assert!(ts.ends_with(']'));
    }

    // ── Quantum Tests ────────────────────────────────────────────────
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
    fn test_version_fidelity_identical() {
        assert!((version_fidelity(5, 5) - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_version_fidelity_different() {
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
}
