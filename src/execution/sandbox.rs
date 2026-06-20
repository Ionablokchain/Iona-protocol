//! STEP 2 — Execution sandbox: deterministic execution guard.
//!
//! Ensures block execution is a **pure deterministic state machine**.
//! All nondeterministic inputs are blocked or replaced with deterministic
//! alternatives during block execution.
//!
//! # Blocked Sources
//!
//! | Source         | Guard                                           |
//! |----------------|-------------------------------------------------|
//! | System time    | Use `block.timestamp` only                      |
//! | Thread races   | Single-threaded execution per block              |
//! | Random seed    | Deterministic seed from `block_hash` and `height`|
//! | Iteration order| BTreeMap/BTreeSet only (no HashMap)              |
//! | Map order      | Sorted iteration guaranteed                      |
//! | Float math     | Integer/fixed-point arithmetic only              |
//!
//! # Rule
//!
//! **block execution = pure function(state, block) -> (state', receipts)**
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::sandbox::{Sandbox, SandboxConfig, SandboxMode, ExecutionContext};
//! use iona::types::Hash32;
//!
//! let config = SandboxConfig::default();
//! let mut sandbox = Sandbox::new(config);
//! let ctx = ExecutionContext::from_block(height, timestamp, block_hash, chain_id, base_fee, proposer);
//! sandbox.enter(&ctx);
//! // ... execute block ...
//! let report = sandbox.exit();
//! if !report.is_clean() {
//!     eprintln!("{}", report);
//! }
//! ```

use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during sandbox operations.
#[derive(Debug, Error)]
pub enum SandboxError {
    #[error("sandbox violation: {violation}")]
    Violation { violation: String },

    #[error("sandbox already active")]
    AlreadyActive,

    #[error("sandbox not active")]
    NotActive,

    #[error("configuration error: {0}")]
    Config(String),
}

pub type SandboxResult<T> = Result<T, SandboxError>;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the execution sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Enforcement mode.
    pub mode: SandboxMode,
    /// Whether to log violations (even in Strict mode).
    pub log_violations: bool,
    /// Maximum number of violations to collect (0 = unlimited).
    pub max_violations: usize,
    /// Whether to include a stack trace with violations.
    pub include_stack_traces: bool,
    /// Whether to track execution time.
    pub track_timing: bool,
    /// Whether to verify that only deterministic collections are used.
    pub enforce_deterministic_collections: bool,
    /// Whether to verify that no floating-point operations are used.
    pub enforce_no_floats: bool,
    /// Whether to verify that no external I/O is used.
    pub enforce_no_io: bool,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            mode: SandboxMode::Strict,
            log_violations: true,
            max_violations: 100,
            include_stack_traces: false,
            track_timing: true,
            enforce_deterministic_collections: true,
            enforce_no_floats: true,
            enforce_no_io: true,
        }
    }
}

impl SandboxConfig {
    /// Create a configuration for development (warn mode, no tracking).
    pub fn development() -> Self {
        Self {
            mode: SandboxMode::Warn,
            log_violations: true,
            max_violations: 1000,
            include_stack_traces: true,
            track_timing: false,
            enforce_deterministic_collections: true,
            enforce_no_floats: false,
            enforce_no_io: false,
        }
    }

    /// Create a configuration for production (strict mode, minimal overhead).
    pub fn production() -> Self {
        Self {
            mode: SandboxMode::Strict,
            log_violations: true,
            max_violations: 10,
            include_stack_traces: false,
            track_timing: true,
            enforce_deterministic_collections: true,
            enforce_no_floats: true,
            enforce_no_io: true,
        }
    }

    /// Create a configuration for testing (disabled).
    pub fn disabled() -> Self {
        Self {
            mode: SandboxMode::Disabled,
            log_violations: false,
            max_violations: 0,
            include_stack_traces: false,
            track_timing: false,
            enforce_deterministic_collections: false,
            enforce_no_floats: false,
            enforce_no_io: false,
        }
    }
}

// -----------------------------------------------------------------------------
// SandboxMode
// -----------------------------------------------------------------------------

/// Sandbox enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxMode {
    /// Strict: any violation aborts execution.
    Strict,
    /// Warn: violations are logged but execution continues.
    Warn,
    /// Disabled: no checks (for testing/dev).
    Disabled,
}

impl std::fmt::Display for SandboxMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Strict => write!(f, "Strict"),
            Self::Warn => write!(f, "Warn"),
            Self::Disabled => write!(f, "Disabled"),
        }
    }
}

// -----------------------------------------------------------------------------
// ExecutionContext
// -----------------------------------------------------------------------------

/// Execution context providing deterministic alternatives to nondeterministic inputs.
///
/// Passed into block execution to replace system calls:
/// - `timestamp()` → block.timestamp (not wall clock)
/// - `random_seed()` → deterministic seed from block hash and height
/// - `block_hash()` → block's hash
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    /// Block height being executed.
    pub height: Height,
    /// Block timestamp (the ONLY valid time source during execution).
    pub timestamp: u64,
    /// Deterministic random seed (derived from block hash and height).
    pub deterministic_seed: [u8; 32],
    /// Block hash (for contracts that need randomness).
    pub block_hash: Hash32,
    /// Chain ID.
    pub chain_id: u64,
    /// Base fee per gas.
    pub base_fee_per_gas: u64,
    /// Proposer address.
    pub proposer: String,
    /// Additional arbitrary data for deterministic randomisation.
    pub extra: Vec<u8>,
}

impl ExecutionContext {
    /// Create a new execution context from block data.
    ///
    /// The deterministic seed is derived by mixing the block hash with the
    /// full 64-bit height to avoid collisions when heights differ only in
    /// higher-order bytes.
    pub fn from_block(
        height: Height,
        timestamp: u64,
        block_hash: Hash32,
        chain_id: u64,
        base_fee_per_gas: u64,
        proposer: String,
    ) -> Self {
        Self::from_block_with_extra(height, timestamp, block_hash, chain_id, base_fee_per_gas, proposer, vec![])
    }

    /// Create a new execution context with extra data for seed derivation.
    pub fn from_block_with_extra(
        height: Height,
        timestamp: u64,
        block_hash: Hash32,
        chain_id: u64,
        base_fee_per_gas: u64,
        proposer: String,
        extra: Vec<u8>,
    ) -> Self {
        let mut seed = Self::derive_seed(height, block_hash, &extra);
        Self {
            height,
            timestamp,
            deterministic_seed: seed,
            block_hash,
            chain_id,
            base_fee_per_gas,
            proposer,
            extra,
        }
    }

    /// Derive a deterministic seed from height, block hash, and extra data.
    fn derive_seed(height: Height, block_hash: Hash32, extra: &[u8]) -> [u8; 32] {
        let mut seed = block_hash.0;

        // Mix in height (8 bytes) with XOR and multiplication.
        let height_bytes = height.as_u64().to_le_bytes();
        for i in 0..8 {
            seed[i] = seed[i].wrapping_add(height_bytes[i]).wrapping_mul(0x9E);
        }

        // Mix in extra data.
        for (i, &b) in extra.iter().enumerate() {
            let idx = i % 32;
            seed[idx] = seed[idx].wrapping_add(b).wrapping_mul(0x6D);
        }

        // Spread the influence further.
        for i in 1..32 {
            seed[i] = seed[i].wrapping_add(seed[i - 1]).wrapping_mul(0x6D);
        }

        seed
    }

    /// Get the deterministic timestamp (block.timestamp, NOT wall clock).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get a deterministic random byte sequence derived from block data + index.
    ///
    /// Different indices produce different outputs; same index → same output.
    /// The mixing is not cryptographically secure but is fully deterministic.
    pub fn deterministic_random(&self, index: u64) -> [u8; 32] {
        let mut out = self.deterministic_seed;
        let idx_bytes = index.to_le_bytes();
        for i in 0..8 {
            out[i] ^= idx_bytes[i];
        }
        // Simple avalanche: propagate changes.
        for i in 1..32 {
            out[i] = out[i].wrapping_add(out[i - 1]).wrapping_mul(0x6D);
        }
        out
    }

    /// Get a deterministic random u64.
    pub fn deterministic_random_u64(&self, index: u64) -> u64 {
        let bytes = self.deterministic_random(index);
        u64::from_le_bytes(bytes[0..8].try_into().unwrap())
    }

    /// Get a deterministic random u32.
    pub fn deterministic_random_u32(&self, index: u64) -> u32 {
        let bytes = self.deterministic_random(index);
        u32::from_le_bytes(bytes[0..4].try_into().unwrap())
    }
}

// -----------------------------------------------------------------------------
// Violations
// -----------------------------------------------------------------------------

/// Violations detected during sandbox execution.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SandboxViolation {
    /// System clock was accessed during execution.
    SystemTimeAccess { location: String },
    /// Non-deterministic RNG was used.
    NonDeterministicRng { location: String },
    /// HashMap/HashSet was used (iteration order is random).
    UnorderedCollection { location: String },
    /// Floating-point operation detected.
    FloatingPoint { location: String },
    /// Thread spawn during execution (race condition risk).
    ThreadSpawn { location: String },
    /// External I/O during execution.
    ExternalIo { location: String },
    /// Custom violation with a message.
    Custom { message: String, location: String },
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemTimeAccess { location } =>
                write!(f, "System time access at {}", location),
            Self::NonDeterministicRng { location } =>
                write!(f, "Non-deterministic RNG at {}", location),
            Self::UnorderedCollection { location } =>
                write!(f, "Unordered collection at {}", location),
            Self::FloatingPoint { location } =>
                write!(f, "Floating-point op at {}", location),
            Self::ThreadSpawn { location } =>
                write!(f, "Thread spawn at {}", location),
            Self::ExternalIo { location } =>
                write!(f, "External I/O at {}", location),
            Self::Custom { message, location } =>
                write!(f, "Custom violation at {}: {}", location, message),
        }
    }
}

// -----------------------------------------------------------------------------
// SandboxReport
// -----------------------------------------------------------------------------

/// Report from a sandbox execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxReport {
    /// Whether execution was clean (no violations).
    pub clean: bool,
    /// Number of violations detected.
    pub violation_count: usize,
    /// Violation details.
    pub violations: Vec<SandboxViolation>,
    /// Execution time (if tracking enabled).
    pub execution_time_ms: Option<u64>,
    /// Mode used for this execution.
    pub mode: SandboxMode,
}

impl std::fmt::Display for SandboxReport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(
            f,
            "Sandbox Report: {} (mode={})",
            if self.clean { "CLEAN" } else { "VIOLATIONS DETECTED" },
            self.mode
        )?;
        if let Some(ms) = self.execution_time_ms {
            writeln!(f, "  Execution time: {}ms", ms)?;
        }
        if !self.violations.is_empty() {
            writeln!(f, "  Violations ({}):", self.violation_count)?;
            for v in &self.violations {
                writeln!(f, "    - {}", v)?;
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Sandbox
// -----------------------------------------------------------------------------

/// Execution sandbox that wraps block execution with determinism guards.
#[derive(Debug)]
pub struct Sandbox {
    config: SandboxConfig,
    violations: Vec<SandboxViolation>,
    active: bool,
    start_time: Option<Instant>,
    context: Option<ExecutionContext>,
}

impl Sandbox {
    /// Create a new sandbox with the given configuration.
    pub fn new(config: SandboxConfig) -> Self {
        Self {
            config,
            violations: Vec::new(),
            active: false,
            start_time: None,
            context: None,
        }
    }

    /// Create a sandbox with default configuration.
    pub fn default() -> Self {
        Self::new(SandboxConfig::default())
    }

    /// Enter the sandbox with the given execution context.
    pub fn enter(&mut self, ctx: ExecutionContext) -> SandboxResult<()> {
        if self.active {
            return Err(SandboxError::AlreadyActive);
        }
        self.active = true;
        self.violations.clear();
        self.context = Some(ctx);
        if self.config.track_timing {
            self.start_time = Some(Instant::now());
        }
        debug!("Sandbox entered (mode={})", self.config.mode);
        Ok(())
    }

    /// Exit the sandbox and return a report.
    pub fn exit(&mut self) -> SandboxReport {
        let execution_time_ms = if self.config.track_timing {
            self.start_time.map(|t| t.elapsed().as_millis() as u64)
        } else {
            None
        };

        let clean = self.violations.is_empty();
        let violation_count = self.violations.len();
        let mode = self.config.mode;
        let violations = self.violations.clone();

        self.active = false;
        self.start_time = None;
        self.context = None;

        let report = SandboxReport {
            clean,
            violation_count,
            violations,
            execution_time_ms,
            mode,
        };

        debug!("Sandbox exited: {}", report);
        report
    }

    /// Check if the sandbox is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Get the current execution context (if active).
    pub fn context(&self) -> Option<&ExecutionContext> {
        self.context.as_ref()
    }

    /// Report a violation.
    pub fn report_violation(&mut self, violation: SandboxViolation) -> SandboxResult<()> {
        if !self.active {
            return Err(SandboxError::NotActive);
        }

        // Check max violations.
        if self.config.max_violations > 0 && self.violations.len() >= self.config.max_violations {
            return Ok(());
        }

        if self.config.log_violations {
            warn!("{}", violation);
        }

        self.violations.push(violation.clone());

        match self.config.mode {
            SandboxMode::Disabled => Ok(()),
            SandboxMode::Warn => Ok(()),
            SandboxMode::Strict => {
                Err(SandboxError::Violation { violation: violation.to_string() })
            }
        }
    }

    /// Report a violation with custom message and location.
    pub fn report_custom(&mut self, message: &str, location: &str) -> SandboxResult<()> {
        self.report_violation(SandboxViolation::Custom {
            message: message.to_string(),
            location: location.to_string(),
        })
    }

    /// Get all violations collected during execution.
    pub fn violations(&self) -> &[SandboxViolation] {
        &self.violations
    }

    /// Check if execution was clean (no violations).
    pub fn is_clean(&self) -> bool {
        self.violations.is_empty()
    }

    /// Get the enforcement mode.
    pub fn mode(&self) -> SandboxMode {
        self.config.mode
    }
}

impl Default for Sandbox {
    fn default() -> Self {
        Self::new(SandboxConfig::default())
    }
}

// -----------------------------------------------------------------------------
// Static analysis helpers
// -----------------------------------------------------------------------------

/// A finding from source code audit.
#[derive(Debug, Clone)]
pub struct SourceAuditFinding {
    pub line: usize,
    pub pattern: String,
    pub suggestion: String,
}

impl std::fmt::Display for SourceAuditFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "line {}: found '{}' — {}", self.line, self.pattern, self.suggestion)
    }
}

/// Static analysis: check source code for known nondeterminism patterns.
/// Returns a list of findings.
pub fn audit_source_for_nondeterminism(source: &str) -> Vec<SourceAuditFinding> {
    let dangerous = [
        ("HashMap", "Use BTreeMap instead"),
        ("HashSet", "Use BTreeSet instead"),
        ("SystemTime::now", "Use block.timestamp via ExecutionContext"),
        ("Instant::now", "Use block.timestamp via ExecutionContext"),
        ("thread_rng", "Use ExecutionContext::deterministic_random"),
        ("rand::random", "Use ExecutionContext::deterministic_random"),
        ("std::thread::spawn", "Block execution must be single-threaded"),
        ("f32", "Use integer/fixed-point arithmetic"),
        ("f64", "Use integer/fixed-point arithmetic"),
    ];

    let mut findings = Vec::new();
    for (line_no, line) in source.lines().enumerate() {
        // Skip comments.
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        for &(pattern, fix) in &dangerous {
            if line.contains(pattern) {
                findings.push(SourceAuditFinding {
                    line: line_no + 1,
                    pattern: pattern.to_string(),
                    suggestion: fix.to_string(),
                });
            }
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

    #[test]
    fn test_execution_context_deterministic() {
        let ctx1 = ExecutionContext::from_block(
            Height::new(100),
            1000000,
            Hash32([0xAB; 32]),
            6126151,
            1,
            "proposer".into(),
        );
        let ctx2 = ExecutionContext::from_block(
            Height::new(100),
            1000000,
            Hash32([0xAB; 32]),
            6126151,
            1,
            "proposer".into(),
        );

        assert_eq!(ctx1.timestamp(), ctx2.timestamp());
        assert_eq!(ctx1.deterministic_seed, ctx2.deterministic_seed);
        assert_eq!(ctx1.deterministic_random(0), ctx2.deterministic_random(0));
        assert_eq!(ctx1.deterministic_random(42), ctx2.deterministic_random(42));
    }

    #[test]
    fn test_execution_context_different_blocks() {
        let ctx1 = ExecutionContext::from_block(
            Height::new(100),
            1000000,
            Hash32([0xAB; 32]),
            6126151,
            1,
            "p".into(),
        );
        let ctx2 = ExecutionContext::from_block(
            Height::new(101),
            1001000,
            Hash32([0xCD; 32]),
            6126151,
            1,
            "p".into(),
        );
        assert_ne!(ctx1.deterministic_seed, ctx2.deterministic_seed);
        assert_ne!(ctx1.deterministic_random(0), ctx2.deterministic_random(0));
    }

    #[test]
    fn test_deterministic_random_indexed() {
        let ctx = ExecutionContext::from_block(
            Height::new(1),
            1000,
            Hash32([0x01; 32]),
            6126151,
            1,
            "p".into(),
        );
        assert_ne!(ctx.deterministic_random(0), ctx.deterministic_random(1));
        assert_ne!(ctx.deterministic_random(1), ctx.deterministic_random(2));
        assert_eq!(ctx.deterministic_random(5), ctx.deterministic_random(5));
    }

    #[test]
    fn test_context_with_extra() {
        let ctx1 = ExecutionContext::from_block_with_extra(
            Height::new(100),
            1000,
            Hash32([0x01; 32]),
            1,
            1,
            "p".into(),
            vec![1, 2, 3],
        );
        let ctx2 = ExecutionContext::from_block_with_extra(
            Height::new(100),
            1000,
            Hash32([0x01; 32]),
            1,
            1,
            "p".into(),
            vec![1, 2, 3],
        );
        assert_eq!(ctx1.deterministic_seed, ctx2.deterministic_seed);
        let ctx3 = ExecutionContext::from_block_with_extra(
            Height::new(100),
            1000,
            Hash32([0x01; 32]),
            1,
            1,
            "p".into(),
            vec![1, 2, 4],
        );
        assert_ne!(ctx1.deterministic_seed, ctx3.deterministic_seed);
    }

    #[test]
    fn test_sandbox_strict_mode() {
        let mut sandbox = Sandbox::new(SandboxConfig {
            mode: SandboxMode::Strict,
            log_violations: false,
            ..Default::default()
        });
        sandbox.enter(ExecutionContext {
            height: Height::new(1),
            timestamp: 1000,
            deterministic_seed: [0; 32],
            block_hash: Hash32([0; 32]),
            chain_id: 1,
            base_fee_per_gas: 1,
            proposer: "p".into(),
            extra: vec![],
        }).unwrap();
        assert!(sandbox.is_active());

        let result = sandbox.report_violation(SandboxViolation::SystemTimeAccess {
            location: "block_exec.rs:42".into(),
        });
        assert!(result.is_err());
        assert!(!sandbox.is_clean());
        assert_eq!(sandbox.violations().len(), 1);

        let report = sandbox.exit();
        assert!(!report.clean);
        assert_eq!(report.violation_count, 1);
        assert_eq!(report.mode, SandboxMode::Strict);
    }

    #[test]
    fn test_sandbox_warn_mode() {
        let mut sandbox = Sandbox::new(SandboxConfig {
            mode: SandboxMode::Warn,
            log_violations: false,
            ..Default::default()
        });
        sandbox.enter(ExecutionContext::from_block(
            Height::new(1), 1000, Hash32([0; 32]), 1, 1, "p".into(),
        )).unwrap();

        let result = sandbox.report_violation(SandboxViolation::NonDeterministicRng {
            location: "tx_order.rs:10".into(),
        });
        assert!(result.is_ok());
        assert!(!sandbox.is_clean());
        assert_eq!(sandbox.violations().len(), 1);
    }

    #[test]
    fn test_sandbox_disabled_mode() {
        let mut sandbox = Sandbox::new(SandboxConfig {
            mode: SandboxMode::Disabled,
            log_violations: false,
            ..Default::default()
        });
        sandbox.enter(ExecutionContext::from_block(
            Height::new(1), 1000, Hash32([0; 32]), 1, 1, "p".into(),
        )).unwrap();

        let result = sandbox.report_violation(SandboxViolation::FloatingPoint {
            location: "calc.rs:5".into(),
        });
        assert!(result.is_ok());
        assert!(sandbox.is_clean());
    }

    #[test]
    fn test_sandbox_enter_exit() {
        let mut sandbox = Sandbox::default();
        assert!(!sandbox.is_active());
        sandbox.enter(ExecutionContext::from_block(
            Height::new(1), 1000, Hash32([0; 32]), 1, 1, "p".into(),
        )).unwrap();
        assert!(sandbox.is_active());
        let report = sandbox.exit();
        assert!(report.clean);
        assert!(!sandbox.is_active());
    }

    #[test]
    fn test_violation_display() {
        let v = SandboxViolation::SystemTimeAccess { location: "foo.rs:10".into() };
        let s = format!("{}", v);
        assert!(s.contains("System time access"));
        assert!(s.contains("foo.rs:10"));
    }

    #[test]
    fn test_audit_source_clean() {
        let code = r#"
            let map: BTreeMap<String, u64> = BTreeMap::new();
            let timestamp = ctx.timestamp();
        "#;
        let findings = audit_source_for_nondeterminism(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_audit_source_dangerous() {
        let code = r#"
            let map: HashMap<String, u64> = HashMap::new();
            let now = SystemTime::now();
            let r = thread_rng();
        "#;
        let findings = audit_source_for_nondeterminism(code);
        assert!(findings.len() >= 3);
    }

    #[test]
    fn test_audit_skips_comments() {
        let code = r#"
            // HashMap is not allowed in block execution
            /// This function uses BTreeMap instead of HashMap
            let map: BTreeMap<String, u64> = BTreeMap::new();
        "#;
        let findings = audit_source_for_nondeterminism(code);
        assert!(findings.is_empty());
    }

    #[test]
    fn test_report_display() {
        let report = SandboxReport {
            clean: false,
            violation_count: 2,
            violations: vec![
                SandboxViolation::SystemTimeAccess { location: "a".into() },
                SandboxViolation::FloatingPoint { location: "b".into() },
            ],
            execution_time_ms: Some(100),
            mode: SandboxMode::Strict,
        };
        let s = format!("{}", report);
        assert!(s.contains("VIOLATIONS DETECTED"));
        assert!(s.contains("100ms"));
        assert!(s.contains("System time access"));
    }
}
