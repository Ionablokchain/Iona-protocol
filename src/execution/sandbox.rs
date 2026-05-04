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
//! | Random seed    | Deterministic seed from `block_hash`             |
//! | Iteration order| BTreeMap/BTreeSet only (no HashMap)              |
//! | Map order      | Sorted iteration guaranteed                      |
//! | Float math     | Integer/fixed-point arithmetic only              |
//!
//! # Rule
//!
//! **block execution = pure function(state, block) -> (state', receipts)**

use crate::types::{Hash32, Height};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during sandbox operation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SandboxError {
    #[error("sandbox violation: {violation}")]
    Violation { violation: String },

    #[error("sandbox is not active; cannot report violation")]
    Inactive,

    #[error("invalid execution context: {reason}")]
    InvalidContext { reason: String },
}

pub type SandboxResult<T> = Result<T, SandboxError>;

// -----------------------------------------------------------------------------
// Execution context
// -----------------------------------------------------------------------------

/// Execution context providing deterministic alternatives to nondeterministic inputs.
///
/// Passed into block execution to replace system calls:
/// - `timestamp()` → block.timestamp (not wall clock)
/// - `random_seed()` → deterministic seed from block hash
/// - `block_hash()` → block's hash
#[derive(Debug, Clone)]
pub struct ExecutionContext {
    pub height: Height,
    pub timestamp: u64,
    pub deterministic_seed: [u8; 32],
    pub block_hash: Hash32,
    pub chain_id: u64,
    pub base_fee_per_gas: u64,
    pub proposer: String,
}

impl ExecutionContext {
    /// Create a new execution context from block data.
    /// Returns an error if any parameter is invalid (e.g., timestamp zero).
    pub fn from_block(
        height: Height,
        timestamp: u64,
        block_hash: Hash32,
        chain_id: u64,
        base_fee_per_gas: u64,
        proposer: String,
    ) -> SandboxResult<Self> {
        if timestamp == 0 {
            return Err(SandboxError::InvalidContext {
                reason: "timestamp cannot be zero".into(),
            });
        }
        if chain_id == 0 {
            return Err(SandboxError::InvalidContext {
                reason: "chain_id cannot be zero".into(),
            });
        }
        if base_fee_per_gas == 0 {
            return Err(SandboxError::InvalidContext {
                reason: "base_fee_per_gas must be > 0".into(),
            });
        }
        let mut seed = [0u8; 32];
        for (i, b) in block_hash.0.iter().enumerate() {
            seed[i] = b.wrapping_add(height as u8).wrapping_mul(0x9E);
        }
        Ok(Self {
            height,
            timestamp,
            deterministic_seed: seed,
            block_hash,
            chain_id,
            base_fee_per_gas,
            proposer,
        })
    }

    /// Get the deterministic timestamp (block.timestamp, NOT wall clock).
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Get a deterministic random byte sequence derived from block hash + index.
    pub fn deterministic_random(&self, index: u64) -> [u8; 32] {
        let mut out = self.deterministic_seed;
        let idx_bytes = index.to_le_bytes();
        for i in 0..8 {
            out[i] ^= idx_bytes[i];
        }
        for i in 1..32 {
            out[i] = out[i].wrapping_add(out[i - 1]).wrapping_mul(0x6D);
        }
        out
    }
}

// -----------------------------------------------------------------------------
// Sandbox violation types
// -----------------------------------------------------------------------------

/// Violations detected during sandbox execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxViolation {
    SystemTimeAccess { location: String },
    NonDeterministicRng { location: String },
    UnorderedCollection { location: String },
    FloatingPoint { location: String },
    ThreadSpawn { location: String },
    ExternalIo { location: String },
}

impl std::fmt::Display for SandboxViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SystemTimeAccess { location } => {
                write!(f, "SANDBOX: system time access at {location}")
            }
            Self::NonDeterministicRng { location } => {
                write!(f, "SANDBOX: non-deterministic RNG at {location}")
            }
            Self::UnorderedCollection { location } => {
                write!(f, "SANDBOX: unordered collection at {location}")
            }
            Self::FloatingPoint { location } => {
                write!(f, "SANDBOX: floating-point op at {location}")
            }
            Self::ThreadSpawn { location } => write!(f, "SANDBOX: thread spawn at {location}"),
            Self::ExternalIo { location } => write!(f, "SANDBOX: external I/O at {location}"),
        }
    }
}

// -----------------------------------------------------------------------------
// Sandbox mode
// -----------------------------------------------------------------------------

/// Sandbox enforcement mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxMode {
    /// Strict: any violation aborts execution.
    Strict,
    /// Warn: violations are logged but execution continues.
    Warn,
    /// Disabled: no checks (for testing/dev).
    Disabled,
}

// -----------------------------------------------------------------------------
// Execution sandbox
// -----------------------------------------------------------------------------

/// Execution sandbox that wraps block execution with determinism guards.
#[derive(Debug)]
pub struct ExecutionSandbox {
    mode: SandboxMode,
    violations: Vec<SandboxViolation>,
    active: bool,
}

impl ExecutionSandbox {
    /// Create a new sandbox with the given enforcement mode.
    pub fn new(mode: SandboxMode) -> Self {
        Self {
            mode,
            violations: Vec::new(),
            active: false,
        }
    }

    /// Enter the sandbox (start of block execution).
    pub fn enter(&mut self) {
        self.active = true;
        self.violations.clear();
    }

    /// Exit the sandbox (end of block execution).
    pub fn exit(&mut self) {
        self.active = false;
    }

    /// Check if the sandbox is active.
    pub fn is_active(&self) -> bool {
        self.active
    }

    /// Report a violation. Returns `Err` in Strict mode, `Ok` otherwise.
    pub fn report_violation(&mut self, violation: SandboxViolation) -> SandboxResult<()> {
        if !self.active {
            return Err(SandboxError::Inactive);
        }
        match self.mode {
            SandboxMode::Disabled => Ok(()),
            SandboxMode::Warn => {
                self.violations.push(violation);
                Ok(())
            }
            SandboxMode::Strict => {
                let err_msg = violation.to_string();
                self.violations.push(violation);
                Err(SandboxError::Violation { violation: err_msg })
            }
        }
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
        self.mode
    }
}

// -----------------------------------------------------------------------------
// Sandbox builder
// -----------------------------------------------------------------------------

/// Builder for configuring an `ExecutionSandbox`.
#[derive(Default)]
pub struct SandboxBuilder {
    mode: SandboxMode,
}

impl SandboxBuilder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mode(mut self, mode: SandboxMode) -> Self {
        self.mode = mode;
        self
    }

    pub fn build(self) -> ExecutionSandbox {
        ExecutionSandbox::new(self.mode)
    }
}

// -----------------------------------------------------------------------------
// Static analysis
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
        write!(
            f,
            "line {}: found '{}' — {}",
            self.line, self.pattern, self.suggestion
        )
    }
}

/// Static analysis: check source code for known nondeterminism patterns.
/// Returns a list of findings.
pub fn audit_source_for_nondeterminism(source: &str) -> Vec<SourceAuditFinding> {
    let dangerous = [
        ("HashMap", "Use BTreeMap instead"),
        ("HashSet", "Use BTreeSet instead"),
        (
            "SystemTime::now",
            "Use block.timestamp via ExecutionContext",
        ),
        ("Instant::now", "Use block.timestamp via ExecutionContext"),
        ("thread_rng", "Use ExecutionContext::deterministic_random"),
        ("rand::random", "Use ExecutionContext::deterministic_random"),
        (
            "std::thread::spawn",
            "Block execution must be single-threaded",
        ),
        ("f32", "Use integer/fixed-point arithmetic"),
        ("f64", "Use integer/fixed-point arithmetic"),
    ];

    let mut findings = Vec::new();
    for (line_no, line) in source.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.starts_with("//") || trimmed.starts_with("///") {
            continue;
        }
        for &(pattern, suggestion) in &dangerous {
            if line.contains(pattern) {
                findings.push(SourceAuditFinding {
                    line: line_no + 1,
                    pattern: pattern.to_string(),
                    suggestion: suggestion.to_string(),
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
    fn test_execution_context_validation() {
        let good = ExecutionContext::from_block(1, 1000, Hash32([0x01; 32]), 1, 1, "p".into());
        assert!(good.is_ok());

        let bad_timestamp = ExecutionContext::from_block(1, 0, Hash32([0x01; 32]), 1, 1, "p".into());
        assert!(matches!(bad_timestamp, Err(SandboxError::InvalidContext { .. })));

        let bad_chain = ExecutionContext::from_block(1, 1000, Hash32([0x01; 32]), 0, 1, "p".into());
        assert!(matches!(bad_chain, Err(SandboxError::InvalidContext { .. })));

        let bad_base_fee = ExecutionContext::from_block(1, 1000, Hash32([0x01; 32]), 1, 0, "p".into());
        assert!(matches!(bad_base_fee, Err(SandboxError::InvalidContext { .. })));
    }

    #[test]
    fn test_execution_context_deterministic() {
        let ctx1 = ExecutionContext::from_block(
            100,
            1000000,
            Hash32([0xAB; 32]),
            6126151,
            1,
            "proposer".into(),
        )
        .unwrap();
        let ctx2 = ExecutionContext::from_block(
            100,
            1000000,
            Hash32([0xAB; 32]),
            6126151,
            1,
            "proposer".into(),
        )
        .unwrap();

        assert_eq!(ctx1.timestamp(), ctx2.timestamp());
        assert_eq!(ctx1.deterministic_seed, ctx2.deterministic_seed);
        assert_eq!(ctx1.deterministic_random(0), ctx2.deterministic_random(0));
        assert_eq!(ctx1.deterministic_random(42), ctx2.deterministic_random(42));
    }

    #[test]
    fn test_execution_context_different_blocks() {
        let ctx1 = ExecutionContext::from_block(100, 1000000, Hash32([0xAB; 32]), 6126151, 1, "p".into())
            .unwrap();
        let ctx2 = ExecutionContext::from_block(101, 1001000, Hash32([0xCD; 32]), 6126151, 1, "p".into())
            .unwrap();

        assert_ne!(ctx1.deterministic_seed, ctx2.deterministic_seed);
        assert_ne!(ctx1.deterministic_random(0), ctx2.deterministic_random(0));
    }

    #[test]
    fn test_deterministic_random_indexed() {
        let ctx = ExecutionContext::from_block(1, 1000, Hash32([0x01; 32]), 6126151, 1, "p".into())
            .unwrap();

        assert_ne!(ctx.deterministic_random(0), ctx.deterministic_random(1));
        assert_ne!(ctx.deterministic_random(1), ctx.deterministic_random(2));
        assert_eq!(ctx.deterministic_random(5), ctx.deterministic_random(5));
    }

    #[test]
    fn test_sandbox_strict_mode() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Strict);
        sandbox.enter();
        assert!(sandbox.is_active());

        let result = sandbox.report_violation(SandboxViolation::SystemTimeAccess {
            location: "block_exec.rs:42".into(),
        });
        assert!(result.is_err());
        assert!(!sandbox.is_clean());
        assert_eq!(sandbox.violations().len(), 1);

        sandbox.exit();
        assert!(!sandbox.is_active());
    }

    #[test]
    fn test_sandbox_warn_mode() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Warn);
        sandbox.enter();

        let result = sandbox.report_violation(SandboxViolation::NonDeterministicRng {
            location: "tx_order.rs:10".into(),
        });
        assert!(result.is_ok());
        assert!(!sandbox.is_clean());
        assert_eq!(sandbox.violations().len(), 1);
    }

    #[test]
    fn test_sandbox_disabled_mode() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Disabled);
        sandbox.enter();

        let result = sandbox.report_violation(SandboxViolation::FloatingPoint {
            location: "calc.rs:5".into(),
        });
        assert!(result.is_ok());
        assert!(sandbox.is_clean());
    }

    #[test]
    fn test_sandbox_inactive_report() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Strict);
        let err = sandbox.report_violation(SandboxViolation::ExternalIo {
            location: "io.rs".into(),
        });
        assert!(matches!(err, Err(SandboxError::Inactive)));
    }

    #[test]
    fn test_sandbox_enter_exit() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Strict);
        assert!(!sandbox.is_active());
        sandbox.enter();
        assert!(sandbox.is_active());
        sandbox.exit();
        assert!(!sandbox.is_active());
    }

    #[test]
    fn test_sandbox_clears_on_enter() {
        let mut sandbox = ExecutionSandbox::new(SandboxMode::Warn);
        sandbox.enter();
        let _ = sandbox.report_violation(SandboxViolation::ThreadSpawn {
            location: "exec.rs:1".into(),
        });
        assert_eq!(sandbox.violations().len(), 1);
        sandbox.enter();
        assert!(sandbox.is_clean());
    }

    #[test]
    fn test_violation_display() {
        let v = SandboxViolation::SystemTimeAccess {
            location: "foo.rs:10".into(),
        };
        let s = format!("{v}");
        assert!(s.contains("system time access"));
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
    fn test_all_violation_types() {
        let violations = vec![
            SandboxViolation::SystemTimeAccess {
                location: "a".into(),
            },
            SandboxViolation::NonDeterministicRng {
                location: "b".into(),
            },
            SandboxViolation::UnorderedCollection {
                location: "c".into(),
            },
            SandboxViolation::FloatingPoint {
                location: "d".into(),
            },
            SandboxViolation::ThreadSpawn {
                location: "e".into(),
            },
            SandboxViolation::ExternalIo {
                location: "f".into(),
            },
        ];

        let mut sandbox = ExecutionSandbox::new(SandboxMode::Warn);
        sandbox.enter();
        for v in violations {
            let _ = sandbox.report_violation(v);
        }
        assert_eq!(sandbox.violations().len(), 6);
    }

    #[test]
    fn test_sandbox_builder() {
        let sandbox = SandboxBuilder::new()
            .mode(SandboxMode::Strict)
            .build();
        assert_eq!(sandbox.mode(), SandboxMode::Strict);
    }
}
