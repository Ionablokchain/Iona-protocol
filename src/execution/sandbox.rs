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
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────────────────┐
//! │                          Sandbox Module                                │
//! ├─────────────┬──────────────┬───────────────┬──────────────────────────┤
//! │   config    │    error     │     types     │        context           │
//! │ (SandboxCfg)│ (SandboxErr) │ (Violation,   │ (ExecutionContext)       │
//! │             │              │  Report)      │                          │
//! ├─────────────┼──────────────┼───────────────┼──────────────────────────┤
//! │   sandbox   │    audit     │    metrics    │        manager           │
//! │ (Sandbox)   │ (source audit)│ (metrics)    │ (SandboxManager)         │
//! └─────────────────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::sandbox::{SandboxManager, SandboxConfig, SandboxMode, ExecutionContext};
//!
//! let config = SandboxConfig::default();
//! let manager = SandboxManager::new(config);
//! let mut sandbox = manager.create();
//! let ctx = ExecutionContext::from_block(height, timestamp, block_hash, chain_id, base_fee, proposer);
//! sandbox.enter(&ctx)?;
//! // ... execute block ...
//! let report = sandbox.exit();
//! if !report.is_clean() {
//!     eprintln!("{}", report);
//! }
//! ```

#![allow(dead_code)]

use crate::types::{Hash32, Height};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Submodules (embedded)
// -----------------------------------------------------------------------------

pub mod config {
    //! Configuration for the execution sandbox.
    use serde::{Deserialize, Serialize};
    use super::types::SandboxMode;

    /// Configuration for the execution sandbox.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxConfig {
        pub mode: SandboxMode,
        pub log_violations: bool,
        pub max_violations: usize,
        pub include_stack_traces: bool,
        pub track_timing: bool,
        pub enforce_deterministic_collections: bool,
        pub enforce_no_floats: bool,
        pub enforce_no_io: bool,
        pub collect_metrics: bool,
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
                collect_metrics: true,
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
                collect_metrics: true,
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
                collect_metrics: true,
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
                collect_metrics: false,
            }
        }

        pub fn validate(&self) -> Result<(), &'static str> {
            if self.max_violations == 0 && self.mode != SandboxMode::Disabled {
                return Err("max_violations must be > 0 when mode is not Disabled");
            }
            Ok(())
        }

        pub fn with_mode(mut self, mode: SandboxMode) -> Self {
            self.mode = mode;
            self
        }

        pub fn with_metrics(mut self) -> Self {
            self.collect_metrics = true;
            self
        }
    }
}

pub mod error {
    //! Error types for the sandbox.
    use thiserror::Error;

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
}

pub mod types {
    //! Core types for the sandbox.
    use serde::{Deserialize, Serialize};
    use crate::types::{Hash32, Height};

    /// Sandbox enforcement mode.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SandboxMode {
        Strict,
        Warn,
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

    /// Violations detected during sandbox execution.
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub enum SandboxViolation {
        SystemTimeAccess { location: String },
        NonDeterministicRng { location: String },
        UnorderedCollection { location: String },
        FloatingPoint { location: String },
        ThreadSpawn { location: String },
        ExternalIo { location: String },
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

    /// Report from a sandbox execution.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxReport {
        pub clean: bool,
        pub violation_count: usize,
        pub violations: Vec<SandboxViolation>,
        pub execution_time_ms: Option<u64>,
        pub mode: SandboxMode,
    }

    impl SandboxReport {
        pub fn is_clean(&self) -> bool {
            self.clean
        }

        pub fn violations(&self) -> &[SandboxViolation] {
            &self.violations
        }

        pub fn violation_count(&self) -> usize {
            self.violation_count
        }
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

    /// Execution context providing deterministic alternatives.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct ExecutionContext {
        pub height: Height,
        pub timestamp: u64,
        pub deterministic_seed: [u8; 32],
        pub block_hash: Hash32,
        pub chain_id: u64,
        pub base_fee_per_gas: u64,
        pub proposer: String,
        pub extra: Vec<u8>,
    }

    impl ExecutionContext {
        /// Create a new execution context from block data.
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
            let height_bytes = height.as_u64().to_le_bytes();
            for i in 0..8 {
                seed[i] = seed[i].wrapping_add(height_bytes[i]).wrapping_mul(0x9E);
            }
            for (i, &b) in extra.iter().enumerate() {
                let idx = i % 32;
                seed[idx] = seed[idx].wrapping_add(b).wrapping_mul(0x6D);
            }
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

        pub fn deterministic_random_u64(&self, index: u64) -> u64 {
            let bytes = self.deterministic_random(index);
            u64::from_le_bytes(bytes[0..8].try_into().unwrap())
        }

        pub fn deterministic_random_u32(&self, index: u64) -> u32 {
            let bytes = self.deterministic_random(index);
            u32::from_le_bytes(bytes[0..4].try_into().unwrap())
        }
    }
}

pub mod sandbox {
    //! Core sandbox implementation.
    use super::{
        config::SandboxConfig,
        error::{SandboxError, SandboxResult},
        types::{SandboxViolation, SandboxReport, SandboxMode, ExecutionContext},
    };
    use std::time::Instant;
    use tracing::{debug, warn};

    /// Execution sandbox that wraps block execution with determinism guards.
    pub struct Sandbox {
        config: SandboxConfig,
        violations: Vec<SandboxViolation>,
        active: bool,
        start_time: Option<Instant>,
        context: Option<ExecutionContext>,
    }

    impl Sandbox {
        pub fn new(config: SandboxConfig) -> Self {
            Self {
                config,
                violations: Vec::with_capacity(config.max_violations.saturating_add(1)),
                active: false,
                start_time: None,
                context: None,
            }
        }

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

            if self.config.max_violations > 0 && self.violations.len() >= self.config.max_violations {
                return Ok(());
            }

            if self.config.log_violations {
                warn!("{}", violation);
            }

            self.violations.push(violation.clone());

            match self.config.mode {
                SandboxMode::Disabled | SandboxMode::Warn => Ok(()),
                SandboxMode::Strict => {
                    Err(SandboxError::Violation { violation: violation.to_string() })
                }
            }
        }

        /// Report a custom violation.
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

        /// Get a reference to the configuration.
        pub fn config(&self) -> &SandboxConfig {
            &self.config
        }
    }

    impl Default for Sandbox {
        fn default() -> Self {
            Self::new(SandboxConfig::default())
        }
    }
}

pub mod audit {
    //! Static analysis helpers for source code auditing.
    use serde::{Deserialize, Serialize};

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

    /// Run audit and return a summary.
    pub fn audit_summary(source: &str) -> String {
        let findings = audit_source_for_nondeterminism(source);
        if findings.is_empty() {
            "No nondeterminism patterns found.".to_string()
        } else {
            let mut s = format!("Found {} potential nondeterminism issues:\n", findings.len());
            for f in findings {
                s.push_str(&format!("  {}\n", f));
            }
            s
        }
    }
}

pub mod metrics {
    //! Metrics for the sandbox.
    use std::sync::atomic::{AtomicU64, Ordering};
    use serde::{Deserialize, Serialize};

    #[derive(Debug, Default)]
    pub struct SandboxMetrics {
        pub total_entries: AtomicU64,
        pub total_exits: AtomicU64,
        pub violations_total: AtomicU64,
        pub strict_violations: AtomicU64,
        pub warn_violations: AtomicU64,
        pub clean_exits: AtomicU64,
        pub dirty_exits: AtomicU64,
        pub execution_time_ms: AtomicU64,
    }

    impl SandboxMetrics {
        pub fn inc_entry(&self) {
            self.total_entries.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_exit(&self) {
            self.total_exits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn add_violation(&self, strict: bool) {
            self.violations_total.fetch_add(1, Ordering::Relaxed);
            if strict {
                self.strict_violations.fetch_add(1, Ordering::Relaxed);
            } else {
                self.warn_violations.fetch_add(1, Ordering::Relaxed);
            }
        }
        pub fn inc_clean(&self) {
            self.clean_exits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn inc_dirty(&self) {
            self.dirty_exits.fetch_add(1, Ordering::Relaxed);
        }
        pub fn add_time_ms(&self, ms: u64) {
            self.execution_time_ms.fetch_add(ms, Ordering::Relaxed);
        }

        pub fn snapshot(&self) -> SandboxMetricsSnapshot {
            SandboxMetricsSnapshot {
                total_entries: self.total_entries.load(Ordering::Relaxed),
                total_exits: self.total_exits.load(Ordering::Relaxed),
                violations_total: self.violations_total.load(Ordering::Relaxed),
                strict_violations: self.strict_violations.load(Ordering::Relaxed),
                warn_violations: self.warn_violations.load(Ordering::Relaxed),
                clean_exits: self.clean_exits.load(Ordering::Relaxed),
                dirty_exits: self.dirty_exits.load(Ordering::Relaxed),
                execution_time_ms: self.execution_time_ms.load(Ordering::Relaxed),
            }
        }
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    pub struct SandboxMetricsSnapshot {
        pub total_entries: u64,
        pub total_exits: u64,
        pub violations_total: u64,
        pub strict_violations: u64,
        pub warn_violations: u64,
        pub clean_exits: u64,
        pub dirty_exits: u64,
        pub execution_time_ms: u64,
    }
}

pub mod manager {
    //! Centralised manager for sandboxes.
    use super::{
        config::SandboxConfig,
        error::SandboxResult,
        sandbox::Sandbox,
        metrics::SandboxMetrics,
        types::{ExecutionContext, SandboxReport},
    };
    use std::sync::Arc;

    /// Manager for sandbox creation and tracking.
    pub struct SandboxManager {
        config: SandboxConfig,
        metrics: Arc<SandboxMetrics>,
    }

    impl SandboxManager {
        pub fn new(config: SandboxConfig) -> Self {
            config.validate().expect("invalid SandboxConfig");
            Self {
                config,
                metrics: Arc::new(SandboxMetrics::default()),
            }
        }

        pub fn default() -> Self {
            Self::new(SandboxConfig::default())
        }

        /// Create a new sandbox using the manager's configuration.
        pub fn create(&self) -> Sandbox {
            Sandbox::new(self.config.clone())
        }

        /// Create a sandbox, enter it, and execute a closure.
        pub fn run<F, R>(&self, ctx: ExecutionContext, f: F) -> SandboxResult<(R, SandboxReport)>
        where
            F: FnOnce(&mut Sandbox) -> SandboxResult<R>,
        {
            let mut sandbox = self.create();
            sandbox.enter(ctx)?;
            self.metrics.inc_entry();
            let result = f(&mut sandbox);
            let report = sandbox.exit();
            self.metrics.inc_exit();
            if report.clean {
                self.metrics.inc_clean();
            } else {
                self.metrics.inc_dirty();
                for _ in &report.violations {
                    self.metrics.add_violation(report.mode == super::types::SandboxMode::Strict);
                }
            }
            if let Some(ms) = report.execution_time_ms {
                self.metrics.add_time_ms(ms);
            }
            match result {
                Ok(v) => Ok((v, report)),
                Err(e) => Err(e),
            }
        }

        /// Get a reference to the metrics.
        pub fn metrics(&self) -> &SandboxMetrics {
            &self.metrics
        }

        /// Get the configuration.
        pub fn config(&self) -> &SandboxConfig {
            &self.config
        }

        /// Reset metrics.
        pub fn reset_metrics(&self) {
            *self.metrics = SandboxMetrics::default();
        }
    }
}

// -----------------------------------------------------------------------------
// Public exports
// -----------------------------------------------------------------------------

pub use config::SandboxConfig;
pub use error::{SandboxError, SandboxResult};
pub use types::{SandboxMode, SandboxViolation, SandboxReport, ExecutionContext};
pub use sandbox::Sandbox;
pub use audit::{SourceAuditFinding, audit_source_for_nondeterminism, audit_summary};
pub use metrics::{SandboxMetrics, SandboxMetricsSnapshot};
pub use manager::SandboxManager;

// -----------------------------------------------------------------------------
// Legacy global functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Create a default sandbox (legacy).
pub fn new_sandbox() -> Sandbox {
    Sandbox::default()
}

/// Create a sandbox with configuration (legacy).
pub fn new_sandbox_with_config(config: SandboxConfig) -> Sandbox {
    Sandbox::new(config)
}

/// Audit source code (legacy).
pub fn audit_source(source: &str) -> Vec<SourceAuditFinding> {
    audit_source_for_nondeterminism(source)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Hash32, Height};

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
    fn test_sandbox_strict_mode() {
        let mut sandbox = Sandbox::new(SandboxConfig {
            mode: SandboxMode::Strict,
            log_violations: false,
            ..Default::default()
        });
        sandbox.enter(ExecutionContext::from_block(
            Height::new(1), 1000, Hash32([0; 32]), 1, 1, "p".into(),
        )).unwrap();
        let result = sandbox.report_violation(SandboxViolation::SystemTimeAccess {
            location: "block_exec.rs:42".into(),
        });
        assert!(result.is_err());
        let report = sandbox.exit();
        assert!(!report.clean);
        assert_eq!(report.violation_count, 1);
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
    fn test_audit_source() {
        let code = r#"
            let map: HashMap<String, u64> = HashMap::new();
            let now = SystemTime::now();
            let r = thread_rng();
        "#;
        let findings = audit_source_for_nondeterminism(code);
        assert!(findings.len() >= 3);
    }

    #[test]
    fn test_manager_run() {
        let config = SandboxConfig {
            mode: SandboxMode::Warn,
            log_violations: false,
            ..Default::default()
        };
        let manager = SandboxManager::new(config);
        let ctx = ExecutionContext::from_block(
            Height::new(1), 1000, Hash32([0; 32]), 1, 1, "p".into(),
        );
        let (result, report) = manager.run(ctx, |sandbox| {
            sandbox.report_custom("test", "test.rs:10")?;
            Ok(42)
        }).unwrap();
        assert_eq!(result, 42);
        assert!(!report.clean);
        assert_eq!(report.violation_count, 1);
        let metrics = manager.metrics().snapshot();
        assert_eq!(metrics.total_entries, 1);
        assert_eq!(metrics.total_exits, 1);
        assert_eq!(metrics.violations_total, 1);
        assert_eq!(metrics.dirty_exits, 1);
    }
}
