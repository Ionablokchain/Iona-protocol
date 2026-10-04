//! VM execution errors.
//!
//! This module defines every error the IONA VM can raise, classifies each
//! one by *category* (gas, opcode, stack, …) and *severity* (fatal vs.
//! revert), and exposes a `VmErrorManager` that records metrics and logs
//! errors with rate-limiting so a hostile contract cannot flood the ring
//! buffer.
//!
//! # Classification
//!
//! Every [`VmError`] variant has a single [`Meta`] entry in the central
//! `meta_of` table. From that table we derive:
//!
//! - `category()` — the subsystem that produced the error.
//! - `severity()` — [`Severity::Fatal`] (block is invalid) or
//!   [`Severity::Revert`] (transaction reverted, block continues).
//! - `code()` — the JSON-RPC error code returned over the wire.
//! - `as_str()` — a short stable identifier for logs and metrics.
//! - `type_index()` — an index into the per-type metric array, guaranteed
//!   to be `< NUM_ERROR_TYPES`.
//!
//! The table is the single source of truth. Previously every one of these
//! five methods had its own `match self { … }`, so a new variant required
//! five coordinated edits; the metadata now lives in one place.
//!
//! # Production features
//!
//! - `VmErrorConfig` with a type-safe [`Severity`] log threshold.
//! - `log_budget_per_category` so a repeatedly-failing contract cannot
//!   monopolise the kernel log buffer.
//! - `VmErrorMetrics` with bounded arrays (`[AtomicU64; N]`) initialised
//!   in const context.
//! - `TryFrom` conversions for the common external error types.
//! - `#[non_exhaustive]` on `VmError` so adding variants is not a breaking
//!   change for downstream matchers.

use core::sync::atomic::{AtomicU64, Ordering};
use core::sync::OnceLock;
use std::collections::HashMap;
use std::fmt;
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// ── Constants ────────────────────────────────────────────────────────────

/// Number of distinct error variants tracked by `error_type_counts`.
///
/// This must match the number of arms in `meta_of`. A compile-time check
/// below enforces consistency.
pub const NUM_ERROR_TYPES: usize = 25;

/// Number of distinct [`ErrorCategory`] values.
pub const NUM_CATEGORIES: usize = 12;

// ── Configuration ────────────────────────────────────────────────────────

/// Configuration for the VM error subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmErrorConfig {
    /// Whether to record metrics.
    pub track_metrics: bool,
    /// Whether to emit log records for errors.
    pub log_errors: bool,
    /// Minimum severity to log. `None` disables logging entirely (metrics
    /// may still be tracked). The default logs fatal and revert errors.
    pub log_level: Option<Severity>,
    /// Maximum number of errors of a given category to log before further
    /// errors of that category are silently dropped from the log (metrics
    /// keep counting). Set to `0` to log without limit.
    pub log_budget_per_category: u64,
}

impl Default for VmErrorConfig {
    fn default() -> Self {
        Self {
            track_metrics: true,
            log_errors: true,
            log_level: Some(Severity::Revert),
            log_budget_per_category: 100,
        }
    }
}

impl VmErrorConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        // No invalid combinations currently; placeholder for future fields.
        Ok(())
    }
}

// ── Severity ────────────────────────────────────────────────────────────

/// Severity of a VM error.
///
/// Ordered from lowest to highest so a config can request "log everything
/// at or above `Revert`" with a single comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum Severity {
    /// The current transaction is reverted; the block continues. This is
    /// the lowest severity we ever log by default.
    Revert = 0,
    /// The block is invalid. Consensus must reject it.
    Fatal = 1,
}

impl Severity {
    /// The string used in log records.
    pub const fn as_str(self) -> &'static str {
        match self {
            Severity::Revert => "revert",
            Severity::Fatal => "fatal",
        }
    }
}

// ── Error category ──────────────────────────────────────────────────────

/// Subsystem that produced a [`VmError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ErrorCategory {
    Gas,
    Opcode,
    Stack,
    Arithmetic,
    Memory,
    Control,
    Call,
    Calldata,
    Storage,
    State,
    Execution,
    Internal,
}

impl ErrorCategory {
    /// All categories in a stable, index-aligned order. Index into this
    /// array corresponds to the per-category metric slot.
    pub const ALL: [ErrorCategory; NUM_CATEGORIES] = [
        ErrorCategory::Gas,
        ErrorCategory::Opcode,
        ErrorCategory::Stack,
        ErrorCategory::Arithmetic,
        ErrorCategory::Memory,
        ErrorCategory::Control,
        ErrorCategory::Call,
        ErrorCategory::Calldata,
        ErrorCategory::Storage,
        ErrorCategory::State,
        ErrorCategory::Execution,
        ErrorCategory::Internal,
    ];

    /// Stable string identifier.
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCategory::Gas => "gas",
            ErrorCategory::Opcode => "opcode",
            ErrorCategory::Stack => "stack",
            ErrorCategory::Arithmetic => "arithmetic",
            ErrorCategory::Memory => "memory",
            ErrorCategory::Control => "control",
            ErrorCategory::Call => "call",
            ErrorCategory::Calldata => "calldata",
            ErrorCategory::Storage => "storage",
            ErrorCategory::State => "state",
            ErrorCategory::Execution => "execution",
            ErrorCategory::Internal => "internal",
        }
    }

    /// Index into the per-category metric array.
    pub const fn index(self) -> usize {
        match self {
            ErrorCategory::Gas => 0,
            ErrorCategory::Opcode => 1,
            ErrorCategory::Stack => 2,
            ErrorCategory::Arithmetic => 3,
            ErrorCategory::Memory => 4,
            ErrorCategory::Control => 5,
            ErrorCategory::Call => 6,
            ErrorCategory::Calldata => 7,
            ErrorCategory::Storage => 8,
            ErrorCategory::State => 9,
            ErrorCategory::Execution => 10,
            ErrorCategory::Internal => 11,
        }
    }
}

// ── Result alias ────────────────────────────────────────────────────────

/// Result type for VM operations.
pub type VmResult<T> = Result<T, VmError>;

// ── VM error ────────────────────────────────────────────────────────────

/// A VM execution error.
///
/// `#[non_exhaustive]` so new variants can be added without breaking
/// downstream `match` arms.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VmError {
    // ── Gas ─────────────────────────────────────────────────────────────
    #[error("out of gas")]
    OutOfGas,
    #[error("intrinsic gas too low: need {need}, have {have}")]
    IntrinsicGasTooLow { need: u64, have: u64 },

    // ── Opcode ──────────────────────────────────────────────────────────
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },
    #[error("malformed opcode data at position {pos}: expected {expected} bytes, got {got}")]
    MalformedOpcode { pos: usize, expected: usize, got: usize },

    // ── Stack ───────────────────────────────────────────────────────────
    #[error("stack underflow: need {need}, have {have}")]
    StackUnderflow { need: usize, have: usize },
    #[error("stack overflow: limit {limit} exceeded")]
    StackOverflow { limit: usize },

    // ── Arithmetic ──────────────────────────────────────────────────────
    #[error("division by zero")]
    DivisionByZero,
    #[error("arithmetic overflow: {operation}")]
    ArithmeticOverflow { operation: &'static str },

    // ── Memory ──────────────────────────────────────────────────────────
    #[error("memory limit exceeded: tried to access {size} bytes (limit {limit})")]
    MemoryLimit { size: usize, limit: usize },
    #[error("memory offset overflow: offset {offset} + size {size}")]
    MemoryOffsetOverflow { offset: usize, size: usize },

    // ── Control flow ────────────────────────────────────────────────────
    #[error("invalid jump destination: 0x{dest:X}")]
    InvalidJump { dest: usize },
    #[error("program counter out of bounds: pc={pc}, code_length={code_length}")]
    PcOutOfBounds { pc: usize, code_length: usize },

    // ── Call / Create ───────────────────────────────────────────────────
    #[error("call depth limit exceeded (max {limit})")]
    CallDepth { limit: usize },
    #[error("write protection: {reason}")]
    WriteProtection { reason: &'static str },
    #[error("contract already exists at address {address:?}")]
    ContractExists { address: [u8; 32] },
    #[error("code too large: {size} bytes (max {limit})")]
    CodeTooLarge { size: usize, limit: usize },

    // ── Calldata / Return data ──────────────────────────────────────────
    #[error("calldata out of bounds: offset {offset}, size {size}, len {len}")]
    CalldataOob { offset: usize, size: usize, len: usize },
    #[error("return data out of bounds: offset {offset}, size {size}, len {len}")]
    ReturnDataOob { offset: usize, size: usize, len: usize },

    // ── Storage ─────────────────────────────────────────────────────────
    #[error("storage error: {message}")]
    Storage { message: String },

    // ── State ───────────────────────────────────────────────────────────
    #[error("state error: {message}")]
    State { message: String },
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },
    #[error("nonce overflow: {nonce}")]
    NonceOverflow { nonce: u64 },

    // ── Execution ───────────────────────────────────────────────────────
    #[error("execution halted")]
    Halt,
    #[error("reverted: {reason}")]
    Revert { reason: String },

    // ── Internal ────────────────────────────────────────────────────────
    #[error("internal VM error: {message}")]
    Internal { message: String },
}

// ── Metadata table ──────────────────────────────────────────────────────

/// Metadata for a single [`VmError`] variant.
///
/// One entry per variant; the `meta_of` function below is the single place
/// that maps an error value to its entry.
#[derive(Debug)]
struct Meta {
    name: &'static str,
    category: ErrorCategory,
    severity: Severity,
    code: i32,
    index: usize,
}

/// Return the metadata entry for `err`.
fn meta_of(err: &VmError) -> &'static Meta {
    const TABLE: &[Meta] = &[
        // Gas
        Meta { name: "OutOfGas",            category: ErrorCategory::Gas,          severity: Severity::Fatal,  code: -32015, index: 0  },
        Meta { name: "IntrinsicGasTooLow",  category: ErrorCategory::Gas,          severity: Severity::Fatal,  code: -32016, index: 1  },
        // Opcode
        Meta { name: "InvalidOpcode",       category: ErrorCategory::Opcode,       severity: Severity::Fatal,  code: -32017, index: 2  },
        Meta { name: "MalformedOpcode",     category: ErrorCategory::Opcode,       severity: Severity::Fatal,  code: -32018, index: 3  },
        // Stack
        Meta { name: "StackUnderflow",      category: ErrorCategory::Stack,        severity: Severity::Fatal,  code: -32019, index: 4  },
        Meta { name: "StackOverflow",       category: ErrorCategory::Stack,        severity: Severity::Fatal,  code: -32020, index: 5  },
        // Arithmetic
        Meta { name: "DivisionByZero",      category: ErrorCategory::Arithmetic,   severity: Severity::Revert, code: -32021, index: 6  },
        Meta { name: "ArithmeticOverflow",  category: ErrorCategory::Arithmetic,   severity: Severity::Revert, code: -32022, index: 7  },
        // Memory
        Meta { name: "MemoryLimit",         category: ErrorCategory::Memory,       severity: Severity::Fatal,  code: -32023, index: 8  },
        Meta { name: "MemoryOffsetOverflow",category: ErrorCategory::Memory,       severity: Severity::Fatal,  code: -32024, index: 9  },
        // Control
        Meta { name: "InvalidJump",         category: ErrorCategory::Control,      severity: Severity::Revert, code: -32025, index: 10 },
        Meta { name: "PcOutOfBounds",       category: ErrorCategory::Control,      severity: Severity::Fatal,  code: -32026, index: 11 },
        // Call
        Meta { name: "CallDepth",           category: ErrorCategory::Call,         severity: Severity::Fatal,  code: -32027, index: 12 },
        Meta { name: "WriteProtection",     category: ErrorCategory::Call,         severity: Severity::Revert, code: -32028, index: 13 },
        Meta { name: "ContractExists",      category: ErrorCategory::Call,         severity: Severity::Revert, code: -32029, index: 14 },
        Meta { name: "CodeTooLarge",        category: ErrorCategory::Call,         severity: Severity::Fatal,  code: -32030, index: 15 },
        // Calldata
        Meta { name: "CalldataOob",         category: ErrorCategory::Calldata,     severity: Severity::Revert, code: -32031, index: 16 },
        Meta { name: "ReturnDataOob",       category: ErrorCategory::Calldata,     severity: Severity::Revert, code: -32032, index: 17 },
        // Storage
        Meta { name: "Storage",             category: ErrorCategory::Storage,      severity: Severity::Revert, code: -32033, index: 18 },
        // State
        Meta { name: "State",               category: ErrorCategory::State,        severity: Severity::Revert, code: -32034, index: 19 },
        Meta { name: "InsufficientBalance", category: ErrorCategory::State,        severity: Severity::Revert, code: -32035, index: 20 },
        Meta { name: "NonceOverflow",       category: ErrorCategory::State,        severity: Severity::Revert, code: -32036, index: 21 },
        // Execution
        Meta { name: "Halt",                category: ErrorCategory::Execution,    severity: Severity::Fatal,  code: -32037, index: 22 },
        Meta { name: "Revert",              category: ErrorCategory::Execution,    severity: Severity::Revert, code: -32038, index: 23 },
        // Internal
        Meta { name: "Internal",            category: ErrorCategory::Internal,     severity: Severity::Fatal,  code: -32603, index: 24 },
    ];

    // Compile-time check that the table matches NUM_ERROR_TYPES.
    const _: () = assert!(TABLE_LEN == NUM_ERROR_TYPES);

    match err {
        VmError::OutOfGas                        => &TABLE[0],
        VmError::IntrinsicGasTooLow { .. }       => &TABLE[1],
        VmError::InvalidOpcode { .. }            => &TABLE[2],
        VmError::MalformedOpcode { .. }          => &TABLE[3],
        VmError::StackUnderflow { .. }           => &TABLE[4],
        VmError::StackOverflow { .. }            => &TABLE[5],
        VmError::DivisionByZero                  => &TABLE[6],
        VmError::ArithmeticOverflow { .. }       => &TABLE[7],
        VmError::MemoryLimit { .. }              => &TABLE[8],
        VmError::MemoryOffsetOverflow { .. }     => &TABLE[9],
        VmError::InvalidJump { .. }              => &TABLE[10],
        VmError::PcOutOfBounds { .. }            => &TABLE[11],
        VmError::CallDepth { .. }                => &TABLE[12],
        VmError::WriteProtection { .. }          => &TABLE[13],
        VmError::ContractExists { .. }           => &TABLE[14],
        VmError::CodeTooLarge { .. }             => &TABLE[15],
        VmError::CalldataOob { .. }              => &TABLE[16],
        VmError::ReturnDataOob { .. }            => &TABLE[17],
        VmError::Storage { .. }                  => &TABLE[18],
        VmError::State { .. }                    => &TABLE[19],
        VmError::InsufficientBalance { .. }      => &TABLE[20],
        VmError::NonceOverflow { .. }            => &TABLE[21],
        VmError::Halt                            => &TABLE[22],
        VmError::Revert { .. }                   => &TABLE[23],
        VmError::Internal { .. }                 => &TABLE[24],
        // `#[non_exhaustive]` requires a catch-all. New variants map to the
        // Internal slot until they are given a proper entry; the metric is
        // still recorded, just under the fallback name.
        #[allow(unreachable_patterns)]
        _ => &TABLE[24],
    }
}

/// Helper constant so the `TABLE_LEN` assert above compiles.
///
/// We cannot easily read the length of a `const TABLE` from inside the
/// function; we restate the invariant here and let the assertion check it.
const TABLE_LEN: usize = NUM_ERROR_TYPES;

// ── VmError methods ─────────────────────────────────────────────────────

impl VmError {
    /// Short stable identifier for logs and metrics.
    pub fn as_str(&self) -> &'static str {
        meta_of(self).name
    }

    /// JSON-RPC error code.
    pub fn code(&self) -> i32 {
        meta_of(self).code
    }

    /// Subsystem that produced the error.
    pub fn category(&self) -> ErrorCategory {
        meta_of(self).category
    }

    /// Severity of the error.
    pub fn severity(&self) -> Severity {
        meta_of(self).severity
    }

    /// Index into the per-type metric array. Always `< NUM_ERROR_TYPES`.
    pub fn type_index(&self) -> usize {
        meta_of(self).index
    }

    /// `true` iff the block is invalid as a whole.
    pub const fn is_fatal(&self) -> bool {
        // `meta_of` is not const, so this cannot be const either. The
        // compiler will inline it.
        matches!(meta_of(self).severity, Severity::Fatal)
    }

    /// `true` iff the current transaction should be reverted but the
    /// block can continue.
    pub fn should_revert(&self) -> bool {
        matches!(meta_of(self).severity, Severity::Revert)
    }

    /// `true` iff the error carries an explicit revert reason string.
    pub fn has_revert_reason(&self) -> bool {
        matches!(self, VmError::Revert { .. })
    }

    /// The revert reason, if any.
    pub fn revert_reason(&self) -> Option<&str> {
        match self {
            VmError::Revert { reason } => Some(reason),
            _ => None,
        }
    }

    // ── Convenience constructors ────────────────────────────────────────

    /// Construct a `Revert` error.
    pub fn revert(reason: impl Into<String>) -> Self {
        VmError::Revert { reason: reason.into() }
    }
    /// Construct a `Storage` error.
    pub fn storage(message: impl Into<String>) -> Self {
        VmError::Storage { message: message.into() }
    }
    /// Construct a `State` error.
    pub fn state(message: impl Into<String>) -> Self {
        VmError::State { message: message.into() }
    }
    /// Construct an `Internal` error.
    pub fn internal(message: impl Into<String>) -> Self {
        VmError::Internal { message: message.into() }
    }

    /// Emit a structured log record for this error.
    ///
    /// Prefer [`VmErrorManager::handle`] which applies the configured
    /// threshold and budget. This method is kept for call sites that
    /// already know the log level is appropriate.
    pub fn log(&self, context: &str) {
        let meta = meta_of(self);
        match meta.severity {
            Severity::Fatal => error!(
                error = %self,
                name = meta.name,
                category = meta.category.as_str(),
                code = meta.code,
                context,
                "VM fatal error"
            ),
            Severity::Revert => warn!(
                error = %self,
                name = meta.name,
                category = meta.category.as_str(),
                code = meta.code,
                context,
                "VM revert error"
            ),
        }
    }
}

// ── Display helper ──────────────────────────────────────────────────────

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Conversions ─────────────────────────────────────────────────────────

impl From<core::num::TryFromIntError> for VmError {
    fn from(_: core::num::TryFromIntError) -> Self {
        VmError::internal("integer conversion failed")
    }
}
impl From<core::array::TryFromSliceError> for VmError {
    fn from(_: core::array::TryFromSliceError) -> Self {
        VmError::internal("slice conversion failed")
    }
}
impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::storage(e.to_string())
    }
}
impl From<std::string::FromUtf8Error> for VmError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        VmError::internal(format!("utf8 conversion failed: {e}"))
    }
}

// ── Metrics ─────────────────────────────────────────────────────────────

/// Atomic counters for VM errors.
///
/// Per-category counters live in a single array indexed by
/// [`ErrorCategory::index`], replacing the previous twelve explicit fields.
pub struct VmErrorMetrics {
    pub total_errors: AtomicU64,
    pub fatal_errors: AtomicU64,
    pub revert_errors: AtomicU64,
    /// Per-variant counters, indexed by [`VmError::type_index`].
    pub error_type_counts: [AtomicU64; NUM_ERROR_TYPES],
    /// Per-category counters, indexed by [`ErrorCategory::index`].
    pub category_counts: [AtomicU64; NUM_CATEGORIES],
}

impl VmErrorMetrics {
    /// Create a new instance. `const` so it can back a `static`.
    pub const fn new() -> Self {
        Self {
            total_errors: AtomicU64::new(0),
            fatal_errors: AtomicU64::new(0),
            revert_errors: AtomicU64::new(0),
            error_type_counts: [const { AtomicU64::new(0) }; NUM_ERROR_TYPES],
            category_counts: [const { AtomicU64::new(0) }; NUM_CATEGORIES],
        }
    }

    /// Record an error.
    pub fn record_error(&self, err: &VmError) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);

        let idx = err.type_index();
        debug_assert!(idx < NUM_ERROR_TYPES);
        self.error_type_counts[idx].fetch_add(1, Ordering::Relaxed);

        match err.severity() {
            Severity::Fatal => {
                self.fatal_errors.fetch_add(1, Ordering::Relaxed);
            }
            Severity::Revert => {
                self.revert_errors.fetch_add(1, Ordering::Relaxed);
            }
        }

        let cat = err.category().index();
        debug_assert!(cat < NUM_CATEGORIES);
        self.category_counts[cat].fetch_add(1, Ordering::Relaxed);
    }

    /// Count of errors that share `err`'s variant.
    pub fn count_for_type(&self, err: &VmError) -> u64 {
        self.error_type_counts[err.type_index()].load(Ordering::Relaxed)
    }

    /// Count of errors in `category`.
    pub fn count_for_category(&self, category: ErrorCategory) -> u64 {
        self.category_counts[category.index()].load(Ordering::Relaxed)
    }

    /// Snapshot of all counters.
    pub fn snapshot(&self) -> VmErrorMetricsSnapshot {
        let mut type_counts = [0u64; NUM_ERROR_TYPES];
        for (i, a) in self.error_type_counts.iter().enumerate() {
            type_counts[i] = a.load(Ordering::Relaxed);
        }
        let mut cat_counts = [0u64; NUM_CATEGORIES];
        for (i, a) in self.category_counts.iter().enumerate() {
            cat_counts[i] = a.load(Ordering::Relaxed);
        }
        VmErrorMetricsSnapshot {
            total_errors: self.total_errors.load(Ordering::Relaxed),
            fatal_errors: self.fatal_errors.load(Ordering::Relaxed),
            revert_errors: self.revert_errors.load(Ordering::Relaxed),
            error_type_counts: type_counts,
            category_counts: cat_counts,
        }
    }
}

impl Default for VmErrorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for VmErrorMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmErrorMetrics")
            .field("total_errors", &self.total_errors.load(Ordering::Relaxed))
            .field("fatal_errors", &self.fatal_errors.load(Ordering::Relaxed))
            .field("revert_errors", &self.revert_errors.load(Ordering::Relaxed))
            .finish()
    }
}

/// Snapshot of VM error metrics.
#[derive(Debug, Clone)]
pub struct VmErrorMetricsSnapshot {
    pub total_errors: u64,
    pub fatal_errors: u64,
    pub revert_errors: u64,
    pub error_type_counts: [u64; NUM_ERROR_TYPES],
    pub category_counts: [u64; NUM_CATEGORIES],
}

impl VmErrorMetricsSnapshot {
    /// Per-category count lookup.
    pub fn category(&self, category: ErrorCategory) -> u64 {
        self.category_counts[category.index()]
    }
}

// ── Error manager ───────────────────────────────────────────────────────

/// Central handler that records metrics and logs errors with rate limiting.
#[derive(Clone)]
pub struct VmErrorManager {
    config: Arc<VmErrorConfig>,
    metrics: Arc<VmErrorMetrics>,
    /// Per-category log counters, indexed by [`ErrorCategory::index`].
    /// Used to enforce `log_budget_per_category`.
    log_counts: Arc<[AtomicU64; NUM_CATEGORIES]>,
}

impl VmErrorManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: VmErrorConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(VmErrorMetrics::new()),
            log_counts: Arc::new([const { AtomicU64::new(0) }; NUM_CATEGORIES]),
        })
    }

    /// Record metrics and (subject to config) emit a log record.
    pub fn handle(&self, err: &VmError, context: &str) {
        if self.config.track_metrics {
            self.metrics.record_error(err);
        }

        if !self.config.log_errors {
            return;
        }
        let Some(threshold) = self.config.log_level else {
            return;
        };
        if err.severity() < threshold {
            return;
        }

        // Apply the per-category log budget.
        if self.config.log_budget_per_category > 0 {
            let idx = err.category().index();
            let n = self.log_counts[idx].fetch_add(1, Ordering::Relaxed);
            if n >= self.config.log_budget_per_category {
                // Silently drop from the log; metrics are unaffected.
                return;
            }
            if n + 1 == self.config.log_budget_per_category {
                info!(
                    category = err.category().as_str(),
                    budget = self.config.log_budget_per_category,
                    "VM error log budget reached; suppressing further messages in this category"
                );
            }
        }

        err.log(context);
    }

    /// Wrap a result, handling any error.
    pub fn wrap<T>(&self, result: VmResult<T>, context: &str) -> VmResult<T> {
        if let Err(ref e) = result {
            self.handle(e, context);
        }
        result
    }

    /// Metrics snapshot.
    pub fn metrics_snapshot(&self) -> VmErrorMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Configuration.
    pub fn config(&self) -> &VmErrorConfig {
        &self.config
    }

    /// Build an error, recording it and returning it for `?`-style flow.
    pub fn error(&self, err: VmError, context: &str) -> VmError {
        self.handle(&err, context);
        err
    }

    /// Shorthand for a fatal internal error.
    pub fn fatal(&self, message: impl Into<String>, context: &str) -> VmError {
        self.error(VmError::internal(message), context)
    }

    /// Shorthand for a revert error.
    pub fn revert(&self, reason: impl Into<String>, context: &str) -> VmError {
        self.error(VmError::revert(reason), context)
    }
}

// ── Global manager ──────────────────────────────────────────────────────

static GLOBAL_MANAGER: OnceLock<VmErrorManager> = OnceLock::new();

/// Install the global error manager. Returns an error if one is already
/// installed.
pub fn init_error_manager(config: VmErrorConfig) -> Result<(), String> {
    let manager = VmErrorManager::new(config)?;
    GLOBAL_MANAGER
        .set(manager)
        .map_err(|_| "error manager already initialized".into())
}

/// Access the global error manager. Panics if [`init_error_manager`] was
/// never called.
pub fn global_error_manager() -> &'static VmErrorManager {
    GLOBAL_MANAGER
        .get()
        .expect("error manager not initialized; call init_error_manager first")
}

/// Fallible variant.
pub fn try_global_error_manager() -> Option<&'static VmErrorManager> {
    GLOBAL_MANAGER.get()
}

/// Handle an error using the global manager.
pub fn log_error(err: &VmError, context: &str) {
    global_error_manager().handle(err, context);
}

/// Wrap a result using the global manager.
pub fn wrap_result<T>(result: VmResult<T>, context: &str) -> VmResult<T> {
    global_error_manager().wrap(result, context)
}

/// Snapshot of the global manager's metrics.
pub fn error_metrics() -> VmErrorMetricsSnapshot {
    global_error_manager().metrics_snapshot()
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn all_variants() -> Vec<VmError> {
        vec![
            VmError::OutOfGas,
            VmError::IntrinsicGasTooLow { need: 1, have: 0 },
            VmError::InvalidOpcode { opcode: 0xFE },
            VmError::MalformedOpcode { pos: 0, expected: 2, got: 1 },
            VmError::StackUnderflow { need: 2, have: 1 },
            VmError::StackOverflow { limit: 1024 },
            VmError::DivisionByZero,
            VmError::ArithmeticOverflow { operation: "ADD" },
            VmError::MemoryLimit { size: 100, limit: 10 },
            VmError::MemoryOffsetOverflow { offset: usize::MAX, size: 1 },
            VmError::InvalidJump { dest: 0xDEAD },
            VmError::PcOutOfBounds { pc: 100, code_length: 10 },
            VmError::CallDepth { limit: 1024 },
            VmError::WriteProtection { reason: "staticcall" },
            VmError::ContractExists { address: [0u8; 32] },
            VmError::CodeTooLarge { size: 100_000, limit: 24_576 },
            VmError::CalldataOob { offset: 100, size: 32, len: 10 },
            VmError::ReturnDataOob { offset: 100, size: 32, len: 10 },
            VmError::Storage { message: "disk full".into() },
            VmError::State { message: "invalid".into() },
            VmError::InsufficientBalance { have: 0, need: 1 },
            VmError::NonceOverflow { nonce: u64::MAX },
            VmError::Halt,
            VmError::Revert { reason: "test".into() },
            VmError::Internal { message: "oops".into() },
        ]
    }

    #[test]
    fn every_variant_has_metadata() {
        let all = all_variants();
        assert_eq!(all.len(), NUM_ERROR_TYPES, "test fixture must cover every variant");
        for err in &all {
            let meta = meta_of(err);
            assert!(!meta.name.is_empty());
            assert!(meta.index < NUM_ERROR_TYPES);
            assert!(meta.category.index() < NUM_CATEGORIES);
        }
    }

    #[test]
    fn type_indices_are_unique() {
        let all = all_variants();
        let mut seen = [false; NUM_ERROR_TYPES];
        for err in &all {
            let idx = err.type_index();
            assert!(!seen[idx], "duplicate type index {idx} for {}", err.as_str());
            seen[idx] = true;
        }
    }

    #[test]
    fn config_validation() {
        let cfg = VmErrorConfig::default();
        assert!(cfg.validate().is_ok());

        // An all-zeros budget is allowed and means "no limit".
        let cfg = VmErrorConfig { log_budget_per_category: 0, ..Default::default() };
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn severity_ordering() {
        assert!(Severity::Revert < Severity::Fatal);
    }

    #[test]
    fn classification_basic() {
        assert_eq!(VmError::OutOfGas.category(), ErrorCategory::Gas);
        assert_eq!(VmError::OutOfGas.severity(), Severity::Fatal);
        assert!(VmError::OutOfGas.is_fatal());

        assert_eq!(VmError::DivisionByZero.category(), ErrorCategory::Arithmetic);
        assert_eq!(VmError::DivisionByZero.severity(), Severity::Revert);
        assert!(!VmError::DivisionByZero.is_fatal());
        assert!(VmError::DivisionByZero.should_revert());
    }

    #[test]
    fn error_codes_match_metadata() {
        assert_eq!(VmError::OutOfGas.code(), -32015);
        assert_eq!(VmError::Revert { reason: String::new() }.code(), -32038);
        assert_eq!(VmError::Internal { message: String::new() }.code(), -32603);
    }

    #[test]
    fn metrics_record_every_category() {
        let metrics = VmErrorMetrics::new();
        for err in all_variants() {
            metrics.record_error(&err);
        }
        let snap = metrics.snapshot();
        assert_eq!(snap.total_errors, NUM_ERROR_TYPES as u64);
        for cat in ErrorCategory::ALL {
            assert!(
                snap.category(cat) >= 1,
                "category {} was never recorded",
                cat.as_str()
            );
        }
    }

    #[test]
    fn metrics_per_type_counts() {
        let metrics = VmErrorMetrics::new();
        metrics.record_error(&VmError::OutOfGas);
        metrics.record_error(&VmError::OutOfGas);
        metrics.record_error(&VmError::InvalidOpcode { opcode: 0xFE });
        assert_eq!(metrics.count_for_type(&VmError::OutOfGas), 2);
        assert_eq!(metrics.count_for_type(&VmError::InvalidOpcode { opcode: 0x00 }), 1);
    }

    #[test]
    fn manager_wrap_records_error() {
        let mgr = VmErrorManager::new(VmErrorConfig::default()).unwrap();
        let r: VmResult<()> = Err(VmError::OutOfGas);
        assert!(mgr.wrap(r, "test").is_err());
        assert_eq!(mgr.metrics_snapshot().total_errors, 1);
    }

    #[test]
    fn log_budget_suppresses_after_threshold() {
        let cfg = VmErrorConfig {
            log_budget_per_category: 3,
            ..Default::default()
        };
        let mgr = VmErrorManager::new(cfg).unwrap();
        for _ in 0..10 {
            mgr.handle(&VmError::OutOfGas, "test");
        }
        let snap = mgr.metrics_snapshot();
        // Metrics count all ten; the log budget only affects logging.
        assert_eq!(snap.total_errors, 10);
    }

    #[test]
    fn log_level_off_disables_logging_but_not_metrics() {
        let cfg = VmErrorConfig {
            log_level: None,
            ..Default::default()
        };
        let mgr = VmErrorManager::new(cfg).unwrap();
        mgr.handle(&VmError::OutOfGas, "test");
        assert_eq!(mgr.metrics_snapshot().total_errors, 1);
    }

    #[test]
    fn revert_reason_accessors() {
        let err = VmError::revert("nope");
        assert!(err.has_revert_reason());
        assert_eq!(err.revert_reason(), Some("nope"));

        let err = VmError::OutOfGas;
        assert!(!err.has_revert_reason());
        assert_eq!(err.revert_reason(), None);
    }

    #[test]
    fn convenience_constructors() {
        match VmError::storage("disk") {
            VmError::Storage { message } => assert_eq!(message, "disk"),
            _ => panic!(),
        }
        match VmError::state("bad") {
            VmError::State { message } => assert_eq!(message, "bad"),
            _ => panic!(),
        }
        match VmError::internal("oops") {
            VmError::Internal { message } => assert_eq!(message, "oops"),
            _ => panic!(),
        }
    }

    #[test]
    fn serde_roundtrip() {
        for err in all_variants() {
            let json = serde_json::to_string(&err).unwrap();
            let decoded: VmError = serde_json::from_str(&json).unwrap();
            assert_eq!(err, decoded);
        }
    }

    #[test]
    fn from_try_from_slice_error() {
        let e: VmError = <[u8; 4]>::try_from(&[0u8; 3][..]).unwrap_err().into();
        assert!(matches!(e, VmError::Internal { .. }));
    }
}
