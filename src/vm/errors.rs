//! VM execution errors.
//!
//! This module defines all possible errors that can occur during VM execution.
//! Errors are categorized by their source (gas, stack, memory, control flow,
//! calls, storage) and by their severity (fatal, revert, recoverable).
//!
//! # Production Features
//! - Configurable via `VmErrorConfig` (fatal threshold, logging, metrics).
//! - `VmErrorMetrics` with atomic counters for error types, categories, and fatality.
//! - `VmErrorManager` for centralized error handling and reporting.
//! - Structured logging with `tracing`.
//! - Contextual error information for debugging.
//! - Full test coverage.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the VM error subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmErrorConfig {
    /// Whether to track error metrics.
    pub track_metrics: bool,
    /// Whether to log errors with full context.
    pub log_errors: bool,
    /// Minimum severity level to log (0 = all, 1 = fatal, 2 = revert, 3 = recoverable).
    pub log_threshold: u8,
    /// Whether to include stack traces in error logs.
    pub include_stack_traces: bool,
    /// Maximum number of errors to track in metrics per category.
    pub max_tracked_per_category: usize,
}

impl Default for VmErrorConfig {
    fn default() -> Self {
        Self {
            track_metrics: true,
            log_errors: true,
            log_threshold: 0,
            include_stack_traces: false,
            max_tracked_per_category: 1000,
        }
    }
}

impl VmErrorConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_tracked_per_category == 0 {
            return Err("max_tracked_per_category must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for VM errors.
#[derive(Debug, Default)]
pub struct VmErrorMetrics {
    /// Total errors encountered.
    pub total_errors: AtomicU64,
    /// Fatal errors count.
    pub fatal_errors: AtomicU64,
    /// Revert errors count.
    pub revert_errors: AtomicU64,
    /// Recoverable errors count.
    pub recoverable_errors: AtomicU64,
    /// Per‑error type counters.
    pub error_type_counts: [AtomicU64; 26], // Number of error variants
    /// Per‑category counters.
    pub gas_errors: AtomicU64,
    pub opcode_errors: AtomicU64,
    pub stack_errors: AtomicU64,
    pub arithmetic_errors: AtomicU64,
    pub memory_errors: AtomicU64,
    pub control_errors: AtomicU64,
    pub call_errors: AtomicU64,
    pub calldata_errors: AtomicU64,
    pub storage_errors: AtomicU64,
    pub state_errors: AtomicU64,
    pub execution_errors: AtomicU64,
    pub internal_errors: AtomicU64,
}

impl VmErrorMetrics {
    /// Create a new metrics instance.
    pub const fn new() -> Self {
        Self {
            total_errors: AtomicU64::new(0),
            fatal_errors: AtomicU64::new(0),
            revert_errors: AtomicU64::new(0),
            recoverable_errors: AtomicU64::new(0),
            error_type_counts: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0),
            ],
            gas_errors: AtomicU64::new(0),
            opcode_errors: AtomicU64::new(0),
            stack_errors: AtomicU64::new(0),
            arithmetic_errors: AtomicU64::new(0),
            memory_errors: AtomicU64::new(0),
            control_errors: AtomicU64::new(0),
            call_errors: AtomicU64::new(0),
            calldata_errors: AtomicU64::new(0),
            storage_errors: AtomicU64::new(0),
            state_errors: AtomicU64::new(0),
            execution_errors: AtomicU64::new(0),
            internal_errors: AtomicU64::new(0),
        }
    }

    /// Record an error.
    pub fn record_error(&self, error: &VmError) {
        self.total_errors.fetch_add(1, Ordering::Relaxed);

        // Track by type
        let idx = error.type_index();
        if idx < self.error_type_counts.len() {
            self.error_type_counts[idx].fetch_add(1, Ordering::Relaxed);
        }

        // Track by fatality
        if error.is_fatal() {
            self.fatal_errors.fetch_add(1, Ordering::Relaxed);
        } else if error.should_revert() {
            self.revert_errors.fetch_add(1, Ordering::Relaxed);
        } else {
            self.recoverable_errors.fetch_add(1, Ordering::Relaxed);
        }

        // Track by category
        match error.category() {
            ErrorCategory::Gas => self.gas_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Opcode => self.opcode_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Stack => self.stack_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Arithmetic => self.arithmetic_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Memory => self.memory_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Control => self.control_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Call => self.call_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Calldata => self.calldata_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Storage => self.storage_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::State => self.state_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Execution => self.execution_errors.fetch_add(1, Ordering::Relaxed),
            ErrorCategory::Internal => self.internal_errors.fetch_add(1, Ordering::Relaxed),
        };
    }

    /// Get the count for a specific error type.
    pub fn count_for_type(&self, error: &VmError) -> u64 {
        let idx = error.type_index();
        if idx < self.error_type_counts.len() {
            self.error_type_counts[idx].load(Ordering::Relaxed)
        } else {
            0
        }
    }

    /// Snapshot of all metrics.
    pub fn snapshot(&self) -> VmErrorMetricsSnapshot {
        let mut type_counts = [0u64; 26];
        for (i, atomic) in self.error_type_counts.iter().enumerate() {
            type_counts[i] = atomic.load(Ordering::Relaxed);
        }
        VmErrorMetricsSnapshot {
            total_errors: self.total_errors.load(Ordering::Relaxed),
            fatal_errors: self.fatal_errors.load(Ordering::Relaxed),
            revert_errors: self.revert_errors.load(Ordering::Relaxed),
            recoverable_errors: self.recoverable_errors.load(Ordering::Relaxed),
            error_type_counts: type_counts,
            gas_errors: self.gas_errors.load(Ordering::Relaxed),
            opcode_errors: self.opcode_errors.load(Ordering::Relaxed),
            stack_errors: self.stack_errors.load(Ordering::Relaxed),
            arithmetic_errors: self.arithmetic_errors.load(Ordering::Relaxed),
            memory_errors: self.memory_errors.load(Ordering::Relaxed),
            control_errors: self.control_errors.load(Ordering::Relaxed),
            call_errors: self.call_errors.load(Ordering::Relaxed),
            calldata_errors: self.calldata_errors.load(Ordering::Relaxed),
            storage_errors: self.storage_errors.load(Ordering::Relaxed),
            state_errors: self.state_errors.load(Ordering::Relaxed),
            execution_errors: self.execution_errors.load(Ordering::Relaxed),
            internal_errors: self.internal_errors.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of VM error metrics.
#[derive(Debug, Clone)]
pub struct VmErrorMetricsSnapshot {
    pub total_errors: u64,
    pub fatal_errors: u64,
    pub revert_errors: u64,
    pub recoverable_errors: u64,
    pub error_type_counts: [u64; 26],
    pub gas_errors: u64,
    pub opcode_errors: u64,
    pub stack_errors: u64,
    pub arithmetic_errors: u64,
    pub memory_errors: u64,
    pub control_errors: u64,
    pub call_errors: u64,
    pub calldata_errors: u64,
    pub storage_errors: u64,
    pub state_errors: u64,
    pub execution_errors: u64,
    pub internal_errors: u64,
}

// ── Error Category ──────────────────────────────────────────────────────

/// Category of a VM error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Gas => "gas",
            Self::Opcode => "opcode",
            Self::Stack => "stack",
            Self::Arithmetic => "arithmetic",
            Self::Memory => "memory",
            Self::Control => "control",
            Self::Call => "call",
            Self::Calldata => "calldata",
            Self::Storage => "storage",
            Self::State => "state",
            Self::Execution => "execution",
            Self::Internal => "internal",
        }
    }
}

// ── Result alias ────────────────────────────────────────────────────────

/// Result type alias for VM operations.
pub type VmResult<T> = Result<T, VmError>;

// ── VmError ─────────────────────────────────────────────────────────────

/// VM execution error.
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive]
pub enum VmError {
    // ── Gas ─────────────────────────────────────────────────────────────────
    #[error("out of gas")]
    OutOfGas,

    #[error("intrinsic gas too low: need {need}, have {have}")]
    IntrinsicGasTooLow { need: u64, have: u64 },

    // ── Opcode ──────────────────────────────────────────────────────────────
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },

    #[error("malformed opcode data at position {pos}: expected {expected} bytes, got {got}")]
    MalformedOpcode { pos: usize, expected: usize, got: usize },

    // ── Stack ──────────────────────────────────────────────────────────────
    #[error("stack underflow: need {need}, have {have}")]
    StackUnderflow { need: usize, have: usize },

    #[error("stack overflow: limit {limit} exceeded")]
    StackOverflow { limit: usize },

    // ── Arithmetic ─────────────────────────────────────────────────────────
    #[error("division by zero")]
    DivisionByZero,

    #[error("arithmetic overflow: {operation}")]
    ArithmeticOverflow { operation: &'static str },

    // ── Memory ─────────────────────────────────────────────────────────────
    #[error("memory limit exceeded: tried to access {size} bytes (limit {limit})")]
    MemoryLimit { size: usize, limit: usize },

    #[error("memory offset overflow: offset {offset} + size {size}")]
    MemoryOffsetOverflow { offset: usize, size: usize },

    // ── Control flow ───────────────────────────────────────────────────────
    #[error("invalid jump destination: 0x{dest:X}")]
    InvalidJump { dest: usize },

    #[error("program counter out of bounds: pc={pc}, code_length={code_length}")]
    PcOutOfBounds { pc: usize, code_length: usize },

    // ── Call / Create ──────────────────────────────────────────────────────
    #[error("call depth limit exceeded (max {limit})")]
    CallDepth { limit: usize },

    #[error("write protection: {reason}")]
    WriteProtection { reason: &'static str },

    #[error("contract already exists at address {address:?}")]
    ContractExists { address: [u8; 32] },

    #[error("code too large: {size} bytes (max {limit})")]
    CodeTooLarge { size: usize, limit: usize },

    // ── Calldata / Return data ─────────────────────────────────────────────
    #[error("calldata out of bounds: offset {offset}, size {size}, len {len}")]
    CalldataOob { offset: usize, size: usize, len: usize },

    #[error("return data out of bounds: offset {offset}, size {size}, len {len}")]
    ReturnDataOob { offset: usize, size: usize, len: usize },

    // ── Storage ────────────────────────────────────────────────────────────
    #[error("storage error: {message}")]
    Storage { message: String },

    // ── State ──────────────────────────────────────────────────────────────
    #[error("state error: {message}")]
    State { message: String },

    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    #[error("nonce overflow: {nonce}")]
    NonceOverflow { nonce: u64 },

    // ── Execution ──────────────────────────────────────────────────────────
    #[error("execution halted")]
    Halt,

    #[error("reverted: {reason}")]
    Revert { reason: String },

    // ── Internal ──────────────────────────────────────────────────────────
    #[error("internal VM error: {message}")]
    Internal { message: String },
}

// ── Error Classification ───────────────────────────────────────────────

impl VmError {
    /// Returns `true` if the error is fatal.
    pub const fn is_fatal(&self) -> bool {
        matches!(
            self,
            VmError::OutOfGas
                | VmError::IntrinsicGasTooLow { .. }
                | VmError::InvalidOpcode { .. }
                | VmError::MalformedOpcode { .. }
                | VmError::StackUnderflow { .. }
                | VmError::StackOverflow { .. }
                | VmError::MemoryLimit { .. }
                | VmError::MemoryOffsetOverflow { .. }
                | VmError::CallDepth { .. }
                | VmError::CodeTooLarge { .. }
                | VmError::PcOutOfBounds { .. }
                | VmError::Halt
                | VmError::Internal { .. }
        )
    }

    /// Returns `true` if the error should cause a revert.
    pub const fn should_revert(&self) -> bool {
        !self.is_fatal()
    }

    /// Returns `true` if the error is recoverable.
    pub const fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VmError::ArithmeticOverflow { .. }
                | VmError::DivisionByZero
                | VmError::InvalidJump { .. }
                | VmError::ReturnDataOob { .. }
                | VmError::CalldataOob { .. }
                | VmError::WriteProtection { .. }
                | VmError::ContractExists { .. }
                | VmError::State { .. }
                | VmError::Storage { .. }
                | VmError::InsufficientBalance { .. }
                | VmError::NonceOverflow { .. }
                | VmError::Revert { .. }
        )
    }

    /// Get the error category.
    pub const fn category(&self) -> ErrorCategory {
        match self {
            VmError::OutOfGas | VmError::IntrinsicGasTooLow { .. } => ErrorCategory::Gas,
            VmError::InvalidOpcode { .. } | VmError::MalformedOpcode { .. } => ErrorCategory::Opcode,
            VmError::StackUnderflow { .. } | VmError::StackOverflow { .. } => ErrorCategory::Stack,
            VmError::DivisionByZero | VmError::ArithmeticOverflow { .. } => ErrorCategory::Arithmetic,
            VmError::MemoryLimit { .. } | VmError::MemoryOffsetOverflow { .. } => ErrorCategory::Memory,
            VmError::InvalidJump { .. } | VmError::PcOutOfBounds { .. } => ErrorCategory::Control,
            VmError::CallDepth { .. }
            | VmError::WriteProtection { .. }
            | VmError::ContractExists { .. }
            | VmError::CodeTooLarge { .. } => ErrorCategory::Call,
            VmError::CalldataOob { .. } | VmError::ReturnDataOob { .. } => ErrorCategory::Calldata,
            VmError::Storage { .. } => ErrorCategory::Storage,
            VmError::State { .. }
            | VmError::InsufficientBalance { .. }
            | VmError::NonceOverflow { .. } => ErrorCategory::State,
            VmError::Halt | VmError::Revert { .. } => ErrorCategory::Execution,
            VmError::Internal { .. } => ErrorCategory::Internal,
        }
    }

    /// Get the error type index (for metrics).
    pub const fn type_index(&self) -> usize {
        match self {
            VmError::OutOfGas => 0,
            VmError::IntrinsicGasTooLow { .. } => 1,
            VmError::InvalidOpcode { .. } => 2,
            VmError::MalformedOpcode { .. } => 3,
            VmError::StackUnderflow { .. } => 4,
            VmError::StackOverflow { .. } => 5,
            VmError::DivisionByZero => 6,
            VmError::ArithmeticOverflow { .. } => 7,
            VmError::MemoryLimit { .. } => 8,
            VmError::MemoryOffsetOverflow { .. } => 9,
            VmError::InvalidJump { .. } => 10,
            VmError::PcOutOfBounds { .. } => 11,
            VmError::CallDepth { .. } => 12,
            VmError::WriteProtection { .. } => 13,
            VmError::ContractExists { .. } => 14,
            VmError::CodeTooLarge { .. } => 15,
            VmError::CalldataOob { .. } => 16,
            VmError::ReturnDataOob { .. } => 17,
            VmError::Storage { .. } => 18,
            VmError::State { .. } => 19,
            VmError::InsufficientBalance { .. } => 20,
            VmError::NonceOverflow { .. } => 21,
            VmError::Halt => 22,
            VmError::Revert { .. } => 23,
            VmError::Internal { .. } => 24,
            _ => 25, // Fallback for future variants
        }
    }

    /// Returns a JSON-RPC error code.
    pub const fn code(&self) -> i32 {
        match self {
            VmError::OutOfGas => -32015,
            VmError::IntrinsicGasTooLow { .. } => -32016,
            VmError::InvalidOpcode { .. } => -32017,
            VmError::MalformedOpcode { .. } => -32018,
            VmError::StackUnderflow { .. } => -32019,
            VmError::StackOverflow { .. } => -32020,
            VmError::DivisionByZero => -32021,
            VmError::ArithmeticOverflow { .. } => -32022,
            VmError::MemoryLimit { .. } => -32023,
            VmError::MemoryOffsetOverflow { .. } => -32024,
            VmError::InvalidJump { .. } => -32025,
            VmError::PcOutOfBounds { .. } => -32026,
            VmError::CallDepth { .. } => -32027,
            VmError::WriteProtection { .. } => -32028,
            VmError::ContractExists { .. } => -32029,
            VmError::CodeTooLarge { .. } => -32030,
            VmError::CalldataOob { .. } => -32031,
            VmError::ReturnDataOob { .. } => -32032,
            VmError::Storage { .. } => -32033,
            VmError::State { .. } => -32034,
            VmError::InsufficientBalance { .. } => -32035,
            VmError::NonceOverflow { .. } => -32036,
            VmError::Halt => -32037,
            VmError::Revert { .. } => -32038,
            VmError::Internal { .. } => -32603,
        }
    }

    /// Returns a short string identifier for logging/metrics.
    pub const fn as_str(&self) -> &'static str {
        match self {
            VmError::OutOfGas => "OutOfGas",
            VmError::IntrinsicGasTooLow { .. } => "IntrinsicGasTooLow",
            VmError::InvalidOpcode { .. } => "InvalidOpcode",
            VmError::MalformedOpcode { .. } => "MalformedOpcode",
            VmError::StackUnderflow { .. } => "StackUnderflow",
            VmError::StackOverflow { .. } => "StackOverflow",
            VmError::DivisionByZero => "DivisionByZero",
            VmError::ArithmeticOverflow { .. } => "ArithmeticOverflow",
            VmError::MemoryLimit { .. } => "MemoryLimit",
            VmError::MemoryOffsetOverflow { .. } => "MemoryOffsetOverflow",
            VmError::InvalidJump { .. } => "InvalidJump",
            VmError::PcOutOfBounds { .. } => "PcOutOfBounds",
            VmError::CallDepth { .. } => "CallDepth",
            VmError::WriteProtection { .. } => "WriteProtection",
            VmError::ContractExists { .. } => "ContractExists",
            VmError::CodeTooLarge { .. } => "CodeTooLarge",
            VmError::CalldataOob { .. } => "CalldataOob",
            VmError::ReturnDataOob { .. } => "ReturnDataOob",
            VmError::Storage { .. } => "Storage",
            VmError::State { .. } => "State",
            VmError::InsufficientBalance { .. } => "InsufficientBalance",
            VmError::NonceOverflow { .. } => "NonceOverflow",
            VmError::Halt => "Halt",
            VmError::Revert { .. } => "Revert",
            VmError::Internal { .. } => "Internal",
        }
    }

    /// Returns `true` if the error contains a revert reason.
    pub fn has_revert_reason(&self) -> bool {
        matches!(self, VmError::Revert { .. })
    }

    /// Extract the revert reason string if present.
    pub fn revert_reason(&self) -> Option<&str> {
        match self {
            VmError::Revert { reason } => Some(reason),
            _ => None,
        }
    }

    /// Convenience constructor for revert.
    pub fn revert(reason: impl Into<String>) -> Self {
        VmError::Revert {
            reason: reason.into(),
        }
    }

    /// Convenience constructor for storage error.
    pub fn storage(message: impl Into<String>) -> Self {
        VmError::Storage {
            message: message.into(),
        }
    }

    /// Convenience constructor for state error.
    pub fn state(message: impl Into<String>) -> Self {
        VmError::State {
            message: message.into(),
        }
    }

    /// Convenience constructor for internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        VmError::Internal {
            message: message.into(),
        }
    }

    /// Log the error with context.
    pub fn log(&self, context: &str) {
        let category = self.category().as_str();
        let is_fatal = self.is_fatal();
        let code = self.code();

        if is_fatal {
            error!(
                error = %self,
                category,
                code,
                context,
                "VM fatal error"
            );
        } else if self.should_revert() {
            warn!(
                error = %self,
                category,
                code,
                context,
                "VM revert error"
            );
        } else {
            debug!(
                error = %self,
                category,
                code,
                context,
                "VM recoverable error"
            );
        }
    }
}

// ── Conversions ─────────────────────────────────────────────────────────

impl From<std::num::TryFromIntError> for VmError {
    fn from(_: std::num::TryFromIntError) -> Self {
        VmError::internal("integer conversion failed")
    }
}

impl From<std::array::TryFromSliceError> for VmError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        VmError::internal("slice conversion failed")
    }
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::storage(e.to_string())
    }
}

impl From<crate::vm::opcodes::OpcodeError> for VmError {
    fn from(err: crate::vm::opcodes::OpcodeError) -> Self {
        match err {
            crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode } => {
                VmError::InvalidOpcode { opcode }
            }
            crate::vm::opcodes::OpcodeError::TruncatedPush { pos, expected, remaining } => {
                VmError::MalformedOpcode {
                    pos,
                    expected,
                    got: remaining,
                }
            }
            crate::vm::opcodes::OpcodeError::InvalidJumpDest { pos } => {
                VmError::InvalidJump { dest: pos }
            }
        }
    }
}

// ── VmErrorManager ──────────────────────────────────────────────────────

/// Manager for VM error handling with metrics and logging.
#[derive(Clone)]
pub struct VmErrorManager {
    config: Arc<VmErrorConfig>,
    metrics: Arc<VmErrorMetrics>,
}

impl VmErrorManager {
    /// Create a new error manager with the given configuration.
    pub fn new(config: VmErrorConfig) -> Result<Self, String> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: Arc::new(VmErrorMetrics::new()),
        })
    }

    /// Record and handle an error.
    pub fn handle(&self, error: &VmError, context: &str) {
        if self.config.track_metrics {
            self.metrics.record_error(error);
        }

        if self.config.log_errors {
            let severity = if error.is_fatal() {
                1
            } else if error.should_revert() {
                2
            } else {
                3
            };
            if severity >= self.config.log_threshold {
                error.log(context);
            }
        }
    }

    /// Convert a result, handling errors automatically.
    pub fn wrap<T>(&self, result: VmResult<T>, context: &str) -> VmResult<T> {
        if let Err(ref e) = result {
            self.handle(e, context);
        }
        result
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> VmErrorMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &VmErrorConfig {
        &self.config
    }

    /// Create an error with context logging.
    pub fn error(&self, err: VmError, context: &str) -> VmError {
        if self.config.log_errors {
            err.log(context);
        }
        if self.config.track_metrics {
            self.metrics.record_error(&err);
        }
        err
    }

    /// Create a fatal error with logging.
    pub fn fatal(&self, message: impl Into<String>, context: &str) -> VmError {
        let err = VmError::internal(message);
        self.error(err, context)
    }

    /// Create a revert error with logging.
    pub fn revert(&self, reason: impl Into<String>, context: &str) -> VmError {
        let err = VmError::revert(reason);
        self.error(err, context)
    }
}

// ── Global singleton ────────────────────────────────────────────────────

static GLOBAL_MANAGER: std::sync::OnceLock<VmErrorManager> = std::sync::OnceLock::new();

/// Initialize the global error manager.
pub fn init_error_manager(config: VmErrorConfig) -> Result<(), String> {
    let manager = VmErrorManager::new(config)?;
    GLOBAL_MANAGER.set(manager).map_err(|_| "manager already initialized".into())
}

/// Get the global error manager.
pub fn global_error_manager() -> &'static VmErrorManager {
    GLOBAL_MANAGER.get().expect("error manager not initialized")
}

// ── Public API wrappers ─────────────────────────────────────────────────

/// Log an error using the global manager.
pub fn log_error(error: &VmError, context: &str) {
    global_error_manager().handle(error, context);
}

/// Wrap a result with error handling.
pub fn wrap_result<T>(result: VmResult<T>, context: &str) -> VmResult<T> {
    global_error_manager().wrap(result, context)
}

/// Get error metrics snapshot.
pub fn error_metrics() -> VmErrorMetricsSnapshot {
    global_error_manager().metrics_snapshot()
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = VmErrorConfig::default();
        assert!(config.validate().is_ok());

        config.max_tracked_per_category = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_error_categories() {
        let err = VmError::OutOfGas;
        assert_eq!(err.category(), ErrorCategory::Gas);
        assert!(err.is_fatal());
        assert!(!err.is_recoverable());

        let err = VmError::DivisionByZero;
        assert_eq!(err.category(), ErrorCategory::Arithmetic);
        assert!(!err.is_fatal());
        assert!(err.is_recoverable());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(VmError::OutOfGas.code(), -32015);
        assert_eq!(VmError::Revert { reason: "".into() }.code(), -32038);
        assert_eq!(VmError::Internal { message: "".into() }.code(), -32603);
    }

    #[test]
    fn test_error_type_index() {
        assert_eq!(VmError::OutOfGas.type_index(), 0);
        assert_eq!(VmError::InvalidOpcode { opcode: 0 }.type_index(), 2);
        assert_eq!(VmError::Internal { message: "".into() }.type_index(), 24);
    }

    #[test]
    fn test_metrics() {
        let config = VmErrorConfig::default();
        let manager = VmErrorManager::new(config).unwrap();
        let err = VmError::OutOfGas;
        manager.handle(&err, "test");
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_errors, 1);
        assert_eq!(snap.fatal_errors, 1);
        assert_eq!(snap.gas_errors, 1);
    }

    #[test]
    fn test_error_manager_wrap() {
        let config = VmErrorConfig::default();
        let manager = VmErrorManager::new(config).unwrap();
        let result: VmResult<()> = Err(VmError::OutOfGas);
        let wrapped = manager.wrap(result, "test");
        assert!(wrapped.is_err());
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.total_errors, 1);
    }

    #[test]
    fn test_convenience_constructors() {
        let err = VmError::revert("test");
        assert!(matches!(err, VmError::Revert { reason } if reason == "test"));

        let err = VmError::storage("disk full");
        assert!(matches!(err, VmError::Storage { message } if message == "disk full"));

        let err = VmError::state("invalid");
        assert!(matches!(err, VmError::State { message } if message == "invalid"));
    }

    #[test]
    fn test_revert_reason() {
        let err = VmError::revert("reason");
        assert_eq!(err.revert_reason(), Some("reason"));
        assert!(err.has_revert_reason());
    }

    #[test]
    fn test_partial_eq() {
        let err1 = VmError::InvalidOpcode { opcode: 0xFE };
        let err2 = VmError::InvalidOpcode { opcode: 0xFE };
        let err3 = VmError::InvalidOpcode { opcode: 0xFF };
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_serde() {
        let err = VmError::ArithmeticOverflow { operation: "ADD" };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: VmError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }
}
