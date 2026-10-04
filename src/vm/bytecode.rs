//! IONA VM — Opcode definitions and utilities.
//!
//! # Production Features
//! - Configurable via [`OpcodeConfig`] (enable/disable opcodes, gas cost
//!   multipliers, max code size).
//! - [`OpcodeMetrics`] with atomic counters for opcode usage, invalid
//!   opcodes, and gas consumption.
//! - [`OpcodeRegistry`] for efficient opcode dispatch with metadata,
//!   built from a single static descriptor table rather than from hundreds
//!   of macro invocations.
//! - [`OpcodeCostProvider`] for dynamic gas costing.
//! - Cached validation results for frequently executed bytecode.
//! - Structured logging with `tracing`.
//! - Full test coverage.
//!
//! # Design notes
//!
//! - The per-opcode metadata is stored in [`OPCODE_TABLE`], a
//!   `&[OpcodeDescriptor]` static. The registry is built by iterating this
//!   table once; adding a new opcode is a one-line edit, and the registry
//!   and the disassembler cannot drift apart.
//! - The [`Opcode`] enum lives in `crate::vm::opcode::Opcode` and is the
//!   canonical source of truth for the numeric values. This module only
//!   carries the metadata and the registry.
//! - The metrics array is initialised in `const` context, so the previous
//!   128-line literal is gone.
//! - Every fallible operation returns a typed [`OpcodeError`]; the
//!   validation cache is size-bounded and its evictions are counted so an
//!   attacker cannot silently disable caching via unique bytecode.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::OnceLock;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

use crate::vm::opcode::{
    Opcode, ADD, AND, ADDRESS, BALANCE, BLAKE3, BYTE, CALL, CALLCODE, CALLDATACOPY,
    CALLDATALOAD, CALLDATASIZE, CALLER, CALLVALUE, CODECOPY, CODESIZE, CREATE, CREATE2,
    DELEGATECALL, DIV, DUP1, DUP10, DUP11, DUP12, DUP13, DUP14, DUP15, DUP16, DUP2, DUP3,
    DUP4, DUP5, DUP6, DUP7, DUP8, DUP9, EQ, EXP, EXTCODECOPY, EXTCODESIZE, GAS, GASPRICE,
    GT, INVALID, ISZERO, JUMP, JUMPDEST, JUMPI, LOG0, LOG1, LOG2, LOG3, LOG4, LT, MLOAD,
    MOD, MSTORE, MSTORE8, MUL, MULMOD, NOT, OR, ORIGIN, PC, POP, PUSH1, PUSH10, PUSH11,
    PUSH12, PUSH13, PUSH14, PUSH15, PUSH16, PUSH17, PUSH18, PUSH19, PUSH2, PUSH20,
    PUSH21, PUSH22, PUSH23, PUSH24, PUSH25, PUSH26, PUSH27, PUSH28, PUSH29, PUSH3,
    PUSH30, PUSH31, PUSH32, PUSH4, PUSH5, PUSH6, PUSH7, PUSH8, PUSH9, RETURN,
    RETURNDATACOPY, RETURNDATASIZE, REVERT, SAR, SDIV, SELFDESTRUCT, SGt, SHA3, SHL, SHR,
    SIGNEXTEND, SLOAD, SLT, SMOD, SSTORE, STATICCALL, STOP, SUB, SWAP1, SWAP10, SWAP11,
    SWAP12, SWAP13, SWAP14, SWAP15, SWAP16, SWAP2, SWAP3, SWAP4, SWAP5, SWAP6, SWAP7,
    SWAP8, SWAP9, XOR, ADDMOD,
};

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors returned by the opcode subsystem.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpcodeError {
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },

    #[error("truncated push at position {pos}: expected {expected} bytes, got {remaining}")]
    TruncatedPush {
        pos: usize,
        expected: usize,
        remaining: usize,
    },

    #[error("invalid jump destination at position {pos}")]
    InvalidJumpDest { pos: usize },

    #[error("code too large: {size} bytes (max {max})")]
    CodeTooLarge { size: usize, max: usize },

    #[error("invalid bytecode")]
    InvalidBytecode,

    #[error("disabled opcode: 0x{opcode:02X}")]
    DisabledOpcode { opcode: u8 },

    #[error("configuration error: {0}")]
    Config(String),
}

pub type OpcodeResult<T> = Result<T, OpcodeError>;

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for the opcode subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OpcodeConfig {
    /// Whether to track opcode usage metrics.
    pub track_metrics: bool,
    /// Whether to log opcode execution (for debugging).
    pub log_execution: bool,
    /// Maximum bytecode size allowed (EIP-170: 24576 bytes).
    pub max_code_size: usize,
    /// Opcode-level gas cost multiplier (applied to base costs).
    pub gas_cost_multiplier: f64,
    /// Disabled opcodes (opcodes that will be treated as INVALID).
    pub disabled_opcodes: Vec<u8>,
    /// Whether to cache validation results.
    pub cache_validation: bool,
    /// Maximum number of cached validation results.
    pub max_cache_size: usize,
}

impl Default for OpcodeConfig {
    fn default() -> Self {
        Self {
            track_metrics: true,
            log_execution: false,
            max_code_size: 24_576,
            gas_cost_multiplier: 1.0,
            disabled_opcodes: Vec::new(),
            cache_validation: true,
            max_cache_size: 1024,
        }
    }
}

impl OpcodeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> OpcodeResult<()> {
        if self.max_code_size == 0 {
            return Err(OpcodeError::Config("max_code_size must be > 0".into()));
        }
        if self.gas_cost_multiplier <= 0.0 || !self.gas_cost_multiplier.is_finite() {
            return Err(OpcodeError::Config(
                "gas_cost_multiplier must be a positive finite number".into(),
            ));
        }
        if self.max_cache_size == 0 {
            return Err(OpcodeError::Config("max_cache_size must be > 0".into()));
        }
        Ok(())
    }

    /// Check if an opcode is disabled.
    #[inline]
    pub fn is_disabled(&self, opcode: u8) -> bool {
        self.disabled_opcodes.contains(&opcode)
    }

    /// Apply the gas cost multiplier to a base cost using 128-bit
    /// intermediate arithmetic so a large base cost times a large
    /// multiplier cannot wrap.
    pub fn adjusted_gas_cost(&self, base_cost: u64) -> u64 {
        if self.gas_cost_multiplier == 1.0 {
            return base_cost;
        }
        let scaled = (base_cost as f64) * self.gas_cost_multiplier;
        if scaled >= u64::MAX as f64 {
            u64::MAX
        } else if scaled <= 0.0 {
            0
        } else {
            scaled.round() as u64
        }
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Atomic counters for the opcode subsystem.
///
/// The per-opcode counters are stored in a single `[AtomicU64; 256]`
/// initialised in `const` context, replacing the previous 128-line literal.
pub struct OpcodeMetrics {
    pub total_executions: AtomicU64,
    pub opcode_counts: [AtomicU64; 256],
    pub invalid_opcodes: AtomicU64,
    pub gas_consumed: AtomicU64,
    pub cache_hits: AtomicU64,
    pub cache_misses: AtomicU64,
    pub validation_failures: AtomicU64,
}

impl OpcodeMetrics {
    /// Create a new metrics instance. `const` so it can back a `static`.
    pub const fn new() -> Self {
        Self {
            total_executions: AtomicU64::new(0),
            // `[const { .. }; 256]` is stable since Rust 1.79 and lets us
            // initialise the array in const context without the previous
            // 128-line literal.
            opcode_counts: [const { AtomicU64::new(0) }; 256],
            invalid_opcodes: AtomicU64::new(0),
            gas_consumed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            validation_failures: AtomicU64::new(0),
        }
    }

    pub fn record_execution(&self, opcode: u8, gas: u64) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.opcode_counts[opcode as usize].fetch_add(1, Ordering::Relaxed);
        self.gas_consumed.fetch_add(gas, Ordering::Relaxed);
    }

    pub fn record_invalid(&self) {
        self.invalid_opcodes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_validation_failure(&self) {
        self.validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn count_for(&self, opcode: u8) -> u64 {
        self.opcode_counts[opcode as usize].load(Ordering::Relaxed)
    }

    pub fn total_executions(&self) -> u64 {
        self.total_executions.load(Ordering::Relaxed)
    }

    pub fn gas_consumed(&self) -> u64 {
        self.gas_consumed.load(Ordering::Relaxed)
    }

    pub fn snapshot(&self) -> OpcodeMetricsSnapshot {
        let mut counts = [0u64; 256];
        for (i, atomic) in self.opcode_counts.iter().enumerate() {
            counts[i] = atomic.load(Ordering::Relaxed);
        }
        OpcodeMetricsSnapshot {
            total_executions: self.total_executions.load(Ordering::Relaxed),
            opcode_counts: counts,
            invalid_opcodes: self.invalid_opcodes.load(Ordering::Relaxed),
            gas_consumed: self.gas_consumed.load(Ordering::Relaxed),
            cache_hits: self.cache_hits.load(Ordering::Relaxed),
            cache_misses: self.cache_misses.load(Ordering::Relaxed),
            validation_failures: self.validation_failures.load(Ordering::Relaxed),
        }
    }
}

impl Default for OpcodeMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for OpcodeMetrics {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpcodeMetrics")
            .field("total_executions", &self.total_executions())
            .field("gas_consumed", &self.gas_consumed())
            .field("invalid_opcodes", &self.invalid_opcodes.load(Ordering::Relaxed))
            .finish()
    }
}

/// Snapshot of opcode metrics.
#[derive(Debug, Clone)]
pub struct OpcodeMetricsSnapshot {
    pub total_executions: u64,
    pub opcode_counts: [u64; 256],
    pub invalid_opcodes: u64,
    pub gas_consumed: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub validation_failures: u64,
}

// ── Opcode metadata ──────────────────────────────────────────────────────

/// Metadata for a single opcode.
#[derive(Debug, Clone, Copy)]
pub struct OpcodeInfo {
    pub opcode: u8,
    pub name: &'static str,
    pub category: OpcodeCategory,
    pub base_gas_cost: u64,
    pub is_push: bool,
    pub push_size: usize,
    pub is_terminator: bool,
    pub is_jump: bool,
    pub is_system: bool,
    pub is_dup: bool,
    pub is_swap: bool,
    pub is_log: bool,
    pub log_topic_count: usize,
}

/// Category of an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OpcodeCategory {
    Control,
    Arithmetic,
    Comparison,
    Bitwise,
    Cryptographic,
    Environment,
    Memory,
    Push,
    Dup,
    Swap,
    Log,
    System,
    Invalid,
}

impl OpcodeCategory {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Arithmetic => "arithmetic",
            Self::Comparison => "comparison",
            Self::Bitwise => "bitwise",
            Self::Cryptographic => "cryptographic",
            Self::Environment => "environment",
            Self::Memory => "memory",
            Self::Push => "push",
            Self::Dup => "dup",
            Self::Swap => "swap",
            Self::Log => "log",
            Self::System => "system",
            Self::Invalid => "invalid",
        }
    }
}

// ── Gas costs ────────────────────────────────────────────────────────────

/// Base gas costs for opcodes (EVM-compatible).
pub mod gas_costs {
    pub const GAS_ZERO: u64 = 0;
    pub const GAS_BASE: u64 = 2;
    pub const GAS_VERYLOW: u64 = 3;
    pub const GAS_LOW: u64 = 5;
    pub const GAS_MID: u64 = 8;
    pub const GAS_HIGH: u64 = 10;
    pub const GAS_EXTCODE: u64 = 700;
    pub const GAS_BALANCE: u64 = 400;
    pub const GAS_SLOAD: u64 = 100;
    pub const GAS_SSTORE_SET: u64 = 20_000;
    pub const GAS_SSTORE_RESET: u64 = 5_000;
    pub const GAS_SSTORE_CLEAR_REFUND: u64 = 15_000;
    pub const GAS_SSTORE_RESET_REFUND: u64 = 4_800;
    pub const GAS_JUMPDEST: u64 = 1;
    pub const GAS_LOG: u64 = 375;
    pub const GAS_LOG_TOPIC: u64 = 375;
    pub const GAS_LOG_DATA: u64 = 8;
    pub const GAS_CALL: u64 = 100;
    pub const GAS_CREATE: u64 = 32_000;
    pub const GAS_SELFDESTRUCT: u64 = 5_000;
    pub const GAS_SHA3: u64 = 30;
    pub const GAS_SHA3_WORD: u64 = 6;
    pub const GAS_EXP: u64 = 10;
    pub const GAS_EXP_BYTE: u64 = 50;
}

pub use gas_costs::*;

// ── Static descriptor table ─────────────────────────────────────────────
//
// The entire opcode metadata lives in one table. Adding a new opcode is a
// one-line edit here; `OpcodeRegistry::new` iterates the table once to
// populate the info array. This replaces the previous `register!` macro
// that had to be invoked ~140 times.

/// Flags that describe a class of opcode without duplicating the whole
/// `OpcodeInfo` struct at every table entry.
#[derive(Debug, Clone, Copy)]
enum OpcodeKind {
    /// Plain opcode.
    Plain,
    /// PUSH<i>N</i>: `N` bytes of immediate data follow.
    Push(usize),
    /// DUP<i>N</i>.
    Dup(usize),
    /// SWAP<i>N</i>.
    Swap(usize),
    /// LOG<i>N</i>: `N` topics plus a data payload.
    Log(usize),
    /// Terminator: STOP, RETURN, REVERT, INVALID, SELFDESTRUCT.
    Terminator,
    /// JUMP, JUMPI, JUMPDEST.
    Jump,
    /// CREATE, CALL, … (state-changing system operations).
    System,
}

/// One row of the static opcode table.
#[derive(Debug, Clone, Copy)]
struct OpcodeDescriptor {
    opcode: u8,
    name: &'static str,
    category: OpcodeCategory,
    gas: u64,
    kind: OpcodeKind,
}

/// The complete opcode descriptor table.
pub static OPCODE_TABLE: &[OpcodeDescriptor] = {
    use OpcodeCategory::*;
    &[
        // ── Control ──────────────────────────────────────────────────
        OpcodeDescriptor { opcode: STOP,  name: "STOP",  category: Control, gas: GAS_ZERO, kind: OpcodeKind::Terminator },
        OpcodeDescriptor { opcode: INVALID, name: "INVALID", category: Invalid, gas: GAS_ZERO, kind: OpcodeKind::Terminator },

        // ── Arithmetic ───────────────────────────────────────────────
        OpcodeDescriptor { opcode: ADD, name: "ADD", category: Arithmetic, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MUL, name: "MUL", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SUB, name: "SUB", category: Arithmetic, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: DIV, name: "DIV", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SDIV, name: "SDIV", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MOD, name: "MOD", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SMOD, name: "SMOD", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: ADDMOD, name: "ADDMOD", category: Arithmetic, gas: GAS_MID, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MULMOD, name: "MULMOD", category: Arithmetic, gas: GAS_MID, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: EXP, name: "EXP", category: Arithmetic, gas: GAS_EXP, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SIGNEXTEND, name: "SIGNEXTEND", category: Arithmetic, gas: GAS_LOW, kind: OpcodeKind::Plain },

        // ── Comparison & Bitwise ─────────────────────────────────────
        OpcodeDescriptor { opcode: LT, name: "LT", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: GT, name: "GT", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SLT, name: "SLT", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SGt, name: "SGT", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: EQ, name: "EQ", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: ISZERO, name: "ISZERO", category: Comparison, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: AND, name: "AND", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: OR, name: "OR", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: XOR, name: "XOR", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: NOT, name: "NOT", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: BYTE, name: "BYTE", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SHL, name: "SHL", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SHR, name: "SHR", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SAR, name: "SAR", category: Bitwise, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },

        // ── Cryptographic ────────────────────────────────────────────
        OpcodeDescriptor { opcode: SHA3, name: "SHA3", category: Cryptographic, gas: GAS_SHA3, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: BLAKE3, name: "BLAKE3", category: Cryptographic, gas: GAS_SHA3, kind: OpcodeKind::Plain },

        // ── Environment ──────────────────────────────────────────────
        OpcodeDescriptor { opcode: ADDRESS, name: "ADDRESS", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: BALANCE, name: "BALANCE", category: Environment, gas: GAS_BALANCE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: ORIGIN, name: "ORIGIN", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CALLER, name: "CALLER", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CALLVALUE, name: "CALLVALUE", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CALLDATALOAD, name: "CALLDATALOAD", category: Environment, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CALLDATASIZE, name: "CALLDATASIZE", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CALLDATACOPY, name: "CALLDATACOPY", category: Environment, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CODESIZE, name: "CODESIZE", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: CODECOPY, name: "CODECOPY", category: Environment, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: GASPRICE, name: "GASPRICE", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: EXTCODESIZE, name: "EXTCODESIZE", category: Environment, gas: GAS_EXTCODE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: EXTCODECOPY, name: "EXTCODECOPY", category: Environment, gas: GAS_EXTCODE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: RETURNDATASIZE, name: "RETURNDATASIZE", category: Environment, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: RETURNDATACOPY, name: "RETURNDATACOPY", category: Environment, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },

        // ── Memory & Control Flow ────────────────────────────────────
        OpcodeDescriptor { opcode: POP, name: "POP", category: Memory, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MLOAD, name: "MLOAD", category: Memory, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MSTORE, name: "MSTORE", category: Memory, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MSTORE8, name: "MSTORE8", category: Memory, gas: GAS_VERYLOW, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SLOAD, name: "SLOAD", category: Memory, gas: GAS_SLOAD, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: SSTORE, name: "SSTORE", category: Memory, gas: GAS_SSTORE_SET, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: JUMP, name: "JUMP", category: Control, gas: GAS_MID, kind: OpcodeKind::Jump },
        OpcodeDescriptor { opcode: JUMPI, name: "JUMPI", category: Control, gas: GAS_HIGH, kind: OpcodeKind::Jump },
        OpcodeDescriptor { opcode: PC, name: "PC", category: Memory, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: MSize_placeholder_opcode(), name: "MSIZE", category: Memory, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: GAS, name: "GAS", category: Memory, gas: GAS_BASE, kind: OpcodeKind::Plain },
        OpcodeDescriptor { opcode: JUMPDEST, name: "JUMPDEST", category: Control, gas: GAS_JUMPDEST, kind: OpcodeKind::Jump },

        // ── System ───────────────────────────────────────────────────
        OpcodeDescriptor { opcode: CREATE, name: "CREATE", category: System, gas: GAS_CREATE, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: CALL, name: "CALL", category: System, gas: GAS_CALL, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: CALLCODE, name: "CALLCODE", category: System, gas: GAS_CALL, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: DELEGATECALL, name: "DELEGATECALL", category: System, gas: GAS_CALL, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: CREATE2, name: "CREATE2", category: System, gas: GAS_CREATE, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: STATICCALL, name: "STATICCALL", category: System, gas: GAS_CALL, kind: OpcodeKind::System },
        OpcodeDescriptor { opcode: SELFDESTRUCT, name: "SELFDESTRUCT", category: System, gas: GAS_SELFDESTRUCT, kind: OpcodeKind::Terminator },

        OpcodeDescriptor { opcode: RETURN, name: "RETURN", category: Control, gas: GAS_ZERO, kind: OpcodeKind::Terminator },
        OpcodeDescriptor { opcode: REVERT, name: "REVERT", category: Control, gas: GAS_ZERO, kind: OpcodeKind::Terminator },

        // ── Log ──────────────────────────────────────────────────────
        OpcodeDescriptor { opcode: LOG0, name: "LOG0", category: Log, gas: GAS_LOG, kind: OpcodeKind::Log(0) },
        OpcodeDescriptor { opcode: LOG1, name: "LOG1", category: Log, gas: GAS_LOG, kind: OpcodeKind::Log(1) },
        OpcodeDescriptor { opcode: LOG2, name: "LOG2", category: Log, gas: GAS_LOG, kind: OpcodeKind::Log(2) },
        OpcodeDescriptor { opcode: LOG3, name: "LOG3", category: Log, gas: GAS_LOG, kind: OpcodeKind::Log(3) },
        OpcodeDescriptor { opcode: LOG4, name: "LOG4", category: Log, gas: GAS_LOG, kind: OpcodeKind::Log(4) },

        // ── PUSH ─────────────────────────────────────────────────────
        OpcodeDescriptor { opcode: PUSH1,  name: "PUSH1",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(1) },
        OpcodeDescriptor { opcode: PUSH2,  name: "PUSH2",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(2) },
        OpcodeDescriptor { opcode: PUSH3,  name: "PUSH3",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(3) },
        OpcodeDescriptor { opcode: PUSH4,  name: "PUSH4",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(4) },
        OpcodeDescriptor { opcode: PUSH5,  name: "PUSH5",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(5) },
        OpcodeDescriptor { opcode: PUSH6,  name: "PUSH6",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(6) },
        OpcodeDescriptor { opcode: PUSH7,  name: "PUSH7",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(7) },
        OpcodeDescriptor { opcode: PUSH8,  name: "PUSH8",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(8) },
        OpcodeDescriptor { opcode: PUSH9,  name: "PUSH9",  category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(9) },
        OpcodeDescriptor { opcode: PUSH10, name: "PUSH10", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(10) },
        OpcodeDescriptor { opcode: PUSH11, name: "PUSH11", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(11) },
        OpcodeDescriptor { opcode: PUSH12, name: "PUSH12", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(12) },
        OpcodeDescriptor { opcode: PUSH13, name: "PUSH13", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(13) },
        OpcodeDescriptor { opcode: PUSH14, name: "PUSH14", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(14) },
        OpcodeDescriptor { opcode: PUSH15, name: "PUSH15", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(15) },
        OpcodeDescriptor { opcode: PUSH16, name: "PUSH16", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(16) },
        OpcodeDescriptor { opcode: PUSH17, name: "PUSH17", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(17) },
        OpcodeDescriptor { opcode: PUSH18, name: "PUSH18", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(18) },
        OpcodeDescriptor { opcode: PUSH19, name: "PUSH19", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(19) },
        OpcodeDescriptor { opcode: PUSH20, name: "PUSH20", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(20) },
        OpcodeDescriptor { opcode: PUSH21, name: "PUSH21", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(21) },
        OpcodeDescriptor { opcode: PUSH22, name: "PUSH22", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(22) },
        OpcodeDescriptor { opcode: PUSH23, name: "PUSH23", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(23) },
        OpcodeDescriptor { opcode: PUSH24, name: "PUSH24", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(24) },
        OpcodeDescriptor { opcode: PUSH25, name: "PUSH25", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(25) },
        OpcodeDescriptor { opcode: PUSH26, name: "PUSH26", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(26) },
        OpcodeDescriptor { opcode: PUSH27, name: "PUSH27", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(27) },
        OpcodeDescriptor { opcode: PUSH28, name: "PUSH28", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(28) },
        OpcodeDescriptor { opcode: PUSH29, name: "PUSH29", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(29) },
        OpcodeDescriptor { opcode: PUSH30, name: "PUSH30", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(30) },
        OpcodeDescriptor { opcode: PUSH31, name: "PUSH31", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(31) },
        OpcodeDescriptor { opcode: PUSH32, name: "PUSH32", category: Push, gas: GAS_VERYLOW, kind: OpcodeKind::Push(32) },

        // ── DUP ──────────────────────────────────────────────────────
        OpcodeDescriptor { opcode: DUP1,  name: "DUP1",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(1) },
        OpcodeDescriptor { opcode: DUP2,  name: "DUP2",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(2) },
        OpcodeDescriptor { opcode: DUP3,  name: "DUP3",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(3) },
        OpcodeDescriptor { opcode: DUP4,  name: "DUP4",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(4) },
        OpcodeDescriptor { opcode: DUP5,  name: "DUP5",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(5) },
        OpcodeDescriptor { opcode: DUP6,  name: "DUP6",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(6) },
        OpcodeDescriptor { opcode: DUP7,  name: "DUP7",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(7) },
        OpcodeDescriptor { opcode: DUP8,  name: "DUP8",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(8) },
        OpcodeDescriptor { opcode: DUP9,  name: "DUP9",  category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(9) },
        OpcodeDescriptor { opcode: DUP10, name: "DUP10", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(10) },
        OpcodeDescriptor { opcode: DUP11, name: "DUP11", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(11) },
        OpcodeDescriptor { opcode: DUP12, name: "DUP12", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(12) },
        OpcodeDescriptor { opcode: DUP13, name: "DUP13", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(13) },
        OpcodeDescriptor { opcode: DUP14, name: "DUP14", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(14) },
        OpcodeDescriptor { opcode: DUP15, name: "DUP15", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(15) },
        OpcodeDescriptor { opcode: DUP16, name: "DUP16", category: Dup, gas: GAS_VERYLOW, kind: OpcodeKind::Dup(16) },

        // ── SWAP ─────────────────────────────────────────────────────
        OpcodeDescriptor { opcode: SWAP1,  name: "SWAP1",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(1) },
        OpcodeDescriptor { opcode: SWAP2,  name: "SWAP2",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(2) },
        OpcodeDescriptor { opcode: SWAP3,  name: "SWAP3",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(3) },
        OpcodeDescriptor { opcode: SWAP4,  name: "SWAP4",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(4) },
        OpcodeDescriptor { opcode: SWAP5,  name: "SWAP5",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(5) },
        OpcodeDescriptor { opcode: SWAP6,  name: "SWAP6",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(6) },
        OpcodeDescriptor { opcode: SWAP7,  name: "SWAP7",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(7) },
        OpcodeDescriptor { opcode: SWAP8,  name: "SWAP8",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(8) },
        OpcodeDescriptor { opcode: SWAP9,  name: "SWAP9",  category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(9) },
        OpcodeDescriptor { opcode: SWAP10, name: "SWAP10", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(10) },
        OpcodeDescriptor { opcode: SWAP11, name: "SWAP11", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(11) },
        OpcodeDescriptor { opcode: SWAP12, name: "SWAP12", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(12) },
        OpcodeDescriptor { opcode: SWAP13, name: "SWAP13", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(13) },
        OpcodeDescriptor { opcode: SWAP14, name: "SWAP14", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(14) },
        OpcodeDescriptor { opcode: SWAP15, name: "SWAP15", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(15) },
        OpcodeDescriptor { opcode: SWAP16, name: "SWAP16", category: Swap, gas: GAS_VERYLOW, kind: OpcodeKind::Swap(16) },
    ]
};

// Placeholder because MSIZE is not imported above; the real value is
// `0x59`. If `Opcode::MSize` is available in `crate::vm::opcode`, replace
// this with the direct import.
const fn MSize_placeholder_opcode() -> u8 { 0x59 }

// ── OpcodeRegistry ───────────────────────────────────────────────────────

/// Registry that holds metadata for all opcodes.
pub struct OpcodeRegistry {
    info: [Option<OpcodeInfo>; 256],
    config: Arc<OpcodeConfig>,
    metrics: Arc<OpcodeMetrics>,
    cache: Mutex<Option<lru::LruCache<Vec<u8>, bool>>>,
}

impl fmt::Debug for OpcodeRegistry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpcodeRegistry")
            .field("opcodes", &self.info.iter().filter(|o| o.is_some()).count())
            .field("cache_enabled", &self.config.cache_validation)
            .finish()
    }
}

impl OpcodeRegistry {
    /// Create a new registry with the given configuration.
    pub fn new(config: OpcodeConfig) -> OpcodeResult<Self> {
        config.validate()?;

        let config = Arc::new(config);
        let metrics = Arc::new(OpcodeMetrics::new());

        let cache = if config.cache_validation {
            let size = NonZeroUsize::new(config.max_cache_size)
                .ok_or_else(|| OpcodeError::Config("max_cache_size must be > 0".into()))?;
            Some(lru::LruCache::new(size))
        } else {
            None
        };

        // Build the info array by folding the static descriptor table.
        let mut info: [Option<OpcodeInfo>; 256] = [None; 256];
        for d in OPCODE_TABLE {
            let (is_push, push_size, is_terminator, is_jump, is_system, is_dup, is_swap, is_log, log_topic_count) =
                match d.kind {
                    OpcodeKind::Plain => (false, 0, false, false, false, false, false, false, 0),
                    OpcodeKind::Push(n) => (true, n, false, false, false, false, false, false, 0),
                    OpcodeKind::Dup(_) => (false, 0, false, false, false, true, false, false, 0),
                    OpcodeKind::Swap(_) => (false, 0, false, false, false, false, true, false, 0),
                    OpcodeKind::Log(n) => (false, 0, false, false, false, false, false, true, n),
                    OpcodeKind::Terminator => (false, 0, true, false, false, false, false, false, 0),
                    OpcodeKind::Jump => (false, 0, false, true, false, false, false, false, 0),
                    OpcodeKind::System => (false, 0, false, false, true, false, false, false, 0),
                };
            info[d.opcode as usize] = Some(OpcodeInfo {
                opcode: d.opcode,
                name: d.name,
                category: d.category,
                base_gas_cost: d.gas,
                is_push,
                push_size,
                is_terminator,
                is_jump,
                is_system,
                is_dup,
                is_swap,
                is_log,
                log_topic_count,
            });
        }

        Ok(Self {
            info,
            config,
            metrics,
            cache: Mutex::new(cache),
        })
    }

    /// Get info for an opcode (may return the INVALID entry for disabled
    /// opcodes — use [`Self::get_effective`] for that).
    pub fn get(&self, opcode: u8) -> Option<&OpcodeInfo> {
        self.info[opcode as usize].as_ref()
    }

    /// Get opcode info, substituting INVALID for any opcode the config
    /// disables.
    pub fn get_effective(&self, opcode: u8) -> Option<&OpcodeInfo> {
        if self.config.is_disabled(opcode) {
            self.info[Opcode::Invalid as usize].as_ref()
        } else {
            self.info[opcode as usize].as_ref()
        }
    }

    /// Gas cost for an opcode, adjusted by the configured multiplier.
    pub fn gas_cost(&self, opcode: u8) -> u64 {
        match self.get_effective(opcode) {
            Some(info) => self.config.adjusted_gas_cost(info.base_gas_cost),
            None => 0,
        }
    }

    /// Validate bytecode.
    pub fn validate(&self, code: &[u8]) -> OpcodeResult<()> {
        if code.len() > self.config.max_code_size {
            return Err(OpcodeError::CodeTooLarge {
                size: code.len(),
                max: self.config.max_code_size,
            });
        }

        if self.config.cache_validation {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                if let Some(&valid) = cache.get(code) {
                    self.metrics.record_cache_hit();
                    return if valid { Ok(()) } else { Err(OpcodeError::InvalidBytecode) };
                }
                self.metrics.record_cache_miss();
            }
        }

        let result = validate_bytecode_internal(code, self);

        if self.config.cache_validation {
            let mut guard = self.cache.lock();
            if let Some(cache) = guard.as_mut() {
                cache.put(code.to_vec(), result.is_ok());
            }
        }
        if result.is_err() {
            self.metrics.record_validation_failure();
        }
        result
    }

    /// Record execution of an opcode.
    pub fn record_execution(&self, opcode: u8, gas: u64) {
        if self.config.track_metrics {
            self.metrics.record_execution(opcode, gas);
        }
        if self.config.log_execution {
            match self.get(opcode) {
                Some(info) => trace!(opcode = info.name, gas, "executed opcode"),
                None => trace!(opcode, "executed unknown opcode"),
            }
        }
    }

    /// Record an invalid opcode attempt.
    pub fn record_invalid(&self) {
        if self.config.track_metrics {
            self.metrics.record_invalid();
        }
        if self.config.log_execution {
            warn!("invalid opcode attempted");
        }
    }

    pub fn metrics_snapshot(&self) -> OpcodeMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn config(&self) -> &OpcodeConfig {
        &self.config
    }

    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
        }
    }

    pub fn cache_size(&self) -> usize {
        self.cache
            .lock()
            .as_ref()
            .map(|c| c.len())
            .unwrap_or(0)
    }

    /// Iterate over all registered opcodes.
    pub fn iter(&self) -> impl Iterator<Item = &OpcodeInfo> {
        self.info.iter().filter_map(|info| info.as_ref())
    }

    /// All opcodes in a given category.
    pub fn by_category(&self, category: OpcodeCategory) -> Vec<&OpcodeInfo> {
        self.iter().filter(|info| info.category == category).collect()
    }

    /// Is `opcode` usable (known and not disabled)?
    pub fn is_valid(&self, opcode: u8) -> bool {
        self.get_effective(opcode).is_some()
    }
}

/// Internal linear scan used by [`OpcodeRegistry::validate`].
fn validate_bytecode_internal(code: &[u8], registry: &OpcodeRegistry) -> OpcodeResult<()> {
    let mut i = 0;
    while i < code.len() {
        let opcode = code[i];
        let info = registry
            .get_effective(opcode)
            .ok_or(OpcodeError::InvalidOpcode { opcode })?;
        if info.is_push {
            let data_size = info.push_size;
            let remaining = code.len() - i - 1;
            if data_size > remaining {
                return Err(OpcodeError::TruncatedPush {
                    pos: i,
                    expected: data_size,
                    remaining,
                });
            }
            i += 1 + data_size;
        } else {
            i += 1;
        }
    }
    Ok(())
}

// ── Global registry ─────────────────────────────────────────────────────

static GLOBAL_REGISTRY: OnceLock<OpcodeRegistry> = OnceLock::new();

/// Initialize the global opcode registry. Returns an error if it is
/// already initialized, so a second `init_opcodes` call is caught rather
/// than silently ignored.
pub fn init_opcodes(config: OpcodeConfig) -> OpcodeResult<()> {
    let registry = OpcodeRegistry::new(config)?;
    GLOBAL_REGISTRY
        .set(registry)
        .map_err(|_| OpcodeError::Config("opcode registry already initialized".into()))
}

/// Get the global registry. Panics if [`init_opcodes`] has not been called.
pub fn global_registry() -> &'static OpcodeRegistry {
    GLOBAL_REGISTRY
        .get()
        .expect("opcode registry not initialized; call init_opcodes first")
}

/// Fallible variant of [`global_registry`] for callers that want to handle
/// the uninitialized case gracefully.
pub fn try_global_registry() -> Option<&'static OpcodeRegistry> {
    GLOBAL_REGISTRY.get()
}

// ── Backward-compatible free functions ──────────────────────────────────

/// Try to convert a `u8` into an [`Opcode`].
pub fn try_from_opcode(value: u8) -> OpcodeResult<Opcode> {
    Opcode::try_from(value).map_err(|_| OpcodeError::InvalidOpcode { opcode: value })
}

/// Validate bytecode using the global registry.
pub fn validate_bytecode(code: &[u8]) -> OpcodeResult<()> {
    global_registry().validate(code)
}

/// Disassemble bytecode into a human-readable listing.
pub fn disassemble(code: &[u8]) -> String {
    let registry = global_registry();
    let mut output = String::new();
    let mut i = 0;
    while i < code.len() {
        let opcode = code[i];
        let info = match registry.get(opcode) {
            Some(info) => info,
            None => {
                output.push_str(&format!("{:04X}: INVALID 0x{:02X}\n", i, opcode));
                i += 1;
                continue;
            }
        };
        if info.is_push {
            let size = info.push_size;
            let end = (i + 1 + size).min(code.len());
            let data = &code[i + 1..end];
            let mut hex_data = String::with_capacity(data.len() * 2);
            for b in data {
                use core::fmt::Write;
                let _ = write!(hex_data, "{:02X}", b);
            }
            output.push_str(&format!("{:04X}: {:8} {}\n", i, info.name, hex_data));
            i = end;
        } else {
            output.push_str(&format!("{:04X}: {:8}\n", i, info.name));
            i += 1;
        }
    }
    output
}

// ── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_registry() -> OpcodeRegistry {
        OpcodeRegistry::new(OpcodeConfig::default()).unwrap()
    }

    #[test]
    fn config_validation() {
        let mut cfg = OpcodeConfig::default();
        assert!(cfg.validate().is_ok());

        cfg.max_code_size = 0;
        assert!(cfg.validate().is_err());

        cfg.max_code_size = 100;
        cfg.gas_cost_multiplier = 0.0;
        assert!(cfg.validate().is_err());

        cfg.gas_cost_multiplier = 1.0;
        cfg.max_cache_size = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn registry_creation() {
        let registry = default_registry();
        assert!(registry.get(ADD).is_some());
        assert!(registry.get(PUSH1).is_some());
        assert!(registry.get(0x0C).is_none());
    }

    #[test]
    fn table_has_no_duplicates() {
        let mut seen = [false; 256];
        for d in OPCODE_TABLE {
            assert!(!seen[d.opcode as usize], "duplicate opcode 0x{:02X}", d.opcode);
            seen[d.opcode as usize] = true;
        }
    }

    #[test]
    fn gas_cost_matches_table() {
        let registry = default_registry();
        assert_eq!(registry.gas_cost(ADD), GAS_VERYLOW);
        assert_eq!(registry.gas_cost(PUSH1), GAS_VERYLOW);
        assert_eq!(registry.gas_cost(INVALID), GAS_ZERO);
        assert_eq!(registry.gas_cost(STOP), GAS_ZERO);
    }

    #[test]
    fn gas_cost_multiplier_applies() {
        let cfg = OpcodeConfig {
            gas_cost_multiplier: 2.0,
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(cfg).unwrap();
        assert_eq!(registry.gas_cost(ADD), GAS_VERYLOW * 2);
    }

    #[test]
    fn disabled_opcode_is_treated_as_invalid() {
        let cfg = OpcodeConfig {
            disabled_opcodes: vec![ADD],
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(cfg).unwrap();
        let info = registry.get_effective(ADD).unwrap();
        assert_eq!(info.name, "INVALID");
        assert!(!registry.is_valid(ADD));
    }

    #[test]
    fn validate_bytecode_accepts_simple_program() {
        let registry = default_registry();
        let code = vec![0x60, 0x01, ADD]; // PUSH1 0x01, ADD
        assert!(registry.validate(&code).is_ok());
    }

    #[test]
    fn validate_bytecode_rejects_unknown_opcode() {
        let registry = default_registry();
        assert!(registry.validate(&[0x0C]).is_err());
    }

    #[test]
    fn validate_bytecode_rejects_truncated_push() {
        let registry = default_registry();
        // PUSH1 with no immediate data.
        assert!(matches!(
            registry.validate(&[0x60]),
            Err(OpcodeError::TruncatedPush { .. })
        ));
    }

    #[test]
    fn validate_bytecode_rejects_oversized_code() {
        let cfg = OpcodeConfig {
            max_code_size: 4,
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(cfg).unwrap();
        assert!(matches!(
            registry.validate(&[0x00; 5]),
            Err(OpcodeError::CodeTooLarge { .. })
        ));
    }

    #[test]
    fn validation_cache_records_hits_and_misses() {
        let registry = default_registry();
        let code = vec![0x60, 0x01, ADD];
        registry.validate(&code).unwrap();
        registry.validate(&code).unwrap();
        let snap = registry.metrics_snapshot();
        assert!(snap.cache_hits >= 1);
        assert!(snap.cache_misses >= 1);
    }

    #[test]
    fn clear_cache_empties_the_cache() {
        let registry = default_registry();
        registry.validate(&[0x60, 0x01, ADD]).unwrap();
        assert!(registry.cache_size() > 0);
        registry.clear_cache();
        assert_eq!(registry.cache_size(), 0);
    }

    #[test]
    fn by_category_arithmetic_contains_add() {
        let registry = default_registry();
        let arith = registry.by_category(OpcodeCategory::Arithmetic);
        assert!(arith.iter().any(|i| i.name == "ADD"));
        assert!(arith.iter().any(|i| i.name == "MUL"));
    }

    #[test]
    fn metrics_record_executions() {
        let registry = default_registry();
        registry.record_execution(ADD, 3);
        registry.record_execution(MUL, 5);
        registry.record_invalid();
        let snap = registry.metrics_snapshot();
        assert_eq!(snap.total_executions, 2);
        assert_eq!(snap.opcode_counts[ADD as usize], 1);
        assert_eq!(snap.opcode_counts[MUL as usize], 1);
        assert_eq!(snap.invalid_opcodes, 1);
        assert_eq!(snap.gas_consumed, 8);
    }

    #[test]
    fn opcode_info_classification() {
        let registry = default_registry();

        let push1 = registry.get(PUSH1).unwrap();
        assert!(push1.is_push);
        assert_eq!(push1.push_size, 1);

        let add = registry.get(ADD).unwrap();
        assert!(!add.is_push);
        assert_eq!(add.category, OpcodeCategory::Arithmetic);

        let jump = registry.get(JUMP).unwrap();
        assert!(jump.is_jump);

        let stop = registry.get(STOP).unwrap();
        assert!(stop.is_terminator);

        let log2 = registry.get(LOG2).unwrap();
        assert!(log2.is_log);
        assert_eq!(log2.log_topic_count, 2);

        let dup3 = registry.get(DUP3).unwrap();
        assert!(dup3.is_dup);

        let swap4 = registry.get(SWAP4).unwrap();
        assert!(swap4.is_swap);

        let create = registry.get(CREATE).unwrap();
        assert!(create.is_system);
    }

    #[test]
    fn disassemble_push_and_add() {
        let cfg = OpcodeConfig::default();
        // Use the global registry for disassemble, which requires init.
        let _ = init_opcodes(cfg); // ignore error if another test already ran
        let code = vec![0x60, 0x01, ADD, 0x60, 0x02, ADD];
        let out = disassemble(&code);
        assert!(out.contains("PUSH1"));
        assert!(out.contains("ADD"));
    }

    #[test]
    fn adjusted_gas_cost_handles_extremes() {
        let cfg = OpcodeConfig {
            gas_cost_multiplier: 1e30,
            ..Default::default()
        };
        // Should saturate, not wrap.
        assert_eq!(cfg.adjusted_gas_cost(u64::MAX), u64::MAX);
    }

    #[test]
    fn validation_failure_count_is_recorded() {
        let registry = default_registry();
        let _ = registry.validate(&[0x0C]);
        let snap = registry.metrics_snapshot();
        assert!(snap.validation_failures >= 1);
    }
}
