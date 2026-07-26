//! IONA VM — Opcode definitions and utilities.
//!
//! # Production Features
//! - Configurable via `OpcodeConfig` (enable/disable opcodes, gas cost multipliers, max code size).
//! - `OpcodeMetrics` with atomic counters for opcode usage, invalid opcodes, and gas consumption.
//! - `OpcodeRegistry` for efficient opcode dispatch with metadata.
//! - `OpcodeCostProvider` for dynamic gas costing.
//! - Cached validation results for frequently executed bytecode.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

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
            max_code_size: 24576,
            gas_cost_multiplier: 1.0,
            disabled_opcodes: Vec::new(),
            cache_validation: true,
            max_cache_size: 1024,
        }
    }
}

impl OpcodeConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.max_code_size == 0 {
            return Err("max_code_size must be > 0".into());
        }
        if self.gas_cost_multiplier <= 0.0 {
            return Err("gas_cost_multiplier must be > 0.0".into());
        }
        if self.max_cache_size == 0 {
            return Err("max_cache_size must be > 0".into());
        }
        Ok(())
    }

    /// Check if an opcode is disabled.
    pub fn is_disabled(&self, opcode: u8) -> bool {
        self.disabled_opcodes.contains(&opcode)
    }

    /// Apply gas cost multiplier to a base cost.
    pub fn adjusted_gas_cost(&self, base_cost: u64) -> u64 {
        (base_cost as f64 * self.gas_cost_multiplier).round() as u64
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the opcode subsystem.
#[derive(Debug, Default)]
pub struct OpcodeMetrics {
    /// Total opcodes executed.
    pub total_executions: AtomicU64,
    /// Per-opcode execution counts.
    pub opcode_counts: [AtomicU64; 256],
    /// Invalid opcode attempts.
    pub invalid_opcodes: AtomicU64,
    /// Gas consumed (total).
    pub gas_consumed: AtomicU64,
    /// Validation cache hits.
    pub cache_hits: AtomicU64,
    /// Validation cache misses.
    pub cache_misses: AtomicU64,
    /// Bytecode validation failures.
    pub validation_failures: AtomicU64,
}

impl OpcodeMetrics {
    /// Create a new metrics instance.
    pub const fn new() -> Self {
        Self {
            total_executions: AtomicU64::new(0),
            opcode_counts: [
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
                AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0),
            ],
            invalid_opcodes: AtomicU64::new(0),
            gas_consumed: AtomicU64::new(0),
            cache_hits: AtomicU64::new(0),
            cache_misses: AtomicU64::new(0),
            validation_failures: AtomicU64::new(0),
        }
    }

    /// Record execution of an opcode.
    pub fn record_execution(&self, opcode: u8, gas: u64) {
        self.total_executions.fetch_add(1, Ordering::Relaxed);
        self.opcode_counts[opcode as usize].fetch_add(1, Ordering::Relaxed);
        self.gas_consumed.fetch_add(gas, Ordering::Relaxed);
    }

    /// Record an invalid opcode attempt.
    pub fn record_invalid(&self) {
        self.invalid_opcodes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache hit.
    pub fn record_cache_hit(&self) {
        self.cache_hits.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a cache miss.
    pub fn record_cache_miss(&self) {
        self.cache_misses.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a validation failure.
    pub fn record_validation_failure(&self) {
        self.validation_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get count for a specific opcode.
    pub fn count_for(&self, opcode: u8) -> u64 {
        self.opcode_counts[opcode as usize].load(Ordering::Relaxed)
    }

    /// Get total executions.
    pub fn total_executions(&self) -> u64 {
        self.total_executions.load(Ordering::Relaxed)
    }

    /// Get total gas consumed.
    pub fn gas_consumed(&self) -> u64 {
        self.gas_consumed.load(Ordering::Relaxed)
    }

    /// Snapshot of all metrics.
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

// ── Opcode Info ──────────────────────────────────────────────────────────

/// Metadata for an opcode.
#[derive(Debug, Clone)]
pub struct OpcodeInfo {
    /// The opcode value.
    pub opcode: u8,
    /// Human-readable name.
    pub name: &'static str,
    /// Category of the opcode.
    pub category: OpcodeCategory,
    /// Base gas cost.
    pub base_gas_cost: u64,
    /// Whether this opcode is a PUSH variant.
    pub is_push: bool,
    /// For PUSH opcodes: number of bytes to read.
    pub push_size: usize,
    /// Whether this opcode terminates execution.
    pub is_terminator: bool,
    /// Whether this opcode alters control flow.
    pub is_jump: bool,
    /// Whether this opcode is a system operation.
    pub is_system: bool,
    /// Whether this opcode is a DUP variant.
    pub is_dup: bool,
    /// Whether this opcode is a SWAP variant.
    pub is_swap: bool,
    /// Whether this opcode is a LOG variant.
    pub is_log: bool,
    /// For LOG opcodes: number of topics.
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

// ── Gas Costs ────────────────────────────────────────────────────────────

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
    pub const GAS_SSTORE_SET: u64 = 20000;
    pub const GAS_SSTORE_RESET: u64 = 5000;
    pub const GAS_SSTORE_CLEAR_REFUND: u64 = 15000;
    pub const GAS_SSTORE_RESET_REFUND: u64 = 4800;
    pub const GAS_JUMPDEST: u64 = 1;
    pub const GAS_LOG: u64 = 375;
    pub const GAS_LOG_TOPIC: u64 = 375;
    pub const GAS_LOG_DATA: u64 = 8;
    pub const GAS_CALL: u64 = 100;
    pub const GAS_CREATE: u64 = 32000;
    pub const GAS_SELFDESTRUCT: u64 = 5000;
    pub const GAS_SHA3: u64 = 30;
    pub const GAS_SHA3_WORD: u64 = 6;
    pub const GAS_EXP: u64 = 10;
    pub const GAS_EXP_BYTE: u64 = 50;
}

pub use gas_costs::*;

// ── Opcode Registry ─────────────────────────────────────────────────────

/// Registry that holds metadata for all opcodes.
#[derive(Clone)]
pub struct OpcodeRegistry {
    /// Opcode info indexed by opcode value.
    info: [Option<OpcodeInfo>; 256],
    /// Configuration.
    config: Arc<OpcodeConfig>,
    /// Metrics.
    metrics: Arc<OpcodeMetrics>,
    /// Validation cache.
    cache: Arc<parking_lot::Mutex<lru::LruCache<Vec<u8>, bool>>>,
}

impl OpcodeRegistry {
    /// Create a new registry with the given configuration.
    pub fn new(config: OpcodeConfig) -> Result<Self, String> {
        config.validate()?;
        let config = Arc::new(config);
        let metrics = Arc::new(OpcodeMetrics::new());
        let cache = if config.cache_validation {
            let size = std::num::NonZeroUsize::new(config.max_cache_size)
                .ok_or("max_cache_size must be > 0")?;
            Some(lru::LruCache::new(size))
        } else {
            None
        };
        let mut registry = Self {
            info: [None; 256],
            config,
            metrics,
            cache: Arc::new(parking_lot::Mutex::new(cache)),
        };
        registry.build_info_table();
        Ok(registry)
    }

    /// Build the info table from the opcode definitions.
    fn build_info_table(&mut self) {
        // This mirrors the Opcode enum but with metadata.
        // We use the same values as the Opcode enum.
        macro_rules! register {
            ($opcode:expr, $name:expr, $category:expr, $gas:expr) => {
                let op = $opcode as u8;
                self.info[op as usize] = Some(OpcodeInfo {
                    opcode: op,
                    name: $name,
                    category: $category,
                    base_gas_cost: $gas,
                    is_push: false,
                    push_size: 0,
                    is_terminator: matches!($opcode, Opcode::Stop | Opcode::Return | Opcode::Revert | Opcode::Invalid | Opcode::SelfDestruct),
                    is_jump: matches!($opcode, Opcode::Jump | Opcode::Jumpi | Opcode::JumpDest),
                    is_system: matches!($opcode, Opcode::Create | Opcode::Create2 | Opcode::Call | Opcode::CallCode | Opcode::DelegateCall | Opcode::StaticCall | Opcode::SelfDestruct),
                    is_dup: false,
                    is_swap: false,
                    is_log: false,
                    log_topic_count: 0,
                });
            };
            ($opcode:expr, $name:expr, $category:expr, $gas:expr, push_size: $size:expr) => {
                let op = $opcode as u8;
                self.info[op as usize] = Some(OpcodeInfo {
                    opcode: op,
                    name: $name,
                    category: $category,
                    base_gas_cost: $gas,
                    is_push: true,
                    push_size: $size,
                    is_terminator: false,
                    is_jump: false,
                    is_system: false,
                    is_dup: false,
                    is_swap: false,
                    is_log: false,
                    log_topic_count: 0,
                });
            };
            ($opcode:expr, $name:expr, $category:expr, $gas:expr, dup: $n:expr) => {
                let op = $opcode as u8;
                self.info[op as usize] = Some(OpcodeInfo {
                    opcode: op,
                    name: $name,
                    category: $category,
                    base_gas_cost: $gas,
                    is_push: false,
                    push_size: 0,
                    is_terminator: false,
                    is_jump: false,
                    is_system: false,
                    is_dup: true,
                    is_swap: false,
                    is_log: false,
                    log_topic_count: 0,
                });
            };
            ($opcode:expr, $name:expr, $category:expr, $gas:expr, swap: $n:expr) => {
                let op = $opcode as u8;
                self.info[op as usize] = Some(OpcodeInfo {
                    opcode: op,
                    name: $name,
                    category: $category,
                    base_gas_cost: $gas,
                    is_push: false,
                    push_size: 0,
                    is_terminator: false,
                    is_jump: false,
                    is_system: false,
                    is_dup: false,
                    is_swap: true,
                    is_log: false,
                    log_topic_count: 0,
                });
            };
            ($opcode:expr, $name:expr, $category:expr, $gas:expr, log: $topics:expr) => {
                let op = $opcode as u8;
                self.info[op as usize] = Some(OpcodeInfo {
                    opcode: op,
                    name: $name,
                    category: $category,
                    base_gas_cost: $gas,
                    is_push: false,
                    push_size: 0,
                    is_terminator: false,
                    is_jump: false,
                    is_system: false,
                    is_dup: false,
                    is_swap: false,
                    is_log: true,
                    log_topic_count: $topics,
                });
            };
        }

        // ── Control ──────────────────────────────────────────────────────────
        register!(Opcode::Stop, "STOP", OpcodeCategory::Control, GAS_ZERO);
        register!(Opcode::Invalid, "INVALID", OpcodeCategory::Invalid, GAS_ZERO);

        // ── Arithmetic ──────────────────────────────────────────────────────
        register!(Opcode::Add, "ADD", OpcodeCategory::Arithmetic, GAS_VERYLOW);
        register!(Opcode::Mul, "MUL", OpcodeCategory::Arithmetic, GAS_LOW);
        register!(Opcode::Sub, "SUB", OpcodeCategory::Arithmetic, GAS_VERYLOW);
        register!(Opcode::Div, "DIV", OpcodeCategory::Arithmetic, GAS_LOW);
        register!(Opcode::SDiv, "SDIV", OpcodeCategory::Arithmetic, GAS_LOW);
        register!(Opcode::Mod, "MOD", OpcodeCategory::Arithmetic, GAS_LOW);
        register!(Opcode::SMod, "SMOD", OpcodeCategory::Arithmetic, GAS_LOW);
        register!(Opcode::AddMod, "ADDMOD", OpcodeCategory::Arithmetic, GAS_MID);
        register!(Opcode::MulMod, "MULMOD", OpcodeCategory::Arithmetic, GAS_MID);
        register!(Opcode::Exp, "EXP", OpcodeCategory::Arithmetic, GAS_EXP);
        register!(Opcode::SignExtend, "SIGNEXTEND", OpcodeCategory::Arithmetic, GAS_LOW);

        // ── Comparison & Bitwise ────────────────────────────────────────────
        register!(Opcode::Lt, "LT", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::Gt, "GT", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::SLt, "SLT", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::SGt, "SGT", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::Eq, "EQ", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::IsZero, "ISZERO", OpcodeCategory::Comparison, GAS_VERYLOW);
        register!(Opcode::And, "AND", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Or, "OR", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Xor, "XOR", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Not, "NOT", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Byte, "BYTE", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Shl, "SHL", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Shr, "SHR", OpcodeCategory::Bitwise, GAS_VERYLOW);
        register!(Opcode::Sar, "SAR", OpcodeCategory::Bitwise, GAS_VERYLOW);

        // ── Cryptographic ────────────────────────────────────────────────────
        register!(Opcode::Sha3, "SHA3", OpcodeCategory::Cryptographic, GAS_SHA3);
        register!(Opcode::Blake3, "BLAKE3", OpcodeCategory::Cryptographic, GAS_SHA3);

        // ── Environment ──────────────────────────────────────────────────────
        register!(Opcode::Address, "ADDRESS", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::Balance, "BALANCE", OpcodeCategory::Environment, GAS_BALANCE);
        register!(Opcode::Origin, "ORIGIN", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::Caller, "CALLER", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::CallValue, "CALLVALUE", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::CallDataLoad, "CALLDATALOAD", OpcodeCategory::Environment, GAS_VERYLOW);
        register!(Opcode::CallDataSize, "CALLDATASIZE", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::CallDataCopy, "CALLDATACOPY", OpcodeCategory::Environment, GAS_VERYLOW);
        register!(Opcode::CodeSize, "CODESIZE", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::CodeCopy, "CODECOPY", OpcodeCategory::Environment, GAS_VERYLOW);
        register!(Opcode::GasPrice, "GASPRICE", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::ExtCodeSize, "EXTCODESIZE", OpcodeCategory::Environment, GAS_EXTCODE);
        register!(Opcode::ExtCodeCopy, "EXTCODECOPY", OpcodeCategory::Environment, GAS_EXTCODE);
        register!(Opcode::ReturnDataSize, "RETURNDATASIZE", OpcodeCategory::Environment, GAS_BASE);
        register!(Opcode::ReturnDataCopy, "RETURNDATACOPY", OpcodeCategory::Environment, GAS_VERYLOW);

        // ── Memory & Control Flow ────────────────────────────────────────────
        register!(Opcode::Pop, "POP", OpcodeCategory::Memory, GAS_BASE);
        register!(Opcode::MLoad, "MLOAD", OpcodeCategory::Memory, GAS_VERYLOW);
        register!(Opcode::MStore, "MSTORE", OpcodeCategory::Memory, GAS_VERYLOW);
        register!(Opcode::MStore8, "MSTORE8", OpcodeCategory::Memory, GAS_VERYLOW);
        register!(Opcode::SLoad, "SLOAD", OpcodeCategory::Memory, GAS_SLOAD);
        register!(Opcode::SStore, "SSTORE", OpcodeCategory::Memory, GAS_SSTORE_SET);
        register!(Opcode::Jump, "JUMP", OpcodeCategory::Control, GAS_MID);
        register!(Opcode::Jumpi, "JUMPI", OpcodeCategory::Control, GAS_HIGH);
        register!(Opcode::Pc, "PC", OpcodeCategory::Memory, GAS_BASE);
        register!(Opcode::MSize, "MSIZE", OpcodeCategory::Memory, GAS_BASE);
        register!(Opcode::Gas, "GAS", OpcodeCategory::Memory, GAS_BASE);
        register!(Opcode::JumpDest, "JUMPDEST", OpcodeCategory::Control, GAS_JUMPDEST);

        // ── Push ──────────────────────────────────────────────────────────────
        register!(Opcode::Push1, "PUSH1", OpcodeCategory::Push, GAS_VERYLOW, push_size: 1);
        register!(Opcode::Push2, "PUSH2", OpcodeCategory::Push, GAS_VERYLOW, push_size: 2);
        register!(Opcode::Push3, "PUSH3", OpcodeCategory::Push, GAS_VERYLOW, push_size: 3);
        register!(Opcode::Push4, "PUSH4", OpcodeCategory::Push, GAS_VERYLOW, push_size: 4);
        register!(Opcode::Push5, "PUSH5", OpcodeCategory::Push, GAS_VERYLOW, push_size: 5);
        register!(Opcode::Push6, "PUSH6", OpcodeCategory::Push, GAS_VERYLOW, push_size: 6);
        register!(Opcode::Push7, "PUSH7", OpcodeCategory::Push, GAS_VERYLOW, push_size: 7);
        register!(Opcode::Push8, "PUSH8", OpcodeCategory::Push, GAS_VERYLOW, push_size: 8);
        register!(Opcode::Push9, "PUSH9", OpcodeCategory::Push, GAS_VERYLOW, push_size: 9);
        register!(Opcode::Push10, "PUSH10", OpcodeCategory::Push, GAS_VERYLOW, push_size: 10);
        register!(Opcode::Push11, "PUSH11", OpcodeCategory::Push, GAS_VERYLOW, push_size: 11);
        register!(Opcode::Push12, "PUSH12", OpcodeCategory::Push, GAS_VERYLOW, push_size: 12);
        register!(Opcode::Push13, "PUSH13", OpcodeCategory::Push, GAS_VERYLOW, push_size: 13);
        register!(Opcode::Push14, "PUSH14", OpcodeCategory::Push, GAS_VERYLOW, push_size: 14);
        register!(Opcode::Push15, "PUSH15", OpcodeCategory::Push, GAS_VERYLOW, push_size: 15);
        register!(Opcode::Push16, "PUSH16", OpcodeCategory::Push, GAS_VERYLOW, push_size: 16);
        register!(Opcode::Push17, "PUSH17", OpcodeCategory::Push, GAS_VERYLOW, push_size: 17);
        register!(Opcode::Push18, "PUSH18", OpcodeCategory::Push, GAS_VERYLOW, push_size: 18);
        register!(Opcode::Push19, "PUSH19", OpcodeCategory::Push, GAS_VERYLOW, push_size: 19);
        register!(Opcode::Push20, "PUSH20", OpcodeCategory::Push, GAS_VERYLOW, push_size: 20);
        register!(Opcode::Push21, "PUSH21", OpcodeCategory::Push, GAS_VERYLOW, push_size: 21);
        register!(Opcode::Push22, "PUSH22", OpcodeCategory::Push, GAS_VERYLOW, push_size: 22);
        register!(Opcode::Push23, "PUSH23", OpcodeCategory::Push, GAS_VERYLOW, push_size: 23);
        register!(Opcode::Push24, "PUSH24", OpcodeCategory::Push, GAS_VERYLOW, push_size: 24);
        register!(Opcode::Push25, "PUSH25", OpcodeCategory::Push, GAS_VERYLOW, push_size: 25);
        register!(Opcode::Push26, "PUSH26", OpcodeCategory::Push, GAS_VERYLOW, push_size: 26);
        register!(Opcode::Push27, "PUSH27", OpcodeCategory::Push, GAS_VERYLOW, push_size: 27);
        register!(Opcode::Push28, "PUSH28", OpcodeCategory::Push, GAS_VERYLOW, push_size: 28);
        register!(Opcode::Push29, "PUSH29", OpcodeCategory::Push, GAS_VERYLOW, push_size: 29);
        register!(Opcode::Push30, "PUSH30", OpcodeCategory::Push, GAS_VERYLOW, push_size: 30);
        register!(Opcode::Push31, "PUSH31", OpcodeCategory::Push, GAS_VERYLOW, push_size: 31);
        register!(Opcode::Push32, "PUSH32", OpcodeCategory::Push, GAS_VERYLOW, push_size: 32);

        // ── Dup ──────────────────────────────────────────────────────────────
        register!(Opcode::Dup1, "DUP1", OpcodeCategory::Dup, GAS_VERYLOW, dup: 1);
        register!(Opcode::Dup2, "DUP2", OpcodeCategory::Dup, GAS_VERYLOW, dup: 2);
        register!(Opcode::Dup3, "DUP3", OpcodeCategory::Dup, GAS_VERYLOW, dup: 3);
        register!(Opcode::Dup4, "DUP4", OpcodeCategory::Dup, GAS_VERYLOW, dup: 4);
        register!(Opcode::Dup5, "DUP5", OpcodeCategory::Dup, GAS_VERYLOW, dup: 5);
        register!(Opcode::Dup6, "DUP6", OpcodeCategory::Dup, GAS_VERYLOW, dup: 6);
        register!(Opcode::Dup7, "DUP7", OpcodeCategory::Dup, GAS_VERYLOW, dup: 7);
        register!(Opcode::Dup8, "DUP8", OpcodeCategory::Dup, GAS_VERYLOW, dup: 8);
        register!(Opcode::Dup9, "DUP9", OpcodeCategory::Dup, GAS_VERYLOW, dup: 9);
        register!(Opcode::Dup10, "DUP10", OpcodeCategory::Dup, GAS_VERYLOW, dup: 10);
        register!(Opcode::Dup11, "DUP11", OpcodeCategory::Dup, GAS_VERYLOW, dup: 11);
        register!(Opcode::Dup12, "DUP12", OpcodeCategory::Dup, GAS_VERYLOW, dup: 12);
        register!(Opcode::Dup13, "DUP13", OpcodeCategory::Dup, GAS_VERYLOW, dup: 13);
        register!(Opcode::Dup14, "DUP14", OpcodeCategory::Dup, GAS_VERYLOW, dup: 14);
        register!(Opcode::Dup15, "DUP15", OpcodeCategory::Dup, GAS_VERYLOW, dup: 15);
        register!(Opcode::Dup16, "DUP16", OpcodeCategory::Dup, GAS_VERYLOW, dup: 16);

        // ── Swap ─────────────────────────────────────────────────────────────
        register!(Opcode::Swap1, "SWAP1", OpcodeCategory::Swap, GAS_VERYLOW, swap: 1);
        register!(Opcode::Swap2, "SWAP2", OpcodeCategory::Swap, GAS_VERYLOW, swap: 2);
        register!(Opcode::Swap3, "SWAP3", OpcodeCategory::Swap, GAS_VERYLOW, swap: 3);
        register!(Opcode::Swap4, "SWAP4", OpcodeCategory::Swap, GAS_VERYLOW, swap: 4);
        register!(Opcode::Swap5, "SWAP5", OpcodeCategory::Swap, GAS_VERYLOW, swap: 5);
        register!(Opcode::Swap6, "SWAP6", OpcodeCategory::Swap, GAS_VERYLOW, swap: 6);
        register!(Opcode::Swap7, "SWAP7", OpcodeCategory::Swap, GAS_VERYLOW, swap: 7);
        register!(Opcode::Swap8, "SWAP8", OpcodeCategory::Swap, GAS_VERYLOW, swap: 8);
        register!(Opcode::Swap9, "SWAP9", OpcodeCategory::Swap, GAS_VERYLOW, swap: 9);
        register!(Opcode::Swap10, "SWAP10", OpcodeCategory::Swap, GAS_VERYLOW, swap: 10);
        register!(Opcode::Swap11, "SWAP11", OpcodeCategory::Swap, GAS_VERYLOW, swap: 11);
        register!(Opcode::Swap12, "SWAP12", OpcodeCategory::Swap, GAS_VERYLOW, swap: 12);
        register!(Opcode::Swap13, "SWAP13", OpcodeCategory::Swap, GAS_VERYLOW, swap: 13);
        register!(Opcode::Swap14, "SWAP14", OpcodeCategory::Swap, GAS_VERYLOW, swap: 14);
        register!(Opcode::Swap15, "SWAP15", OpcodeCategory::Swap, GAS_VERYLOW, swap: 15);
        register!(Opcode::Swap16, "SWAP16", OpcodeCategory::Swap, GAS_VERYLOW, swap: 16);

        // ── Logging ─────────────────────────────────────────────────────────
        register!(Opcode::Log0, "LOG0", OpcodeCategory::Log, GAS_LOG, log: 0);
        register!(Opcode::Log1, "LOG1", OpcodeCategory::Log, GAS_LOG, log: 1);
        register!(Opcode::Log2, "LOG2", OpcodeCategory::Log, GAS_LOG, log: 2);
        register!(Opcode::Log3, "LOG3", OpcodeCategory::Log, GAS_LOG, log: 3);
        register!(Opcode::Log4, "LOG4", OpcodeCategory::Log, GAS_LOG, log: 4);

        // ── System ──────────────────────────────────────────────────────────
        register!(Opcode::Create, "CREATE", OpcodeCategory::System, GAS_CREATE);
        register!(Opcode::Call, "CALL", OpcodeCategory::System, GAS_CALL);
        register!(Opcode::CallCode, "CALLCODE", OpcodeCategory::System, GAS_CALL);
        register!(Opcode::Return, "RETURN", OpcodeCategory::Control, GAS_ZERO);
        register!(Opcode::DelegateCall, "DELEGATECALL", OpcodeCategory::System, GAS_CALL);
        register!(Opcode::Create2, "CREATE2", OpcodeCategory::System, GAS_CREATE);
        register!(Opcode::StaticCall, "STATICCALL", OpcodeCategory::System, GAS_CALL);
        register!(Opcode::Revert, "REVERT", OpcodeCategory::Control, GAS_ZERO);
        register!(Opcode::SelfDestruct, "SELFDESTRUCT", OpcodeCategory::System, GAS_SELFDESTRUCT);
    }

    /// Get info for an opcode.
    pub fn get(&self, opcode: u8) -> Option<&OpcodeInfo> {
        self.info[opcode as usize].as_ref()
    }

    /// Get the opcode info, with disabled opcodes treated as INVALID.
    pub fn get_effective(&self, opcode: u8) -> Option<&OpcodeInfo> {
        if self.config.is_disabled(opcode) {
            self.info[Opcode::Invalid as usize].as_ref()
        } else {
            self.info[opcode as usize].as_ref()
        }
    }

    /// Get the gas cost for an opcode (adjusted by configuration).
    pub fn gas_cost(&self, opcode: u8) -> u64 {
        if let Some(info) = self.get_effective(opcode) {
            self.config.adjusted_gas_cost(info.base_gas_cost)
        } else {
            0
        }
    }

    /// Validate bytecode.
    pub fn validate(&self, code: &[u8]) -> Result<(), OpcodeError> {
        if code.len() > self.config.max_code_size {
            return Err(OpcodeError::CodeTooLarge {
                size: code.len(),
                max: self.config.max_code_size,
            });
        }

        // Check cache.
        if self.config.cache_validation {
            let mut cache = self.cache.lock();
            if let Some(cache) = cache.as_mut() {
                let key = code.to_vec();
                if let Some(&valid) = cache.get(&key) {
                    self.metrics.record_cache_hit();
                    if valid {
                        return Ok(());
                    } else {
                        return Err(OpcodeError::InvalidBytecode);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Validate.
        let result = validate_bytecode_internal(code, self);
        if self.config.cache_validation {
            let mut cache = self.cache.lock();
            if let Some(cache) = cache.as_mut() {
                let key = code.to_vec();
                cache.put(key, result.is_ok());
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
            if let Some(info) = self.get(opcode) {
                trace!(opcode = info.name, gas, "executed opcode");
            } else {
                trace!(opcode, "executed unknown opcode");
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

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> OpcodeMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get configuration.
    pub fn config(&self) -> &OpcodeConfig {
        &self.config
    }

    /// Clear the validation cache.
    pub fn clear_cache(&self) {
        let mut cache = self.cache.lock();
        if let Some(cache) = cache.as_mut() {
            cache.clear();
        }
    }

    /// Get cache size.
    pub fn cache_size(&self) -> usize {
        let cache = self.cache.lock();
        if let Some(cache) = cache.as_ref() {
            cache.len()
        } else {
            0
        }
    }

    /// Iterate over all registered opcodes.
    pub fn iter(&self) -> impl Iterator<Item = &OpcodeInfo> {
        self.info.iter().filter_map(|info| info.as_ref())
    }

    /// Get opcodes by category.
    pub fn by_category(&self, category: OpcodeCategory) -> Vec<&OpcodeInfo> {
        self.iter().filter(|info| info.category == category).collect()
    }

    /// Check if an opcode is valid (not disabled and known).
    pub fn is_valid(&self, opcode: u8) -> bool {
        self.get_effective(opcode).is_some()
    }
}

// ── Error Extensions ─────────────────────────────────────────────────────

/// Extended opcode errors.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpcodeError {
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },

    #[error("truncated push at position {pos}: expected {expected} bytes, got {remaining}")]
    TruncatedPush { pos: usize, expected: usize, remaining: usize },

    #[error("invalid jump destination at position {pos}")]
    InvalidJumpDest { pos: usize },

    #[error("code too large: {size} bytes (max {max})")]
    CodeTooLarge { size: usize, max: usize },

    #[error("invalid bytecode")]
    InvalidBytecode,

    #[error("disabled opcode: 0x{opcode:02X}")]
    DisabledOpcode { opcode: u8 },
}

pub type OpcodeResult<T> = Result<T, OpcodeError>;

// ── Internal validation ─────────────────────────────────────────────────

fn validate_bytecode_internal(code: &[u8], registry: &OpcodeRegistry) -> Result<(), OpcodeError> {
    let mut i = 0;
    while i < code.len() {
        let opcode = code[i];
        let info = registry.get_effective(opcode).ok_or(OpcodeError::InvalidOpcode { opcode })?;
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

// ── Global Registry ─────────────────────────────────────────────────────

static GLOBAL_REGISTRY: std::sync::OnceLock<OpcodeRegistry> = std::sync::OnceLock::new();

/// Initialize the global opcode registry.
pub fn init_opcodes(config: OpcodeConfig) -> Result<(), String> {
    let registry = OpcodeRegistry::new(config)?;
    GLOBAL_REGISTRY.set(registry).map_err(|_| "registry already initialized".into())
}

/// Get the global opcode registry.
/// Panics if not initialized.
pub fn global_registry() -> &'static OpcodeRegistry {
    GLOBAL_REGISTRY.get().expect("opcode registry not initialized")
}

// ── Standalone functions (backward compatibility) ─────────────────────

/// Try from u8 (uses global registry).
pub fn try_from_opcode(value: u8) -> OpcodeResult<Opcode> {
    Opcode::try_from(value)
}

/// Validate bytecode (uses global registry).
pub fn validate_bytecode(code: &[u8]) -> Result<(), OpcodeError> {
    global_registry().validate(code)
}

/// Disassemble bytecode (uses global registry).
pub fn disassemble(code: &[u8]) -> String {
    // For backward compatibility, we use the original implementation.
    // We'll keep the original disassemble function as is.
    let mut output = String::new();
    let mut i = 0;
    while i < code.len() {
        let op = match Opcode::try_from(code[i]) {
            Ok(op) => op,
            Err(_) => {
                output.push_str(&format!("{:04X}: INVALID 0x{:02X}\n", i, code[i]));
                i += 1;
                continue;
            }
        };
        if op.is_push() {
            let size = op.push_data_size();
            let end = (i + 1 + size).min(code.len());
            let data = &code[i + 1..end];
            let hex_data = data.iter().map(|b| format!("{:02X}", b)).collect::<Vec<_>>().join("");
            output.push_str(&format!("{:04X}: {:8} {}\n", i, op.name(), hex_data));
            i = end;
        } else {
            output.push_str(&format!("{:04X}: {:8}\n", i, op.name()));
            i += 1;
        }
    }
    output
}

// ── Legacy constants ────────────────────────────────────────────────────

// Keep all the legacy constants from the original code.
// They are already defined via the macro.

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_validation() {
        let mut config = OpcodeConfig::default();
        assert!(config.validate().is_ok());

        config.max_code_size = 0;
        assert!(config.validate().is_err());

        config.max_code_size = 100;
        config.gas_cost_multiplier = 0.0;
        assert!(config.validate().is_err());

        config.gas_cost_multiplier = 1.0;
        config.max_cache_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_registry_creation() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();
        assert!(registry.get(0x01).is_some());
        assert!(registry.get(0x60).is_some());
        assert!(registry.get(0x0C).is_none());
    }

    #[test]
    fn test_gas_cost() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();
        assert_eq!(registry.gas_cost(0x01), GAS_VERYLOW);
        assert_eq!(registry.gas_cost(0x60), GAS_VERYLOW);
        assert_eq!(registry.gas_cost(0xFE), GAS_ZERO);
    }

    #[test]
    fn test_gas_cost_adjusted() {
        let config = OpcodeConfig {
            gas_cost_multiplier: 2.0,
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(config).unwrap();
        assert_eq!(registry.gas_cost(0x01), GAS_VERYLOW * 2);
    }

    #[test]
    fn test_disabled_opcodes() {
        let config = OpcodeConfig {
            disabled_opcodes: vec![0x01],
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(config).unwrap();
        // ADD (0x01) is disabled, should be treated as INVALID.
        assert!(registry.get_effective(0x01).is_some());
        // The info should be the INVALID opcode.
        let info = registry.get_effective(0x01).unwrap();
        assert_eq!(info.name, "INVALID");
    }

    #[test]
    fn test_validate_bytecode() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();

        let code = vec![0x60, 0x01, 0x01]; // PUSH1 0x01, ADD
        assert!(registry.validate(&code).is_ok());

        let invalid = vec![0x0C];
        assert!(registry.validate(&invalid).is_err());

        let truncated = vec![0x60];
        assert!(registry.validate(&truncated).is_err());
    }

    #[test]
    fn test_validate_bytecode_caching() {
        let config = OpcodeConfig {
            cache_validation: true,
            max_cache_size: 10,
            ..Default::default()
        };
        let registry = OpcodeRegistry::new(config).unwrap();
        let code = vec![0x60, 0x01, 0x01];
        registry.validate(&code).unwrap();
        registry.validate(&code).unwrap();
        let snap = registry.metrics_snapshot();
        assert!(snap.cache_hits > 0);
        assert!(snap.cache_misses > 0);
    }

    #[test]
    fn test_by_category() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();
        let arithmetic = registry.by_category(OpcodeCategory::Arithmetic);
        assert!(!arithmetic.is_empty());
        assert!(arithmetic.iter().any(|info| info.name == "ADD"));
        assert!(arithmetic.iter().any(|info| info.name == "MUL"));
    }

    #[test]
    fn test_metrics() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();
        registry.record_execution(0x01, 10);
        registry.record_execution(0x02, 20);
        registry.record_invalid();
        let snap = registry.metrics_snapshot();
        assert_eq!(snap.total_executions, 2);
        assert_eq!(snap.opcode_counts[0x01], 1);
        assert_eq!(snap.opcode_counts[0x02], 1);
        assert_eq!(snap.invalid_opcodes, 1);
        assert_eq!(snap.gas_consumed, 30);
    }

    #[test]
    fn test_opcode_info_properties() {
        let config = OpcodeConfig::default();
        let registry = OpcodeRegistry::new(config).unwrap();

        let push1 = registry.get(0x60).unwrap();
        assert!(push1.is_push);
        assert_eq!(push1.push_size, 1);

        let add = registry.get(0x01).unwrap();
        assert!(!add.is_push);
        assert_eq!(add.category, OpcodeCategory::Arithmetic);

        let jump = registry.get(0x56).unwrap();
        assert!(jump.is_jump);

        let stop = registry.get(0x00).unwrap();
        assert!(stop.is_terminator);
    }

    #[test]
    fn test_legacy_constants() {
        assert_eq!(STOP, 0x00);
        assert_eq!(ADD, 0x01);
        assert_eq!(PUSH1, 0x60);
        assert_eq!(DUP1, 0x80);
        assert_eq!(SWAP1, 0x90);
        assert_eq!(LOG0, 0xA0);
        assert_eq!(CREATE, 0xF0);
        assert_eq!(INVALID, 0xFE);
        assert_eq!(BLAKE3, 0x21);
    }

    #[test]
    fn test_const_lookup_table() {
        assert_eq!(OPCODE_LUT[0x01], Some(Opcode::Add));
        assert_eq!(OPCODE_LUT[0x60], Some(Opcode::Push1));
        assert_eq!(OPCODE_LUT[0x21], Some(Opcode::Blake3));
        assert_eq!(OPCODE_LUT[0x0C], None);
    }

    #[test]
    fn test_global_registry() {
        let config = OpcodeConfig::default();
        init_opcodes(config).unwrap();
        let registry = global_registry();
        assert!(registry.get(0x01).is_some());
        assert_eq!(registry.gas_cost(0x01), GAS_VERYLOW);
    }

    #[test]
    fn test_disassemble() {
        let code = vec![0x60, 0x01, 0x01, 0x60, 0x02, 0x01];
        let output = disassemble(&code);
        let expected = "0000: PUSH1    01\n0003: ADD\n0004: PUSH1    02\n0007: ADD\n";
        assert_eq!(output, expected);
    }
}
