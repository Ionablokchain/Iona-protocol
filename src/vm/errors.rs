//! VM execution errors.
//!
//! This module defines all possible errors that can occur during VM execution.
//! Errors are categorized by their source (gas, stack, memory, control flow,
//! calls, storage) and by their severity (fatal, revert, recoverable).
//!
//! # Error handling philosophy
//!
//! - **Fatal errors** (`is_fatal()`) immediately terminate execution. No state
//!   changes are persisted, and the transaction is marked as failed.
//! - **Revert errors** (`should_revert()`) undo the current call's state
//!   changes but allow the caller to handle the error (e.g., via `try/catch`).
//! - **Recoverable errors** (`is_recoverable()`) can be caught by the calling
//!   contract using `REVERT` semantics or pattern matching in higher-level
//!   languages targeting the IONA VM.

use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Result alias
// -----------------------------------------------------------------------------

/// Result type alias for VM operations.
pub type VmResult<T> = Result<T, VmError>;

// -----------------------------------------------------------------------------
// VmError
// -----------------------------------------------------------------------------

/// VM execution error.
///
/// Each variant maps to a specific JSON-RPC error code (see [`VmError::code`]).
#[derive(Debug, Error, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[non_exhaustive] // Allow future error variants without breaking changes
pub enum VmError {
    // ── Gas ─────────────────────────────────────────────────────────────────
    /// Execution ran out of gas.
    ///
    /// **Fatal**. The transaction is reverted and gas is consumed.
    #[error("out of gas")]
    OutOfGas,

    /// Intrinsic gas (base cost) exceeds the gas limit.
    ///
    /// **Fatal**. Transaction is rejected before execution starts.
    #[error("intrinsic gas too low: need {need}, have {have}")]
    IntrinsicGasTooLow { need: u64, have: u64 },

    // ── Opcode ──────────────────────────────────────────────────────────────
    /// Encountered an invalid or unknown opcode.
    ///
    /// **Fatal**. Execution cannot continue.
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },

    /// Opcode data is malformed (e.g., truncated push).
    ///
    /// **Fatal**. Bytecode is invalid.
    #[error("malformed opcode data at position {pos}: expected {expected} bytes, got {got}")]
    MalformedOpcode { pos: usize, expected: usize, got: usize },

    // ── Stack ──────────────────────────────────────────────────────────────
    /// Not enough items on the stack for the operation.
    ///
    /// **Fatal**. Typically caused by malformed bytecode.
    #[error("stack underflow: need {need}, have {have}")]
    StackUnderflow { need: usize, have: usize },

    /// Stack limit exceeded (max 1024 items).
    ///
    /// **Fatal**. Prevents infinite stack growth.
    #[error("stack overflow: limit {limit} exceeded")]
    StackOverflow { limit: usize },

    // ── Arithmetic ─────────────────────────────────────────────────────────
    /// Division by zero (DIV, SDIV, MOD, SMOD).
    ///
    /// **Revert**. The caller can handle this gracefully.
    #[error("division by zero")]
    DivisionByZero,

    /// Arithmetic overflow (e.g., ADD, MUL with carry beyond 256 bits).
    ///
    /// **Revert**. The operation result does not fit in 256 bits.
    #[error("arithmetic overflow: {operation}")]
    ArithmeticOverflow { operation: &'static str },

    // ── Memory ─────────────────────────────────────────────────────────────
    /// Memory limit exceeded (max 4 MiB).
    ///
    /// **Fatal**. Prevents unbounded memory allocation.
    #[error("memory limit exceeded: tried to access {size} bytes (limit {limit})")]
    MemoryLimit { size: usize, limit: usize },

    /// Memory offset overflow (offset + size > u64::MAX).
    ///
    /// **Fatal**. Arithmetic overflow in memory addressing.
    #[error("memory offset overflow: offset {offset} + size {size}")]
    MemoryOffsetOverflow { offset: usize, size: usize },

    // ── Control flow ───────────────────────────────────────────────────────
    /// Jump destination is not a valid JUMPDEST.
    ///
    /// **Revert**. The caller can catch this and handle invalid jumps.
    #[error("invalid jump destination: 0x{dest:X}")]
    InvalidJump { dest: usize },

    /// Program counter out of bounds (tried to execute beyond code length).
    ///
    /// **Fatal**. Execution cannot continue past the code.
    #[error("program counter out of bounds: pc={pc}, code_length={code_length}")]
    PcOutOfBounds { pc: usize, code_length: usize },

    // ── Call / Create ──────────────────────────────────────────────────────
    /// Call depth limit exceeded (max 1024 nested calls).
    ///
    /// **Fatal**. Prevents stack overflow from recursion.
    #[error("call depth limit exceeded (max {limit})")]
    CallDepth { limit: usize },

    /// Attempt to write to read-only state (STATICCALL violation).
    ///
    /// **Revert**. The static call context forbids state modifications.
    #[error("write protection: {reason}")]
    WriteProtection { reason: &'static str },

    /// Contract already exists at the target address.
    ///
    /// **Revert**. CREATE/CREATE2 collision detected.
    #[error("contract already exists at address {address:?}")]
    ContractExists { address: [u8; 32] },

    /// Code is too large (EIP-170: max 24576 bytes).
    ///
    /// **Fatal**. Prevents DoS via oversized contracts.
    #[error("code too large: {size} bytes (max {limit})")]
    CodeTooLarge { size: usize, limit: usize },

    // ── Calldata / Return data ─────────────────────────────────────────────
    /// Calldata access out of bounds.
    ///
    /// **Revert**. The caller tried to read beyond calldata size.
    #[error("calldata out of bounds: offset {offset}, size {size}, len {len}")]
    CalldataOob { offset: usize, size: usize, len: usize },

    /// Return data access out of bounds (RETURNDATACOPY).
    ///
    /// **Revert**. The caller tried to read beyond return data size.
    #[error("return data out of bounds: offset {offset}, size {size}, len {len}")]
    ReturnDataOob { offset: usize, size: usize, len: usize },

    // ── Storage ────────────────────────────────────────────────────────────
    /// Storage access error (e.g., I/O failure, database corruption).
    ///
    /// **Revert**. Storage operation could not be completed.
    #[error("storage error: {message}")]
    Storage { message: String },

    // ── State ──────────────────────────────────────────────────────────────
    /// Generic state error (e.g., missing account, insufficient balance).
    ///
    /// **Revert**. The requested state operation is invalid.
    #[error("state error: {message}")]
    State { message: String },

    /// Insufficient balance for the operation.
    ///
    /// **Revert**. Call value exceeds available balance.
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    /// Account nonce overflow (nonce > u64::MAX).
    ///
    /// **Revert**. Cannot create a new contract with nonce overflow.
    #[error("nonce overflow: {nonce}")]
    NonceOverflow { nonce: u64 },

    // ── Execution ──────────────────────────────────────────────────────────
    /// Execution halted (STOP, RETURN, REVERT, or unrecoverable).
    ///
    /// **Fatal**. The execution context is terminated.
    #[error("execution halted")]
    Halt,

    /// Revert with a reason (REVERT opcode with data).
    ///
    /// **Revert**. The call was reverted by the contract with a reason.
    #[error("reverted: {reason}")]
    Revert { reason: String },

    // ── Internal VM errors ──────────────────────────────────────────────────
    /// Unexpected internal VM error (should not happen).
    ///
    /// **Fatal**. Indicates a bug in the VM implementation.
    #[error("internal VM error: {message}")]
    Internal { message: String },
}

// -----------------------------------------------------------------------------
// Classification methods
// -----------------------------------------------------------------------------

impl VmError {
    /// Returns `true` if the error is fatal and the execution cannot continue.
    ///
    /// Fatal errors consume all remaining gas and mark the transaction as
    /// failed. No state changes are persisted.
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

    /// Returns `true` if the error should cause a revert (state changes
    /// discarded, but the transaction is not marked as failed unless the
    /// top-level call also reverts).
    pub const fn should_revert(&self) -> bool {
        !self.is_fatal()
    }

    /// Returns `true` if the error is recoverable by the calling contract
    /// (e.g., can be caught by a `try/catch` mechanism or handled by
    /// inspecting the return data).
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

    /// Returns a JSON-RPC error code suitable for API responses.
    ///
    /// Codes follow the Ethereum JSON-RPC convention where VM errors are
    /// in the range `-32015` to `-32099` and internal errors use `-32603`.
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
}

// -----------------------------------------------------------------------------
// Convenience constructors for common errors
// -----------------------------------------------------------------------------

impl VmError {
    /// Create a new revert error with a reason string.
    pub fn revert(reason: impl Into<String>) -> Self {
        VmError::Revert {
            reason: reason.into(),
        }
    }

    /// Create a new storage error with a message.
    pub fn storage(message: impl Into<String>) -> Self {
        VmError::Storage {
            message: message.into(),
        }
    }

    /// Create a new state error with a message.
    pub fn state(message: impl Into<String>) -> Self {
        VmError::State {
            message: message.into(),
        }
    }

    /// Create a new internal error with a message.
    pub fn internal(message: impl Into<String>) -> Self {
        VmError::Internal {
            message: message.into(),
        }
    }
}

// -----------------------------------------------------------------------------
// Conversions from standard library and other error types
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display ──────────────────────────────────────────────────────────
    #[test]
    fn test_error_display() {
        let err = VmError::InvalidOpcode { opcode: 0xFE };
        assert_eq!(format!("{}", err), "invalid opcode: 0xFE");

        let err = VmError::ReturnDataOob {
            offset: 10,
            size: 20,
            len: 15,
        };
        assert!(format!("{}", err).contains("return data out of bounds"));
        assert!(format!("{}", err).contains("offset 10"));
        assert!(format!("{}", err).contains("size 20"));
        assert!(format!("{}", err).contains("len 15"));

        let err = VmError::StackUnderflow { need: 3, have: 1 };
        assert_eq!(format!("{}", err), "stack underflow: need 3, have 1");

        let err = VmError::IntrinsicGasTooLow { need: 21000, have: 10000 };
        assert!(format!("{}", err).contains("intrinsic gas too low"));
        assert!(format!("{}", err).contains("need 21000"));
        assert!(format!("{}", err).contains("have 10000"));
    }

    // ── Classification ───────────────────────────────────────────────────
    #[test]
    fn test_is_fatal() {
        assert!(VmError::OutOfGas.is_fatal());
        assert!(VmError::IntrinsicGasTooLow { need: 0, have: 0 }.is_fatal());
        assert!(VmError::StackUnderflow { need: 1, have: 0 }.is_fatal());
        assert!(VmError::StackOverflow { limit: 1024 }.is_fatal());
        assert!(VmError::MemoryLimit { size: 0, limit: 0 }.is_fatal());
        assert!(VmError::MemoryOffsetOverflow { offset: 0, size: 0 }.is_fatal());
        assert!(VmError::CallDepth { limit: 0 }.is_fatal());
        assert!(VmError::CodeTooLarge { size: 0, limit: 0 }.is_fatal());
        assert!(VmError::PcOutOfBounds { pc: 0, code_length: 0 }.is_fatal());
        assert!(VmError::Internal { message: "".into() }.is_fatal());
        assert!(VmError::Halt.is_fatal());
        // Non-fatal
        assert!(!VmError::State { message: "".into() }.is_fatal());
        assert!(!VmError::DivisionByZero.is_fatal());
        assert!(!VmError::Revert { reason: "".into() }.is_fatal());
    }

    #[test]
    fn test_should_revert() {
        // All revert errors should NOT be fatal
        assert!(VmError::State { message: "".into() }.should_revert());
        assert!(VmError::DivisionByZero.should_revert());
        assert!(VmError::Revert { reason: "".into() }.should_revert());
        // Fatal errors should not revert
        assert!(!VmError::OutOfGas.should_revert());
        assert!(!VmError::InvalidOpcode { opcode: 0 }.should_revert());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(VmError::State { message: "".into() }.is_recoverable());
        assert!(VmError::ArithmeticOverflow { operation: "overflow" }.is_recoverable());
        assert!(VmError::InsufficientBalance { have: 0, need: 1 }.is_recoverable());
        assert!(!VmError::OutOfGas.is_recoverable());
        assert!(!VmError::StackUnderflow { need: 1, have: 0 }.is_recoverable());
    }

    // ── Error codes ──────────────────────────────────────────────────────
    #[test]
    fn test_error_codes() {
        assert_eq!(VmError::OutOfGas.code(), -32015);
        assert_eq!(VmError::InvalidOpcode { opcode: 0 }.code(), -32017);
        assert_eq!(VmError::Internal { message: "".into() }.code(), -32603);
        assert_eq!(VmError::Revert { reason: "".into() }.code(), -32038);
        assert_eq!(VmError::InsufficientBalance { have: 0, need: 0 }.code(), -32035);
    }

    #[test]
    fn test_error_codes_unique() {
        use std::collections::HashSet;
        let codes: Vec<i32> = vec![
            VmError::OutOfGas.code(),
            VmError::IntrinsicGasTooLow { need: 0, have: 0 }.code(),
            VmError::InvalidOpcode { opcode: 0 }.code(),
            VmError::MalformedOpcode { pos: 0, expected: 0, got: 0 }.code(),
            VmError::StackUnderflow { need: 0, have: 0 }.code(),
            VmError::StackOverflow { limit: 0 }.code(),
            VmError::DivisionByZero.code(),
            VmError::ArithmeticOverflow { operation: "" }.code(),
            VmError::MemoryLimit { size: 0, limit: 0 }.code(),
            VmError::MemoryOffsetOverflow { offset: 0, size: 0 }.code(),
            VmError::InvalidJump { dest: 0 }.code(),
            VmError::PcOutOfBounds { pc: 0, code_length: 0 }.code(),
            VmError::CallDepth { limit: 0 }.code(),
            VmError::WriteProtection { reason: "" }.code(),
            VmError::ContractExists { address: [0u8; 32] }.code(),
            VmError::CodeTooLarge { size: 0, limit: 0 }.code(),
            VmError::CalldataOob { offset: 0, size: 0, len: 0 }.code(),
            VmError::ReturnDataOob { offset: 0, size: 0, len: 0 }.code(),
            VmError::Storage { message: "".into() }.code(),
            VmError::State { message: "".into() }.code(),
            VmError::InsufficientBalance { have: 0, need: 0 }.code(),
            VmError::NonceOverflow { nonce: 0 }.code(),
            VmError::Halt.code(),
            VmError::Revert { reason: "".into() }.code(),
            VmError::Internal { message: "".into() }.code(),
        ];
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len(), "Error codes must be unique");
    }

    // ── as_str ───────────────────────────────────────────────────────────
    #[test]
    fn test_as_str() {
        assert_eq!(VmError::OutOfGas.as_str(), "OutOfGas");
        assert_eq!(VmError::DivisionByZero.as_str(), "DivisionByZero");
        assert_eq!(VmError::Internal { message: "".into() }.as_str(), "Internal");
        assert_eq!(VmError::MalformedOpcode { pos: 0, expected: 0, got: 0 }.as_str(), "MalformedOpcode");
    }

    // ── Convenience constructors ────────────────────────────────────────
    #[test]
    fn test_convenience_constructors() {
        let err = VmError::revert("test reason");
        assert!(matches!(err, VmError::Revert { reason } if reason == "test reason"));

        let err = VmError::storage("disk full");
        assert!(matches!(err, VmError::Storage { message } if message == "disk full"));

        let err = VmError::state("invalid account");
        assert!(matches!(err, VmError::State { message } if message == "invalid account"));

        let err = VmError::internal("bug");
        assert!(matches!(err, VmError::Internal { message } if message == "bug"));
    }

    #[test]
    fn test_revert_reason_extraction() {
        let err = VmError::revert("custom reason");
        assert_eq!(err.revert_reason(), Some("custom reason"));
        assert!(err.has_revert_reason());

        let err = VmError::OutOfGas;
        assert_eq!(err.revert_reason(), None);
        assert!(!err.has_revert_reason());
    }

    // ── Conversions ──────────────────────────────────────────────────────
    #[test]
    fn test_conversion_try_from_int_error() {
        let err: VmError = std::num::TryFromIntError::from(()).into();
        assert!(matches!(err, VmError::Internal { message } if message.contains("integer conversion failed")));
    }

    #[test]
    fn test_conversion_io_error() {
        let err: VmError = std::io::Error::new(std::io::ErrorKind::Other, "disk full").into();
        assert!(matches!(err, VmError::Storage { message } if message.contains("disk full")));
    }

    #[test]
    fn test_conversion_opcode_error() {
        let op_err = crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode: 0x42 };
        let err: VmError = op_err.into();
        assert!(matches!(err, VmError::InvalidOpcode { opcode: 0x42 }));

        let op_err = crate::vm::opcodes::OpcodeError::TruncatedPush {
            pos: 10,
            expected: 2,
            remaining: 1,
        };
        let err: VmError = op_err.into();
        assert!(matches!(err, VmError::MalformedOpcode { pos: 10, expected: 2, got: 1 }));
    }

    // ── PartialEq & Clone ───────────────────────────────────────────────
    #[test]
    fn test_partial_eq() {
        let err1 = VmError::InvalidOpcode { opcode: 0xFE };
        let err2 = VmError::InvalidOpcode { opcode: 0xFE };
        let err3 = VmError::InvalidOpcode { opcode: 0xFF };
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_clone() {
        let err = VmError::Storage { message: "test".into() };
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }

    // ── Serialization (serde) ───────────────────────────────────────────
    #[test]
    fn test_serde_roundtrip() {
        let err = VmError::ArithmeticOverflow { operation: "ADD" };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: VmError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);

        let err = VmError::Revert { reason: "test".into() };
        let json = serde_json::to_string(&err).unwrap();
        let decoded: VmError = serde_json::from_str(&json).unwrap();
        assert_eq!(err, decoded);
    }
}
