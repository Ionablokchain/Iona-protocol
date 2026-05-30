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
#[derive(Debug, Error, Clone, PartialEq, Eq)]
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
    #[error("intrinsic gas too low: need {0}, have {1}")]
    IntrinsicGasTooLow(u64, u64),

    // ── Opcode ──────────────────────────────────────────────────────────────
    /// Encountered an invalid or unknown opcode.
    ///
    /// **Fatal**. Execution cannot continue.
    #[error("invalid opcode: 0x{0:02X}")]
    InvalidOpcode(u8),

    // ── Stack ──────────────────────────────────────────────────────────────
    /// Not enough items on the stack for the operation.
    ///
    /// **Fatal**. Typically caused by malformed bytecode.
    #[error("stack underflow: need {need}, have {have}")]
    StackUnderflow { need: usize, have: usize },

    /// Stack limit exceeded (max 1024 items).
    ///
    /// **Fatal**. Prevents infinite stack growth.
    #[error("stack overflow: limit {0} exceeded")]
    StackOverflow(usize),

    // ── Arithmetic ─────────────────────────────────────────────────────────
    /// Division by zero (DIV, SDIV, MOD, SMOD).
    ///
    /// **Revert**. The caller can handle this gracefully.
    #[error("division by zero")]
    DivisionByZero,

    /// Arithmetic overflow (e.g., ADD, MUL with carry beyond 256 bits).
    ///
    /// **Revert**. The operation result does not fit in 256 bits.
    #[error("arithmetic overflow: {0}")]
    ArithmeticOverflow(&'static str),

    // ── Memory ─────────────────────────────────────────────────────────────
    /// Memory limit exceeded (max 4 MiB).
    ///
    /// **Fatal**. Prevents unbounded memory allocation.
    #[error("memory limit exceeded: tried to access {0} bytes")]
    MemoryLimit(usize),

    /// Memory offset overflow (offset + size > u64::MAX).
    ///
    /// **Fatal**. Arithmetic overflow in memory addressing.
    #[error("memory offset overflow: offset {0} + size {1}")]
    MemoryOffsetOverflow(usize, usize),

    // ── Control flow ───────────────────────────────────────────────────────
    /// Jump destination is not a valid JUMPDEST.
    ///
    /// **Revert**. The caller can catch this and handle invalid jumps.
    #[error("invalid jump destination: 0x{0:X}")]
    InvalidJump(usize),

    /// Program counter out of bounds (tried to execute beyond code length).
    ///
    /// **Fatal**. Execution cannot continue past the code.
    #[error("program counter out of bounds: pc={pc}, code_length={code_length}")]
    PcOutOfBounds { pc: usize, code_length: usize },

    // ── Call / Create ──────────────────────────────────────────────────────
    /// Call depth limit exceeded (max 1024 nested calls).
    ///
    /// **Fatal**. Prevents stack overflow from recursion.
    #[error("call depth limit exceeded (max {0})")]
    CallDepth(usize),

    /// Attempt to write to read-only state (STATICCALL violation).
    ///
    /// **Revert**. The static call context forbids state modifications.
    #[error("write protection: {0}")]
    WriteProtection(&'static str),

    /// Contract already exists at the target address.
    ///
    /// **Revert**. CREATE/CREATE2 collision detected.
    #[error("contract already exists at address {0:?}")]
    ContractExists([u8; 32]),

    /// Code is too large (EIP-170: max 24576 bytes).
    ///
    /// **Fatal**. Prevents DoS via oversized contracts.
    #[error("code too large: {0} bytes (max {1})")]
    CodeTooLarge(usize, usize),

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
    #[error("storage error: {0}")]
    Storage(String),

    // ── State ──────────────────────────────────────────────────────────────
    /// Generic state error (e.g., missing account, insufficient balance).
    ///
    /// **Revert**. The requested state operation is invalid.
    #[error("state error: {0}")]
    State(String),

    /// Insufficient balance for the operation.
    ///
    /// **Revert**. Call value exceeds available balance.
    #[error("insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u128, need: u128 },

    /// Account nonce overflow (nonce > u64::MAX).
    ///
    /// **Revert**. Cannot create a new contract with nonce overflow.
    #[error("nonce overflow: {0}")]
    NonceOverflow(u64),

    // ── Execution ──────────────────────────────────────────────────────────
    /// Execution halted (STOP, RETURN, REVERT, or unrecoverable).
    ///
    /// **Fatal**. The execution context is terminated.
    #[error("execution halted")]
    Halt,

    /// Revert with a reason (REVERT opcode with data).
    ///
    /// **Revert**. The call was reverted by the contract with a reason.
    #[error("reverted: {0}")]
    Revert(String),

    // ── Internal VM errors ──────────────────────────────────────────────────
    /// Unexpected internal VM error (should not happen).
    ///
    /// **Fatal**. Indicates a bug in the VM implementation.
    #[error("internal VM error: {0}")]
    Internal(String),
}

// -----------------------------------------------------------------------------
// Classification methods
// -----------------------------------------------------------------------------

impl VmError {
    /// Returns `true` if the error is fatal and the execution cannot continue.
    ///
    /// Fatal errors consume all remaining gas and mark the transaction as
    /// failed. No state changes are persisted.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            VmError::OutOfGas
                | VmError::IntrinsicGasTooLow(_, _)
                | VmError::InvalidOpcode(_)
                | VmError::StackUnderflow { .. }
                | VmError::StackOverflow(_)
                | VmError::MemoryLimit(_)
                | VmError::MemoryOffsetOverflow(_, _)
                | VmError::CallDepth(_)
                | VmError::CodeTooLarge(_, _)
                | VmError::PcOutOfBounds { .. }
                | VmError::Internal(_)
        )
    }

    /// Returns `true` if the error should cause a revert (state changes
    /// discarded, but the transaction is not marked as failed unless the
    /// top-level call also reverts).
    pub fn should_revert(&self) -> bool {
        !self.is_fatal()
    }

    /// Returns `true` if the error is recoverable by the calling contract
    /// (e.g., can be caught by a `try/catch` mechanism or handled by
    /// inspecting the return data).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VmError::ArithmeticOverflow(_)
                | VmError::DivisionByZero
                | VmError::InvalidJump(_)
                | VmError::ReturnDataOob { .. }
                | VmError::CalldataOob { .. }
                | VmError::WriteProtection(_)
                | VmError::ContractExists(_)
                | VmError::State(_)
                | VmError::Storage(_)
                | VmError::InsufficientBalance { .. }
                | VmError::NonceOverflow(_)
                | VmError::Revert(_)
        )
    }

    /// Returns a JSON-RPC error code suitable for API responses.
    ///
    /// Codes follow the Ethereum JSON-RPC convention where VM errors are
    /// in the range `-32015` to `-32099` and internal errors use `-32603`.
    pub fn code(&self) -> i32 {
        match self {
            VmError::OutOfGas => -32015,
            VmError::IntrinsicGasTooLow(_, _) => -32016,
            VmError::InvalidOpcode(_) => -32017,
            VmError::StackUnderflow { .. } => -32018,
            VmError::StackOverflow(_) => -32019,
            VmError::DivisionByZero => -32020,
            VmError::ArithmeticOverflow(_) => -32021,
            VmError::MemoryLimit(_) => -32022,
            VmError::MemoryOffsetOverflow(_, _) => -32023,
            VmError::InvalidJump(_) => -32024,
            VmError::PcOutOfBounds { .. } => -32025,
            VmError::CallDepth(_) => -32026,
            VmError::WriteProtection(_) => -32027,
            VmError::ContractExists(_) => -32028,
            VmError::CodeTooLarge(_, _) => -32029,
            VmError::CalldataOob { .. } => -32030,
            VmError::ReturnDataOob { .. } => -32031,
            VmError::Storage(_) => -32032,
            VmError::State(_) => -32033,
            VmError::InsufficientBalance { .. } => -32034,
            VmError::NonceOverflow(_) => -32035,
            VmError::Halt => -32036,
            VmError::Revert(_) => -32037,
            VmError::Internal(_) => -32603,
        }
    }

    /// Returns a short string identifier for logging/metrics.
    pub fn as_str(&self) -> &'static str {
        match self {
            VmError::OutOfGas => "OutOfGas",
            VmError::IntrinsicGasTooLow(_, _) => "IntrinsicGasTooLow",
            VmError::InvalidOpcode(_) => "InvalidOpcode",
            VmError::StackUnderflow { .. } => "StackUnderflow",
            VmError::StackOverflow(_) => "StackOverflow",
            VmError::DivisionByZero => "DivisionByZero",
            VmError::ArithmeticOverflow(_) => "ArithmeticOverflow",
            VmError::MemoryLimit(_) => "MemoryLimit",
            VmError::MemoryOffsetOverflow(_, _) => "MemoryOffsetOverflow",
            VmError::InvalidJump(_) => "InvalidJump",
            VmError::PcOutOfBounds { .. } => "PcOutOfBounds",
            VmError::CallDepth(_) => "CallDepth",
            VmError::WriteProtection(_) => "WriteProtection",
            VmError::ContractExists(_) => "ContractExists",
            VmError::CodeTooLarge(_, _) => "CodeTooLarge",
            VmError::CalldataOob { .. } => "CalldataOob",
            VmError::ReturnDataOob { .. } => "ReturnDataOob",
            VmError::Storage(_) => "Storage",
            VmError::State(_) => "State",
            VmError::InsufficientBalance { .. } => "InsufficientBalance",
            VmError::NonceOverflow(_) => "NonceOverflow",
            VmError::Halt => "Halt",
            VmError::Revert(_) => "Revert",
            VmError::Internal(_) => "Internal",
        }
    }
}

// -----------------------------------------------------------------------------
// Conversions from standard library and other error types
// -----------------------------------------------------------------------------

impl From<std::num::TryFromIntError> for VmError {
    fn from(_: std::num::TryFromIntError) -> Self {
        VmError::Internal("integer conversion failed".into())
    }
}

impl From<std::array::TryFromSliceError> for VmError {
    fn from(_: std::array::TryFromSliceError) -> Self {
        VmError::Internal("slice conversion failed".into())
    }
}

impl From<std::io::Error> for VmError {
    fn from(e: std::io::Error) -> Self {
        VmError::Storage(e.to_string())
    }
}

impl From<crate::vm::opcodes::OpcodeError> for VmError {
    fn from(err: crate::vm::opcodes::OpcodeError) -> Self {
        match err {
            crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode } => {
                VmError::InvalidOpcode(opcode)
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
        let err = VmError::InvalidOpcode(0xFE);
        assert_eq!(format!("{}", err), "invalid opcode: 0xFE");

        let err = VmError::ReturnDataOob {
            offset: 10,
            size: 20,
            len: 15,
        };
        assert!(format!("{}", err).contains("return data out of bounds"));

        let err = VmError::StackUnderflow { need: 3, have: 1 };
        assert_eq!(format!("{}", err), "stack underflow: need 3, have 1");

        let err = VmError::IntrinsicGasTooLow(21000, 10000);
        assert!(format!("{}", err).contains("intrinsic gas too low"));
    }

    // ── Classification ───────────────────────────────────────────────────
    #[test]
    fn test_is_fatal() {
        assert!(VmError::OutOfGas.is_fatal());
        assert!(VmError::IntrinsicGasTooLow(0, 0).is_fatal());
        assert!(VmError::StackUnderflow { need: 1, have: 0 }.is_fatal());
        assert!(VmError::StackOverflow(1024).is_fatal());
        assert!(VmError::MemoryLimit(0).is_fatal());
        assert!(VmError::MemoryOffsetOverflow(0, 0).is_fatal());
        assert!(VmError::CallDepth(0).is_fatal());
        assert!(VmError::CodeTooLarge(0, 0).is_fatal());
        assert!(VmError::PcOutOfBounds { pc: 0, code_length: 0 }.is_fatal());
        assert!(VmError::Internal("".into()).is_fatal());
        // Non-fatal
        assert!(!VmError::State("".into()).is_fatal());
        assert!(!VmError::DivisionByZero.is_fatal());
        assert!(!VmError::Revert("".into()).is_fatal());
    }

    #[test]
    fn test_should_revert() {
        // All revert errors should NOT be fatal
        assert!(VmError::State("".into()).should_revert());
        assert!(VmError::DivisionByZero.should_revert());
        assert!(VmError::Revert("".into()).should_revert());
        // Fatal errors should not revert
        assert!(!VmError::OutOfGas.should_revert());
        assert!(!VmError::InvalidOpcode(0).should_revert());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(VmError::State("".into()).is_recoverable());
        assert!(VmError::ArithmeticOverflow("overflow").is_recoverable());
        assert!(VmError::InsufficientBalance { have: 0, need: 1 }.is_recoverable());
        assert!(!VmError::OutOfGas.is_recoverable());
        assert!(!VmError::StackUnderflow { need: 1, have: 0 }.is_recoverable());
    }

    // ── Error codes ──────────────────────────────────────────────────────
    #[test]
    fn test_error_codes() {
        assert_eq!(VmError::OutOfGas.code(), -32015);
        assert_eq!(VmError::InvalidOpcode(0).code(), -32017);
        assert_eq!(VmError::Internal("".into()).code(), -32603);
        assert_eq!(VmError::Revert("".into()).code(), -32037);
        assert_eq!(VmError::InsufficientBalance { have: 0, need: 0 }.code(), -32034);
    }

    #[test]
    fn test_error_codes_unique() {
        use std::collections::HashSet;
        let codes: Vec<i32> = vec![
            VmError::OutOfGas.code(),
            VmError::IntrinsicGasTooLow(0, 0).code(),
            VmError::InvalidOpcode(0).code(),
            VmError::StackUnderflow { need: 0, have: 0 }.code(),
            VmError::StackOverflow(0).code(),
            VmError::DivisionByZero.code(),
            VmError::ArithmeticOverflow("").code(),
            VmError::MemoryLimit(0).code(),
            VmError::MemoryOffsetOverflow(0, 0).code(),
            VmError::InvalidJump(0).code(),
            VmError::PcOutOfBounds { pc: 0, code_length: 0 }.code(),
            VmError::CallDepth(0).code(),
            VmError::WriteProtection("").code(),
            VmError::ContractExists([0u8; 32]).code(),
            VmError::CodeTooLarge(0, 0).code(),
            VmError::CalldataOob { offset: 0, size: 0, len: 0 }.code(),
            VmError::ReturnDataOob { offset: 0, size: 0, len: 0 }.code(),
            VmError::Storage("".into()).code(),
            VmError::State("".into()).code(),
            VmError::InsufficientBalance { have: 0, need: 0 }.code(),
            VmError::NonceOverflow(0).code(),
            VmError::Halt.code(),
            VmError::Revert("".into()).code(),
            VmError::Internal("".into()).code(),
        ];
        let unique: HashSet<_> = codes.iter().collect();
        assert_eq!(codes.len(), unique.len(), "Error codes must be unique");
    }

    // ── as_str ───────────────────────────────────────────────────────────
    #[test]
    fn test_as_str() {
        assert_eq!(VmError::OutOfGas.as_str(), "OutOfGas");
        assert_eq!(VmError::DivisionByZero.as_str(), "DivisionByZero");
        assert_eq!(VmError::Internal("".into()).as_str(), "Internal");
    }

    // ── Conversions ──────────────────────────────────────────────────────
    #[test]
    fn test_conversion_try_from_int_error() {
        let err: VmError = std::num::TryFromIntError::from(()).into();
        assert!(matches!(err, VmError::Internal(_)));
    }

    #[test]
    fn test_conversion_io_error() {
        let err: VmError = std::io::Error::new(std::io::ErrorKind::Other, "disk full").into();
        assert!(matches!(err, VmError::Storage(s) if s.contains("disk full")));
    }

    #[test]
    fn test_conversion_opcode_error() {
        let op_err = crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode: 0x42 };
        let err: VmError = op_err.into();
        assert!(matches!(err, VmError::InvalidOpcode(0x42)));
    }

    // ── PartialEq ────────────────────────────────────────────────────────
    #[test]
    fn test_partial_eq() {
        let err1 = VmError::InvalidOpcode(0xFE);
        let err2 = VmError::InvalidOpcode(0xFE);
        let err3 = VmError::InvalidOpcode(0xFF);
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }

    #[test]
    fn test_clone() {
        let err = VmError::Storage("test".into());
        let cloned = err.clone();
        assert_eq!(err, cloned);
    }
}
