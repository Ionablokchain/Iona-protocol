//! VM execution errors.
//!
//! This module defines all possible errors that can occur during VM execution.
//! Errors are categorized by their source and severity.

use thiserror::Error;

// -----------------------------------------------------------------------------
// Result alias
// -----------------------------------------------------------------------------

/// Result type alias for VM operations.
pub type VmResult<T> = Result<T, VmError>;

// -----------------------------------------------------------------------------
// Error definition
// -----------------------------------------------------------------------------

/// VM execution error.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum VmError {
    // ── Gas ─────────────────────────────────────────────────────────────────
    /// Execution ran out of gas.
    #[error("out of gas")]
    OutOfGas,

    // ── Opcode ──────────────────────────────────────────────────────────────
    /// Encountered an invalid or unknown opcode.
    #[error("invalid opcode: {0:#x}")]
    InvalidOpcode(u8),

    // ── Stack ──────────────────────────────────────────────────────────────
    /// Not enough items on the stack for operation.
    #[error("stack underflow")]
    StackUnderflow,
    /// Stack limit exceeded (max 1024 items).
    #[error("stack overflow")]
    StackOverflow,

    // ── Arithmetic ─────────────────────────────────────────────────────────
    /// Division by zero (DIV, SDIV, MOD, SMOD).
    #[error("division by zero")]
    DivisionByZero,
    /// Arithmetic overflow (e.g., ADD, MUL with carry beyond 256 bits).
    #[error("arithmetic overflow")]
    ArithmeticOverflow,

    // ── Memory ─────────────────────────────────────────────────────────────
    /// Memory limit exceeded (max 4 MiB).
    #[error("memory limit exceeded")]
    MemoryLimit,

    // ── Control flow ───────────────────────────────────────────────────────
    /// Jump destination is not a valid JUMPDEST.
    #[error("invalid jump destination: {0}")]
    InvalidJump(usize),

    // ── Call / Create ──────────────────────────────────────────────────────
    /// Call depth limit exceeded (max 1024).
    #[error("call depth limit exceeded")]
    CallDepth,
    /// Attempt to write to read-only state (static call).
    #[error("write protection")]
    WriteProtection,
    /// Contract already exists at the target address.
    #[error("contract already exists at address")]
    ContractExists,
    /// Code is too large (EIP-170: max 24576 bytes).
    #[error("code too large (max 24576 bytes)")]
    CodeTooLarge,

    // ── Calldata / Return data ─────────────────────────────────────────────
    /// Calldata access out of bounds.
    #[error("invalid calldata access at offset {0}")]
    CalldataOob(usize),
    /// Return data access out of bounds (RETURNDATACOPY).
    #[error("return data access out of bounds: offset {offset} size {size} (len {len})")]
    ReturnDataOob { offset: usize, size: usize, len: usize },

    // ── Storage ────────────────────────────────────────────────────────────
    /// Storage access error (e.g., I/O failure).
    #[error("storage error: {0}")]
    Storage(String),

    // ── State ──────────────────────────────────────────────────────────────
    /// Generic state error (e.g., missing account).
    #[error("state error: {0}")]
    State(String),

    // ── Execution ──────────────────────────────────────────────────────────
    /// Execution halted (e.g., STOP, REVERT, or unrecoverable).
    #[error("execution halted")]
    Halt,

    // ─── Internal VM errors ────────────────────────────────────────────────
    /// Unexpected internal VM error (should not happen).
    #[error("internal VM error: {0}")]
    Internal(String),
}

impl VmError {
    /// Returns `true` if the error is fatal and the execution cannot continue.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            VmError::OutOfGas
                | VmError::InvalidOpcode(_)
                | VmError::StackUnderflow
                | VmError::StackOverflow
                | VmError::MemoryLimit
                | VmError::CallDepth
                | VmError::CodeTooLarge
                | VmError::Internal(_)
        )
    }

    /// Returns `true` if the error should cause a revert (state changes discarded).
    pub fn should_revert(&self) -> bool {
        !matches!(
            self,
            VmError::OutOfGas
                | VmError::StackUnderflow
                | VmError::StackOverflow
                | VmError::MemoryLimit
                | VmError::InvalidJump(_)
                | VmError::CallDepth
                | VmError::Internal(_)
        )
    }

    /// Returns `true` if the error is recoverable (e.g., can be caught by caller).
    pub fn is_recoverable(&self) -> bool {
        matches!(
            self,
            VmError::ArithmeticOverflow
                | VmError::DivisionByZero
                | VmError::InvalidJump(_)
                | VmError::ReturnDataOob { .. }
                | VmError::CalldataOob(_)
                | VmError::WriteProtection
                | VmError::ContractExists
                | VmError::State(_)
                | VmError::Storage(_)
        )
    }

    /// Returns an error code suitable for RPC error responses.
    pub fn code(&self) -> i32 {
        match self {
            VmError::OutOfGas => -32015,
            VmError::InvalidOpcode(_) => -32016,
            VmError::StackUnderflow => -32017,
            VmError::StackOverflow => -32018,
            VmError::DivisionByZero => -32019,
            VmError::ArithmeticOverflow => -32020,
            VmError::MemoryLimit => -32021,
            VmError::InvalidJump(_) => -32022,
            VmError::CallDepth => -32023,
            VmError::WriteProtection => -32024,
            VmError::ContractExists => -32025,
            VmError::CodeTooLarge => -32026,
            VmError::CalldataOob(_) => -32027,
            VmError::ReturnDataOob { .. } => -32028,
            VmError::Storage(_) => -32029,
            VmError::State(_) => -32030,
            VmError::Halt => -32031,
            VmError::Internal(_) => -32603,
        }
    }
}

// -----------------------------------------------------------------------------
// Conversion from standard library and other error types
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
            crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode } => VmError::InvalidOpcode(opcode),
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = VmError::InvalidOpcode(0xFE);
        assert_eq!(format!("{}", err), "invalid opcode: 0xfe");

        let err = VmError::ReturnDataOob { offset: 10, size: 20, len: 15 };
        assert!(format!("{}", err).contains("return data access out of bounds"));
    }

    #[test]
    fn test_is_fatal() {
        assert!(VmError::OutOfGas.is_fatal());
        assert!(VmError::StackUnderflow.is_fatal());
        assert!(!VmError::State("".into()).is_fatal());
    }

    #[test]
    fn test_should_revert() {
        assert!(VmError::State("".into()).should_revert());
        assert!(!VmError::OutOfGas.should_revert());
    }

    #[test]
    fn test_is_recoverable() {
        assert!(VmError::State("".into()).is_recoverable());
        assert!(!VmError::OutOfGas.is_recoverable());
    }

    #[test]
    fn test_error_codes() {
        assert_eq!(VmError::OutOfGas.code(), -32015);
        assert_eq!(VmError::Internal("".into()).code(), -32603);
    }

    #[test]
    fn test_conversion() {
        let err: VmError = std::num::TryFromIntError::from(());
        assert!(matches!(err, VmError::Internal(_)));

        let err: VmError = std::io::Error::new(std::io::ErrorKind::Other, "disk full").into();
        assert!(matches!(err, VmError::Storage(_)));

        let op_err = crate::vm::opcodes::OpcodeError::InvalidOpcode { opcode: 0x42 };
        let err: VmError = op_err.into();
        assert!(matches!(err, VmError::InvalidOpcode(0x42)));
    }

    #[test]
    fn test_partial_eq() {
        let err1 = VmError::InvalidOpcode(0xFE);
        let err2 = VmError::InvalidOpcode(0xFE);
        let err3 = VmError::InvalidOpcode(0xFF);
        assert_eq!(err1, err2);
        assert_ne!(err1, err3);
    }
}
