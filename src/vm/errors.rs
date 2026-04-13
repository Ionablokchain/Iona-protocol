//! VM execution errors.
//!
//! This module defines all possible errors that can occur during VM execution.
//! Errors are categorized by their source and severity.

use thiserror::Error;

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
    ReturnDataOob {
        offset: usize,
        size: usize,
        len: usize,
    },

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

    /// Returns the gas cost penalty (if any) for this error.
    /// For most errors, all gas is consumed; some errors (like REVERT) refund unused gas.
    pub fn gas_penalty(&self) -> Option<u64> {
        match self {
            // REVERT consumes only the gas used up to that point
            VmError::Halt => None,
            // Other errors consume all gas
            _ => Some(0), // Placeholder; actual logic would compute remaining gas
        }
    }
}

// -----------------------------------------------------------------------------
// Conversion from standard error types
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
    fn test_conversion() {
        let err: VmError = std::num::TryFromIntError::from(());
        assert!(matches!(err, VmError::Internal(_)));

        let err: VmError = std::io::Error::new(std::io::ErrorKind::Other, "disk full").into();
        assert!(matches!(err, VmError::Storage(_)));
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
