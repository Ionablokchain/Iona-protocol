use thiserror::Error;

/// Result type used by the VM interpreter.
pub type VmResult<T> = Result<T, VmError>;

/// Normal execution exit states.
///
/// These are not errors. They represent successful or intentional termination
/// of bytecode execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmExit {
    /// STOP or clean termination without return data.
    Stop,
    /// Successful RETURN with return bytes.
    Return(Vec<u8>),
    /// REVERT with revert bytes.
    Revert(Vec<u8>),
}

/// Fatal or exceptional VM execution errors.
///
/// These errors occur during bytecode execution or state transition inside
/// the VM/interpreter.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VmError {
    // ---------------------------------------------------------------------
    // Gas & resource errors
    // ---------------------------------------------------------------------
    #[error("out of gas")]
    OutOfGas,

    #[error("call depth limit exceeded at pc {pc}: depth {depth}, limit {limit}")]
    CallDepth {
        pc: usize,
        depth: usize,
        limit: usize,
    },

    #[error("memory limit exceeded at pc {pc}: requested {requested} bytes, limit {limit}")]
    MemoryLimit {
        pc: usize,
        requested: usize,
        limit: usize,
    },

    // ---------------------------------------------------------------------
    // Invalid program / bytecode
    // ---------------------------------------------------------------------
    #[error("invalid opcode {opcode:#x} at pc {pc}")]
    InvalidOpcode {
        opcode: u8,
        pc: usize,
    },

    #[error("invalid jump destination {dest} at pc {pc}")]
    InvalidJump {
        pc: usize,
        dest: usize,
    },

    // ---------------------------------------------------------------------
    // Stack errors
    // ---------------------------------------------------------------------
    #[error("stack underflow at pc {pc}: needed {needed}, available {available}")]
    StackUnderflow {
        pc: usize,
        needed: usize,
        available: usize,
    },

    #[error("stack overflow at pc {pc}: limit {limit}")]
    StackOverflow {
        pc: usize,
        limit: usize,
    },

    // ---------------------------------------------------------------------
    // Memory / data access errors
    // ---------------------------------------------------------------------
    #[error("memory access out of bounds at pc {pc}: offset {offset}, size {size}, memory len {len}")]
    MemoryOob {
        pc: usize,
        offset: usize,
        size: usize,
        len: usize,
    },

    #[error("invalid calldata access at pc {pc}: offset {offset}, size {size}, calldata len {len}")]
    CalldataOob {
        pc: usize,
        offset: usize,
        size: usize,
        len: usize,
    },

    #[error("invalid return-data access at pc {pc}: offset {offset}, size {size}, return-data len {len}")]
    ReturnDataOob {
        pc: usize,
        offset: usize,
        size: usize,
        len: usize,
    },

    #[error("invalid return data at pc {pc}: expected {expected} bytes, got {got}")]
    InvalidReturnData {
        pc: usize,
        expected: usize,
        got: usize,
    },

    // ---------------------------------------------------------------------
    // State / account / balance errors
    // ---------------------------------------------------------------------
    #[error("insufficient balance: needed {needed}, available {available}")]
    InsufficientBalance {
        needed: u128,
        available: u128,
    },

    #[error("create collision at pc {pc}: address {address:?}")]
    CreateCollision {
        pc: usize,
        address: [u8; 20],
    },

    #[error("code too large: {size} bytes (max {max})")]
    CodeTooLarge {
        size: usize,
        max: usize,
    },

    // ---------------------------------------------------------------------
    // Permissions / execution context
    // ---------------------------------------------------------------------
    #[error("write protection at pc {pc}")]
    WriteProtection {
        pc: usize,
    },

    #[error("reentrancy detected at pc {pc}")]
    Reentrancy {
        pc: usize,
    },

    // ---------------------------------------------------------------------
    // Precompile / state backend / internal errors
    // ---------------------------------------------------------------------
    #[error("precompile error: {message}")]
    Precompile {
        message: String,
    },

    #[error("state error: {message}")]
    State {
        message: String,
    },

    #[error("internal VM error: {message}")]
    Internal {
        message: String,
    },
}

impl VmError {
    /// Helper constructor for simple string-based state errors.
    pub fn state(message: impl Into<String>) -> Self {
        Self::State {
            message: message.into(),
        }
    }

    /// Helper constructor for simple internal errors.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
        }
    }

    /// Helper constructor for precompile failures.
    pub fn precompile(message: impl Into<String>) -> Self {
        Self::Precompile {
            message: message.into(),
        }
    }

    /// Returns true when the error is caused by gas exhaustion.
    pub fn is_out_of_gas(&self) -> bool {
        matches!(self, Self::OutOfGas)
    }

    /// Returns true when the error is caused by invalid bytecode or control flow.
    pub fn is_invalid_program(&self) -> bool {
        matches!(self, Self::InvalidOpcode { .. } | Self::InvalidJump { .. })
    }

    /// Returns true when the error is caused by write restrictions.
    pub fn is_write_protection(&self) -> bool {
        matches!(self, Self::WriteProtection { .. })
    }

    /// Numeric status code useful for CLI / RPC mapping.
    pub fn status_code(&self) -> i32 {
        match self {
            Self::OutOfGas => 1,
            Self::CallDepth { .. } => 2,
            Self::MemoryLimit { .. } => 3,
            Self::InvalidOpcode { .. } => 4,
            Self::InvalidJump { .. } => 5,
            Self::StackUnderflow { .. } => 6,
            Self::StackOverflow { .. } => 7,
            Self::MemoryOob { .. } => 8,
            Self::CalldataOob { .. } => 9,
            Self::ReturnDataOob { .. } => 10,
            Self::InvalidReturnData { .. } => 11,
            Self::InsufficientBalance { .. } => 12,
            Self::CreateCollision { .. } => 13,
            Self::CodeTooLarge { .. } => 14,
            Self::WriteProtection { .. } => 15,
            Self::Reentrancy { .. } => 16,
            Self::Precompile { .. } => 17,
            Self::State { .. } => 18,
            Self::Internal { .. } => 19,
        }
    }
}

/// Result type used during transaction validation before VM execution.
pub type TxValidationResult<T> = Result<T, TxValidationError>;

/// Transaction / envelope validation errors.
///
/// These occur before bytecode execution begins and should usually not be mixed
/// into `VmError`.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TxValidationError {
    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid chain id: expected {expected}, got {got}")]
    InvalidChainId {
        expected: u64,
        got: u64,
    },

    #[error("invalid nonce: expected {expected}, got {got}")]
    InvalidNonce {
        expected: u64,
        got: u64,
    },

    #[error("invalid access list: {reason}")]
    InvalidAccessList {
        reason: String,
    },

    #[error("intrinsic gas too low: required {required}, provided {provided}")]
    IntrinsicGasTooLow {
        required: u64,
        provided: u64,
    },

    #[error("max fee per gas less than max priority fee per gas")]
    InvalidFeeCapRelation,

    #[error("tx sender has insufficient balance: needed {needed}, available {available}")]
    InsufficientBalance {
        needed: u128,
        available: u128,
    },

    #[error("transaction size too large: {size} bytes (max {max})")]
    TxTooLarge {
        size: usize,
        max: usize,
    },

    #[error("transaction error: {message}")]
    Other {
        message: String,
    },
}

impl TxValidationError {
    pub fn other(message: impl Into<String>) -> Self {
        Self::Other {
            message: message.into(),
        }
    }

    pub fn status_code(&self) -> i32 {
        match self {
            Self::InvalidSignature => 100,
            Self::InvalidChainId { .. } => 101,
            Self::InvalidNonce { .. } => 102,
            Self::InvalidAccessList { .. } => 103,
            Self::IntrinsicGasTooLow { .. } => 104,
            Self::InvalidFeeCapRelation => 105,
            Self::InsufficientBalance { .. } => 106,
            Self::TxTooLarge { .. } => 107,
            Self::Other { .. } => 108,
        }
    }
}
