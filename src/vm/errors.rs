use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum VmError {
    #[error("out of gas")]
    OutOfGas,
    #[error("invalid opcode: {0:#x}")]
    InvalidOpcode(u8),
    #[error("stack underflow")]
    StackUnderflow,
    #[error("stack overflow")]
    StackOverflow,
    #[error("state error: {0}")]
    State(String),
    #[error("execution halted")]
    Halt,
    #[error("memory limit exceeded")]
    MemoryLimit,
    #[error("invalid jump destination: {0}")]
    InvalidJump(usize),
    #[error("call depth limit exceeded")]
    CallDepth,
    #[error("write protection")]
    WriteProtection,
    #[error("contract already exists at address")]
    ContractExists,
    #[error("code too large (max 24576 bytes)")]
    CodeTooLarge,
    #[error("invalid calldata access at offset {0}")]
    CalldataOob(usize),
}
