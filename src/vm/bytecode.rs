//! IONA VM — Opcode definitions and utilities.
//!
//! Stack words are 256-bit (stored as [u8; 32]).
//! Gas costs follow EVM conventions where appropriate.
//!
//! # Opcode Groups
//!
//! - Arithmetic (0x00–0x0F)
//! - Comparison & Bitwise (0x10–0x1F)
//! - SHA3 (0x20)
//! - Environment (0x30–0x3F)
//! - Memory & Storage (0x50–0x5F)
//! - Stack (0x60–0x8F)
//! - Control Flow (0x50–0x5F, 0x56–0x5B)
//! - Logging (0xA0–0xA4)
//! - System (0xF0–0xFF)

use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when working with opcodes.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum OpcodeError {
    #[error("invalid opcode: 0x{opcode:02X}")]
    InvalidOpcode { opcode: u8 },
}

pub type OpcodeResult<T> = Result<T, OpcodeError>;

// -----------------------------------------------------------------------------
// Opcode enum (exhaustive)
// -----------------------------------------------------------------------------

/// All known IONA VM opcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // Arithmetic
    Stop = 0x00,
    Add = 0x01,
    Mul = 0x02,
    Sub = 0x03,
    Div = 0x04,
    SDiv = 0x05,
    Mod = 0x06,
    SMod = 0x07,
    AddMod = 0x08,
    MulMod = 0x09,
    Exp = 0x0A,
    SignExtend = 0x0B,

    // Comparison & Bitwise
    Lt = 0x10,
    Gt = 0x11,
    SLt = 0x12,
    SGt = 0x13,
    Eq = 0x14,
    IsZero = 0x15,
    And = 0x16,
    Or = 0x17,
    Xor = 0x18,
    Not = 0x19,
    Byte = 0x1A,
    Shl = 0x1B,
    Shr = 0x1C,
    Sar = 0x1D,

    // SHA3
    Sha3 = 0x20,

    // Environment
    Address = 0x30,
    Balance = 0x31,
    Origin = 0x32,
    Caller = 0x33,
    CallValue = 0x34,
    CallDataLoad = 0x35,
    CallDataSize = 0x36,
    CallDataCopy = 0x37,
    CodeSize = 0x38,
    CodeCopy = 0x39,
    GasPrice = 0x3A,
    ExtCodeSize = 0x3B,
    ExtCodeCopy = 0x3C,
    ReturnDataSize = 0x3D,
    ReturnDataCopy = 0x3E,
    Gas = 0x5A,

    // Memory & Storage / Control Flow
    Pop = 0x50,
    MLoad = 0x51,
    MStore = 0x52,
    MStore8 = 0x53,
    SLoad = 0x54,
    SStore = 0x55,
    Jump = 0x56,
    Jumpi = 0x57,
    Pc = 0x58,
    MSize = 0x59,
    JumpDest = 0x5B,

    // Push
    Push1 = 0x60,
    Push2 = 0x61,
    Push3 = 0x62,
    Push4 = 0x63,
    Push5 = 0x64,
    Push6 = 0x65,
    Push7 = 0x66,
    Push8 = 0x67,
    Push9 = 0x68,
    Push10 = 0x69,
    Push11 = 0x6A,
    Push12 = 0x6B,
    Push13 = 0x6C,
    Push14 = 0x6D,
    Push15 = 0x6E,
    Push16 = 0x6F,
    Push17 = 0x70,
    Push18 = 0x71,
    Push19 = 0x72,
    Push20 = 0x73,
    Push21 = 0x74,
    Push22 = 0x75,
    Push23 = 0x76,
    Push24 = 0x77,
    Push25 = 0x78,
    Push26 = 0x79,
    Push27 = 0x7A,
    Push28 = 0x7B,
    Push29 = 0x7C,
    Push30 = 0x7D,
    Push31 = 0x7E,
    Push32 = 0x7F,

    // Dup
    Dup1 = 0x80,
    Dup2 = 0x81,
    Dup3 = 0x82,
    Dup4 = 0x83,
    Dup5 = 0x84,
    Dup6 = 0x85,
    Dup7 = 0x86,
    Dup8 = 0x87,
    Dup9 = 0x88,
    Dup10 = 0x89,
    Dup11 = 0x8A,
    Dup12 = 0x8B,
    Dup13 = 0x8C,
    Dup14 = 0x8D,
    Dup15 = 0x8E,
    Dup16 = 0x8F,

    // Swap
    Swap1 = 0x90,
    Swap2 = 0x91,
    Swap3 = 0x92,
    Swap4 = 0x93,
    Swap5 = 0x94,
    Swap6 = 0x95,
    Swap7 = 0x96,
    Swap8 = 0x97,
    Swap9 = 0x98,
    Swap10 = 0x99,
    Swap11 = 0x9A,
    Swap12 = 0x9B,
    Swap13 = 0x9C,
    Swap14 = 0x9D,
    Swap15 = 0x9E,
    Swap16 = 0x9F,

    // Logging
    Log0 = 0xA0,
    Log1 = 0xA1,
    Log2 = 0xA2,
    Log3 = 0xA3,
    Log4 = 0xA4,

    // System
    Create = 0xF0,
    Call = 0xF1,
    CallCode = 0xF2,
    Return = 0xF3,
    DelegateCall = 0xF4,
    Create2 = 0xF5,
    StaticCall = 0xFA,
    Revert = 0xFD,
    Invalid = 0xFE,
    SelfDestruct = 0xFF,
}

impl TryFrom<u8> for Opcode {
    type Error = OpcodeError;

    fn try_from(value: u8) -> OpcodeResult<Self> {
        match value {
            0x00 => Ok(Opcode::Stop),
            0x01 => Ok(Opcode::Add),
            0x02 => Ok(Opcode::Mul),
            0x03 => Ok(Opcode::Sub),
            0x04 => Ok(Opcode::Div),
            0x05 => Ok(Opcode::SDiv),
            0x06 => Ok(Opcode::Mod),
            0x07 => Ok(Opcode::SMod),
            0x08 => Ok(Opcode::AddMod),
            0x09 => Ok(Opcode::MulMod),
            0x0A => Ok(Opcode::Exp),
            0x0B => Ok(Opcode::SignExtend),
            0x10 => Ok(Opcode::Lt),
            0x11 => Ok(Opcode::Gt),
            0x12 => Ok(Opcode::SLt),
            0x13 => Ok(Opcode::SGt),
            0x14 => Ok(Opcode::Eq),
            0x15 => Ok(Opcode::IsZero),
            0x16 => Ok(Opcode::And),
            0x17 => Ok(Opcode::Or),
            0x18 => Ok(Opcode::Xor),
            0x19 => Ok(Opcode::Not),
            0x1A => Ok(Opcode::Byte),
            0x1B => Ok(Opcode::Shl),
            0x1C => Ok(Opcode::Shr),
            0x1D => Ok(Opcode::Sar),
            0x20 => Ok(Opcode::Sha3),
            0x30 => Ok(Opcode::Address),
            0x31 => Ok(Opcode::Balance),
            0x32 => Ok(Opcode::Origin),
            0x33 => Ok(Opcode::Caller),
            0x34 => Ok(Opcode::CallValue),
            0x35 => Ok(Opcode::CallDataLoad),
            0x36 => Ok(Opcode::CallDataSize),
            0x37 => Ok(Opcode::CallDataCopy),
            0x38 => Ok(Opcode::CodeSize),
            0x39 => Ok(Opcode::CodeCopy),
            0x3A => Ok(Opcode::GasPrice),
            0x3B => Ok(Opcode::ExtCodeSize),
            0x3C => Ok(Opcode::ExtCodeCopy),
            0x3D => Ok(Opcode::ReturnDataSize),
            0x3E => Ok(Opcode::ReturnDataCopy),
            0x5A => Ok(Opcode::Gas),
            0x50 => Ok(Opcode::Pop),
            0x51 => Ok(Opcode::MLoad),
            0x52 => Ok(Opcode::MStore),
            0x53 => Ok(Opcode::MStore8),
            0x54 => Ok(Opcode::SLoad),
            0x55 => Ok(Opcode::SStore),
            0x56 => Ok(Opcode::Jump),
            0x57 => Ok(Opcode::Jumpi),
            0x58 => Ok(Opcode::Pc),
            0x59 => Ok(Opcode::MSize),
            0x5B => Ok(Opcode::JumpDest),
            0x60..=0x7F => {
                let idx = value - 0x60 + 1;
                // SAFETY: idx is 1..=32
                Ok(unsafe { std::mem::transmute((0x60 + idx - 1) as u8) })
            }
            0x80..=0x8F => Ok(unsafe { std::mem::transmute(value) }),
            0x90..=0x9F => Ok(unsafe { std::mem::transmute(value) }),
            0xA0..=0xA4 => Ok(unsafe { std::mem::transmute(value) }),
            0xF0 => Ok(Opcode::Create),
            0xF1 => Ok(Opcode::Call),
            0xF2 => Ok(Opcode::CallCode),
            0xF3 => Ok(Opcode::Return),
            0xF4 => Ok(Opcode::DelegateCall),
            0xF5 => Ok(Opcode::Create2),
            0xFA => Ok(Opcode::StaticCall),
            0xFD => Ok(Opcode::Revert),
            0xFE => Ok(Opcode::Invalid),
            0xFF => Ok(Opcode::SelfDestruct),
            _ => Err(OpcodeError::InvalidOpcode { opcode: value }),
        }
    }
}

impl Opcode {
    /// Returns the number of bytes a PUSH opcode reads from code (0 for non‑PUSH).
    pub fn push_data_size(self) -> usize {
        match self {
            Opcode::Push1 => 1,
            Opcode::Push2 => 2,
            Opcode::Push3 => 3,
            Opcode::Push4 => 4,
            Opcode::Push5 => 5,
            Opcode::Push6 => 6,
            Opcode::Push7 => 7,
            Opcode::Push8 => 8,
            Opcode::Push9 => 9,
            Opcode::Push10 => 10,
            Opcode::Push11 => 11,
            Opcode::Push12 => 12,
            Opcode::Push13 => 13,
            Opcode::Push14 => 14,
            Opcode::Push15 => 15,
            Opcode::Push16 => 16,
            Opcode::Push17 => 17,
            Opcode::Push18 => 18,
            Opcode::Push19 => 19,
            Opcode::Push20 => 20,
            Opcode::Push21 => 21,
            Opcode::Push22 => 22,
            Opcode::Push23 => 23,
            Opcode::Push24 => 24,
            Opcode::Push25 => 25,
            Opcode::Push26 => 26,
            Opcode::Push27 => 27,
            Opcode::Push28 => 28,
            Opcode::Push29 => 29,
            Opcode::Push30 => 30,
            Opcode::Push31 => 31,
            Opcode::Push32 => 32,
            _ => 0,
        }
    }

    /// Returns true for PUSH1..PUSH32.
    pub fn is_push(self) -> bool {
        matches!(self, Opcode::Push1..=Opcode::Push32)
    }

    /// Returns true for DUP1..DUP16.
    pub fn is_dup(self) -> bool {
        matches!(self, Opcode::Dup1..=Opcode::Dup16)
    }

    /// Returns true for SWAP1..SWAP16.
    pub fn is_swap(self) -> bool {
        matches!(self, Opcode::Swap1..=Opcode::Swap16)
    }

    /// Returns true for LOG0..LOG4.
    pub fn is_log(self) -> bool {
        matches!(self, Opcode::Log0..=Opcode::Log4)
    }

    /// Returns the number of topics for a LOG opcode (0‑4), or 0 for non‑LOG.
    pub fn log_topic_count(self) -> usize {
        match self {
            Opcode::Log0 => 0,
            Opcode::Log1 => 1,
            Opcode::Log2 => 2,
            Opcode::Log3 => 3,
            Opcode::Log4 => 4,
            _ => 0,
        }
    }
}

// -----------------------------------------------------------------------------
// Backward‑compatible constants (re‑exported as raw u8)
// -----------------------------------------------------------------------------

// Arithmetic
pub const STOP: u8 = Opcode::Stop as u8;
pub const ADD: u8 = Opcode::Add as u8;
pub const MUL: u8 = Opcode::Mul as u8;
pub const SUB: u8 = Opcode::Sub as u8;
pub const DIV: u8 = Opcode::Div as u8;
pub const SDIV: u8 = Opcode::SDiv as u8;
pub const MOD: u8 = Opcode::Mod as u8;
pub const SMOD: u8 = Opcode::SMod as u8;
pub const ADDMOD: u8 = Opcode::AddMod as u8;
pub const MULMOD: u8 = Opcode::MulMod as u8;
pub const EXP: u8 = Opcode::Exp as u8;
pub const SIGNEXTEND: u8 = Opcode::SignExtend as u8;

// Comparison & Bitwise
pub const LT: u8 = Opcode::Lt as u8;
pub const GT: u8 = Opcode::Gt as u8;
pub const SLT: u8 = Opcode::SLt as u8;
pub const SGT: u8 = Opcode::SGt as u8;
pub const EQ: u8 = Opcode::Eq as u8;
pub const ISZERO: u8 = Opcode::IsZero as u8;
pub const AND: u8 = Opcode::And as u8;
pub const OR: u8 = Opcode::Or as u8;
pub const XOR: u8 = Opcode::Xor as u8;
pub const NOT: u8 = Opcode::Not as u8;
pub const BYTE: u8 = Opcode::Byte as u8;
pub const SHL: u8 = Opcode::Shl as u8;
pub const SHR: u8 = Opcode::Shr as u8;
pub const SAR: u8 = Opcode::Sar as u8;

// SHA3
pub const SHA3: u8 = Opcode::Sha3 as u8;

// Environment
pub const ADDRESS: u8 = Opcode::Address as u8;
pub const BALANCE: u8 = Opcode::Balance as u8;
pub const ORIGIN: u8 = Opcode::Origin as u8;
pub const CALLER: u8 = Opcode::Caller as u8;
pub const CALLVALUE: u8 = Opcode::CallValue as u8;
pub const CALLDATALOAD: u8 = Opcode::CallDataLoad as u8;
pub const CALLDATASIZE: u8 = Opcode::CallDataSize as u8;
pub const CALLDATACOPY: u8 = Opcode::CallDataCopy as u8;
pub const CODESIZE: u8 = Opcode::CodeSize as u8;
pub const CODECOPY: u8 = Opcode::CodeCopy as u8;
pub const GASPRICE: u8 = Opcode::GasPrice as u8;
pub const EXTCODESIZE: u8 = Opcode::ExtCodeSize as u8;
pub const EXTCODECOPY: u8 = Opcode::ExtCodeCopy as u8;
pub const RETURNDATASIZE: u8 = Opcode::ReturnDataSize as u8;
pub const RETURNDATACOPY: u8 = Opcode::ReturnDataCopy as u8;
pub const GAS: u8 = Opcode::Gas as u8;

// Memory & Storage / Control Flow
pub const POP: u8 = Opcode::Pop as u8;
pub const MLOAD: u8 = Opcode::MLoad as u8;
pub const MSTORE: u8 = Opcode::MStore as u8;
pub const MSTORE8: u8 = Opcode::MStore8 as u8;
pub const SLOAD: u8 = Opcode::SLoad as u8;
pub const SSTORE: u8 = Opcode::SStore as u8;
pub const JUMP: u8 = Opcode::Jump as u8;
pub const JUMPI: u8 = Opcode::Jumpi as u8;
pub const PC: u8 = Opcode::Pc as u8;
pub const MSIZE: u8 = Opcode::MSize as u8;
pub const JUMPDEST: u8 = Opcode::JumpDest as u8;

// Push
pub const PUSH1: u8 = Opcode::Push1 as u8;
pub const PUSH2: u8 = Opcode::Push2 as u8;
pub const PUSH3: u8 = Opcode::Push3 as u8;
pub const PUSH4: u8 = Opcode::Push4 as u8;
pub const PUSH5: u8 = Opcode::Push5 as u8;
pub const PUSH6: u8 = Opcode::Push6 as u8;
pub const PUSH7: u8 = Opcode::Push7 as u8;
pub const PUSH8: u8 = Opcode::Push8 as u8;
pub const PUSH9: u8 = Opcode::Push9 as u8;
pub const PUSH10: u8 = Opcode::Push10 as u8;
pub const PUSH11: u8 = Opcode::Push11 as u8;
pub const PUSH12: u8 = Opcode::Push12 as u8;
pub const PUSH13: u8 = Opcode::Push13 as u8;
pub const PUSH14: u8 = Opcode::Push14 as u8;
pub const PUSH15: u8 = Opcode::Push15 as u8;
pub const PUSH16: u8 = Opcode::Push16 as u8;
pub const PUSH17: u8 = Opcode::Push17 as u8;
pub const PUSH18: u8 = Opcode::Push18 as u8;
pub const PUSH19: u8 = Opcode::Push19 as u8;
pub const PUSH20: u8 = Opcode::Push20 as u8;
pub const PUSH21: u8 = Opcode::Push21 as u8;
pub const PUSH22: u8 = Opcode::Push22 as u8;
pub const PUSH23: u8 = Opcode::Push23 as u8;
pub const PUSH24: u8 = Opcode::Push24 as u8;
pub const PUSH25: u8 = Opcode::Push25 as u8;
pub const PUSH26: u8 = Opcode::Push26 as u8;
pub const PUSH27: u8 = Opcode::Push27 as u8;
pub const PUSH28: u8 = Opcode::Push28 as u8;
pub const PUSH29: u8 = Opcode::Push29 as u8;
pub const PUSH30: u8 = Opcode::Push30 as u8;
pub const PUSH31: u8 = Opcode::Push31 as u8;
pub const PUSH32: u8 = Opcode::Push32 as u8;

// Dup
pub const DUP1: u8 = Opcode::Dup1 as u8;
pub const DUP2: u8 = Opcode::Dup2 as u8;
pub const DUP3: u8 = Opcode::Dup3 as u8;
pub const DUP4: u8 = Opcode::Dup4 as u8;
pub const DUP5: u8 = Opcode::Dup5 as u8;
pub const DUP6: u8 = Opcode::Dup6 as u8;
pub const DUP7: u8 = Opcode::Dup7 as u8;
pub const DUP8: u8 = Opcode::Dup8 as u8;
pub const DUP9: u8 = Opcode::Dup9 as u8;
pub const DUP10: u8 = Opcode::Dup10 as u8;
pub const DUP11: u8 = Opcode::Dup11 as u8;
pub const DUP12: u8 = Opcode::Dup12 as u8;
pub const DUP13: u8 = Opcode::Dup13 as u8;
pub const DUP14: u8 = Opcode::Dup14 as u8;
pub const DUP15: u8 = Opcode::Dup15 as u8;
pub const DUP16: u8 = Opcode::Dup16 as u8;

// Swap
pub const SWAP1: u8 = Opcode::Swap1 as u8;
pub const SWAP2: u8 = Opcode::Swap2 as u8;
pub const SWAP3: u8 = Opcode::Swap3 as u8;
pub const SWAP4: u8 = Opcode::Swap4 as u8;
pub const SWAP5: u8 = Opcode::Swap5 as u8;
pub const SWAP6: u8 = Opcode::Swap6 as u8;
pub const SWAP7: u8 = Opcode::Swap7 as u8;
pub const SWAP8: u8 = Opcode::Swap8 as u8;
pub const SWAP9: u8 = Opcode::Swap9 as u8;
pub const SWAP10: u8 = Opcode::Swap10 as u8;
pub const SWAP11: u8 = Opcode::Swap11 as u8;
pub const SWAP12: u8 = Opcode::Swap12 as u8;
pub const SWAP13: u8 = Opcode::Swap13 as u8;
pub const SWAP14: u8 = Opcode::Swap14 as u8;
pub const SWAP15: u8 = Opcode::Swap15 as u8;
pub const SWAP16: u8 = Opcode::Swap16 as u8;

// Logging
pub const LOG0: u8 = Opcode::Log0 as u8;
pub const LOG1: u8 = Opcode::Log1 as u8;
pub const LOG2: u8 = Opcode::Log2 as u8;
pub const LOG3: u8 = Opcode::Log3 as u8;
pub const LOG4: u8 = Opcode::Log4 as u8;

// System
pub const CREATE: u8 = Opcode::Create as u8;
pub const CALL: u8 = Opcode::Call as u8;
pub const CALLCODE: u8 = Opcode::CallCode as u8;
pub const RETURN: u8 = Opcode::Return as u8;
pub const DELEGATECALL: u8 = Opcode::DelegateCall as u8;
pub const CREATE2: u8 = Opcode::Create2 as u8;
pub const STATICCALL: u8 = Opcode::StaticCall as u8;
pub const REVERT: u8 = Opcode::Revert as u8;
pub const INVALID: u8 = Opcode::Invalid as u8;
pub const SELFDESTRUCT: u8 = Opcode::SelfDestruct as u8;

// -----------------------------------------------------------------------------
// Legacy helper functions (now delegate to Opcode enum)
// -----------------------------------------------------------------------------

/// Returns how many bytes a PUSH<n> opcode reads from code.
pub fn push_data_size(opcode: u8) -> usize {
    Opcode::try_from(opcode)
        .map(|op| op.push_data_size())
        .unwrap_or(0)
}

/// Checks if an opcode is a PUSH.
pub fn is_push(opcode: u8) -> bool {
    Opcode::try_from(opcode)
        .map(|op| op.is_push())
        .unwrap_or(false)
}

/// Checks if an opcode is a DUP.
pub fn is_dup(opcode: u8) -> bool {
    Opcode::try_from(opcode)
        .map(|op| op.is_dup())
        .unwrap_or(false)
}

/// Checks if an opcode is a SWAP.
pub fn is_swap(opcode: u8) -> bool {
    Opcode::try_from(opcode)
        .map(|op| op.is_swap())
        .unwrap_or(false)
}

/// Checks if an opcode is a LOG.
pub fn is_log(opcode: u8) -> bool {
    Opcode::try_from(opcode)
        .map(|op| op.is_log())
        .unwrap_or(false)
}

/// Returns the number of topics for a LOG opcode (0-4).
pub fn log_topic_count(opcode: u8) -> usize {
    Opcode::try_from(opcode)
        .map(|op| op.log_topic_count())
        .unwrap_or(0)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_try_from() {
        assert_eq!(Opcode::try_from(0x01).unwrap(), Opcode::Add);
        assert_eq!(Opcode::try_from(0x60).unwrap(), Opcode::Push1);
        assert_eq!(Opcode::try_from(0x7F).unwrap(), Opcode::Push32);
        assert!(Opcode::try_from(0xFE).unwrap() == Opcode::Invalid);
        assert!(Opcode::try_from(0xBA).is_err());
    }

    #[test]
    fn test_push_data_size() {
        assert_eq!(Opcode::Push1.push_data_size(), 1);
        assert_eq!(Opcode::Push32.push_data_size(), 32);
        assert_eq!(Opcode::Add.push_data_size(), 0);
    }

    #[test]
    fn test_is_push() {
        assert!(Opcode::Push1.is_push());
        assert!(Opcode::Push32.is_push());
        assert!(!Opcode::Add.is_push());
    }

    #[test]
    fn test_is_dup() {
        assert!(Opcode::Dup1.is_dup());
        assert!(Opcode::Dup16.is_dup());
        assert!(!Opcode::Swap1.is_dup());
    }

    #[test]
    fn test_is_swap() {
        assert!(Opcode::Swap1.is_swap());
        assert!(Opcode::Swap16.is_swap());
        assert!(!Opcode::Dup1.is_swap());
    }

    #[test]
    fn test_is_log() {
        assert!(Opcode::Log0.is_log());
        assert!(Opcode::Log4.is_log());
        assert!(!Opcode::Add.is_log());
    }

    #[test]
    fn test_log_topic_count() {
        assert_eq!(Opcode::Log0.log_topic_count(), 0);
        assert_eq!(Opcode::Log2.log_topic_count(), 2);
        assert_eq!(Opcode::Log4.log_topic_count(), 4);
        assert_eq!(Opcode::Add.log_topic_count(), 0);
    }

    #[test]
    fn test_legacy_functions() {
        assert_eq!(push_data_size(PUSH1), 1);
        assert_eq!(push_data_size(PUSH32), 32);
        assert_eq!(push_data_size(ADD), 0);
        assert!(is_push(PUSH1));
        assert!(!is_push(ADD));
        assert!(is_dup(DUP1));
        assert!(!is_dup(SWAP1));
        assert!(is_swap(SWAP1));
        assert!(is_log(LOG0));
        assert_eq!(log_topic_count(LOG3), 3);
        assert_eq!(log_topic_count(INVALID), 0);
    }

    #[test]
    fn test_opcode_constants_match() {
        assert_eq!(STOP, 0x00);
        assert_eq!(ADD, 0x01);
        assert_eq!(PUSH1, 0x60);
        assert_eq!(DUP1, 0x80);
        assert_eq!(SWAP1, 0x90);
        assert_eq!(LOG0, 0xA0);
        assert_eq!(CREATE, 0xF0);
        assert_eq!(INVALID, 0xFE);
    }
}
