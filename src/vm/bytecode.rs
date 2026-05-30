//! IONA VM — Opcode definitions and utilities.
//!
//! Stack words are 256-bit (stored as `[u8; 32]`).
//! Gas costs follow EVM conventions where appropriate.
//!
//! # Opcode Groups
//!
//! | Range      | Category              |
//! |------------|-----------------------|
//! | `0x00`     | Stop                  |
//! | `0x01–0x0B`| Arithmetic            |
//! | `0x10–0x1D`| Comparison & Bitwise  |
//! | `0x20`     | SHA3                  |
//! | `0x30–0x3E`| Environment           |
//! | `0x50–0x5B`| Memory / Ctrl Flow    |
//! | `0x60–0x7F`| Push (1–32 bytes)    |
//! | `0x80–0x8F`| Dup (1–16)           |
//! | `0x90–0x9F`| Swap (1–16)          |
//! | `0xA0–0xA4`| Logging              |
//! | `0xF0–0xFF`| System               |

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
// Opcode enum
// -----------------------------------------------------------------------------

/// All known IONA VM opcodes.
///
/// The numeric values follow the EVM specification, with some IONA-specific
/// extensions (e.g., `BLAKE3` at `0x21`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Opcode {
    // ── Control (0x00) ──────────────────────────────────────────────────
    Stop = 0x00,

    // ── Arithmetic (0x01–0x0B) ──────────────────────────────────────────
    Add         = 0x01,
    Mul         = 0x02,
    Sub         = 0x03,
    Div         = 0x04,
    SDiv        = 0x05,
    Mod         = 0x06,
    SMod        = 0x07,
    AddMod      = 0x08,
    MulMod      = 0x09,
    Exp         = 0x0A,
    SignExtend  = 0x0B,

    // ── Comparison & Bitwise (0x10–0x1D) ────────────────────────────────
    Lt      = 0x10,
    Gt      = 0x11,
    SLt     = 0x12,
    SGt     = 0x13,
    Eq      = 0x14,
    IsZero  = 0x15,
    And     = 0x16,
    Or      = 0x17,
    Xor     = 0x18,
    Not     = 0x19,
    Byte    = 0x1A,
    Shl     = 0x1B,
    Shr     = 0x1C,
    Sar     = 0x1D,

    // ── Cryptographic (0x20–0x21) ───────────────────────────────────────
    Sha3   = 0x20,
    Blake3 = 0x21,  // IONA extension

    // ── Environment (0x30–0x3E) ─────────────────────────────────────────
    Address         = 0x30,
    Balance         = 0x31,
    Origin          = 0x32,
    Caller          = 0x33,
    CallValue       = 0x34,
    CallDataLoad    = 0x35,
    CallDataSize    = 0x36,
    CallDataCopy    = 0x37,
    CodeSize        = 0x38,
    CodeCopy        = 0x39,
    GasPrice        = 0x3A,
    ExtCodeSize     = 0x3B,
    ExtCodeCopy     = 0x3C,
    ReturnDataSize  = 0x3D,
    ReturnDataCopy  = 0x3E,

    // ── Memory & Control Flow (0x50–0x5B) ───────────────────────────────
    Pop         = 0x50,
    MLoad       = 0x51,
    MStore      = 0x52,
    MStore8     = 0x53,
    SLoad       = 0x54,
    SStore      = 0x55,
    Jump        = 0x56,
    Jumpi       = 0x57,
    Pc          = 0x58,
    MSize       = 0x59,
    Gas         = 0x5A,
    JumpDest    = 0x5B,

    // ── Push (0x60–0x7F) ────────────────────────────────────────────────
    Push1  = 0x60, Push2  = 0x61, Push3  = 0x62, Push4  = 0x63,
    Push5  = 0x64, Push6  = 0x65, Push7  = 0x66, Push8  = 0x67,
    Push9  = 0x68, Push10 = 0x69, Push11 = 0x6A, Push12 = 0x6B,
    Push13 = 0x6C, Push14 = 0x6D, Push15 = 0x6E, Push16 = 0x6F,
    Push17 = 0x70, Push18 = 0x71, Push19 = 0x72, Push20 = 0x73,
    Push21 = 0x74, Push22 = 0x75, Push23 = 0x76, Push24 = 0x77,
    Push25 = 0x78, Push26 = 0x79, Push27 = 0x7A, Push28 = 0x7B,
    Push29 = 0x7C, Push30 = 0x7D, Push31 = 0x7E, Push32 = 0x7F,

    // ── Duplication (0x80–0x8F) ─────────────────────────────────────────
    Dup1  = 0x80, Dup2  = 0x81, Dup3  = 0x82, Dup4  = 0x83,
    Dup5  = 0x84, Dup6  = 0x85, Dup7  = 0x86, Dup8  = 0x87,
    Dup9  = 0x88, Dup10 = 0x89, Dup11 = 0x8A, Dup12 = 0x8B,
    Dup13 = 0x8C, Dup14 = 0x8D, Dup15 = 0x8E, Dup16 = 0x8F,

    // ── Swap (0x90–0x9F) ────────────────────────────────────────────────
    Swap1  = 0x90, Swap2  = 0x91, Swap3  = 0x92, Swap4  = 0x93,
    Swap5  = 0x94, Swap6  = 0x95, Swap7  = 0x96, Swap8  = 0x97,
    Swap9  = 0x98, Swap10 = 0x99, Swap11 = 0x9A, Swap12 = 0x9B,
    Swap13 = 0x9C, Swap14 = 0x9D, Swap15 = 0x9E, Swap16 = 0x9F,

    // ── Logging (0xA0–0xA4) ─────────────────────────────────────────────
    Log0 = 0xA0, Log1 = 0xA1, Log2 = 0xA2, Log3 = 0xA3, Log4 = 0xA4,

    // ── System (0xF0–0xFF) ──────────────────────────────────────────────
    Create       = 0xF0,
    Call         = 0xF1,
    CallCode     = 0xF2,
    Return       = 0xF3,
    DelegateCall = 0xF4,
    Create2      = 0xF5,
    StaticCall   = 0xFA,
    Revert       = 0xFD,
    Invalid      = 0xFE,
    SelfDestruct = 0xFF,
}

// -----------------------------------------------------------------------------
// Conversion: u8 ↔ Opcode
// -----------------------------------------------------------------------------

impl TryFrom<u8> for Opcode {
    type Error = OpcodeError;

    fn try_from(value: u8) -> OpcodeResult<Self> {
        // Use a lookup table for O(1) conversion without unsafe.
        // The table covers the full 0x00–0xFF range; invalid slots hold None.
        static LUT: Lazy<[Option<Opcode>; 256]> = Lazy::new(|| {
            let mut table = [None; 256];
            // Arithmetic
            table[0x00] = Some(Opcode::Stop);
            table[0x01] = Some(Opcode::Add);
            table[0x02] = Some(Opcode::Mul);
            table[0x03] = Some(Opcode::Sub);
            table[0x04] = Some(Opcode::Div);
            table[0x05] = Some(Opcode::SDiv);
            table[0x06] = Some(Opcode::Mod);
            table[0x07] = Some(Opcode::SMod);
            table[0x08] = Some(Opcode::AddMod);
            table[0x09] = Some(Opcode::MulMod);
            table[0x0A] = Some(Opcode::Exp);
            table[0x0B] = Some(Opcode::SignExtend);
            // Comparison & Bitwise
            table[0x10] = Some(Opcode::Lt);
            table[0x11] = Some(Opcode::Gt);
            table[0x12] = Some(Opcode::SLt);
            table[0x13] = Some(Opcode::SGt);
            table[0x14] = Some(Opcode::Eq);
            table[0x15] = Some(Opcode::IsZero);
            table[0x16] = Some(Opcode::And);
            table[0x17] = Some(Opcode::Or);
            table[0x18] = Some(Opcode::Xor);
            table[0x19] = Some(Opcode::Not);
            table[0x1A] = Some(Opcode::Byte);
            table[0x1B] = Some(Opcode::Shl);
            table[0x1C] = Some(Opcode::Shr);
            table[0x1D] = Some(Opcode::Sar);
            // Cryptographic
            table[0x20] = Some(Opcode::Sha3);
            table[0x21] = Some(Opcode::Blake3);
            // Environment
            table[0x30] = Some(Opcode::Address);
            table[0x31] = Some(Opcode::Balance);
            table[0x32] = Some(Opcode::Origin);
            table[0x33] = Some(Opcode::Caller);
            table[0x34] = Some(Opcode::CallValue);
            table[0x35] = Some(Opcode::CallDataLoad);
            table[0x36] = Some(Opcode::CallDataSize);
            table[0x37] = Some(Opcode::CallDataCopy);
            table[0x38] = Some(Opcode::CodeSize);
            table[0x39] = Some(Opcode::CodeCopy);
            table[0x3A] = Some(Opcode::GasPrice);
            table[0x3B] = Some(Opcode::ExtCodeSize);
            table[0x3C] = Some(Opcode::ExtCodeCopy);
            table[0x3D] = Some(Opcode::ReturnDataSize);
            table[0x3E] = Some(Opcode::ReturnDataCopy);
            // Memory & Control Flow
            table[0x50] = Some(Opcode::Pop);
            table[0x51] = Some(Opcode::MLoad);
            table[0x52] = Some(Opcode::MStore);
            table[0x53] = Some(Opcode::MStore8);
            table[0x54] = Some(Opcode::SLoad);
            table[0x55] = Some(Opcode::SStore);
            table[0x56] = Some(Opcode::Jump);
            table[0x57] = Some(Opcode::Jumpi);
            table[0x58] = Some(Opcode::Pc);
            table[0x59] = Some(Opcode::MSize);
            table[0x5A] = Some(Opcode::Gas);
            table[0x5B] = Some(Opcode::JumpDest);
            // Push (0x60–0x7F)
            table[0x60] = Some(Opcode::Push1);
            table[0x61] = Some(Opcode::Push2);
            table[0x62] = Some(Opcode::Push3);
            table[0x63] = Some(Opcode::Push4);
            table[0x64] = Some(Opcode::Push5);
            table[0x65] = Some(Opcode::Push6);
            table[0x66] = Some(Opcode::Push7);
            table[0x67] = Some(Opcode::Push8);
            table[0x68] = Some(Opcode::Push9);
            table[0x69] = Some(Opcode::Push10);
            table[0x6A] = Some(Opcode::Push11);
            table[0x6B] = Some(Opcode::Push12);
            table[0x6C] = Some(Opcode::Push13);
            table[0x6D] = Some(Opcode::Push14);
            table[0x6E] = Some(Opcode::Push15);
            table[0x6F] = Some(Opcode::Push16);
            table[0x70] = Some(Opcode::Push17);
            table[0x71] = Some(Opcode::Push18);
            table[0x72] = Some(Opcode::Push19);
            table[0x73] = Some(Opcode::Push20);
            table[0x74] = Some(Opcode::Push21);
            table[0x75] = Some(Opcode::Push22);
            table[0x76] = Some(Opcode::Push23);
            table[0x77] = Some(Opcode::Push24);
            table[0x78] = Some(Opcode::Push25);
            table[0x79] = Some(Opcode::Push26);
            table[0x7A] = Some(Opcode::Push27);
            table[0x7B] = Some(Opcode::Push28);
            table[0x7C] = Some(Opcode::Push29);
            table[0x7D] = Some(Opcode::Push30);
            table[0x7E] = Some(Opcode::Push31);
            table[0x7F] = Some(Opcode::Push32);
            // Dup (0x80–0x8F)
            table[0x80] = Some(Opcode::Dup1);
            table[0x81] = Some(Opcode::Dup2);
            table[0x82] = Some(Opcode::Dup3);
            table[0x83] = Some(Opcode::Dup4);
            table[0x84] = Some(Opcode::Dup5);
            table[0x85] = Some(Opcode::Dup6);
            table[0x86] = Some(Opcode::Dup7);
            table[0x87] = Some(Opcode::Dup8);
            table[0x88] = Some(Opcode::Dup9);
            table[0x89] = Some(Opcode::Dup10);
            table[0x8A] = Some(Opcode::Dup11);
            table[0x8B] = Some(Opcode::Dup12);
            table[0x8C] = Some(Opcode::Dup13);
            table[0x8D] = Some(Opcode::Dup14);
            table[0x8E] = Some(Opcode::Dup15);
            table[0x8F] = Some(Opcode::Dup16);
            // Swap (0x90–0x9F)
            table[0x90] = Some(Opcode::Swap1);
            table[0x91] = Some(Opcode::Swap2);
            table[0x92] = Some(Opcode::Swap3);
            table[0x93] = Some(Opcode::Swap4);
            table[0x94] = Some(Opcode::Swap5);
            table[0x95] = Some(Opcode::Swap6);
            table[0x96] = Some(Opcode::Swap7);
            table[0x97] = Some(Opcode::Swap8);
            table[0x98] = Some(Opcode::Swap9);
            table[0x99] = Some(Opcode::Swap10);
            table[0x9A] = Some(Opcode::Swap11);
            table[0x9B] = Some(Opcode::Swap12);
            table[0x9C] = Some(Opcode::Swap13);
            table[0x9D] = Some(Opcode::Swap14);
            table[0x9E] = Some(Opcode::Swap15);
            table[0x9F] = Some(Opcode::Swap16);
            // Logging
            table[0xA0] = Some(Opcode::Log0);
            table[0xA1] = Some(Opcode::Log1);
            table[0xA2] = Some(Opcode::Log2);
            table[0xA3] = Some(Opcode::Log3);
            table[0xA4] = Some(Opcode::Log4);
            // System
            table[0xF0] = Some(Opcode::Create);
            table[0xF1] = Some(Opcode::Call);
            table[0xF2] = Some(Opcode::CallCode);
            table[0xF3] = Some(Opcode::Return);
            table[0xF4] = Some(Opcode::DelegateCall);
            table[0xF5] = Some(Opcode::Create2);
            table[0xFA] = Some(Opcode::StaticCall);
            table[0xFD] = Some(Opcode::Revert);
            table[0xFE] = Some(Opcode::Invalid);
            table[0xFF] = Some(Opcode::SelfDestruct);
            table
        });

        LUT[value as usize].ok_or(OpcodeError::InvalidOpcode { opcode: value })
    }
}

impl From<Opcode> for u8 {
    fn from(op: Opcode) -> u8 {
        op as u8
    }
}

// -----------------------------------------------------------------------------
// Opcode properties
// -----------------------------------------------------------------------------

impl Opcode {
    /// Returns the number of bytes a PUSH opcode reads from code (0 for non‑PUSH).
    pub const fn push_data_size(self) -> usize {
        match self {
            Opcode::Push1  => 1,  Opcode::Push2  => 2,  Opcode::Push3  => 3,
            Opcode::Push4  => 4,  Opcode::Push5  => 5,  Opcode::Push6  => 6,
            Opcode::Push7  => 7,  Opcode::Push8  => 8,  Opcode::Push9  => 9,
            Opcode::Push10 => 10, Opcode::Push11 => 11, Opcode::Push12 => 12,
            Opcode::Push13 => 13, Opcode::Push14 => 14, Opcode::Push15 => 15,
            Opcode::Push16 => 16, Opcode::Push17 => 17, Opcode::Push18 => 18,
            Opcode::Push19 => 19, Opcode::Push20 => 20, Opcode::Push21 => 21,
            Opcode::Push22 => 22, Opcode::Push23 => 23, Opcode::Push24 => 24,
            Opcode::Push25 => 25, Opcode::Push26 => 26, Opcode::Push27 => 27,
            Opcode::Push28 => 28, Opcode::Push29 => 29, Opcode::Push30 => 30,
            Opcode::Push31 => 31, Opcode::Push32 => 32,
            _ => 0,
        }
    }

    /// Returns `true` for `PUSH1..=PUSH32`.
    pub const fn is_push(self) -> bool {
        matches!(self, Opcode::Push1..=Opcode::Push32)
    }

    /// Returns `true` for `DUP1..=DUP16`.
    pub const fn is_dup(self) -> bool {
        matches!(self, Opcode::Dup1..=Opcode::Dup16)
    }

    /// Returns `true` for `SWAP1..=SWAP16`.
    pub const fn is_swap(self) -> bool {
        matches!(self, Opcode::Swap1..=Opcode::Swap16)
    }

    /// Returns `true` for `LOG0..=LOG4`.
    pub const fn is_log(self) -> bool {
        matches!(self, Opcode::Log0..=Opcode::Log4)
    }

    /// Returns the number of topics for a LOG opcode (0‑4), or 0 for non‑LOG.
    pub const fn log_topic_count(self) -> usize {
        match self {
            Opcode::Log0 => 0,
            Opcode::Log1 => 1,
            Opcode::Log2 => 2,
            Opcode::Log3 => 3,
            Opcode::Log4 => 4,
            _ => 0,
        }
    }

    /// Returns `true` if the opcode terminates execution.
    pub const fn is_terminator(self) -> bool {
        matches!(self, Opcode::Stop | Opcode::Return | Opcode::Revert | Opcode::Invalid | Opcode::SelfDestruct)
    }

    /// Returns `true` if the opcode alters control flow (jump, call, etc.).
    pub const fn is_jump(self) -> bool {
        matches!(self, Opcode::Jump | Opcode::Jumpi | Opcode::JumpDest)
    }
}

// -----------------------------------------------------------------------------
// Backward-compatible constants (re‑exported as raw u8)
// -----------------------------------------------------------------------------

// Helper macro to generate constants
macro_rules! opcode_consts {
    ($($name:ident = $op:ident),* $(,)?) => {
        $(
            #[allow(non_upper_case_globals)]
            pub const $name: u8 = Opcode::$op as u8;
        )*
    };
}

opcode_consts! {
    STOP = Stop, ADD = Add, MUL = Mul, SUB = Sub,
    DIV = Div, SDIV = SDiv, MOD = Mod, SMOD = SMod,
    ADDMOD = AddMod, MULMOD = MulMod, EXP = Exp, SIGNEXTEND = SignExtend,

    LT = Lt, GT = Gt, SLT = SLt, SGT = SGt,
    EQ = Eq, ISZERO = IsZero, AND = And, OR = Or,
    XOR = Xor, NOT = Not, BYTE = Byte,
    SHL = Shl, SHR = Shr, SAR = Sar,

    SHA3 = Sha3, BLAKE3 = Blake3,

    ADDRESS = Address, BALANCE = Balance, ORIGIN = Origin,
    CALLER = Caller, CALLVALUE = CallValue,
    CALLDATALOAD = CallDataLoad, CALLDATASIZE = CallDataSize,
    CALLDATACOPY = CallDataCopy, CODESIZE = CodeSize, CODECOPY = CodeCopy,
    GASPRICE = GasPrice, EXTCODESIZE = ExtCodeSize, EXTCODECOPY = ExtCodeCopy,
    RETURNDATASIZE = ReturnDataSize, RETURNDATACOPY = ReturnDataCopy,

    POP = Pop, MLOAD = MLoad, MSTORE = MStore, MSTORE8 = MStore8,
    SLOAD = SLoad, SSTORE = SStore,
    JUMP = Jump, JUMPI = Jumpi, PC = Pc, MSIZE = MSize,
    GAS = Gas, JUMPDEST = JumpDest,

    PUSH1 = Push1, PUSH2 = Push2, PUSH3 = Push3, PUSH4 = Push4,
    PUSH5 = Push5, PUSH6 = Push6, PUSH7 = Push7, PUSH8 = Push8,
    PUSH9 = Push9, PUSH10 = Push10, PUSH11 = Push11, PUSH12 = Push12,
    PUSH13 = Push13, PUSH14 = Push14, PUSH15 = Push15, PUSH16 = Push16,
    PUSH17 = Push17, PUSH18 = Push18, PUSH19 = Push19, PUSH20 = Push20,
    PUSH21 = Push21, PUSH22 = Push22, PUSH23 = Push23, PUSH24 = Push24,
    PUSH25 = Push25, PUSH26 = Push26, PUSH27 = Push27, PUSH28 = Push28,
    PUSH29 = Push29, PUSH30 = Push30, PUSH31 = Push31, PUSH32 = Push32,

    DUP1 = Dup1, DUP2 = Dup2, DUP3 = Dup3, DUP4 = Dup4,
    DUP5 = Dup5, DUP6 = Dup6, DUP7 = Dup7, DUP8 = Dup8,
    DUP9 = Dup9, DUP10 = Dup10, DUP11 = Dup11, DUP12 = Dup12,
    DUP13 = Dup13, DUP14 = Dup14, DUP15 = Dup15, DUP16 = Dup16,

    SWAP1 = Swap1, SWAP2 = Swap2, SWAP3 = Swap3, SWAP4 = Swap4,
    SWAP5 = Swap5, SWAP6 = Swap6, SWAP7 = Swap7, SWAP8 = Swap8,
    SWAP9 = Swap9, SWAP10 = Swap10, SWAP11 = Swap11, SWAP12 = Swap12,
    SWAP13 = Swap13, SWAP14 = Swap14, SWAP15 = Swap15, SWAP16 = Swap16,

    LOG0 = Log0, LOG1 = Log1, LOG2 = Log2, LOG3 = Log3, LOG4 = Log4,

    CREATE = Create, CALL = Call, CALLCODE = CallCode,
    RETURN = Return, DELEGATECALL = DelegateCall,
    CREATE2 = Create2, STATICCALL = StaticCall,
    REVERT = Revert, INVALID = Invalid, SELFDESTRUCT = SelfDestruct,
}

// -----------------------------------------------------------------------------
// Bytecode validation
// -----------------------------------------------------------------------------

/// Validates that every byte in `code` is a defined opcode.
pub fn validate_bytecode(code: &[u8]) -> Result<(), OpcodeError> {
    let mut i = 0;
    while i < code.len() {
        let op = Opcode::try_from(code[i])?;
        if op.is_push() {
            let data_size = op.push_data_size();
            // Ensure push data does not exceed remaining bytes
            if i + data_size >= code.len() {
                return Err(OpcodeError::InvalidOpcode { opcode: code[i] });
            }
            i += 1 + data_size;
        } else {
            i += 1;
        }
    }
    Ok(())
}

// -----------------------------------------------------------------------------
// Lazy initialisation helper
// -----------------------------------------------------------------------------

use spin::Lazy;

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_opcode_try_from_explicit() {
        assert_eq!(Opcode::try_from(0x01).unwrap(), Opcode::Add);
        assert_eq!(Opcode::try_from(0x60).unwrap(), Opcode::Push1);
        assert_eq!(Opcode::try_from(0x7F).unwrap(), Opcode::Push32);
        assert_eq!(Opcode::try_from(0xFE).unwrap(), Opcode::Invalid);
        assert_eq!(Opcode::try_from(0x21).unwrap(), Opcode::Blake3);
    }

    #[test]
    fn test_opcode_try_from_invalid() {
        assert!(Opcode::try_from(0x0C).is_err());
        assert!(Opcode::try_from(0x2F).is_err());
        assert!(Opcode::try_from(0xBA).is_err());
    }

    #[test]
    fn test_push_data_size() {
        assert_eq!(Opcode::Push1.push_data_size(), 1);
        assert_eq!(Opcode::Push32.push_data_size(), 32);
        assert_eq!(Opcode::Add.push_data_size(), 0);
        assert_eq!(push_data_size(PUSH1), 1);
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
    fn test_is_terminator() {
        assert!(Opcode::Stop.is_terminator());
        assert!(Opcode::Return.is_terminator());
        assert!(Opcode::Revert.is_terminator());
        assert!(!Opcode::Add.is_terminator());
    }

    #[test]
    fn test_is_jump() {
        assert!(Opcode::Jump.is_jump());
        assert!(Opcode::Jumpi.is_jump());
        assert!(!Opcode::Push1.is_jump());
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
    }

    #[test]
    fn test_validate_bytecode_valid() {
        let code = vec![0x60, 0x01, 0x01]; // PUSH1 0x01, ADD
        assert!(validate_bytecode(&code).is_ok());
    }

    #[test]
    fn test_validate_bytecode_truncated_push() {
        let code = vec![0x60]; // PUSH1 without data
        assert!(validate_bytecode(&code).is_err());
    }

    #[test]
    fn test_validate_bytecode_invalid_opcode() {
        let code = vec![0x0C]; // undefined opcode
        assert!(validate_bytecode(&code).is_err());
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
        assert_eq!(BLAKE3, 0x21);
    }
}
