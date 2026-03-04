//! IONA VM — Opcode definitions.
//!
//! Stack words are 256-bit (stored as [u8;32]).
//! Gas costs follow EVM conventions where appropriate.

// ── Arithmetic ─────────────────────────────────────────────────────────────
pub const STOP:    u8 = 0x00;
pub const ADD:     u8 = 0x01;
pub const MUL:     u8 = 0x02;
pub const SUB:     u8 = 0x03;
pub const DIV:     u8 = 0x04;
pub const MOD:     u8 = 0x06;
pub const EXP:     u8 = 0x0A;
pub const LT:      u8 = 0x10;
pub const GT:      u8 = 0x11;
pub const EQ:      u8 = 0x14;
pub const ISZERO:  u8 = 0x15;
pub const AND:     u8 = 0x16;
pub const OR:      u8 = 0x17;
pub const XOR:     u8 = 0x18;
pub const NOT:     u8 = 0x19;
pub const SHL:     u8 = 0x1B;
pub const SHR:     u8 = 0x1C;

// ── SHA3 ───────────────────────────────────────────────────────────────────
pub const SHA3:    u8 = 0x20;

// ── Environment ────────────────────────────────────────────────────────────
pub const CALLER:  u8 = 0x33;   // push caller address (low 20 bytes as u256)
pub const CALLVALUE: u8 = 0x34; // push transferred value (0 for now)
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const GAS:     u8 = 0x5A;   // push remaining gas

// ── Memory ─────────────────────────────────────────────────────────────────
pub const MLOAD:   u8 = 0x51;
pub const MSTORE:  u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const MSIZE:   u8 = 0x59;

// ── Storage ────────────────────────────────────────────────────────────────
pub const SLOAD:   u8 = 0x54;
pub const SSTORE:  u8 = 0x55;

// ── Stack ──────────────────────────────────────────────────────────────────
pub const POP:     u8 = 0x50;

// PUSH1..PUSH32
pub const PUSH1:   u8 = 0x60;
pub const PUSH2:   u8 = 0x61;
pub const PUSH4:   u8 = 0x63;
pub const PUSH8:   u8 = 0x67;
pub const PUSH16:  u8 = 0x6F;
pub const PUSH20:  u8 = 0x73;
pub const PUSH32:  u8 = 0x7F;

// DUP1..DUP16
pub const DUP1:    u8 = 0x80;
pub const DUP2:    u8 = 0x81;
pub const DUP3:    u8 = 0x82;
pub const DUP4:    u8 = 0x83;
pub const DUP5:    u8 = 0x84;
pub const DUP6:    u8 = 0x85;
pub const DUP7:    u8 = 0x86;
pub const DUP16:   u8 = 0x8F;

// SWAP1..SWAP16
pub const SWAP1:   u8 = 0x90;
pub const SWAP2:   u8 = 0x91;
pub const SWAP3:   u8 = 0x92;
pub const SWAP4:   u8 = 0x93;
pub const SWAP16:  u8 = 0x9F;

// ── Control flow ───────────────────────────────────────────────────────────
pub const JUMP:    u8 = 0x56;
pub const JUMPI:   u8 = 0x57;
pub const JUMPDEST: u8 = 0x5B;
pub const PC:      u8 = 0x58;

// ── Logging ────────────────────────────────────────────────────────────────
pub const LOG0:    u8 = 0xA0;
pub const LOG1:    u8 = 0xA1;
pub const LOG2:    u8 = 0xA2;
pub const LOG3:    u8 = 0xA3;
pub const LOG4:    u8 = 0xA4;

// ── System ─────────────────────────────────────────────────────────────────
pub const RETURN:  u8 = 0xF3;
pub const REVERT:  u8 = 0xFD;
pub const INVALID: u8 = 0xFE;
pub const SELFDESTRUCT: u8 = 0xFF;

// ── Gas costs ──────────────────────────────────────────────────────────────
pub const GAS_VERYLOW: u64  = 3;    // ADD, SUB, LT, GT, EQ, ...
pub const GAS_LOW: u64      = 5;    // MUL, DIV, MOD
pub const GAS_EXP_BASE: u64 = 10;
pub const GAS_EXP_BYTE: u64 = 50;
pub const GAS_SHA3: u64     = 30;
pub const GAS_SLOAD: u64    = 100;
pub const GAS_SSTORE_SET: u64 = 20_000;
pub const GAS_SSTORE_RESET: u64 = 2_900;
pub const GAS_SSTORE_CLEAR: u64 = 15_000;
pub const GAS_JUMP: u64     = 8;
pub const GAS_JUMPI: u64    = 10;
pub const GAS_LOG_BASE: u64 = 375;
pub const GAS_LOG_TOPIC: u64 = 375;
pub const GAS_LOG_BYTE: u64 = 8;
pub const GAS_MEMORY: u64   = 3;    // per word accessed
pub const GAS_COPY_WORD: u64 = 3;   // per word copied (CALLDATACOPY etc)

/// Returns how many bytes a PUSH<n> opcode reads from code.
/// Returns 0 for non-PUSH opcodes.
pub fn push_data_size(opcode: u8) -> usize {
    if opcode >= PUSH1 && opcode <= PUSH32 {
        (opcode - PUSH1 + 1) as usize
    } else {
        0
    }
}
