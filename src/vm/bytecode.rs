//! IONA VM — Opcode definitions.
//!
//! Stack words are 256-bit (stored as [u8; 32]).
//! Gas costs follow EVM conventions where appropriate.
//!
//! # Opcode Groups
//!
//! - Arithmetic (0x00–0x1F)
//! - Comparison & Bitwise (0x10–0x1F)
//! - SHA3 (0x20)
//! - Environment (0x30–0x3F)
//! - Memory & Storage (0x50–0x5F)
//! - Stack (0x60–0x8F)
//! - Control Flow (0x50–0x5F, 0x56–0x5B)
//! - Logging (0xA0–0xA4)
//! - System (0xF0–0xFF)

// ── Arithmetic (0x00–0x0F) ────────────────────────────────────────────────
pub const STOP: u8 = 0x00;
pub const ADD: u8 = 0x01;
pub const MUL: u8 = 0x02;
pub const SUB: u8 = 0x03;
pub const DIV: u8 = 0x04;
pub const SDIV: u8 = 0x05;      // signed divide
pub const MOD: u8 = 0x06;
pub const SMOD: u8 = 0x07;      // signed modulo
pub const ADDMOD: u8 = 0x08;    // addition modulo
pub const MULMOD: u8 = 0x09;    // multiplication modulo
pub const EXP: u8 = 0x0A;
pub const SIGNEXTEND: u8 = 0x0B;

// ── Comparison & Bitwise (0x10–0x1F) ───────────────────────────────────────
pub const LT: u8 = 0x10;
pub const GT: u8 = 0x11;
pub const SLT: u8 = 0x12;       // signed less than
pub const SGT: u8 = 0x13;       // signed greater than
pub const EQ: u8 = 0x14;
pub const ISZERO: u8 = 0x15;
pub const AND: u8 = 0x16;
pub const OR: u8 = 0x17;
pub const XOR: u8 = 0x18;
pub const NOT: u8 = 0x19;
pub const BYTE: u8 = 0x1A;      // fetch byte from word
pub const SHL: u8 = 0x1B;
pub const SHR: u8 = 0x1C;
pub const SAR: u8 = 0x1D;       // arithmetic shift right

// ── SHA3 (0x20) ────────────────────────────────────────────────────────────
pub const SHA3: u8 = 0x20;

// ── Environment (0x30–0x3F) ────────────────────────────────────────────────
pub const ADDRESS: u8 = 0x30;   // current contract address
pub const BALANCE: u8 = 0x31;   // balance of given address
pub const ORIGIN: u8 = 0x32;    // transaction origin
pub const CALLER: u8 = 0x33;    // caller address
pub const CALLVALUE: u8 = 0x34; // value sent with call
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE: u8 = 0x38;
pub const CODECOPY: u8 = 0x39;
pub const GASPRICE: u8 = 0x3A;  // gas price of transaction
pub const EXTCODESIZE: u8 = 0x3B;
pub const EXTCODECOPY: u8 = 0x3C;
pub const RETURNDATASIZE: u8 = 0x3D;
pub const RETURNDATACOPY: u8 = 0x3E;
pub const GAS: u8 = 0x5A;       // remaining gas (actually in 0x5A)

// ── Memory & Storage (0x50–0x5F) ───────────────────────────────────────────
pub const POP: u8 = 0x50;
pub const MLOAD: u8 = 0x51;
pub const MSTORE: u8 = 0x52;
pub const MSTORE8: u8 = 0x53;
pub const SLOAD: u8 = 0x54;
pub const SSTORE: u8 = 0x55;
pub const JUMP: u8 = 0x56;
pub const JUMPI: u8 = 0x57;
pub const PC: u8 = 0x58;
pub const MSIZE: u8 = 0x59;
pub const JUMPDEST: u8 = 0x5B;

// ── Stack (PUSH1..PUSH32, DUP1..DUP16, SWAP1..SWAP16) ─────────────────────
pub const PUSH1: u8 = 0x60;
pub const PUSH2: u8 = 0x61;
pub const PUSH3: u8 = 0x62;
pub const PUSH4: u8 = 0x63;
pub const PUSH5: u8 = 0x64;
pub const PUSH6: u8 = 0x65;
pub const PUSH7: u8 = 0x66;
pub const PUSH8: u8 = 0x67;
pub const PUSH9: u8 = 0x68;
pub const PUSH10: u8 = 0x69;
pub const PUSH11: u8 = 0x6A;
pub const PUSH12: u8 = 0x6B;
pub const PUSH13: u8 = 0x6C;
pub const PUSH14: u8 = 0x6D;
pub const PUSH15: u8 = 0x6E;
pub const PUSH16: u8 = 0x6F;
pub const PUSH17: u8 = 0x70;
pub const PUSH18: u8 = 0x71;
pub const PUSH19: u8 = 0x72;
pub const PUSH20: u8 = 0x73;
pub const PUSH21: u8 = 0x74;
pub const PUSH22: u8 = 0x75;
pub const PUSH23: u8 = 0x76;
pub const PUSH24: u8 = 0x77;
pub const PUSH25: u8 = 0x78;
pub const PUSH26: u8 = 0x79;
pub const PUSH27: u8 = 0x7A;
pub const PUSH28: u8 = 0x7B;
pub const PUSH29: u8 = 0x7C;
pub const PUSH30: u8 = 0x7D;
pub const PUSH31: u8 = 0x7E;
pub const PUSH32: u8 = 0x7F;

pub const DUP1: u8 = 0x80;
pub const DUP2: u8 = 0x81;
pub const DUP3: u8 = 0x82;
pub const DUP4: u8 = 0x83;
pub const DUP5: u8 = 0x84;
pub const DUP6: u8 = 0x85;
pub const DUP7: u8 = 0x86;
pub const DUP8: u8 = 0x87;
pub const DUP9: u8 = 0x88;
pub const DUP10: u8 = 0x89;
pub const DUP11: u8 = 0x8A;
pub const DUP12: u8 = 0x8B;
pub const DUP13: u8 = 0x8C;
pub const DUP14: u8 = 0x8D;
pub const DUP15: u8 = 0x8E;
pub const DUP16: u8 = 0x8F;

pub const SWAP1: u8 = 0x90;
pub const SWAP2: u8 = 0x91;
pub const SWAP3: u8 = 0x92;
pub const SWAP4: u8 = 0x93;
pub const SWAP5: u8 = 0x94;
pub const SWAP6: u8 = 0x95;
pub const SWAP7: u8 = 0x96;
pub const SWAP8: u8 = 0x97;
pub const SWAP9: u8 = 0x98;
pub const SWAP10: u8 = 0x99;
pub const SWAP11: u8 = 0x9A;
pub const SWAP12: u8 = 0x9B;
pub const SWAP13: u8 = 0x9C;
pub const SWAP14: u8 = 0x9D;
pub const SWAP15: u8 = 0x9E;
pub const SWAP16: u8 = 0x9F;

// ── Logging (0xA0–0xA4) ────────────────────────────────────────────────────
pub const LOG0: u8 = 0xA0;
pub const LOG1: u8 = 0xA1;
pub const LOG2: u8 = 0xA2;
pub const LOG3: u8 = 0xA3;
pub const LOG4: u8 = 0xA4;

// ── System (0xF0–0xFF) ─────────────────────────────────────────────────────
pub const CREATE: u8 = 0xF0;
pub const CALL: u8 = 0xF1;
pub const CALLCODE: u8 = 0xF2;
pub const RETURN: u8 = 0xF3;
pub const DELEGATECALL: u8 = 0xF4;
pub const CREATE2: u8 = 0xF5;
pub const STATICCALL: u8 = 0xFA;
pub const REVERT: u8 = 0xFD;
pub const INVALID: u8 = 0xFE;
pub const SELFDESTRUCT: u8 = 0xFF;

// ── Gas costs (base) ───────────────────────────────────────────────────────
pub const GAS_ZERO: u64 = 0;       // STOP, RETURN, REVERT, JUMPDEST
pub const GAS_BASE: u64 = 2;       // JUMP, PC, POP
pub const GAS_VERYLOW: u64 = 3;    // ADD, SUB, LT, GT, EQ, etc.
pub const GAS_LOW: u64 = 5;        // MUL, DIV, MOD, ADDMOD, MULMOD
pub const GAS_MID: u64 = 8;        // JUMPI, CALLDATALOAD
pub const GAS_HIGH: u64 = 10;      // EXP base (additional per byte)
pub const GAS_SHA3: u64 = 30;      // SHA3
pub const GAS_SLOAD: u64 = 100;    // SLOAD
pub const GAS_SSTORE_SET: u64 = 20_000;   // new storage slot
pub const GAS_SSTORE_RESET: u64 = 2_900;  // modify existing slot
pub const GAS_SSTORE_CLEAR: u64 = 15_000; // clear slot (refund)
pub const GAS_LOG_BASE: u64 = 375;        // LOG0
pub const GAS_LOG_TOPIC: u64 = 375;       // per topic
pub const GAS_LOG_BYTE: u64 = 8;          // per byte of data
pub const GAS_MEMORY: u64 = 3;            // per word (32 bytes)
pub const GAS_COPY_WORD: u64 = 3;         // per word copied (CALLDATACOPY, CODECOPY)
pub const GAS_EXTCODE: u64 = 700;         // EXTCODESIZE, EXTCODECOPY
pub const GAS_CALL: u64 = 700;            // CALL, CALLCODE, DELEGATECALL
pub const GAS_CREATE: u64 = 32_000;       // CREATE, CREATE2

/// Returns how many bytes a PUSH<n> opcode reads from code.
pub fn push_data_size(opcode: u8) -> usize {
    if opcode >= PUSH1 && opcode <= PUSH32 {
        (opcode - PUSH1 + 1) as usize
    } else {
        0
    }
}

/// Checks if an opcode is a PUSH.
pub fn is_push(opcode: u8) -> bool {
    opcode >= PUSH1 && opcode <= PUSH32
}

/// Checks if an opcode is a DUP.
pub fn is_dup(opcode: u8) -> bool {
    opcode >= DUP1 && opcode <= DUP16
}

/// Checks if an opcode is a SWAP.
pub fn is_swap(opcode: u8) -> bool {
    opcode >= SWAP1 && opcode <= SWAP16
}

/// Checks if an opcode is a LOG.
pub fn is_log(opcode: u8) -> bool {
    opcode >= LOG0 && opcode <= LOG4
}

/// Returns the number of topics for a LOG opcode (0-4).
pub fn log_topic_count(opcode: u8) -> usize {
    if opcode >= LOG0 && opcode <= LOG4 {
        (opcode - LOG0) as usize
    } else {
        0
    }
}

