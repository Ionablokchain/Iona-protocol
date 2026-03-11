//! IONA VM — Opcode definitions.
//!
//! Stack words are 256-bit (stored as [u8;32]).
//! Gas costs follow EVM conventions where appropriate, but note that this is
//! a simplified schedule; dynamic costs (memory expansion, storage refunds, etc.)
//! are handled in the interpreter, not here.
//!
//! The opcode set is largely EVM-compatible but may omit or adjust certain
//! instructions. Use `is_supported_opcode` to check if an opcode is implemented.

// ── Arithmetic & Comparison ─────────────────────────────────────────────
pub const STOP:       u8 = 0x00;
pub const ADD:        u8 = 0x01;
pub const MUL:        u8 = 0x02;
pub const SUB:        u8 = 0x03;
pub const DIV:        u8 = 0x04;
pub const SDIV:       u8 = 0x05;
pub const MOD:        u8 = 0x06;
pub const SMOD:       u8 = 0x07;
pub const ADDMOD:     u8 = 0x08;
pub const MULMOD:     u8 = 0x09;
pub const EXP:        u8 = 0x0A;
pub const SIGNEXTEND: u8 = 0x0B;

pub const LT:         u8 = 0x10;
pub const GT:         u8 = 0x11;
pub const SLT:        u8 = 0x12;
pub const SGT:        u8 = 0x13;
pub const EQ:         u8 = 0x14;
pub const ISZERO:     u8 = 0x15;
pub const AND:        u8 = 0x16;
pub const OR:         u8 = 0x17;
pub const XOR:        u8 = 0x18;
pub const NOT:        u8 = 0x19;
pub const BYTE:       u8 = 0x1A;
pub const SHL:        u8 = 0x1B;
pub const SHR:        u8 = 0x1C;
pub const SAR:        u8 = 0x1D;   // arithmetic shift right

// ── SHA3 ───────────────────────────────────────────────────────────────
pub const SHA3:       u8 = 0x20;

// ── Environment ────────────────────────────────────────────────────────
pub const ADDRESS:    u8 = 0x30;
pub const BALANCE:    u8 = 0x31;
pub const ORIGIN:     u8 = 0x32;
pub const CALLER:     u8 = 0x33;
pub const CALLVALUE:  u8 = 0x34;
pub const CALLDATALOAD: u8 = 0x35;
pub const CALLDATASIZE: u8 = 0x36;
pub const CALLDATACOPY: u8 = 0x37;
pub const CODESIZE:   u8 = 0x38;
pub const CODECOPY:   u8 = 0x39;
pub const GASPRICE:   u8 = 0x3A;
pub const EXTCODESIZE: u8 = 0x3B;
pub const EXTCODECOPY: u8 = 0x3C;
pub const RETURNDATASIZE: u8 = 0x3D;
pub const RETURNDATACOPY: u8 = 0x3E;
pub const EXTCODEHASH: u8 = 0x3F;

// ── Block information ──────────────────────────────────────────────────
pub const BLOCKHASH:  u8 = 0x40;
pub const COINBASE:   u8 = 0x41;
pub const TIMESTAMP:  u8 = 0x42;
pub const NUMBER:     u8 = 0x43;
pub const DIFFICULTY: u8 = 0x44;   // or PREVRANDAO after merge
pub const GASLIMIT:   u8 = 0x45;
pub const CHAINID:    u8 = 0x46;
pub const SELFBALANCE: u8 = 0x47;
pub const BASEFEE:    u8 = 0x48;   // EIP-3198

// ── Memory ─────────────────────────────────────────────────────────────
pub const MLOAD:      u8 = 0x51;
pub const MSTORE:     u8 = 0x52;
pub const MSTORE8:    u8 = 0x53;
pub const MSIZE:      u8 = 0x59;

// ── Storage ────────────────────────────────────────────────────────────
pub const SLOAD:      u8 = 0x54;
pub const SSTORE:     u8 = 0x55;

// ── Stack ──────────────────────────────────────────────────────────────
pub const POP:        u8 = 0x50;
pub const PUSH0:      u8 = 0x5F;   // introduced in Shanghai
pub const PUSH1:      u8 = 0x60;
pub const PUSH2:      u8 = 0x61;
pub const PUSH3:      u8 = 0x62;
pub const PUSH4:      u8 = 0x63;
pub const PUSH5:      u8 = 0x64;
pub const PUSH6:      u8 = 0x65;
pub const PUSH7:      u8 = 0x66;
pub const PUSH8:      u8 = 0x67;
pub const PUSH9:      u8 = 0x68;
pub const PUSH10:     u8 = 0x69;
pub const PUSH11:     u8 = 0x6A;
pub const PUSH12:     u8 = 0x6B;
pub const PUSH13:     u8 = 0x6C;
pub const PUSH14:     u8 = 0x6D;
pub const PUSH15:     u8 = 0x6E;
pub const PUSH16:     u8 = 0x6F;
pub const PUSH17:     u8 = 0x70;
pub const PUSH18:     u8 = 0x71;
pub const PUSH19:     u8 = 0x72;
pub const PUSH20:     u8 = 0x73;
pub const PUSH21:     u8 = 0x74;
pub const PUSH22:     u8 = 0x75;
pub const PUSH23:     u8 = 0x76;
pub const PUSH24:     u8 = 0x77;
pub const PUSH25:     u8 = 0x78;
pub const PUSH26:     u8 = 0x79;
pub const PUSH27:     u8 = 0x7A;
pub const PUSH28:     u8 = 0x7B;
pub const PUSH29:     u8 = 0x7C;
pub const PUSH30:     u8 = 0x7D;
pub const PUSH31:     u8 = 0x7E;
pub const PUSH32:     u8 = 0x7F;

pub const DUP1:       u8 = 0x80;
pub const DUP2:       u8 = 0x81;
pub const DUP3:       u8 = 0x82;
pub const DUP4:       u8 = 0x83;
pub const DUP5:       u8 = 0x84;
pub const DUP6:       u8 = 0x85;
pub const DUP7:       u8 = 0x86;
pub const DUP8:       u8 = 0x87;
pub const DUP9:       u8 = 0x88;
pub const DUP10:      u8 = 0x89;
pub const DUP11:      u8 = 0x8A;
pub const DUP12:      u8 = 0x8B;
pub const DUP13:      u8 = 0x8C;
pub const DUP14:      u8 = 0x8D;
pub const DUP15:      u8 = 0x8E;
pub const DUP16:      u8 = 0x8F;

pub const SWAP1:      u8 = 0x90;
pub const SWAP2:      u8 = 0x91;
pub const SWAP3:      u8 = 0x92;
pub const SWAP4:      u8 = 0x93;
pub const SWAP5:      u8 = 0x94;
pub const SWAP6:      u8 = 0x95;
pub const SWAP7:      u8 = 0x96;
pub const SWAP8:      u8 = 0x97;
pub const SWAP9:      u8 = 0x98;
pub const SWAP10:     u8 = 0x99;
pub const SWAP11:     u8 = 0x9A;
pub const SWAP12:     u8 = 0x9B;
pub const SWAP13:     u8 = 0x9C;
pub const SWAP14:     u8 = 0x9D;
pub const SWAP15:     u8 = 0x9E;
pub const SWAP16:     u8 = 0x9F;

// ── Control flow ───────────────────────────────────────────────────────
pub const JUMP:       u8 = 0x56;
pub const JUMPI:      u8 = 0x57;
pub const JUMPDEST:   u8 = 0x5B;
pub const PC:         u8 = 0x58;
pub const GAS:        u8 = 0x5A;   // remaining gas (push)

// ── Logging ────────────────────────────────────────────────────────────
pub const LOG0:       u8 = 0xA0;
pub const LOG1:       u8 = 0xA1;
pub const LOG2:       u8 = 0xA2;
pub const LOG3:       u8 = 0xA3;
pub const LOG4:       u8 = 0xA4;

// ── Calls ──────────────────────────────────────────────────────────────
pub const CREATE:     u8 = 0xF0;
pub const CALL:       u8 = 0xF1;
pub const CALLCODE:   u8 = 0xF2;
pub const RETURN:     u8 = 0xF3;
pub const DELEGATECALL: u8 = 0xF4;
pub const CREATE2:    u8 = 0xF5;
pub const STATICCALL: u8 = 0xFA;
pub const REVERT:     u8 = 0xFD;
pub const INVALID:    u8 = 0xFE;
pub const SELFDESTRUCT: u8 = 0xFF;

// ── Gas costs (static part) ────────────────────────────────────────────
pub const GAS_ZERO:           u64 = 0;      // for STOP, RETURN when no-op
pub const GAS_VERYLOW:        u64 = 3;      // ADD, SUB, LT, GT, EQ, ...
pub const GAS_LOW:            u64 = 5;      // MUL, DIV, MOD, ...
pub const GAS_MID:            u64 = 8;      // JUMP, JUMPDEST, ...
pub const GAS_HIGH:           u64 = 10;     // JUMPI, ...
pub const GAS_EXT:            u64 = 20;     // BALANCE, EXTCODESIZE, ...
pub const GAS_EXP_BASE:       u64 = 10;
pub const GAS_EXP_BYTE:       u64 = 50;
pub const GAS_SHA3:           u64 = 30;
pub const GAS_SLOAD:          u64 = 100;
pub const GAS_SSTORE_SET:     u64 = 20_000;
pub const GAS_SSTORE_RESET:   u64 = 2_900;
pub const GAS_SSTORE_CLEAR:   u64 = 15_000;   // refund
pub const GAS_LOG_BASE:       u64 = 375;
pub const GAS_LOG_TOPIC:      u64 = 375;
pub const GAS_LOG_BYTE:       u64 = 8;
pub const GAS_MEMORY:         u64 = 3;        // per word accessed (linear component)
pub const GAS_COPY_WORD:      u64 = 3;        // per word copied
pub const GAS_CALL:           u64 = 40;
pub const GAS_CALL_VALUE:     u64 = 9_000;    // additional when sending value
pub const GAS_CALL_STIPEND:   u64 = 2_300;    // stipend for child call
pub const GAS_DELEGATECALL:   u64 = 40;
pub const GAS_STATICCALL:     u64 = 40;
pub const GAS_CREATE:         u64 = 32_000;
pub const GAS_CREATE2:        u64 = 32_000;
pub const GAS_SELFDESTRUCT:   u64 = 5_000;

// ============================================================================
// Helper functions
// ============================================================================

/// Returns the number of immediate bytes an opcode reads from code (for PUSHn).
/// Returns 0 for non-PUSH opcodes.
pub fn push_data_size(opcode: u8) -> usize {
    match opcode {
        PUSH0 => 0,
        PUSH1..=PUSH32 => (opcode - PUSH1 + 1) as usize,
        _ => 0,
    }
}

/// True if opcode is any PUSH (including PUSH0).
pub fn is_push(opcode: u8) -> bool {
    matches!(opcode, PUSH0..=PUSH32)
}

/// True if opcode is DUP1..DUP16.
pub fn is_dup(opcode: u8) -> bool {
    matches!(opcode, DUP1..=DUP16)
}

/// True if opcode is SWAP1..SWAP16.
pub fn is_swap(opcode: u8) -> bool {
    matches!(opcode, SWAP1..=SWAP16)
}

/// True if opcode is LOG0..LOG4.
pub fn is_log(opcode: u8) -> bool {
    matches!(opcode, LOG0..=LOG4)
}

/// True if opcode ends execution immediately.
pub fn is_terminating_opcode(opcode: u8) -> bool {
    matches!(opcode, STOP | RETURN | REVERT | INVALID | SELFDESTRUCT)
}

/// True if opcode affects control flow.
pub fn is_control_flow_opcode(opcode: u8) -> bool {
    matches!(opcode, JUMP | JUMPI | JUMPDEST | PC)
}

/// For DUP opcodes, returns the depth (1..16). Returns None if not a DUP.
pub fn dup_depth(opcode: u8) -> Option<usize> {
    if is_dup(opcode) {
        Some((opcode - DUP1 + 1) as usize)
    } else {
        None
    }
}

/// For SWAP opcodes, returns the depth (1..16). Returns None if not a SWAP.
pub fn swap_depth(opcode: u8) -> Option<usize> {
    if is_swap(opcode) {
        Some((opcode - SWAP1 + 1) as usize)
    } else {
        None
    }
}

/// Returns the static base gas cost for an opcode, if known.
///
/// Dynamic components such as memory expansion, copy length, EXP exponent bytes,
/// SSTORE state transitions, LOG topics/data length, and CALL value-related
/// charges are handled by the interpreter.
pub fn base_gas_cost(opcode: u8) -> Option<u64> {
    match opcode {
        // Arithmetic & comparison
        STOP => Some(GAS_ZERO),

        ADD | SUB | LT | GT | SLT | SGT | EQ | ISZERO | AND | OR | XOR | NOT | BYTE
        | SHL | SHR | SAR => Some(GAS_VERYLOW),

        MUL | DIV | SDIV | MOD | SMOD | ADDMOD | MULMOD | SIGNEXTEND => Some(GAS_LOW),

        EXP => None, // dynamic
        SHA3 => None, // dynamic

        // Environment
        ADDRESS | ORIGIN | CALLER | CALLVALUE | CALLDATASIZE | CODESIZE | GASPRICE
        | RETURNDATASIZE | COINBASE | TIMESTAMP | NUMBER | DIFFICULTY | GASLIMIT
        | CHAINID | SELFBALANCE | PC | GAS | MSIZE | BASEFEE => Some(GAS_VERYLOW),

        BALANCE | EXTCODESIZE | EXTCODEHASH | BLOCKHASH => Some(GAS_EXT),

        CALLDATALOAD => Some(GAS_VERYLOW),

        CALLDATACOPY | CODECOPY | RETURNDATACOPY | EXTCODECOPY => None, // dynamic
        MLOAD | MSTORE | MSTORE8 => Some(GAS_VERYLOW), // expansion handled elsewhere

        // Storage
        SLOAD => Some(GAS_SLOAD),
        SSTORE => None, // dynamic

        // Stack
        POP => Some(GAS_VERYLOW),
        PUSH0 | PUSH1..=PUSH32 => Some(GAS_VERYLOW),
        DUP1..=DUP16 => Some(GAS_VERYLOW),
        SWAP1..=SWAP16 => Some(GAS_VERYLOW),

        // Control flow
        JUMP => Some(GAS_MID),
        JUMPI => Some(GAS_HIGH),
        JUMPDEST => Some(GAS_MID),

        // Logging
        LOG0..=LOG4 => None, // dynamic

        // Calls / creation
        CREATE => Some(GAS_CREATE),
        CREATE2 => Some(GAS_CREATE2),
        CALL => Some(GAS_CALL),
        CALLCODE => Some(GAS_CALL),
        DELEGATECALL => Some(GAS_DELEGATECALL),
        STATICCALL => Some(GAS_STATICCALL),

        // Return / revert / abort
        RETURN | REVERT => None, // dynamic
        INVALID => Some(GAS_ZERO),
        SELFDESTRUCT => Some(GAS_SELFDESTRUCT),

        _ => None,
    }
}

/// Returns a human-readable name for an opcode.
pub fn opcode_name(opcode: u8) -> &'static str {
    match opcode {
        STOP => "STOP",
        ADD => "ADD",
        MUL => "MUL",
        SUB => "SUB",
        DIV => "DIV",
        SDIV => "SDIV",
        MOD => "MOD",
        SMOD => "SMOD",
        ADDMOD => "ADDMOD",
        MULMOD => "MULMOD",
        EXP => "EXP",
        SIGNEXTEND => "SIGNEXTEND",
        LT => "LT",
        GT => "GT",
        SLT => "SLT",
        SGT => "SGT",
        EQ => "EQ",
        ISZERO => "ISZERO",
        AND => "AND",
        OR => "OR",
        XOR => "XOR",
        NOT => "NOT",
        BYTE => "BYTE",
        SHL => "SHL",
        SHR => "SHR",
        SAR => "SAR",
        SHA3 => "SHA3",
        ADDRESS => "ADDRESS",
        BALANCE => "BALANCE",
        ORIGIN => "ORIGIN",
        CALLER => "CALLER",
        CALLVALUE => "CALLVALUE",
        CALLDATALOAD => "CALLDATALOAD",
        CALLDATASIZE => "CALLDATASIZE",
        CALLDATACOPY => "CALLDATACOPY",
        CODESIZE => "CODESIZE",
        CODECOPY => "CODECOPY",
        GASPRICE => "GASPRICE",
        EXTCODESIZE => "EXTCODESIZE",
        EXTCODECOPY => "EXTCODECOPY",
        RETURNDATASIZE => "RETURNDATASIZE",
        RETURNDATACOPY => "RETURNDATACOPY",
        EXTCODEHASH => "EXTCODEHASH",
        BLOCKHASH => "BLOCKHASH",
        COINBASE => "COINBASE",
        TIMESTAMP => "TIMESTAMP",
        NUMBER => "NUMBER",
        DIFFICULTY => "DIFFICULTY",
        GASLIMIT => "GASLIMIT",
        CHAINID => "CHAINID",
        SELFBALANCE => "SELFBALANCE",
        BASEFEE => "BASEFEE",
        POP => "POP",
        MLOAD => "MLOAD",
        MSTORE => "MSTORE",
        MSTORE8 => "MSTORE8",
        SLOAD => "SLOAD",
        SSTORE => "SSTORE",
        JUMP => "JUMP",
        JUMPI => "JUMPI",
        PC => "PC",
        MSIZE => "MSIZE",
        GAS => "GAS",
        JUMPDEST => "JUMPDEST",
        PUSH0 => "PUSH0",
        PUSH1 => "PUSH1",
        PUSH2 => "PUSH2",
        PUSH3 => "PUSH3",
        PUSH4 => "PUSH4",
        PUSH5 => "PUSH5",
        PUSH6 => "PUSH6",
        PUSH7 => "PUSH7",
        PUSH8 => "PUSH8",
        PUSH9 => "PUSH9",
        PUSH10 => "PUSH10",
        PUSH11 => "PUSH11",
        PUSH12 => "PUSH12",
        PUSH13 => "PUSH13",
        PUSH14 => "PUSH14",
        PUSH15 => "PUSH15",
        PUSH16 => "PUSH16",
        PUSH17 => "PUSH17",
        PUSH18 => "PUSH18",
        PUSH19 => "PUSH19",
        PUSH20 => "PUSH20",
        PUSH21 => "PUSH21",
        PUSH22 => "PUSH22",
        PUSH23 => "PUSH23",
        PUSH24 => "PUSH24",
        PUSH25 => "PUSH25",
        PUSH26 => "PUSH26",
        PUSH27 => "PUSH27",
        PUSH28 => "PUSH28",
        PUSH29 => "PUSH29",
        PUSH30 => "PUSH30",
        PUSH31 => "PUSH31",
        PUSH32 => "PUSH32",
        DUP1 => "DUP1",
        DUP2 => "DUP2",
        DUP3 => "DUP3",
        DUP4 => "DUP4",
        DUP5 => "DUP5",
        DUP6 => "DUP6",
        DUP7 => "DUP7",
        DUP8 => "DUP8",
        DUP9 => "DUP9",
        DUP10 => "DUP10",
        DUP11 => "DUP11",
        DUP12 => "DUP12",
        DUP13 => "DUP13",
        DUP14 => "DUP14",
        DUP15 => "DUP15",
        DUP16 => "DUP16",
        SWAP1 => "SWAP1",
        SWAP2 => "SWAP2",
        SWAP3 => "SWAP3",
        SWAP4 => "SWAP4",
        SWAP5 => "SWAP5",
        SWAP6 => "SWAP6",
        SWAP7 => "SWAP7",
        SWAP8 => "SWAP8",
        SWAP9 => "SWAP9",
        SWAP10 => "SWAP10",
        SWAP11 => "SWAP11",
        SWAP12 => "SWAP12",
        SWAP13 => "SWAP13",
        SWAP14 => "SWAP14",
        SWAP15 => "SWAP15",
        SWAP16 => "SWAP16",
        LOG0 => "LOG0",
        LOG1 => "LOG1",
        LOG2 => "LOG2",
        LOG3 => "LOG3",
        LOG4 => "LOG4",
        CREATE => "CREATE",
        CALL => "CALL",
        CALLCODE => "CALLCODE",
        RETURN => "RETURN",
        DELEGATECALL => "DELEGATECALL",
        CREATE2 => "CREATE2",
        STATICCALL => "STATICCALL",
        REVERT => "REVERT",
        INVALID => "INVALID",
        SELFDESTRUCT => "SELFDESTRUCT",
        _ => "UNKNOWN",
    }
}

/// Returns true if the opcode is implemented by this VM.
///
/// Tighten this list if the interpreter does not yet implement every opcode
/// defined in this file.
pub fn is_supported_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        0x00..=0x0B
            | 0x10..=0x1D
            | 0x20
            | 0x30..=0x3F
            | 0x40..=0x48   // up to BASEFEE
            | 0x50..=0x5B
            | 0x5F..=0x7F
            | 0x80..=0x8F
            | 0x90..=0x9F
            | 0xA0..=0xA4
            | 0xF0..=0xF5
            | 0xFA
            | 0xFD..=0xFF
    )
}

/// Returns true if the opcode is recognized by this VM opcode table.
///
/// At the moment this is the same as `is_supported_opcode`. If you later add
/// partially-recognized but intentionally-unimplemented opcodes, widen this
/// function separately.
pub fn is_valid_opcode(opcode: u8) -> bool {
    is_supported_opcode(opcode)
}

// ============================================================================
// New additions: stack delta, memory expansion, opcode group
// ============================================================================

/// Category of an opcode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpcodeGroup {
    Arithmetic,
    Comparison,
    Sha3,
    Environment,
    BlockInfo,
    Memory,
    Storage,
    Stack,
    ControlFlow,
    Logging,
    Call,
    System,
}

/// Returns the group (category) of an opcode, if known.
pub fn opcode_group(opcode: u8) -> Option<OpcodeGroup> {
    match opcode {
        // Arithmetic
        ADD | MUL | SUB | DIV | SDIV | MOD | SMOD | ADDMOD | MULMOD | EXP | SIGNEXTEND =>
            Some(OpcodeGroup::Arithmetic),
        // Comparison
        LT | GT | SLT | SGT | EQ | ISZERO | AND | OR | XOR | NOT | BYTE | SHL | SHR | SAR =>
            Some(OpcodeGroup::Comparison),
        // SHA3
        SHA3 => Some(OpcodeGroup::Sha3),
        // Environment
        ADDRESS | BALANCE | ORIGIN | CALLER | CALLVALUE | CALLDATALOAD | CALLDATASIZE |
        CALLDATACOPY | CODESIZE | CODECOPY | GASPRICE | EXTCODESIZE | EXTCODECOPY |
        RETURNDATASIZE | RETURNDATACOPY | EXTCODEHASH =>
            Some(OpcodeGroup::Environment),
        // Block info
        BLOCKHASH | COINBASE | TIMESTAMP | NUMBER | DIFFICULTY | GASLIMIT | CHAINID |
        SELFBALANCE | BASEFEE =>
            Some(OpcodeGroup::BlockInfo),
        // Memory
        MLOAD | MSTORE | MSTORE8 | MSIZE =>
            Some(OpcodeGroup::Memory),
        // Storage
        SLOAD | SSTORE =>
            Some(OpcodeGroup::Storage),
        // Stack
        POP | PUSH0 | PUSH1..=PUSH32 | DUP1..=DUP16 | SWAP1..=SWAP16 =>
            Some(OpcodeGroup::Stack),
        // Control flow
        JUMP | JUMPI | JUMPDEST | PC | GAS =>
            Some(OpcodeGroup::ControlFlow),
        // Logging
        LOG0..=LOG4 =>
            Some(OpcodeGroup::Logging),
        // Call & creation
        CREATE | CREATE2 | CALL | CALLCODE | DELEGATECALL | STATICCALL =>
            Some(OpcodeGroup::Call),
        // System (return, revert, selfdestruct, invalid)
        RETURN | REVERT | STOP | INVALID | SELFDESTRUCT =>
            Some(OpcodeGroup::System),
        _ => None,
    }
}

/// Returns the number of stack elements consumed and produced by an opcode.
/// Returns None if the opcode is not recognized or has variable stack effects
/// (e.g., DUP/SWAP are handled by separate functions).
pub fn stack_delta(opcode: u8) -> Option<(usize, usize)> {
    match opcode {
        // Arithmetic (binary -> one)
        ADD | MUL | SUB | DIV | SDIV | MOD | SMOD | ADDMOD | MULMOD | EXP
        | LT | GT | SLT | SGT | EQ | AND | OR | XOR | SHL | SHR | SAR
        | BYTE | SIGNEXTEND => Some((2, 1)),

        // Unary
        NOT | ISZERO => Some((1, 1)),

        // SHA3
        SHA3 => Some((2, 1)),

        // Zero-input environment/block info
        ADDRESS | ORIGIN | CALLER | CALLVALUE | CALLDATASIZE | CODESIZE
        | GASPRICE | RETURNDATASIZE | COINBASE | TIMESTAMP | NUMBER
        | DIFFICULTY | GASLIMIT | CHAINID | SELFBALANCE | BASEFEE
        | MSIZE | GAS | PC => Some((0, 1)),

        // One-input environment/block info
        BALANCE | EXTCODESIZE | EXTCODEHASH | BLOCKHASH | CALLDATALOAD => Some((1, 1)),

        // Copy opcodes
        CALLDATACOPY | CODECOPY | RETURNDATACOPY => Some((3, 0)),
        EXTCODECOPY => Some((4, 0)),

        // Memory / storage
        MLOAD => Some((1, 1)),
        MSTORE | MSTORE8 => Some((2, 0)),
        SLOAD => Some((1, 1)),
        SSTORE => Some((2, 0)),

        // Stack
        POP => Some((1, 0)),
        PUSH0 | PUSH1..=PUSH32 => Some((0, 1)),
        DUP1..=DUP16 | SWAP1..=SWAP16 => None,

        // Control flow
        JUMP => Some((1, 0)),
        JUMPI => Some((2, 0)),
        JUMPDEST | STOP => Some((0, 0)),

        // Return / revert
        RETURN | REVERT => Some((2, 0)),

        // Logging
        LOG0 => Some((2, 0)),
        LOG1 => Some((3, 0)),
        LOG2 => Some((4, 0)),
        LOG3 => Some((5, 0)),
        LOG4 => Some((6, 0)),

        // Calls / creation
        CREATE => Some((3, 1)),
        CREATE2 => Some((4, 1)),
        CALL | CALLCODE => Some((7, 1)),
        DELEGATECALL | STATICCALL => Some((6, 1)),

        // System
        SELFDESTRUCT => Some((1, 0)),
        INVALID => Some((0, 0)),

        _ => None,
    }
}

/// Calculates the additional gas cost for expanding memory from `prev_size` to `new_size`
/// (both in bytes). The formula follows EVM: linear cost per word plus a quadratic
/// component to account for memory expansion.
pub fn memory_expansion_cost(prev_size: usize, new_size: usize) -> u64 {
    if new_size <= prev_size {
        return 0;
    }

    let prev_words = (prev_size + 31) / 32;
    let new_words = (new_size + 31) / 32;

    // Linear component: difference in words times per-word cost.
    let linear = ((new_words - prev_words) * GAS_MEMORY as usize) as u64;
    // Quadratic component: (new_words^2 - prev_words^2) / 512
    // Since (new^2 - prev^2) = (new - prev)*(new + prev), but we'll keep it simple.
    let quadratic =
        ((new_words * new_words) / 512).saturating_sub((prev_words * prev_words) / 512) as u64;

    linear + quadratic
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_sizes() {
        assert_eq!(push_data_size(PUSH0), 0);
        for i in PUSH1..=PUSH32 {
            assert_eq!(push_data_size(i), (i - PUSH1 + 1) as usize);
        }
        assert_eq!(push_data_size(ADD), 0);
        assert_eq!(push_data_size(0xFF), 0);
    }

    #[test]
    fn classification() {
        assert!(is_push(PUSH0));
        assert!(is_push(PUSH1));
        assert!(is_push(PUSH32));
        assert!(!is_push(ADD));

        assert!(is_dup(DUP1));
        assert!(is_dup(DUP16));
        assert!(!is_dup(ADD));

        assert!(is_swap(SWAP1));
        assert!(is_swap(SWAP16));
        assert!(!is_swap(ADD));

        assert!(is_log(LOG0));
        assert!(is_log(LOG4));
        assert!(!is_log(ADD));

        assert_eq!(dup_depth(DUP1), Some(1));
        assert_eq!(dup_depth(DUP16), Some(16));
        assert_eq!(dup_depth(ADD), None);

        assert_eq!(swap_depth(SWAP1), Some(1));
        assert_eq!(swap_depth(SWAP16), Some(16));
        assert_eq!(swap_depth(ADD), None);
    }

    #[test]
    fn opcode_names() {
        assert_eq!(opcode_name(STOP), "STOP");
        assert_eq!(opcode_name(ADD), "ADD");
        assert_eq!(opcode_name(PUSH32), "PUSH32");
        assert_eq!(opcode_name(BASEFEE), "BASEFEE");
        assert_eq!(opcode_name(0xFE), "INVALID");
        assert_eq!(opcode_name(0xEE), "UNKNOWN");
    }

    #[test]
    fn base_gas_costs() {
        // Some known costs
        assert_eq!(base_gas_cost(ADD), Some(GAS_VERYLOW));
        assert_eq!(base_gas_cost(MUL), Some(GAS_LOW));
        assert_eq!(base_gas_cost(SLOAD), Some(GAS_SLOAD));
        assert_eq!(base_gas_cost(EXP), None); // dynamic
        assert_eq!(base_gas_cost(BASEFEE), Some(GAS_VERYLOW));
        assert_eq!(base_gas_cost(0xEE), None);
    }

    #[test]
    fn support() {
        assert!(is_supported_opcode(ADD));
        assert!(is_supported_opcode(PUSH0));
        assert!(is_supported_opcode(BASEFEE));
        assert!(!is_supported_opcode(0xEE)); // not in our list
    }

    #[test]
    fn opcode_group_works() {
        assert_eq!(opcode_group(ADD), Some(OpcodeGroup::Arithmetic));
        assert_eq!(opcode_group(LT), Some(OpcodeGroup::Comparison));
        assert_eq!(opcode_group(SHA3), Some(OpcodeGroup::Sha3));
        assert_eq!(opcode_group(ADDRESS), Some(OpcodeGroup::Environment));
        assert_eq!(opcode_group(BLOCKHASH), Some(OpcodeGroup::BlockInfo));
        assert_eq!(opcode_group(MLOAD), Some(OpcodeGroup::Memory));
        assert_eq!(opcode_group(SLOAD), Some(OpcodeGroup::Storage));
        assert_eq!(opcode_group(PUSH1), Some(OpcodeGroup::Stack));
        assert_eq!(opcode_group(JUMP), Some(OpcodeGroup::ControlFlow));
        assert_eq!(opcode_group(LOG0), Some(OpcodeGroup::Logging));
        assert_eq!(opcode_group(CALL), Some(OpcodeGroup::Call));
        assert_eq!(opcode_group(RETURN), Some(OpcodeGroup::System));
        assert_eq!(opcode_group(0xEE), None);
    }

    #[test]
    fn stack_delta_works() {
        // Binary ops
        assert_eq!(stack_delta(ADD), Some((2, 1)));
        assert_eq!(stack_delta(BYTE), Some((2, 1)));
        assert_eq!(stack_delta(SIGNEXTEND), Some((2, 1)));
        // Unary
        assert_eq!(stack_delta(NOT), Some((1, 1)));
        assert_eq!(stack_delta(ISZERO), Some((1, 1)));
        // Zero-input
        assert_eq!(stack_delta(ADDRESS), Some((0, 1)));
        assert_eq!(stack_delta(BASEFEE), Some((0, 1)));
        // One-input environment
        assert_eq!(stack_delta(BALANCE), Some((1, 1)));
        assert_eq!(stack_delta(EXTCODESIZE), Some((1, 1)));
        // Copy
        assert_eq!(stack_delta(CALLDATACOPY), Some((3, 0)));
        assert_eq!(stack_delta(EXTCODECOPY), Some((4, 0)));
        // Memory
        assert_eq!(stack_delta(MLOAD), Some((1, 1)));
        assert_eq!(stack_delta(MSTORE), Some((2, 0)));
        assert_eq!(stack_delta(SLOAD), Some((1, 1)));
        assert_eq!(stack_delta(SSTORE), Some((2, 0)));
        // Stack
        assert_eq!(stack_delta(POP), Some((1, 0)));
        assert_eq!(stack_delta(PUSH1), Some((0, 1)));
        assert_eq!(stack_delta(DUP1), None); // handled separately
        assert_eq!(stack_delta(SWAP1), None);
        // Control flow
        assert_eq!(stack_delta(JUMP), Some((1, 0)));
        assert_eq!(stack_delta(JUMPI), Some((2, 0)));
        assert_eq!(stack_delta(JUMPDEST), Some((0, 0)));
        // Return/revert
        assert_eq!(stack_delta(RETURN), Some((2, 0)));
        // Logging
        assert_eq!(stack_delta(LOG0), Some((2, 0)));
        assert_eq!(stack_delta(LOG4), Some((6, 0)));
        // Calls
        assert_eq!(stack_delta(CREATE), Some((3, 1)));
        assert_eq!(stack_delta(CALL), Some((7, 1)));
        assert_eq!(stack_delta(DELEGATECALL), Some((6, 1)));
        // System
        assert_eq!(stack_delta(SELFDESTRUCT), Some((1, 0)));
        assert_eq!(stack_delta(INVALID), Some((0, 0)));
        // Unknown
        assert_eq!(stack_delta(0xEE), None);
    }

    #[test]
    fn memory_expansion_cost_works() {
        // No expansion
        assert_eq!(memory_expansion_cost(100, 50), 0);
        assert_eq!(memory_expansion_cost(0, 0), 0);
        // Simple cases: 1 word (32 bytes)
        let cost1 = ((1) * GAS_MEMORY as usize) as u64 + ((1*1)/512) as u64;
        assert_eq!(memory_expansion_cost(0, 32), cost1);
        // Two words
        let cost2 = ((2) * GAS_MEMORY as usize) as u64 + ((4)/512) as u64;
        assert_eq!(memory_expansion_cost(0, 64), cost2);
        // Incremental from 32 to 64
        let inc = memory_expansion_cost(32, 64);
        assert_eq!(inc, cost2 - cost1);
        // Larger numbers to check quadratic
        let cost_100 = memory_expansion_cost(0, 100);
        let cost_200 = memory_expansion_cost(0, 200);
        assert!(cost_200 > cost_100);
    }
}
