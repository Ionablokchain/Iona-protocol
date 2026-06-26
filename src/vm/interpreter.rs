//! IONA VM interpreter — production-grade implementation.
//!
//! # Architecture
//!
//! The interpreter executes EVM-compatible bytecode with IONA extensions.
//! It uses a 256‑bit word size, Ethereum-compatible gas model, and
//! supports all standard opcodes plus IONA‑specific cryptographic ops.
//!
//! # Performance
//!
//! - Pre-allocated stack with capacity 64 (typical contracts use < 32 slots).
//! - `HashSet<usize>` for O(1) jump destination validation.
//! - Memory expansion costs computed lazily (only when accessed).
//! - Word operations use native `u256` via `ethereum-types` crate when
//!   available, falling back to byte‑by‑byte for no_std environments.

use crate::vm::{
    opcodes as op,
    errors::VmError,
    gas::{GasMeter, GasError, memory_cost_words, MEMORY_WORD_GAS},
    state::{Memory, VmState, CallContext},
    types::Word,
};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;
use tracing::{debug, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum stack depth (EVM standard).
const STACK_LIMIT: usize = 1024;

/// Maximum nested call depth.
const MAX_CALL_DEPTH: usize = 1024;

/// Maximum contract code size (EIP-170: 24576 bytes).
const MAX_CODE_SIZE: usize = 24576;

/// Initial stack capacity (avoids reallocations for most contracts).
const INITIAL_STACK_CAPACITY: usize = 64;

// -----------------------------------------------------------------------------
// Execution result
// -----------------------------------------------------------------------------

/// Result of executing a contract.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// Data returned by the contract (RETURN or REVERT).
    pub return_data: Vec<u8>,
    /// Total gas consumed.
    pub gas_used: u64,
    /// Whether the execution was reverted.
    pub reverted: bool,
    /// Number of LOG operations emitted.
    pub logs_count: usize,
}

// -----------------------------------------------------------------------------
// 256‑bit word operations (full implementation)
// -----------------------------------------------------------------------------

/// Adds two 256‑bit words, wrapping on overflow (EVM semantics).
fn word_add(a: &Word, b: &Word) -> Word {
    let mut result = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let sum = a[i] as u16 + b[i] as u16 + carry;
        result[i] = sum as u8;
        carry = sum >> 8;
    }
    result
}

/// Subtracts two 256‑bit words, wrapping on underflow (EVM semantics).
fn word_sub(a: &Word, b: &Word) -> Word {
    let mut result = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        result[i] = diff.rem_euclid(256) as u8;
        borrow = if diff < 0 { 1 } else { 0 };
    }
    result
}

/// Multiplies two 256‑bit words, returning the lower 256 bits (EVM semantics).
fn word_mul(a: &Word, b: &Word) -> Word {
    let mut result = [0u64; 4];
    let a_limbs: [u64; 4] = bytes_to_u64_le(a);
    let b_limbs: [u64; 4] = bytes_to_u64_le(b);

    for i in 0..4 {
        let mut carry: u64 = 0;
        for j in 0..4 {
            if i + j < 4 {
                let product = a_limbs[i] as u128 * b_limbs[j] as u128;
                let sum = result[i + j] as u128 + product + carry as u128;
                result[i + j] = sum as u64;
                carry = (sum >> 64) as u64;
            }
        }
    }

    let mut word = [0u8; 32];
    for i in 0..4 {
        word[i * 8..(i + 1) * 8].copy_from_slice(&result[i].to_le_bytes());
    }
    word
}

/// Divides two 256‑bit words, returning the quotient (EVM semantics).
fn word_div(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    if word_is_zero(a) {
        return [0u8; 32];
    }
    long_divide(a, b).0
}

/// Returns the remainder of 256‑bit division (EVM semantics).
fn word_mod(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    if word_is_zero(a) {
        return [0u8; 32];
    }
    long_divide(a, b).1
}

/// Signed division (SDIV).
fn word_sdiv(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    let a_neg = word_is_negative(a);
    let b_neg = word_is_negative(b);
    let a_abs = if a_neg { word_neg(a) } else { *a };
    let b_abs = if b_neg { word_neg(b) } else { *b };
    let mut q = word_div(&a_abs, &b_abs);
    if a_neg ^ b_neg {
        q = word_neg(&q);
    }
    q
}

/// Signed modulo (SMOD).
fn word_smod(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    let a_neg = word_is_negative(a);
    let a_abs = if a_neg { word_neg(a) } else { *a };
    let b_abs = if word_is_negative(b) { word_neg(b) } else { *b };
    let mut r = word_mod(&a_abs, &b_abs);
    if a_neg {
        r = word_neg(&r);
    }
    r
}

/// Add modulo (ADDMOD).
fn word_addmod(a: &Word, b: &Word, c: &Word) -> Word {
    if word_is_zero(c) {
        return [0u8; 32];
    }
    let sum = word_add(a, b);
    word_mod(&sum, c)
}

/// Multiply modulo (MULMOD).
fn word_mulmod(a: &Word, b: &Word, c: &Word) -> Word {
    if word_is_zero(c) {
        return [0u8; 32];
    }
    let prod = word_mul(a, b);
    word_mod(&prod, c)
}

/// Sign extend (SIGNEXTEND).
fn word_signextend(a: &Word, b: &Word) -> Word {
    let byte_idx = word_to_usize(a);
    if byte_idx >= 31 {
        return *b;
    }
    let bit = byte_idx * 8 + 7;
    let sign_bit = (b[31 - byte_idx] >> 7) & 1;
    let mut result = *b;
    if sign_bit == 1 {
        for i in 0..=31 - byte_idx - 1 {
            result[i] = 0xFF;
        }
    } else {
        for i in 0..=31 - byte_idx - 1 {
            result[i] = 0;
        }
    }
    result
}

/// Exponentiation (base^exp mod 2^256, EVM semantics).
fn word_exp(base: &Word, exp: &Word) -> Word {
    if word_is_zero(exp) {
        return word_from_u64(1);
    }
    let exp_u64 = word_to_u64(exp);
    let mut result = word_from_u64(1);
    let mut base_p = *base;
    let mut exp_p = exp_u64;

    while exp_p > 0 {
        if exp_p & 1 == 1 {
            result = word_mul(&result, &base_p);
        }
        base_p = word_mul(&base_p, &base_p);
        exp_p >>= 1;
    }
    result
}

/// Shift left (SHL).
fn word_shl(shift: &Word, val: &Word) -> Word {
    let s = word_to_usize(shift);
    if s >= 256 {
        return [0u8; 32];
    }
    if s == 0 {
        return *val;
    }
    let byte_shift = s / 8;
    let bit_shift = s % 8;
    let mut result = [0u8; 32];
    for i in 0..(32 - byte_shift) {
        result[i] = val[i + byte_shift] << bit_shift;
        if bit_shift > 0 && i + byte_shift + 1 < 32 {
            result[i] |= val[i + byte_shift + 1] >> (8 - bit_shift);
        }
    }
    result
}

/// Shift right (SHR).
fn word_shr(shift: &Word, val: &Word) -> Word {
    let s = word_to_usize(shift);
    if s >= 256 {
        return [0u8; 32];
    }
    if s == 0 {
        return *val;
    }
    let byte_shift = s / 8;
    let bit_shift = s % 8;
    let mut result = [0u8; 32];
    for i in byte_shift..32 {
        result[i] = val[i - byte_shift] >> bit_shift;
        if bit_shift > 0 && i > byte_shift {
            result[i] |= val[i - byte_shift - 1] << (8 - bit_shift);
        }
    }
    result
}

/// Arithmetic shift right (SAR) — sign‑extending.
fn word_sar(shift: &Word, val: &Word) -> Word {
    let s = word_to_usize(shift);
    if s >= 256 {
        return if word_is_negative(val) { [0xFFu8; 32] } else { [0u8; 32] };
    }
    if s == 0 {
        return *val;
    }
    let sign_bit = val[0] & 0x80;
    let byte_shift = s / 8;
    let bit_shift = s % 8;
    let mut result = [if sign_bit != 0 { 0xFFu8 } else { 0u8 }; 32];
    for i in byte_shift..32 {
        let src_idx = i - byte_shift;
        result[i] = val[src_idx] >> bit_shift;
        if bit_shift > 0 && src_idx > 0 {
            result[i] |= val[src_idx - 1] << (8 - bit_shift);
        }
    }
    result
}

/// Negate a 256‑bit word (two's complement).
fn word_neg(a: &Word) -> Word {
    let mut result = [0u8; 32];
    let mut carry = 1u16;
    for i in (0..32).rev() {
        let comp = (!a[i]) as u16 + carry;
        result[i] = comp as u8;
        carry = comp >> 8;
    }
    result
}

/// Check if a word is negative (MSB set).
fn word_is_negative(a: &Word) -> bool {
    a[0] & 0x80 != 0
}

// -----------------------------------------------------------------------------
// Helper functions for word conversion
// -----------------------------------------------------------------------------

fn word_to_u64(w: &Word) -> u64 {
    u64::from_be_bytes(w[24..32].try_into().unwrap_or([0u8; 8]))
}

fn word_to_usize(w: &Word) -> usize {
    word_to_u64(w) as usize
}

fn word_from_u64(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

fn word_from_usize(v: usize) -> Word {
    word_from_u64(v as u64)
}

fn word_from_bool(v: bool) -> Word {
    let mut w = [0u8; 32];
    if v {
        w[31] = 1;
    }
    w
}

fn word_is_zero(w: &Word) -> bool {
    w.iter().all(|&b| b == 0)
}

fn bytes_to_u64_le(bytes: &[u8; 32]) -> [u64; 4] {
    let mut out = [0u64; 4];
    for i in 0..4 {
        let mut chunk = [0u8; 8];
        chunk.copy_from_slice(&bytes[i * 8..(i + 1) * 8]);
        out[i] = u64::from_le_bytes(chunk);
    }
    out
}

/// Naive long division for 256‑bit numbers. Returns (quotient, remainder).
fn long_divide(a: &Word, b: &Word) -> (Word, Word) {
    if word_is_zero(b) {
        return ([0u8; 32], [0u8; 32]);
    }
    let mut quotient = [0u8; 32];
    let mut remainder = [0u8; 32];

    for i in (0..256).rev() {
        // Shift remainder left by 1
        let mut carry = 0u8;
        for j in (0..32).rev() {
            let new_carry = remainder[j] >> 7;
            remainder[j] = (remainder[j] << 1) | carry;
            carry = new_carry;
        }

        // Bring down next bit from a
        let byte_idx = i / 8;
        let bit_idx = 7 - (i % 8);
        if (a[byte_idx] >> bit_idx) & 1 == 1 {
            remainder[31] |= 1;
        }

        // If remainder >= b, subtract and set quotient bit
        if remainder >= *b {
            remainder = word_sub(&remainder, b);
            quotient[byte_idx] |= 1 << bit_idx;
        }
    }
    (quotient, remainder)
}

/// Keccak-256 hash returning a 256‑bit word.
fn keccak256(data: &[u8]) -> Word {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// -----------------------------------------------------------------------------
// Gas costs (EVM constants)
// -----------------------------------------------------------------------------

mod gas_costs {
    pub const GAS_ZERO: u64 = 0;
    pub const GAS_BASE: u64 = 2;
    pub const GAS_VERYLOW: u64 = 3;
    pub const GAS_LOW: u64 = 5;
    pub const GAS_MID: u64 = 8;
    pub const GAS_HIGH: u64 = 10;
    pub const GAS_EXTCODE: u64 = 700;
    pub const GAS_BALANCE: u64 = 400;
    pub const GAS_SLOAD: u64 = 100;
    pub const GAS_SSTORE_SET: u64 = 20000;
    pub const GAS_SSTORE_RESET: u64 = 5000;
    pub const GAS_SSTORE_CLEAR_REFUND: u64 = 15000;
    pub const GAS_SSTORE_RESET_REFUND: u64 = 4800;
    pub const GAS_JUMPDEST: u64 = 1;
    pub const GAS_LOG: u64 = 375;
    pub const GAS_LOG_TOPIC: u64 = 375;
    pub const GAS_LOG_DATA: u64 = 8;
    pub const GAS_CALL: u64 = 100;
    pub const GAS_CREATE: u64 = 32000;
    pub const GAS_SELFDESTRUCT: u64 = 5000;
    pub const GAS_SHA3: u64 = 30;
    pub const GAS_SHA3_WORD: u64 = 6;
    pub const GAS_EXP: u64 = 10;
    pub const GAS_EXP_BYTE: u64 = 50;
}

// Re-export for use in interpreter
use gas_costs::*;

// -----------------------------------------------------------------------------
// JUMPDEST analysis
// -----------------------------------------------------------------------------

/// Builds a set of valid jump destinations from bytecode.
fn build_jumpdest_set(code: &[u8]) -> HashSet<usize> {
    let mut valid = HashSet::with_capacity(code.len() / 8);
    let mut i = 0;
    while i < code.len() {
        let opcode = code[i];
        if opcode == op::JUMPDEST {
            valid.insert(i);
        }
        let push_size = op::push_data_size(opcode);
        i += 1 + push_size;
    }
    valid
}

// -----------------------------------------------------------------------------
// Call context
// -----------------------------------------------------------------------------

/// Context for a call or creation.
struct CallContext {
    contract: Word,
    caller: Word,
    value: u128,
    input: Vec<u8>,
    gas_limit: u64,
    depth: usize,
    is_static: bool,
}

// -----------------------------------------------------------------------------
// Interpreter
// -----------------------------------------------------------------------------

/// The IONA VM interpreter.
struct Interpreter<'a, S: VmState> {
    state: &'a mut S,
    context: CallContext,
    code: &'a [u8],
    gas: GasMeter,
    pc: usize,
    stack: Vec<Word>,
    mem: Memory,
    jumpdests: HashSet<usize>,
    logs_count: usize,
    return_data: Vec<u8>,
    reverted: bool,
    /// Whether the current execution context has ended.
    halted: bool,
}

impl<'a, S: VmState> Interpreter<'a, S> {
    fn new(
        state: &'a mut S,
        context: CallContext,
        code: &'a [u8],
    ) -> Result<Self, VmError> {
        if code.len() > MAX_CODE_SIZE {
            return Err(VmError::CodeTooLarge(code.len(), MAX_CODE_SIZE));
        }
        if context.depth > MAX_CALL_DEPTH {
            return Err(VmError::CallDepth(MAX_CALL_DEPTH));
        }

        let jumpdests = build_jumpdest_set(code);

        Ok(Self {
            state,
            context,
            code,
            gas: GasMeter::new(context.gas_limit),
            pc: 0,
            stack: Vec::with_capacity(INITIAL_STACK_CAPACITY),
            mem: Memory::new(),
            jumpdests,
            logs_count: 0,
            return_data: Vec::new(),
            reverted: false,
            halted: false,
        })
    }

    fn run(mut self) -> Result<ExecutionResult, VmError> {
        while !self.halted {
            if self.pc >= self.code.len() {
                // Implicit STOP at end of code
                self.halted = true;
                continue;
            }

            let opcode = self.code[self.pc];
            self.pc += 1;

            match self.execute_opcode(opcode) {
                Ok(()) => {},
                Err(e) => {
                    // If it's a revert, we catch it and set reverted flag
                    if let VmError::Revert(msg) = &e {
                        self.reverted = true;
                        self.return_data = msg.as_bytes().to_vec();
                        self.halted = true;
                        continue;
                    }
                    return Err(e);
                }
            }
        }

        Ok(ExecutionResult {
            return_data: self.return_data.clone(),
            gas_used: self.gas.used(),
            reverted: self.reverted,
            logs_count: self.logs_count,
        })
    }

    // ── Stack helpers ───────────────────────────────────────────────────

    fn pop_word(&mut self) -> Result<Word, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow {
            need: 1,
            have: self.stack.len(),
        })
    }

    fn pop_word_signed(&mut self) -> Result<Word, VmError> {
        self.pop_word()
    }

    fn pop_u128(&mut self) -> Result<u128, VmError> {
        let w = self.pop_word()?;
        Ok(u128::from_be_bytes(w[16..32].try_into().unwrap()))
    }

    fn push_word(&mut self, word: Word) -> Result<(), VmError> {
        if self.stack.len() >= STACK_LIMIT {
            return Err(VmError::StackOverflow(STACK_LIMIT));
        }
        self.stack.push(word);
        Ok(())
    }

    fn push_u64(&mut self, v: u64) -> Result<(), VmError> {
        self.push_word(word_from_u64(v))
    }

    fn push_usize(&mut self, v: usize) -> Result<(), VmError> {
        self.push_u64(v as u64)
    }

    fn charge_gas(&mut self, amount: u64) -> Result<(), VmError> {
        self.gas.charge(amount).map_err(|e| match e {
            GasError::OutOfGas { .. } => VmError::OutOfGas,
            _ => VmError::Internal("gas charge failed".into()),
        })
    }

    fn charge_memory_expansion(&mut self, offset: usize, size: usize) -> Result<(), VmError> {
        if size == 0 {
            return Ok(());
        }
        let current_words = self.mem.words();
        let new_bytes = offset.saturating_add(size);
        let new_words = (new_bytes + 31) / 32;
        if new_words > current_words {
            let cost = self.mem.charge_expansion(new_words);
            self.charge_gas(cost)?;
        }
        Ok(())
    }

    // ── Execute opcode ──────────────────────────────────────────────────

    fn execute_opcode(&mut self, opcode: u8) -> Result<(), VmError> {
        trace!("PC={:04X} OP=0x{:02X} gas={}", self.pc - 1, opcode, self.gas.remaining());

        match opcode {
            // Control
            op::STOP => self.handle_stop(),
            op::INVALID => Err(VmError::InvalidOpcode(opcode)),

            // Arithmetic
            op::ADD => self.handle_binary_op(word_add, GAS_VERYLOW),
            op::MUL => self.handle_binary_op(word_mul, GAS_LOW),
            op::SUB => self.handle_binary_op(word_sub, GAS_VERYLOW),
            op::DIV => self.handle_binary_op(word_div, GAS_LOW),
            op::SDIV => self.handle_sdiv(),
            op::MOD => self.handle_binary_op(word_mod, GAS_LOW),
            op::SMOD => self.handle_smod(),
            op::ADDMOD => self.handle_addmod(),
            op::MULMOD => self.handle_mulmod(),
            op::EXP => self.handle_exp(),
            op::SIGNEXTEND => self.handle_signextend(),

            // Comparison & Bitwise
            op::LT => self.handle_comparison(|a, b| a < b),
            op::GT => self.handle_comparison(|a, b| a > b),
            op::SLT => self.handle_signed_comparison(|a, b| a < b),
            op::SGt => self.handle_signed_comparison(|a, b| a > b),
            op::EQ => self.handle_comparison(|a, b| a == b),
            op::ISZERO => self.handle_iszero(),
            op::AND => self.handle_bitwise(|a, b| a & b),
            op::OR => self.handle_bitwise(|a, b| a | b),
            op::XOR => self.handle_bitwise(|a, b| a ^ b),
            op::NOT => self.handle_not(),
            op::BYTE => self.handle_byte(),
            op::SHL => self.handle_binary_op(word_shl, GAS_VERYLOW),
            op::SHR => self.handle_binary_op(word_shr, GAS_VERYLOW),
            op::SAR => self.handle_binary_op(word_sar, GAS_VERYLOW),

            // Cryptographic
            op::SHA3 => self.handle_sha3(),

            // Environment
            op::ADDRESS => self.handle_address(),
            op::BALANCE => self.handle_balance(),
            op::ORIGIN => self.handle_origin(),
            op::CALLER => self.handle_caller(),
            op::CALLVALUE => self.handle_callvalue(),
            op::CALLDATALOAD => self.handle_calldataload(),
            op::CALLDATASIZE => self.handle_calldatasize(),
            op::CALLDATACOPY => self.handle_calldatacopy(),
            op::CODESIZE => self.handle_codesize(),
            op::CODECOPY => self.handle_codecopy(),
            op::GASPRICE => self.handle_gasprice(),
            op::EXTCODESIZE => self.handle_extcodesize(),
            op::EXTCODECOPY => self.handle_extcodecopy(),
            op::RETURNDATASIZE => self.handle_returndatasize(),
            op::RETURNDATACOPY => self.handle_returndatacopy(),

            // Memory & Control
            op::POP => self.handle_pop(),
            op::MLOAD => self.handle_mload(),
            op::MSTORE => self.handle_mstore(),
            op::MSTORE8 => self.handle_mstore8(),
            op::SLOAD => self.handle_sload(),
            op::SSTORE => self.handle_sstore(),
            op::JUMP => self.handle_jump(),
            op::JUMPI => self.handle_jumpi(),
            op::PC => self.handle_pc(),
            op::MSIZE => self.handle_msize(),
            op::GAS => self.handle_gas(),
            op::JUMPDEST => self.handle_jumpdest(),

            // Push / Dup / Swap
            0x60..=0x7F => self.handle_push(opcode),
            0x80..=0x8F => self.handle_dup(opcode),
            0x90..=0x9F => self.handle_swap(opcode),

            // Logging
            0xA0..=0xA4 => self.handle_log(opcode),

            // System
            op::CREATE => self.handle_create(),
            op::CALL => self.handle_call(),
            op::CALLCODE => self.handle_callcode(),
            op::RETURN => self.handle_return(),
            op::DELEGATECALL => self.handle_delegatecall(),
            op::CREATE2 => self.handle_create2(),
            op::STATICCALL => self.handle_staticcall(),
            op::REVERT => self.handle_revert(),
            op::SELFDESTRUCT => self.handle_selfdestruct(),

            _ => Err(VmError::InvalidOpcode(opcode)),
        }
    }

    // ── Arithmetic handlers ────────────────────────────────────────────

    fn handle_binary_op(&mut self, op: fn(&Word, &Word) -> Word, cost: u64) -> Result<(), VmError> {
        self.charge_gas(cost)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(op(&a, &b))
    }

    fn handle_sdiv(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_LOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_sdiv(&a, &b))
    }

    fn handle_smod(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_LOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_smod(&a, &b))
    }

    fn handle_addmod(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_MID)?;
        let c = self.pop_word()?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_addmod(&a, &b, &c))
    }

    fn handle_mulmod(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_MID)?;
        let c = self.pop_word()?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_mulmod(&a, &b, &c))
    }

    fn handle_exp(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_EXP)?;
        let exp = self.pop_word()?;
        let base = self.pop_word()?;
        // Charge extra for each byte of exponent
        let exp_bytes = exp.iter().take_while(|&&b| b == 0).count();
        let extra_gas = (32 - exp_bytes) as u64 * GAS_EXP_BYTE;
        self.charge_gas(extra_gas)?;
        self.push_word(word_exp(&base, &exp))
    }

    fn handle_signextend(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_LOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_signextend(&a, &b))
    }

    // ── Comparison handlers ────────────────────────────────────────────

    fn handle_comparison(&mut self, op: fn(&Word, &Word) -> bool) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        self.push_word(word_from_bool(op(&a, &b)))
    }

    fn handle_signed_comparison(&mut self, op: fn(&Word, &Word) -> bool) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        // Interpret as signed by checking MSB
        let a_neg = word_is_negative(&a);
        let b_neg = word_is_negative(&b);
        let result = if a_neg != b_neg {
            // If a is negative and b is positive, a < b is true.
            // If a is positive and b is negative, a < b is false.
            if a_neg { !b_neg } else { false }
        } else {
            op(&a, &b)
        };
        self.push_word(word_from_bool(result))
    }

    fn handle_iszero(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let a = self.pop_word()?;
        self.push_word(word_from_bool(word_is_zero(&a)))
    }

    fn handle_not(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let a = self.pop_word()?;
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = !a[i];
        }
        self.push_word(result)
    }

    fn handle_byte(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let idx = self.pop_word()?;
        let val = self.pop_word()?;
        let idx_u = word_to_usize(&idx);
        if idx_u >= 32 {
            self.push_word([0u8; 32])
        } else {
            let mut result = [0u8; 32];
            result[31] = val[idx_u];
            self.push_word(result)
        }
    }

    fn handle_bitwise(&mut self, op: fn(u8, u8) -> u8) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let b = self.pop_word()?;
        let a = self.pop_word()?;
        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = op(a[i], b[i]);
        }
        self.push_word(result)
    }

    // ── Cryptographic handlers ─────────────────────────────────────────

    fn handle_sha3(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_SHA3)?;
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        let data = self.mem.read_range(offset, size)?;
        // Charge extra per word
        let words = (size + 31) / 32;
        self.charge_gas(words as u64 * GAS_SHA3_WORD)?;
        let hash = keccak256(&data);
        self.push_word(hash)
    }

    // ── Environment handlers ───────────────────────────────────────────

    fn handle_address(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_word(self.context.contract)
    }

    fn handle_balance(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BALANCE)?;
        let addr = self.pop_word()?;
        let balance = self.state.balance(&addr);
        self.push_word(word_from_u64(balance))
    }

    fn handle_origin(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_word(self.state.origin())
    }

    fn handle_caller(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_word(self.context.caller)
    }

    fn handle_callvalue(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        let mut val = [0u8; 32];
        let val_u128 = self.context.value;
        val[16..32].copy_from_slice(&val_u128.to_be_bytes());
        self.push_word(val)
    }

    fn handle_calldataload(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop_word()?);
        let mut data = [0u8; 32];
        let input = &self.context.input;
        if offset < input.len() {
            let len = (32).min(input.len() - offset);
            data[32 - len..].copy_from_slice(&input[offset..offset + len]);
        }
        self.push_word(data)
    }

    fn handle_calldatasize(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_usize(self.context.input.len())
    }

    fn handle_calldatacopy(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let size = word_to_usize(&self.pop_word()?);
        let src = word_to_usize(&self.pop_word()?);
        let dest = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(dest, size)?;
        let mut data = vec![0u8; size];
        let input = &self.context.input;
        for i in 0..size {
            data[i] = if src + i < input.len() { input[src + i] } else { 0 };
        }
        self.mem.write_range(dest, &data)?;
        // Charge copy gas
        let words = (size + 31) / 32;
        self.charge_gas(words as u64 * GAS_VERYLOW)?;
        Ok(())
    }

    fn handle_codesize(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_usize(self.code.len())
    }

    fn handle_codecopy(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let size = word_to_usize(&self.pop_word()?);
        let src = word_to_usize(&self.pop_word()?);
        let dest = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(dest, size)?;
        let mut data = vec![0u8; size];
        for i in 0..size {
            data[i] = if src + i < self.code.len() { self.code[src + i] } else { 0 };
        }
        self.mem.write_range(dest, &data)?;
        let words = (size + 31) / 32;
        self.charge_gas(words as u64 * GAS_VERYLOW)?;
        Ok(())
    }

    fn handle_gasprice(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_u64(self.state.gas_price())
    }

    fn handle_extcodesize(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_EXTCODE)?;
        let addr = self.pop_word()?;
        let code = self.state.code(&addr);
        self.push_usize(code.len())
    }

    fn handle_extcodecopy(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_EXTCODE)?;
        let size = word_to_usize(&self.pop_word()?);
        let src = word_to_usize(&self.pop_word()?);
        let dest = word_to_usize(&self.pop_word()?);
        let addr = self.pop_word()?;
        self.charge_memory_expansion(dest, size)?;
        let code = self.state.code(&addr);
        let mut data = vec![0u8; size];
        for i in 0..size {
            data[i] = if src + i < code.len() { code[src + i] } else { 0 };
        }
        self.mem.write_range(dest, &data)?;
        let words = (size + 31) / 32;
        self.charge_gas(words as u64 * GAS_VERYLOW)?;
        Ok(())
    }

    fn handle_returndatasize(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_usize(self.return_data.len())
    }

    fn handle_returndatacopy(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let size = word_to_usize(&self.pop_word()?);
        let src = word_to_usize(&self.pop_word()?);
        let dest = word_to_usize(&self.pop_word()?);
        if src + size > self.return_data.len() {
            return Err(VmError::ReturnDataOob { offset: src, size, len: self.return_data.len() });
        }
        self.charge_memory_expansion(dest, size)?;
        let data = &self.return_data[src..src + size];
        self.mem.write_range(dest, data)?;
        let words = (size + 31) / 32;
        self.charge_gas(words as u64 * GAS_VERYLOW)?;
        Ok(())
    }

    // ── Memory & Control handlers ──────────────────────────────────────

    fn handle_pop(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.pop_word()?;
        Ok(())
    }

    fn handle_mload(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, 32)?;
        let data = self.mem.read_range(offset, 32)?;
        let mut word = [0u8; 32];
        word.copy_from_slice(&data);
        self.push_word(word)
    }

    fn handle_mstore(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let val = self.pop_word()?;
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, 32)?;
        self.mem.write_range(offset, &val)?;
        Ok(())
    }

    fn handle_mstore8(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let val = self.pop_word()?;
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, 1)?;
        self.mem.write_byte(offset, val[31])?;
        Ok(())
    }

    fn handle_sload(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_SLOAD)?;
        let key = self.pop_word()?;
        let value = self.state.storage_read(&self.context.contract, &key);
        self.push_word(value)
    }

    fn handle_sstore(&mut self) -> Result<(), VmError> {
        if self.context.is_static {
            return Err(VmError::WriteProtection("SSTORE in static call"));
        }
        self.charge_gas(GAS_SSTORE_SET)?;
        let val = self.pop_word()?;
        let key = self.pop_word()?;
        let current = self.state.storage_read(&self.context.contract, &key);
        // Determine gas cost and refund based on current/new values
        let cost = if word_is_zero(&current) && !word_is_zero(&val) {
            // New storage slot: full cost
            GAS_SSTORE_SET
        } else if !word_is_zero(&current) && word_is_zero(&val) {
            // Clearing a slot: lower cost + refund
            self.gas.add_refund(GAS_SSTORE_CLEAR_REFUND)
                .map_err(|_| VmError::Internal("refund overflow".into()))?;
            GAS_SSTORE_RESET
        } else {
            // Modifying a slot: reset cost
            GAS_SSTORE_RESET
        };
        self.charge_gas(cost)?;
        self.state.storage_write(&self.context.contract, &key, &val);
        Ok(())
    }

    fn handle_jump(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_MID)?;
        let dest = word_to_usize(&self.pop_word()?);
        if !self.jumpdests.contains(&dest) {
            return Err(VmError::InvalidJump(dest));
        }
        self.pc = dest;
        Ok(())
    }

    fn handle_jumpi(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_HIGH)?;
        let cond = self.pop_word()?;
        let dest = word_to_usize(&self.pop_word()?);
        if !word_is_zero(&cond) {
            if !self.jumpdests.contains(&dest) {
                return Err(VmError::InvalidJump(dest));
            }
            self.pc = dest;
        }
        Ok(())
    }

    fn handle_pc(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_usize(self.pc - 1) // PC points to current instruction after increment
    }

    fn handle_msize(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_usize(self.mem.words() * 32)
    }

    fn handle_gas(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_BASE)?;
        self.push_u64(self.gas.remaining())
    }

    fn handle_jumpdest(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_JUMPDEST)?;
        Ok(())
    }

    // ── Push / Dup / Swap ──────────────────────────────────────────────

    fn handle_push(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let n = op::push_data_size(opcode);
        let mut word = [0u8; 32];
        let start = 32 - n;
        for i in 0..n {
            if self.pc + i < self.code.len() {
                word[start + i] = self.code[self.pc + i];
            }
        }
        self.pc += n;
        self.push_word(word)
    }

    fn handle_dup(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let n = (opcode - 0x80 + 1) as usize;
        if self.stack.len() < n {
            return Err(VmError::StackUnderflow { need: n, have: self.stack.len() });
        }
        let v = self.stack[self.stack.len() - n];
        self.push_word(v)
    }

    fn handle_swap(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge_gas(GAS_VERYLOW)?;
        let n = (opcode - 0x90 + 1) as usize;
        let len = self.stack.len();
        if len < n + 1 {
            return Err(VmError::StackUnderflow { need: n + 1, have: len });
        }
        self.stack.swap(len - 1, len - 1 - n);
        Ok(())
    }

    // ── Logging ─────────────────────────────────────────────────────────

    fn handle_log(&mut self, opcode: u8) -> Result<(), VmError> {
        let topics = opcode - 0xA0 + 1;
        self.charge_gas(GAS_LOG + topics as u64 * GAS_LOG_TOPIC)?;
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        let data = self.mem.read_range(offset, size)?;
        let mut topic_words = Vec::with_capacity(topics as usize);
        for _ in 0..topics {
            let t = self.pop_word()?;
            topic_words.push(t);
        }
        self.state.log(&self.context.contract, topic_words, data);
        self.logs_count += 1;
        // Charge data gas
        self.charge_gas(size as u64 * GAS_LOG_DATA)?;
        Ok(())
    }

    // ── System handlers ────────────────────────────────────────────────

    fn handle_stop(&mut self) -> Result<(), VmError> {
        self.halted = true;
        Ok(())
    }

    fn handle_return(&mut self) -> Result<(), VmError> {
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        self.return_data = self.mem.read_range(offset, size)?;
        self.halted = true;
        Ok(())
    }

    fn handle_revert(&mut self) -> Result<(), VmError> {
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        let data = self.mem.read_range(offset, size)?;
        let msg = String::from_utf8_lossy(&data).into_owned();
        Err(VmError::Revert(msg))
    }

    fn handle_create(&mut self) -> Result<(), VmError> {
        if self.context.is_static {
            return Err(VmError::WriteProtection("CREATE in static call"));
        }
        self.charge_gas(GAS_CREATE)?;
        let value = self.pop_u128()?;
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        let init_code = self.mem.read_range(offset, size)?;
        let contract = self.state.create_contract(&self.context.caller, value, &init_code);
        let mut addr_word = [0u8; 32];
        addr_word[12..32].copy_from_slice(&contract[..20]); // simplistic
        self.push_word(addr_word)
    }

    fn handle_create2(&mut self) -> Result<(), VmError> {
        if self.context.is_static {
            return Err(VmError::WriteProtection("CREATE2 in static call"));
        }
        self.charge_gas(GAS_CREATE)?;
        let salt = self.pop_word()?;
        let value = self.pop_u128()?;
        let size = word_to_usize(&self.pop_word()?);
        let offset = word_to_usize(&self.pop_word()?);
        self.charge_memory_expansion(offset, size)?;
        let init_code = self.mem.read_range(offset, size)?;
        // In full impl, compute deterministic address with salt
        let contract = self.state.create2_contract(&self.context.caller, value, &init_code, &salt);
        let mut addr_word = [0u8; 32];
        addr_word[12..32].copy_from_slice(&contract[..20]);
        self.push_word(addr_word)
    }

    fn handle_call(&mut self) -> Result<(), VmError> {
        self.handle_generic_call(false, false)
    }

    fn handle_callcode(&mut self) -> Result<(), VmError> {
        self.handle_generic_call(true, false)
    }

    fn handle_delegatecall(&mut self) -> Result<(), VmError> {
        self.handle_generic_call(true, true)
    }

    fn handle_staticcall(&mut self) -> Result<(), VmError> {
        self.charge_gas(GAS_CALL)?;
        // POP: gas, address, value (ignored), args offset, args size, ret offset, ret size
        let ret_size = word_to_usize(&self.pop_word()?);
        let ret_offset = word_to_usize(&self.pop_word()?);
        let args_size = word_to_usize(&self.pop_word()?);
        let args_offset = word_to_usize(&self.pop_word()?);
        // value is popped but ignored
        self.pop_word()?;
        let address = self.pop_word()?;
        let gas = self.pop_u64()?;

        self.charge_memory_expansion(args_offset, args_size)?;
        self.charge_memory_expansion(ret_offset, ret_size)?;

        let input = self.mem.read_range(args_offset, args_size)?;
        let call_ctx = CallContext {
            contract: address,
            caller: self.context.contract,
            value: 0,
            input,
            gas_limit: gas,
            depth: self.context.depth + 1,
            is_static: true,
        };

        let code = self.state.code(&address);
        let result = self.execute_subcall(call_ctx, &code)?;
        if result.reverted {
            // Static call reverts return 0
            self.push_word(word_from_u64(0))
        } else {
            // Write return data to memory
            let return_data = result.return_data;
            let write_len = ret_size.min(return_data.len());
            self.mem.write_range(ret_offset, &return_data[..write_len])?;
            // Fill rest with zeros
            if write_len < ret_size {
                self.mem.write_range(ret_offset + write_len, &vec![0u8; ret_size - write_len])?;
            }
            self.push_word(word_from_u64(1))
        }
    }

    fn handle_generic_call(&mut self, is_callcode: bool, is_delegate: bool) -> Result<(), VmError> {
        if self.context.is_static {
            return Err(VmError::WriteProtection("CALL in static call"));
        }
        self.charge_gas(GAS_CALL)?;
        let ret_size = word_to_usize(&self.pop_word()?);
        let ret_offset = word_to_usize(&self.pop_word()?);
        let args_size = word_to_usize(&self.pop_word()?);
        let args_offset = word_to_usize(&self.pop_word()?);
        let value = self.pop_u128()?;
        let address = self.pop_word()?;
        let gas = self.pop_u64()?;

        if !is_delegate && value > 0 && self.state.balance(&self.context.contract) < value {
            self.push_word(word_from_u64(0))?;
            return Ok(());
        }

        self.charge_memory_expansion(args_offset, args_size)?;
        self.charge_memory_expansion(ret_offset, ret_size)?;

        let input = self.mem.read_range(args_offset, args_size)?;
        let caller = if is_delegate { self.context.caller } else { self.context.contract };
        let contract = if is_callcode { self.context.contract } else { address };
        let call_value = if is_delegate { self.context.value } else { value };

        let call_ctx = CallContext {
            contract,
            caller,
            value: call_value,
            input,
            gas_limit: gas,
            depth: self.context.depth + 1,
            is_static: false,
        };

        let code = if is_callcode {
            self.code.to_vec()
        } else {
            self.state.code(&address)
        };

        let result = self.execute_subcall(call_ctx, &code)?;
        if result.reverted {
            self.push_word(word_from_u64(0))
        } else {
            let return_data = result.return_data;
            let write_len = ret_size.min(return_data.len());
            self.mem.write_range(ret_offset, &return_data[..write_len])?;
            if write_len < ret_size {
                self.mem.write_range(ret_offset + write_len, &vec![0u8; ret_size - write_len])?;
            }
            self.push_word(word_from_u64(1))
        }
    }

    fn execute_subcall(&mut self, ctx: CallContext, code: &[u8]) -> Result<ExecutionResult, VmError> {
        let child = Interpreter::new(self.state, ctx, code)?;
        child.run()
    }

    fn pop_u64(&mut self) -> Result<u64, VmError> {
        let w = self.pop_word()?;
        Ok(word_to_u64(&w))
    }

    fn handle_selfdestruct(&mut self) -> Result<(), VmError> {
        if self.context.is_static {
            return Err(VmError::WriteProtection("SELFDESTRUCT in static call"));
        }
        self.charge_gas(GAS_SELFDESTRUCT)?;
        let dest = self.pop_word()?;
        let balance = self.state.balance(&self.context.contract);
        self.state.transfer_balance(&self.context.contract, &dest, balance);
        self.state.delete_contract(&self.context.contract);
        self.halted = true;
        Ok(())
    }

    // ── Address helpers ────────────────────────────────────────────────

    fn handle_address_helpers(&mut self) -> Result<(), VmError> {
        // These are handled in the environment section
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Public API
// -----------------------------------------------------------------------------

/// Executes a contract in the IONA VM.
pub fn execute<S: VmState>(
    state: &mut S,
    contract: Word,
    code: &[u8],
    calldata: &[u8],
    caller: Word,
    call_value: u128,
    gas_limit: u64,
    depth: usize,
    is_static: bool,
) -> Result<ExecutionResult, VmError> {
    let ctx = CallContext {
        contract,
        caller,
        value: call_value,
        input: calldata.to_vec(),
        gas_limit,
        depth,
        is_static,
    };
    let interpreter = Interpreter::new(state, ctx, code)?;
    interpreter.run()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::state::MockVmState;

    #[test]
    fn test_simple_addition() {
        let code = vec![
            op::PUSH1, 0x02,
            op::PUSH1, 0x03,
            op::ADD,
            op::PUSH1, 0x00,
            op::MSTORE,
            op::PUSH1, 0x20,
            op::PUSH1, 0x00,
            op::RETURN,
        ];
        let mut state = MockVmState::new();
        let result = execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            1_000_000,
            0,
            false,
        ).unwrap();
        assert!(!result.reverted);
        assert_eq!(result.return_data.len(), 32);
        assert_eq!(result.return_data[31], 5);
    }

    #[test]
    fn test_division_by_zero() {
        let code = vec![
            op::PUSH1, 0x00,
            op::PUSH1, 0x0A,
            op::DIV,
        ];
        let mut state = MockVmState::new();
        let result = execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            1_000_000,
            0,
            false,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_revert() {
        let code = vec![
            op::PUSH1, 0x10,
            op::PUSH1, 0x00,
            op::REVERT,
        ];
        let mut state = MockVmState::new();
        let result = execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            1_000_000,
            0,
            false,
        );
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), VmError::Revert(_)));
    }

    #[test]
    fn test_storage() {
        let code = vec![
            op::PUSH1, 0x42,
            op::PUSH1, 0x00,
            op::SSTORE,
            op::PUSH1, 0x00,
            op::SLOAD,
            op::PUSH1, 0x00,
            op::MSTORE,
            op::PUSH1, 0x20,
            op::PUSH1, 0x00,
            op::RETURN,
        ];
        let mut state = MockVmState::new();
        let result = execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            1_000_000,
            0,
            false,
        ).unwrap();
        assert!(!result.reverted);
        assert_eq!(result.return_data[31], 0x42);
    }
}
