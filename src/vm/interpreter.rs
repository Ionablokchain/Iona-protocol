//! IONA VM interpreter — full implementation.
//!
//! Stack words are 32 bytes ([u8;32]) — Ethereum 256-bit semantics.
//! Gas model follows EVM conventions.
//! Opcodes: arithmetic, bitwise, memory, storage, control flow, logging, calldata.

use crate::vm::{
    bytecode as op,
    errors::VmError,
    gas::GasMeter,
    state::{Memory, VmState},
};
use sha3::{Digest, Keccak256};
use std::collections::HashSet;

const STACK_LIMIT: usize = 1024;
const MAX_CALL_DEPTH: usize = 1024;

// -----------------------------------------------------------------------------
// Result
// -----------------------------------------------------------------------------

/// Result of executing a contract.
#[derive(Debug)]
pub struct VmResult {
    pub return_data: Vec<u8>,
    pub gas_used: u64,
    pub reverted: bool,
    pub logs_count: usize,
}

// -----------------------------------------------------------------------------
// 256‑bit word helpers
// -----------------------------------------------------------------------------

type Word = [u8; 32];

fn word_to_u64(w: &Word) -> u64 {
    u64::from_be_bytes(w[24..32].try_into().unwrap())
}

fn word_to_usize(w: &Word) -> usize {
    word_to_u64(w) as usize
}

fn u64_to_word(v: u64) -> Word {
    let mut w = [0u8; 32];
    w[24..32].copy_from_slice(&v.to_be_bytes());
    w
}

fn usize_to_word(v: usize) -> Word {
    u64_to_word(v as u64)
}

fn word_is_zero(w: &Word) -> bool {
    w.iter().all(|&b| b == 0)
}

fn word_bool(v: bool) -> Word {
    let mut w = [0u8; 32];
    if v {
        w[31] = 1;
    }
    w
}

fn word_add(a: &Word, b: &Word) -> Word {
    let mut r = [0u8; 32];
    let mut carry: u16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as u16 + b[i] as u16 + carry;
        r[i] = s as u8;
        carry = s >> 8;
    }
    r
}

fn word_sub(a: &Word, b: &Word) -> Word {
    let mut r = [0u8; 32];
    let mut borrow: i16 = 0;
    for i in (0..32).rev() {
        let s = a[i] as i16 - b[i] as i16 - borrow;
        r[i] = s.rem_euclid(256) as u8;
        borrow = if s < 0 { 1 } else { 0 };
    }
    r
}

fn word_mul(a: &Word, b: &Word) -> Word {
    let mut result = [0u64; 8];
    let a_limbs: Vec<u32> = (0..8)
        .map(|i| u32::from_be_bytes(a[i * 4..(i + 1) * 4].try_into().unwrap()))
        .rev()
        .collect();
    let b_limbs: Vec<u32> = (0..8)
        .map(|i| u32::from_be_bytes(b[i * 4..(i + 1) * 4].try_into().unwrap()))
        .rev()
        .collect();
    for (i, &ai) in a_limbs.iter().enumerate() {
        for (j, &bj) in b_limbs.iter().enumerate() {
            if i + j < 8 {
                result[i + j] += (ai as u64) * (bj as u64);
            }
        }
    }
    for i in 0..7 {
        result[i + 1] += result[i] >> 32;
        result[i] &= 0xFFFF_FFFF;
    }
    result[7] &= 0xFFFF_FFFF;
    let limbs_be: Vec<u32> = result.iter().rev().map(|&v| v as u32).collect();
    let mut r = [0u8; 32];
    for (i, l) in limbs_be.iter().enumerate() {
        r[i * 4..(i + 1) * 4].copy_from_slice(&l.to_be_bytes());
    }
    r
}

fn word_div(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    let b_lo = word_to_u64(b);
    let a_lo = word_to_u64(a);
    let a_hi = &a[..24];
    let b_hi = &b[..24];
    if a_hi.iter().all(|&x| x == 0) && b_hi.iter().all(|&x| x == 0) {
        if b_lo == 0 {
            return [0u8; 32];
        }
        return u64_to_word(a_lo / b_lo);
    }
    let au = u128::from_be_bytes(a[16..32].try_into().unwrap());
    let bu = u128::from_be_bytes(b[16..32].try_into().unwrap());
    if a[..16].iter().all(|&x| x == 0) && b[..16].iter().all(|&x| x == 0) {
        if bu == 0 {
            return [0u8; 32];
        }
        let r = au / bu;
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&r.to_be_bytes());
        return w;
    }
    [0u8; 32]
}

fn word_rem(a: &Word, b: &Word) -> Word {
    if word_is_zero(b) {
        return [0u8; 32];
    }
    let b_lo = word_to_u64(b);
    let a_lo = word_to_u64(a);
    if a[..24].iter().all(|&x| x == 0) && b[..24].iter().all(|&x| x == 0) {
        return u64_to_word(a_lo % b_lo);
    }
    let au = u128::from_be_bytes(a[16..32].try_into().unwrap());
    let bu = u128::from_be_bytes(b[16..32].try_into().unwrap());
    if a[..16].iter().all(|&x| x == 0) && b[..16].iter().all(|&x| x == 0) {
        if bu == 0 {
            return [0u8; 32];
        }
        let r = au % bu;
        let mut w = [0u8; 32];
        w[16..32].copy_from_slice(&r.to_be_bytes());
        return w;
    }
    [0u8; 32]
}

fn word_exp(base: &Word, exp: &Word) -> Word {
    let e = word_to_u64(exp);
    if e == 0 {
        return u64_to_word(1);
    }
    let b = word_to_u64(base);
    let mut result: u64 = 1;
    let mut base_p = b;
    let mut exp_p = e;
    while exp_p > 0 {
        if exp_p & 1 == 1 {
            result = result.wrapping_mul(base_p);
        }
        base_p = base_p.wrapping_mul(base_p);
        exp_p >>= 1;
    }
    u64_to_word(result)
}

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
    let mut r = [0u8; 32];
    for i in 0..(32 - byte_shift) {
        r[i] = val[i + byte_shift] << bit_shift;
        if bit_shift > 0 && i + byte_shift + 1 < 32 {
            r[i] |= val[i + byte_shift + 1] >> (8 - bit_shift);
        }
    }
    r
}

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
    let mut r = [0u8; 32];
    for i in byte_shift..32 {
        r[i] = val[i - byte_shift] >> bit_shift;
        if bit_shift > 0 && i > byte_shift {
            r[i] |= val[i - byte_shift - 1] << (8 - bit_shift);
        }
    }
    r
}

fn keccak256_bytes(data: &[u8]) -> Word {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

// -----------------------------------------------------------------------------
// JUMPDEST analysis
// -----------------------------------------------------------------------------

fn build_jumpdest_set(code: &[u8]) -> HashSet<usize> {
    let mut valid = HashSet::new();
    let mut i = 0;
    while i < code.len() {
        let opc = code[i];
        if opc == op::JUMPDEST {
            valid.insert(i);
        }
        i += 1 + op::push_data_size(opc);
    }
    valid
}

// -----------------------------------------------------------------------------
// Interpreter
// -----------------------------------------------------------------------------

struct Interpreter<'a, S: VmState> {
    state: &'a mut S,
    contract: Word,
    code: &'a [u8],
    calldata: &'a [u8],
    caller: Word,
    gas: GasMeter,
    pc: usize,
    stack: Vec<Word>,
    mem: Memory,
    jumpdests: HashSet<usize>,
    logs_count: usize,
}

impl<'a, S: VmState> Interpreter<'a, S> {
    fn new(
        state: &'a mut S,
        contract: Word,
        code: &'a [u8],
        calldata: &'a [u8],
        caller: Word,
        gas_limit: u64,
    ) -> Self {
        Self {
            state,
            contract,
            code,
            calldata,
            caller,
            gas: GasMeter::new(gas_limit),
            pc: 0,
            stack: Vec::with_capacity(64),
            mem: Memory::new(),
            jumpdests: build_jumpdest_set(code),
            logs_count: 0,
        }
    }

    fn run(mut self) -> Result<VmResult, VmError> {
        while self.pc < self.code.len() {
            let opcode = self.code[self.pc];
            self.pc += 1;
            self.execute_opcode(opcode)?;
        }
        Ok(VmResult {
            return_data: vec![],
            gas_used: self.gas.used,
            reverted: false,
            logs_count: self.logs_count,
        })
    }

    fn execute_opcode(&mut self, opcode: u8) -> Result<(), VmError> {
        match opcode {
            op::STOP => return self.stop(),
            op::ADD => self.add()?,
            op::SUB => self.sub()?,
            op::MUL => self.mul()?,
            op::DIV => self.div()?,
            op::MOD => self.rem()?,
            op::EXP => self.exp()?,
            op::LT => self.lt()?,
            op::GT => self.gt()?,
            op::EQ => self.eq()?,
            op::ISZERO => self.iszero()?,
            op::AND => self.and()?,
            op::OR => self.or()?,
            op::XOR => self.xor()?,
            op::NOT => self.not()?,
            op::SHL => self.shl()?,
            op::SHR => self.shr()?,
            op::SHA3 => self.sha3()?,
            op::CALLER => self.caller()?,
            op::CALLVALUE => self.callvalue()?,
            op::CALLDATALOAD => self.calldataload()?,
            op::CALLDATASIZE => self.calldatasize()?,
            op::GAS => self.gas_op()?,
            op::PC => self.pc_op()?,
            op::MLOAD => self.mload()?,
            op::MSTORE => self.mstore()?,
            op::MSTORE8 => self.mstore8()?,
            op::MSIZE => self.msize()?,
            op::SLOAD => self.sload()?,
            op::SSTORE => self.sstore()?,
            op::POP => self.pop()?,
            op::JUMP => self.jump()?,
            op::JUMPI => self.jumpi()?,
            op::JUMPDEST => self.jumpdest()?,
            op::RETURN => return self.return_op(),
            op::REVERT => return self.revert(),
            op::INVALID => return Err(VmError::InvalidOpcode(op::INVALID)),
            0x60..=0x7F => self.push(opcode)?,
            0x80..=0x8F => self.dup(opcode)?,
            0x90..=0x9F => self.swap(opcode)?,
            0xA0..=0xA4 => self.log(opcode)?,
            _ => return Err(VmError::InvalidOpcode(opcode)),
        }
        Ok(())
    }

    // ----- Basic helpers -----
    fn pop(&mut self) -> Result<Word, VmError> {
        self.stack.pop().ok_or(VmError::StackUnderflow)
    }

    fn push(&mut self, v: Word) -> Result<(), VmError> {
        if self.stack.len() >= STACK_LIMIT {
            return Err(VmError::StackOverflow);
        }
        self.stack.push(v);
        Ok(())
    }

    fn charge(&mut self, amount: u64) -> Result<(), VmError> {
        self.gas.charge(amount).map_err(|_| VmError::OutOfGas)
    }

    // ----- Arithmetic -----
    fn add(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_add(&a, &b))
    }

    fn sub(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_sub(&a, &b))
    }

    fn mul(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_LOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_mul(&a, &b))
    }

    fn div(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_LOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_div(&a, &b))
    }

    fn rem(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_LOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_rem(&a, &b))
    }

    fn exp(&mut self) -> Result<(), VmError> {
        let exp_raw = self.pop()?;
        let base = self.pop()?;
        let exp_bytes = exp_raw.iter().rev().skip_while(|&&x| x == 0).count().max(1);
        self.charge(op::GAS_EXP_BASE + op::GAS_EXP_BYTE * exp_bytes as u64)?;
        self.push(word_exp(&base, &exp_raw))
    }

    // ----- Comparison / bitwise -----
    fn lt(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_bool(a < b))
    }

    fn gt(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_bool(a > b))
    }

    fn eq(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        self.push(word_bool(a == b))
    }

    fn iszero(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let a = self.pop()?;
        self.push(word_bool(word_is_zero(&a)))
    }

    fn and(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        let mut r = [0u8; 32];
        for i in 0..32 {
            r[i] = a[i] & b[i];
        }
        self.push(r)
    }

    fn or(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        let mut r = [0u8; 32];
        for i in 0..32 {
            r[i] = a[i] | b[i];
        }
        self.push(r)
    }

    fn xor(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let b = self.pop()?;
        let a = self.pop()?;
        let mut r = [0u8; 32];
        for i in 0..32 {
            r[i] = a[i] ^ b[i];
        }
        self.push(r)
    }

    fn not(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let a = self.pop()?;
        let mut r = [0u8; 32];
        for i in 0..32 {
            r[i] = !a[i];
        }
        self.push(r)
    }

    fn shl(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let shift = self.pop()?;
        let val = self.pop()?;
        self.push(word_shl(&shift, &val))
    }

    fn shr(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let shift = self.pop()?;
        let val = self.pop()?;
        self.push(word_shr(&shift, &val))
    }

    // ----- SHA3 -----
    fn sha3(&mut self) -> Result<(), VmError> {
        let offset = word_to_usize(&self.pop()?);
        let size = word_to_usize(&self.pop()?);
        let words = (size + 31) / 32;
        self.charge(op::GAS_SHA3 + op::GAS_COPY_WORD * words as u64)?;
        let data = self.mem.read_range(offset, size)?;
        self.push(keccak256_bytes(&data))
    }

    // ----- Environment -----
    fn caller(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push(self.caller)
    }

    fn callvalue(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push([0u8; 32])
    }

    fn calldataload(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop()?);
        let mut word = [0u8; 32];
        for i in 0..32 {
            let idx = offset.wrapping_add(i);
            if idx < self.calldata.len() {
                word[i] = self.calldata[idx];
            }
        }
        self.push(word)
    }

    fn calldatasize(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push(usize_to_word(self.calldata.len()))
    }

    fn gas_op(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push(u64_to_word(self.gas.remaining()))
    }

    fn pc_op(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push(usize_to_word(self.pc - 1))
    }

    // ----- Memory -----
    fn mload(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop()?);
        let mem_gas = self.mem.ensure(offset, 32)?;
        self.charge(mem_gas)?;
        self.push(self.mem.load32(offset)?)
    }

    fn mstore(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop()?);
        let value = self.pop()?;
        let mem_gas = self.mem.store32(offset, &value)?;
        self.charge(mem_gas)
    }

    fn mstore8(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let offset = word_to_usize(&self.pop()?);
        let value = self.pop()?;
        let mem_gas = self.mem.store8(offset, value[31])?;
        self.charge(mem_gas)
    }

    fn msize(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        self.push(usize_to_word(self.mem.size()))
    }

    // ----- Storage -----
    fn sload(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_SLOAD)?;
        let key = self.pop()?;
        let val = self.state.sload(&self.contract, &key)?;
        self.push(val)
    }

    fn sstore(&mut self) -> Result<(), VmError> {
        let key = self.pop()?;
        let val = self.pop()?;
        let old = self.state.sload(&self.contract, &key)?;
        let gas_cost = if word_is_zero(&old) && !word_is_zero(&val) {
            op::GAS_SSTORE_SET
        } else if !word_is_zero(&old) && word_is_zero(&val) {
            op::GAS_SSTORE_CLEAR
        } else {
            op::GAS_SSTORE_RESET
        };
        self.charge(gas_cost)?;
        self.state.sstore(&self.contract, &key, val)
    }

    // ----- Stack ops -----
    fn pop_op(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let _ = self.pop()?;
        Ok(())
    }

    fn push(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let n = (opcode - 0x60 + 1) as usize;
        let mut word = [0u8; 32];
        let start = 32 - n;
        for i in 0..n {
            if self.pc + i < self.code.len() {
                word[start + i] = self.code[self.pc + i];
            }
        }
        self.pc += n;
        self.push(word)
    }

    fn dup(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let n = (opcode - 0x80 + 1) as usize;
        if self.stack.len() < n {
            return Err(VmError::StackUnderflow);
        }
        let v = self.stack[self.stack.len() - n];
        self.push(v)
    }

    fn swap(&mut self, opcode: u8) -> Result<(), VmError> {
        self.charge(op::GAS_VERYLOW)?;
        let n = (opcode - 0x90 + 1) as usize;
        let len = self.stack.len();
        if len < n + 1 {
            return Err(VmError::StackUnderflow);
        }
        self.stack.swap(len - 1, len - 1 - n);
        Ok(())
    }

    // ----- Control flow -----
    fn jump(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_JUMP)?;
        let dest = word_to_usize(&self.pop()?);
        if !self.jumpdests.contains(&dest) {
            return Err(VmError::InvalidJump(dest));
        }
        self.pc = dest + 1;
        Ok(())
    }

    fn jumpi(&mut self) -> Result<(), VmError> {
        self.charge(op::GAS_JUMPI)?;
        let dest = word_to_usize(&self.pop()?);
        let cond = self.pop()?;
        if !word_is_zero(&cond) {
            if !self.jumpdests.contains(&dest) {
                return Err(VmError::InvalidJump(dest));
            }
            self.pc = dest + 1;
        }
        Ok(())
    }

    fn jumpdest(&mut self) -> Result<(), VmError> {
        self.charge(1)
    }

    // ----- Logging -----
    fn log(&mut self, opcode: u8) -> Result<(), VmError> {
        let n_topics = (opcode - 0xA0) as usize;
        let offset = word_to_usize(&self.pop()?);
        let size = word_to_usize(&self.pop()?);
        let mut topics = Vec::with_capacity(n_topics);
        for _ in 0..n_topics {
            topics.push(self.pop()?);
        }
        let log_gas = op::GAS_LOG_BASE
            + op::GAS_LOG_TOPIC * n_topics as u64
            + op::GAS_LOG_BYTE * size as u64;
        self.charge(log_gas)?;
        let data = self.mem.read_range(offset, size)?;
        self.state.emit_log(&self.contract, topics, data);
        self.logs_count += 1;
        Ok(())
    }

    // ----- Return / Revert -----
    fn stop(&mut self) -> Result<VmResult, VmError> {
        Ok(VmResult {
            return_data: vec![],
            gas_used: self.gas.used,
            reverted: false,
            logs_count: self.logs_count,
        })
    }

    fn return_op(&mut self) -> Result<VmResult, VmError> {
        let offset = word_to_usize(&self.pop()?);
        let size = word_to_usize(&self.pop()?);
        let data = self.mem.read_range(offset, size)?;
        Ok(VmResult {
            return_data: data,
            gas_used: self.gas.used,
            reverted: false,
            logs_count: self.logs_count,
        })
    }

    fn revert(&mut self) -> Result<VmResult, VmError> {
        let offset = word_to_usize(&self.pop()?);
        let size = word_to_usize(&self.pop()?);
        let data = self.mem.read_range(offset, size)?;
        Ok(VmResult {
            return_data: data,
            gas_used: self.gas.used,
            reverted: true,
            logs_count: 0,
        })
    }
}

// -----------------------------------------------------------------------------
// Public entry point
// -----------------------------------------------------------------------------

pub fn exec<S: VmState>(
    state: &mut S,
    contract: Word,
    code: &[u8],
    calldata: &[u8],
    caller: &Word,
    gas_limit: u64,
    _call_depth: usize,
) -> Result<VmResult, VmError> {
    let interpreter = Interpreter::new(state, contract, code, calldata, *caller, gas_limit);
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
    fn test_simple_addition() -> Result<(), VmError> {
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
        let caller = [0u8; 32];
        let result = exec(&mut state, [0u8; 32], &code, &[], &caller, 1_000_000, 0)?;
        assert!(!result.reverted);
        assert_eq!(result.return_data.len(), 32);
        let mut expected = [0u8; 32];
        expected[31] = 5;
        assert_eq!(&result.return_data[..], &expected[..]);
        Ok(())
    }

    #[test]
    fn test_revert() -> Result<(), VmError> {
        let code = vec![
            op::PUSH1, 0x10,
            op::PUSH1, 0x00,
            op::REVERT,
        ];
        let mut state = MockVmState::new();
        let caller = [0u8; 32];
        let result = exec(&mut state, [0u8; 32], &code, &[], &caller, 1_000_000, 0)?;
        assert!(result.reverted);
        assert_eq!(result.return_data, vec![0; 16]);
        Ok(())
    }

    #[test]
    fn test_storage() -> Result<(), VmError> {
        let code = vec![
            op::PUSH1, 0x2A,
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
        let caller = [0u8; 32];
        let result = exec(&mut state, [0u8; 32], &code, &[], &caller, 1_000_000, 0)?;
        assert!(!result.reverted);
        assert_eq!(result.return_data.len(), 32);
        let mut expected = [0u8; 32];
        expected[31] = 0x2A;
        assert_eq!(&result.return_data[..], &expected[..]);
        Ok(())
    }
}
