#![no_main]
//! Fuzzing harness for the IONA VM interpreter.
//!
//! Executes arbitrary bytecode with a minimal VM state implementation.
//! The safety guarantee is that executing arbitrary bytecode must NEVER panic.
//! All errors (out‑of‑gas, invalid opcode, stack underflow, etc.) must be
//! returned as a `VmError`, not an `unwrap`/`unreachable` panic.
//!
//! # Run instructions
//! ```bash
//! cargo fuzz run vm_interpreter -- -max_len=4194304 -max_total_time=300
//! ```
//!
//! # Security
//! - Maximum input size: 4 MiB
//! - Gas limit: 10 million (prevents infinite loops)
//! - Logs capped at 64 entries (prevents OOM)
//! - Panics are caught and reported as I1 violation
//! - `black_box` prevents compiler optimisations

use libfuzzer_sys::fuzz_target;
use std::hint::black_box;
use std::panic;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Maximum input size: 4 MiB (prevents OOM in fuzzer)
const MAX_INPUT_SIZE: usize = 4 * 1024 * 1024;

/// Gas limit for each execution (10 million – enough for complex bytecode, but bounded)
const GAS_LIMIT: u64 = 10_000_000;

/// Maximum number of logs to keep (prevents memory blowup)
const MAX_LOGS: usize = 64;

// -----------------------------------------------------------------------------
// Minimal VmState implementation for fuzzing
// -----------------------------------------------------------------------------

use iona::vm::interpreter::exec;
use iona::vm::gas::GasMeter;
use iona::vm::state::{VmState, VmLog};

struct FuzzState {
    storage: std::collections::BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
    code: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
    logs: Vec<VmLog>,
}

impl VmState for FuzzState {
    fn sload(&self, contract: &[u8; 32], slot: &[u8; 32]) -> [u8; 32] {
        self.storage
            .get(&(*contract, *slot))
            .copied()
            .unwrap_or([0u8; 32])
    }

    fn sstore(&mut self, contract: &[u8; 32], slot: [u8; 32], value: [u8; 32]) {
        if value == [0u8; 32] {
            self.storage.remove(&(*contract, slot));
        } else {
            self.storage.insert((*contract, slot), value);
        }
    }

    fn get_code(&self, addr: &[u8; 32]) -> Vec<u8> {
        self.code.get(addr).cloned().unwrap_or_default()
    }

    fn set_code(&mut self, addr: &[u8; 32], code: Vec<u8>) {
        self.code.insert(*addr, code);
    }

    fn emit_log(&mut self, log: VmLog) {
        if self.logs.len() < MAX_LOGS {
            self.logs.push(log);
        }
    }
}

// -----------------------------------------------------------------------------
// Fuzz target
// -----------------------------------------------------------------------------

fuzz_target!(|data: &[u8]| {
    // 1. Truncate oversized input
    let data = if data.len() > MAX_INPUT_SIZE {
        &data[..MAX_INPUT_SIZE]
    } else {
        data
    };

    if data.is_empty() {
        return;
    }

    // 2. Extract contract address (first 32 bytes) and calldata (rest)
    let (contract_addr, calldata) = if data.len() >= 32 {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&data[..32]);
        (addr, &data[32..])
    } else {
        ([0u8; 32], data)
    };

    // 3. Prepare VM state and gas meter
    let mut state = FuzzState {
        storage: std::collections::BTreeMap::new(),
        code: std::collections::BTreeMap::new(),
        logs: Vec::new(),
    };
    let mut gas = GasMeter::new(GAS_LIMIT);

    // 4. Execute with panic capture – must never panic (I1)
    let result = panic::catch_unwind(|| {
        exec(calldata, &contract_addr, &mut state, &mut gas, 0)
    });

    match result {
        Ok(_) => {
            // Even if execution returned an error, we are safe.
            black_box(());
        }
        Err(_) => {
            panic!("I1 violated: VM execution panicked on arbitrary bytecode");
        }
    }
});

// -----------------------------------------------------------------------------
// Unit tests (for local debugging, not run by fuzzer)
// -----------------------------------------------------------------------------
#[cfg(not(fuzzing))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_input() {
        let empty: &[u8] = &[];
        fuzz_target!(empty);
    }

    #[test]
    fn test_max_size_input() {
        let large = vec![0u8; MAX_INPUT_SIZE];
        fuzz_target!(&large);
    }

    #[test]
    fn test_valid_bytecode() {
        // Simple EVM‑style bytecode: PUSH1 0x00 PUSH1 0x00 STOP
        let bytecode = &[0x60, 0x00, 0x60, 0x00, 0x00];
        fuzz_target!(bytecode);
    }

    #[test]
    fn test_invalid_opcode() {
        // Invalid opcode 0xff should return error, not panic
        let bytecode = &[0xff];
        fuzz_target!(bytecode);
    }

    #[test]
    fn test_overflow_loop() {
        // Bytecode that would loop forever – gas limit will stop it
        // JUMPDEST (0x5b) followed by PUSH1 0x00 (0x60 0x00) and JUMP (0x56)
        let bytecode = &[0x5b, 0x60, 0x00, 0x56];
        fuzz_target!(bytecode);
    }
}
