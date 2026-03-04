#![no_main]
use libfuzzer_sys::fuzz_target;

// Fuzz the custom VM interpreter with arbitrary bytecode.
//
// Safety guarantee: executing arbitrary bytecode must NEVER panic.
// All errors (out-of-gas, invalid opcode, stack underflow, etc.) must be
// returned as a VmError, not an unwrap/unreachable panic.
fuzz_target!(|data: &[u8]| {
    use iona::vm::interpreter::exec;
    use iona::vm::gas::GasMeter;
    use iona::vm::state::{VmStorage, VmLog};

    // Minimal VmState implementation for fuzzing.
    struct FuzzState {
        storage: std::collections::BTreeMap<([u8; 32], [u8; 32]), [u8; 32]>,
        code: std::collections::BTreeMap<[u8; 32], Vec<u8>>,
        logs: Vec<VmLog>,
    }

    impl iona::vm::state::VmState for FuzzState {
        fn sload(&self, contract: &[u8; 32], slot: &[u8; 32]) -> [u8; 32] {
            self.storage.get(&(*contract, *slot)).copied().unwrap_or([0u8; 32])
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
            // Cap logs to avoid OOM under fuzzing.
            if self.logs.len() < 64 {
                self.logs.push(log);
            }
        }
    }

    let mut state = FuzzState {
        storage: std::collections::BTreeMap::new(),
        code: std::collections::BTreeMap::new(),
        logs: Vec::new(),
    };

    // Use first 32 bytes as a fake contract address, rest as calldata.
    let (contract_addr, calldata) = if data.len() >= 32 {
        let mut addr = [0u8; 32];
        addr.copy_from_slice(&data[..32]);
        (addr, &data[32..])
    } else {
        ([0u8; 32], data)
    };

    // Budget: 10M gas — enough to exercise complex bytecode without hanging.
    let mut gas = GasMeter::new(10_000_000);

    // Execute; the result (ok or err) is intentionally discarded —
    // we only care that this never panics.
    let _ = exec(data, calldata, &contract_addr, &mut state, &mut gas, 0);
});
