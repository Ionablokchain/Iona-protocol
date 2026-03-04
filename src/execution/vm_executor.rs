//! VM contract executor — deploy and call contracts in the IONA custom VM.
//!
//! Contract address derivation:
//!   address = blake3(sender_addr || sender_nonce)[..32]
//!
//! Deploy flow:
//!   1. Derive contract address from sender + nonce
//!   2. Reject if address already has code
//!   3. Run init_code with the VM; return_data becomes the deployed code
//!   4. Store code at derived address; increment sender VM nonce
//!
//! Call flow:
//!   1. Load code from vm.code[contract]
//!   2. Run code with provided calldata
//!   3. Return result (success/revert, return_data, gas_used, logs)

use crate::execution::KvState;
use crate::vm::{errors::VmError, interpreter, state::VmState};
use crate::vm::state::VmLog;
use serde::{Deserialize, Serialize};

/// Max bytecode size (matches Ethereum EIP-170: 24 576 bytes).
pub const MAX_CODE_SIZE: usize = 24_576;

/// Result of a VM deploy or call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmExecResult {
    pub success:     bool,
    pub reverted:    bool,
    pub gas_used:    u64,
    pub return_data: Vec<u8>,
    pub contract:    Option<[u8; 32]>,  // set on deploy
    pub logs:        Vec<VmLog>,
    pub error:       Option<String>,
}

/// Deploy a contract.
///
/// `sender`    — 32-byte sender address (derived from pubkey in execution layer)
/// `init_code` — bytecode to execute as constructor
/// `gas_limit` — gas budget
pub fn vm_deploy(
    state:     &mut KvState,
    sender:    &[u8; 32],
    init_code: &[u8],
    gas_limit: u64,
) -> VmExecResult {
    // 1. Derive contract address
    let sender_nonce = *state.vm.nonces.get(sender).unwrap_or(&0);
    let contract_addr = derive_contract_address(sender, sender_nonce);

    // 2. Reject duplicate
    if !state.vm.get_code(&contract_addr).is_empty() {
        return VmExecResult {
            success: false, reverted: false, gas_used: gas_limit,
            return_data: vec![], contract: None,
            logs: vec![],
            error: Some(format!("contract already exists at {}", hex::encode(contract_addr))),
        };
    }

    // 3. Run init_code — use a temporary clone so we can discard on revert
    let mut tmp_state = state.vm.clone();
    let result = interpreter::exec(
        &mut tmp_state,
        contract_addr,
        init_code,
        &[],  // no calldata for deploy
        sender,
        gas_limit,
        0,
    );

    let logs = tmp_state.logs.drain(..).collect::<Vec<_>>();

    match result {
        Err(e) => VmExecResult {
            success: false, reverted: false, gas_used: gas_limit,
            return_data: vec![], contract: None, logs: vec![],
            error: Some(e.to_string()),
        },
        Ok(r) if r.reverted => VmExecResult {
            success: false, reverted: true, gas_used: r.gas_used,
            return_data: r.return_data, contract: None, logs: vec![],
            error: Some("constructor reverted".into()),
        },
        Ok(r) => {
            let deployed_code = r.return_data.clone();
            if deployed_code.len() > MAX_CODE_SIZE {
                return VmExecResult {
                    success: false, reverted: false, gas_used: r.gas_used,
                    return_data: vec![], contract: None, logs: vec![],
                    error: Some(format!("code too large: {} bytes (max {})", deployed_code.len(), MAX_CODE_SIZE)),
                };
            }
            // Commit state changes
            state.vm = tmp_state;
            state.vm.set_code(&contract_addr, deployed_code);
            *state.vm.nonces.entry(*sender).or_insert(0) += 1;

            VmExecResult {
                success: true, reverted: false, gas_used: r.gas_used,
                return_data: r.return_data,
                contract: Some(contract_addr),
                logs,
                error: None,
            }
        }
    }
}

/// Call a deployed contract.
///
/// `sender`   — 32-byte caller address
/// `contract` — 32-byte contract address
/// `calldata` — ABI-encoded call arguments
/// `gas_limit` — gas budget
pub fn vm_call(
    state:    &mut KvState,
    sender:   &[u8; 32],
    contract: &[u8; 32],
    calldata: &[u8],
    gas_limit: u64,
) -> VmExecResult {
    let code = state.vm.get_code(contract);
    if code.is_empty() {
        return VmExecResult {
            success: false, reverted: false, gas_used: 0,
            return_data: vec![], contract: None,
            logs: vec![],
            error: Some(format!("no code at {}", hex::encode(contract))),
        };
    }

    let mut tmp_state = state.vm.clone();
    let result = interpreter::exec(
        &mut tmp_state,
        *contract,
        &code,
        calldata,
        sender,
        gas_limit,
        0,
    );

    let logs = tmp_state.logs.drain(..).collect::<Vec<_>>();

    match result {
        Err(e) => VmExecResult {
            success: false, reverted: false, gas_used: gas_limit,
            return_data: vec![], contract: None, logs: vec![],
            error: Some(e.to_string()),
        },
        Ok(r) if r.reverted => {
            // On revert: discard state changes, keep gas used
            VmExecResult {
                success: false, reverted: true, gas_used: r.gas_used,
                return_data: r.return_data, contract: None, logs: vec![],
                error: Some("execution reverted".into()),
            }
        }
        Ok(r) => {
            // Commit state changes
            state.vm = tmp_state;
            VmExecResult {
                success: true, reverted: false, gas_used: r.gas_used,
                return_data: r.return_data,
                contract: Some(*contract),
                logs,
                error: None,
            }
        }
    }
}

/// Derive contract address from sender address and nonce.
/// address = blake3(sender || nonce_bytes)[..32]
pub fn derive_contract_address(sender: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(sender);
    input[32..40].copy_from_slice(&nonce.to_be_bytes());
    *blake3::hash(&input).as_bytes()
}

/// Parse a VM transaction from a payload string.
/// Formats:
///   vm deploy <hex_initcode>
///   vm call <contract_hex> <hex_calldata>
#[derive(Debug)]
pub enum VmTxPayload {
    Deploy { init_code: Vec<u8> },
    Call   { contract: [u8; 32], calldata: Vec<u8> },
}

pub fn parse_vm_payload(payload: &str) -> Option<VmTxPayload> {
    let payload = payload.trim();
    if !payload.starts_with("vm ") { return None; }
    let parts: Vec<&str> = payload.split_whitespace().collect();
    match parts.get(1)? {
        &"deploy" => {
            let hex = parts.get(2).unwrap_or(&"");
            let init_code = hex::decode(hex.trim_start_matches("0x")).ok()?;
            Some(VmTxPayload::Deploy { init_code })
        }
        &"call" => {
            let contract_hex = parts.get(2)?;
            let calldata_hex = parts.get(3).unwrap_or(&"");
            let cb = hex::decode(contract_hex.trim_start_matches("0x")).ok()?;
            if cb.len() != 32 { return None; }
            let mut contract = [0u8; 32];
            contract.copy_from_slice(&cb);
            let calldata = hex::decode(calldata_hex.trim_start_matches("0x")).unwrap_or_default();
            Some(VmTxPayload::Call { contract, calldata })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;

    fn sender() -> [u8; 32] {
        let mut a = [0u8; 32];
        a[31] = 0xAB;
        a
    }

    /// Build bytecode: PUSH1 <val> STOP
    fn push1_stop(val: u8) -> Vec<u8> {
        vec![0x60, val, 0x00]
    }

    /// Build bytecode: PUSH1 42, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
    fn return_42() -> Vec<u8> {
        vec![
            0x60, 42,   // PUSH1 42
            0x60, 0,    // PUSH1 0
            0x52,       // MSTORE
            0x60, 32,   // PUSH1 32 (size)
            0x60, 0,    // PUSH1 0  (offset)
            0xF3,       // RETURN
        ]
    }

    /// Build simple storage contract:
    /// Deploy: stores 99 at slot 0, returns empty
    /// Call:   loads slot 0, stores in memory, returns it
    fn counter_contract_init() -> Vec<u8> {
        vec![
            // init: SSTORE slot 0 = 99, then return empty bytecode (the runtime code)
            0x60, 99,   // PUSH1 99 (value)
            0x60, 0,    // PUSH1 0  (slot)
            0x55,       // SSTORE
            // return empty (deployed code = empty, so call will fail with "no code")
            // Actually return the runtime bytecode below
            // For test simplicity: return the SLOAD+RETURN bytecode
            // PUSH1 0, SLOAD, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
            0x60, 0,    // PUSH1 0 (offset for RETURN)
            0x60, 0,    // PUSH1 0 (size for RETURN)
            0xF3,       // RETURN (returns 0 bytes = empty deployed code)
        ]
    }

    #[test]
    fn test_derive_contract_address_deterministic() {
        let s = sender();
        let a1 = derive_contract_address(&s, 0);
        let a2 = derive_contract_address(&s, 0);
        assert_eq!(a1, a2, "Address derivation must be deterministic");
    }

    #[test]
    fn test_derive_contract_address_nonce_changes() {
        let s = sender();
        let a0 = derive_contract_address(&s, 0);
        let a1 = derive_contract_address(&s, 1);
        assert_ne!(a0, a1, "Different nonces must produce different addresses");
    }

    #[test]
    fn test_deploy_simple_contract() {
        let mut state = KvState::default();
        // Deploy: PUSH1 42, PUSH1 0, MSTORE, PUSH1 32, PUSH1 0, RETURN
        // init_code returns 32 bytes starting at offset 0 (which contains 42 in the word)
        let init_code = return_42();
        let result = vm_deploy(&mut state, &sender(), &init_code, 100_000);
        assert!(result.success, "Deploy should succeed: {:?}", result.error);
        assert!(result.contract.is_some(), "Should have contract address");
        let contract = result.contract.unwrap();
        // The deployed bytecode is the 32 bytes returned by the constructor (containing 42)
        let code = state.vm.get_code(&contract);
        assert_eq!(code.len(), 32, "Deployed code should be 32 bytes");
    }

    #[test]
    fn test_deploy_increments_nonce() {
        let mut state = KvState::default();
        let s = sender();
        let init = push1_stop(1);
        vm_deploy(&mut state, &s, &init, 100_000);
        assert_eq!(*state.vm.nonces.get(&s).unwrap_or(&0), 1, "Nonce should be 1 after first deploy");
        // Second deploy gets different address
        let r2 = vm_deploy(&mut state, &s, &init, 100_000);
        assert_eq!(*state.vm.nonces.get(&s).unwrap_or(&0), 2, "Nonce should be 2");
        assert_ne!(r2.contract, state.vm.nonces.get(&s).map(|_| derive_contract_address(&s, 0)));
    }

    #[test]
    fn test_call_nonexistent_contract_fails() {
        let mut state = KvState::default();
        let contract = [0x99u8; 32];
        let result = vm_call(&mut state, &sender(), &contract, &[], 100_000);
        assert!(!result.success, "Call to nonexistent contract should fail");
        assert!(result.error.as_deref().map(|e| e.contains("no code")).unwrap_or(false));
    }

    #[test]
    fn test_call_sload_sstore() {
        let mut state = KvState::default();
        let s = sender();

        // Deploy a contract that on init: SSTOREs 42 at slot 7, returns runtime code
        // Runtime: SLOADs slot 7, MSTOREs at 0, RETURNs 32 bytes from 0
        let runtime: Vec<u8> = vec![
            0x60, 7,    // PUSH1 7   — slot
            0x54,       // SLOAD
            0x60, 0,    // PUSH1 0   — mem offset
            0x52,       // MSTORE
            0x60, 32,   // PUSH1 32  — size
            0x60, 0,    // PUSH1 0   — offset
            0xF3,       // RETURN
        ];

        // init_code: SSTORE slot 7 = 42, then return runtime bytes
        let mut init_code: Vec<u8> = vec![
            0x60, 42,   // PUSH1 42
            0x60, 7,    // PUSH1 7
            0x55,       // SSTORE
        ];
        // RETURN the runtime code: need MSTORE it first
        // Simpler: store runtime in memory then RETURN it
        // Use PUSH+MSTORE8 to write each byte
        let runtime_offset: usize = 0;
        for (i, &byte) in runtime.iter().enumerate() {
            init_code.extend_from_slice(&[
                0x60, byte,                 // PUSH1 <byte>
                0x60, (runtime_offset + i) as u8, // PUSH1 <offset>
                0x53,                       // MSTORE8
            ]);
        }
        init_code.extend_from_slice(&[
            0x60, runtime.len() as u8,  // PUSH1 <len>
            0x60, 0,                    // PUSH1 0
            0xF3,                       // RETURN
        ]);

        let deploy_result = vm_deploy(&mut state, &s, &init_code, 500_000);
        assert!(deploy_result.success, "Deploy failed: {:?}", deploy_result.error);
        let contract = deploy_result.contract.unwrap();

        // Verify slot 7 = 42 after deploy
        let mut key = [0u8; 32]; key[31] = 7;
        let stored = state.vm.sload(&contract, &key).unwrap();
        assert_eq!(stored[31], 42, "SSTORE during init should persist");

        // Call the contract — should read slot 7 and return it
        let call_result = vm_call(&mut state, &s, &contract, &[], 100_000);
        assert!(call_result.success, "Call failed: {:?}", call_result.error);
        assert_eq!(call_result.return_data.len(), 32);
        assert_eq!(call_result.return_data[31], 42, "SLOAD should return 42");
    }

    #[test]
    fn test_revert_does_not_persist_state() {
        let mut state = KvState::default();
        let s = sender();

        // Deploy: SSTORE slot 0 = 99, then REVERT
        let init_code: Vec<u8> = vec![
            0x60, 99,   // PUSH1 99
            0x60, 0,    // PUSH1 0
            0x55,       // SSTORE (slot 0 = 99)
            0x60, 0,    // PUSH1 0 (size)
            0x60, 0,    // PUSH1 0 (offset)
            0xFD,       // REVERT
        ];

        let result = vm_deploy(&mut state, &s, &init_code, 100_000);
        assert!(!result.success, "Reverted deploy should not succeed");
        // State must not be modified
        assert!(state.vm.code.is_empty(), "No code should be stored after revert");
        assert!(state.vm.storage.is_empty(), "No storage should be stored after revert");
    }

    #[test]
    fn test_out_of_gas_deploy() {
        let mut state = KvState::default();
        // Deploy with tiny gas — should fail
        let init_code = return_42();
        let result = vm_deploy(&mut state, &sender(), &init_code, 3); // way too low
        assert!(!result.success, "Should fail with insufficient gas");
    }

    #[test]
    fn test_parse_vm_payload_deploy() {
        let code = hex::encode(vec![0x60u8, 0x01, 0x00]);
        let payload = format!("vm deploy {}", code);
        match parse_vm_payload(&payload) {
            Some(VmTxPayload::Deploy { init_code }) => {
                assert_eq!(init_code, vec![0x60, 0x01, 0x00]);
            }
            other => panic!("Expected Deploy, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_vm_payload_call() {
        let contract = hex::encode([0xABu8; 32]);
        let calldata = hex::encode([0x01u8, 0x02u8]);
        let payload = format!("vm call {} {}", contract, calldata);
        match parse_vm_payload(&payload) {
            Some(VmTxPayload::Call { contract: c, calldata: cd }) => {
                assert_eq!(c, [0xABu8; 32]);
                assert_eq!(cd, vec![0x01, 0x02]);
            }
            other => panic!("Expected Call, got {:?}", other),
        }
    }

    #[test]
    fn test_parse_non_vm_payload_returns_none() {
        assert!(parse_vm_payload("set foo bar").is_none());
        assert!(parse_vm_payload("stake delegate alice 1000").is_none());
        assert!(parse_vm_payload("gov vote 0 yes").is_none());
    }

    #[test]
    fn test_state_root_changes_after_deploy() {
        let mut s1 = KvState::default();
        let root_before = s1.root();
        vm_deploy(&mut s1, &sender(), &return_42(), 100_000);
        let root_after = s1.root();
        assert_ne!(root_before.0, root_after.0, "State root must change after deploy");
    }
}
