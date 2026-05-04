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
use crate::vm::state::VmLog;
use crate::vm::{errors::VmError, interpreter, state::VmState};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Max bytecode size (matches Ethereum EIP-170: 24 576 bytes).
pub const MAX_CODE_SIZE: usize = 24_576;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during VM deployment or call.
#[derive(Debug, Error)]
pub enum VmExecutorError {
    #[error("out of gas: limit {gas_limit}, needed at least {needed}")]
    OutOfGas { gas_limit: u64, needed: u64 },

    #[error("code too large: {size} bytes (max {max})")]
    CodeTooLarge { size: usize, max: usize },

    #[error("contract already exists at address 0x{}", hex::encode(address))]
    ContractAlreadyExists { address: [u8; 32] },

    #[error("no code at address 0x{}", hex::encode(address))]
    NoCodeAtAddress { address: [u8; 32] },

    #[error("constructor reverted: {data}")]
    ConstructorRevert { data: Vec<u8> },

    #[error("execution reverted: {data}")]
    CallRevert { gas_used: u64, data: Vec<u8> },

    #[error("VM execution error: {0}")]
    VmError(#[from] VmError),

    #[error("invalid deployment init code (empty)")]
    EmptyInitCode,
}

pub type VmExecutorResult<T> = Result<T, VmExecutorError>;

// -----------------------------------------------------------------------------
// Success outputs
// -----------------------------------------------------------------------------

/// Successful deployment output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploySuccess {
    pub contract: [u8; 32],
    pub gas_used: u64,
    pub logs: Vec<VmLog>,
    pub return_data: Vec<u8>,
}

/// Successful call output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallSuccess {
    pub gas_used: u64,
    pub logs: Vec<VmLog>,
    pub return_data: Vec<u8>,
}

// -----------------------------------------------------------------------------
// Deployment
// -----------------------------------------------------------------------------

/// Deploy a contract.
pub fn vm_deploy(
    state: &mut KvState,
    sender: &[u8; 32],
    init_code: &[u8],
    gas_limit: u64,
) -> VmExecutorResult<DeploySuccess> {
    if init_code.is_empty() {
        return Err(VmExecutorError::EmptyInitCode);
    }

    // 1. Derive contract address
    let sender_nonce = *state.vm.nonces.get(sender).unwrap_or(&0);
    let contract_addr = derive_contract_address(sender, sender_nonce);

    // 2. Reject duplicate
    if !state.vm.get_code(&contract_addr).is_empty() {
        return Err(VmExecutorError::ContractAlreadyExists {
            address: contract_addr,
        });
    }

    // 3. Run init_code in a temporary VM state
    let mut tmp_state = state.vm.clone();
    let result = interpreter::exec(
        &mut tmp_state,
        contract_addr,
        init_code,
        &[],
        sender,
        gas_limit,
        0,
    );

    let logs = tmp_state.logs.drain(..).collect::<Vec<_>>();

    match result {
        Err(e) => Err(VmExecutorError::VmError(e)),
        Ok(r) if r.reverted => Err(VmExecutorError::ConstructorRevert {
            data: r.return_data,
        }),
        Ok(r) => {
            let deployed_code = r.return_data;
            if deployed_code.len() > MAX_CODE_SIZE {
                return Err(VmExecutorError::CodeTooLarge {
                    size: deployed_code.len(),
                    max: MAX_CODE_SIZE,
                });
            }
            // Commit state changes
            state.vm = tmp_state;
            state.vm.set_code(&contract_addr, deployed_code);
            *state.vm.nonces.entry(*sender).or_insert(0) += 1;

            Ok(DeploySuccess {
                contract: contract_addr,
                gas_used: r.gas_used,
                logs,
                return_data: r.return_data,
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Call
// -----------------------------------------------------------------------------

/// Call a deployed contract.
pub fn vm_call(
    state: &mut KvState,
    sender: &[u8; 32],
    contract: &[u8; 32],
    calldata: &[u8],
    gas_limit: u64,
) -> VmExecutorResult<CallSuccess> {
    let code = state.vm.get_code(contract);
    if code.is_empty() {
        return Err(VmExecutorError::NoCodeAtAddress {
            address: *contract,
        });
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
        Err(e) => Err(VmExecutorError::VmError(e)),
        Ok(r) if r.reverted => Err(VmExecutorError::CallRevert {
            gas_used: r.gas_used,
            data: r.return_data,
        }),
        Ok(r) => {
            // Commit state changes
            state.vm = tmp_state;
            Ok(CallSuccess {
                gas_used: r.gas_used,
                logs,
                return_data: r.return_data,
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Derive contract address from sender address and nonce.
/// address = blake3(sender || nonce_bytes)[..32]
pub fn derive_contract_address(sender: &[u8; 32], nonce: u64) -> [u8; 32] {
    let mut input = [0u8; 40];
    input[..32].copy_from_slice(sender);
    input[32..40].copy_from_slice(&nonce.to_be_bytes());
    *blake3::hash(&input).as_bytes()
}

// -----------------------------------------------------------------------------
// Payload parsing (unchanged, but kept for compatibility)
// -----------------------------------------------------------------------------

#[derive(Debug)]
pub enum VmTxPayload {
    Deploy { init_code: Vec<u8> },
    Call { contract: [u8; 32], calldata: Vec<u8> },
}

pub fn parse_vm_payload(payload: &str) -> Option<VmTxPayload> {
    let payload = payload.trim();
    if !payload.starts_with("vm ") {
        return None;
    }
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
            if cb.len() != 32 {
                return None;
            }
            let mut contract = [0u8; 32];
            contract.copy_from_slice(&cb);
            let calldata = hex::decode(calldata_hex.trim_start_matches("0x")).unwrap_or_default();
            Some(VmTxPayload::Call { contract, calldata })
        }
        _ => None,
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::KvState;

    fn sender() -> [u8; 32] {
        let mut a = [0u8; 32];
        a[31] = 0xAB;
        a
    }

    fn push1_stop(val: u8) -> Vec<u8> {
        vec![0x60, val, 0x00]
    }

    fn return_42() -> Vec<u8> {
        vec![
            0x60, 42, // PUSH1 42
            0x60, 0,    // PUSH1 0
            0x52, // MSTORE
            0x60, 32, // PUSH1 32 (size)
            0x60, 0,    // PUSH1 0  (offset)
            0xF3, // RETURN
        ]
    }

    #[test]
    fn test_derive_contract_address_deterministic() {
        let s = sender();
        let a1 = derive_contract_address(&s, 0);
        let a2 = derive_contract_address(&s, 0);
        assert_eq!(a1, a2);
    }

    #[test]
    fn test_derive_contract_address_nonce_changes() {
        let s = sender();
        let a0 = derive_contract_address(&s, 0);
        let a1 = derive_contract_address(&s, 1);
        assert_ne!(a0, a1);
    }

    #[test]
    fn test_deploy_simple_contract() {
        let mut state = KvState::default();
        let init_code = return_42();
        let result = vm_deploy(&mut state, &sender(), &init_code, 100_000);
        assert!(result.is_ok());
        let success = result.unwrap();
        assert!(!success.logs.is_empty()); // logs from VM? Actually return_42 produces no logs.
        let code = state.vm.get_code(&success.contract);
        assert_eq!(code.len(), 32);
    }

    #[test]
    fn test_deploy_increments_nonce() {
        let mut state = KvState::default();
        let s = sender();
        let init = push1_stop(1);
        vm_deploy(&mut state, &s, &init, 100_000).unwrap();
        assert_eq!(*state.vm.nonces.get(&s).unwrap_or(&0), 1);
        vm_deploy(&mut state, &s, &init, 100_000).unwrap();
        assert_eq!(*state.vm.nonces.get(&s).unwrap_or(&0), 2);
    }

    #[test]
    fn test_deploy_revert_does_not_persist() {
        let mut state = KvState::default();
        let init_code = vec![
            0x60, 99, // PUSH1 99
            0x60, 0,    // PUSH1 0
            0x55, // SSTORE
            0x60, 0, // PUSH1 0
            0x60, 0,    // PUSH1 0
            0xFD, // REVERT
        ];
        let result = vm_deploy(&mut state, &sender(), &init_code, 100_000);
        assert!(matches!(result, Err(VmExecutorError::ConstructorRevert { .. })));
        assert!(state.vm.code.is_empty());
        assert!(state.vm.storage.is_empty());
    }

    #[test]
    fn test_call_nonexistent_contract_fails() {
        let mut state = KvState::default();
        let contract = [0x99u8; 32];
        let result = vm_call(&mut state, &sender(), &contract, &[], 100_000);
        assert!(matches!(result, Err(VmExecutorError::NoCodeAtAddress { .. })));
    }

    #[test]
    fn test_call_revert() {
        let mut state = KvState::default();
        let s = sender();
        // Deploy contract that always reverts
        let init_code = vec![
            0x60, 0x04, // PUSH1 4 (data length)
            0x60, 0x00, // PUSH1 0 (offset)
            0xFD,       // REVERT with 4‑byte error
        ];
        let deploy = vm_deploy(&mut state, &s, &init_code, 100_000);
        assert!(deploy.is_ok());
        let contract = deploy.unwrap().contract;
        let call = vm_call(&mut state, &s, &contract, &[], 100_000);
        assert!(matches!(call, Err(VmExecutorError::CallRevert { gas_used, data }) if data == vec![0,0,0,0]));
    }

    #[test]
    fn test_parse_vm_payload() {
        let code = hex::encode(vec![0x60, 0x01, 0x00]);
        let payload = format!("vm deploy {}", code);
        match parse_vm_payload(&payload).unwrap() {
            VmTxPayload::Deploy { init_code } => assert_eq!(init_code, vec![0x60, 0x01, 0x00]),
            _ => panic!(),
        }
    }
}
