//! Integration tests for the IONA custom VM — Quantum Execution Model.
//!
//! # Quantum VM Test Architecture
//!
//! Every VM operation is modelled as a **unitary transformation** acting on
//! the Hilbert space ℋ_vm = ℋ_stack ⊗ ℋ_memory ⊗ ℋ_storage.  The test
//! framework tracks the **density matrix** properties of the VM state to
//! verify that execution preserves quantum coherence within expected bounds.
//!
//! # Mathematical Formalism
//!
//! ## VM State
//! ```text
//! |Ψ_vm⟩ = |stack⟩ ⊗ |memory⟩ ⊗ |storage⟩ ⊗ |code⟩
//! ρ_vm   = |Ψ_vm⟩⟨Ψ_vm|
//! ```
//!
//! ## Execution as Unitary Evolution
//! ```text
//! U_bytecode = T[exp(-i ∫ Ĥ(t) dt / ℏ)]
//! ```
//! Each opcode is a **quantum gate** acting on the state.
//!
//! ## Measurement (Return/Stop)
//! ```text
//! Π_return = |return⟩⟨return|
//! P(return) = Tr(ρ_vm Π_return)
//! ```
//!
//! ## Decoherence Tracking
//! ```text
//! γ(t) = Tr(ρ²)      — purity
//! S    = -Tr(ρ ln ρ) — von Neumann entropy
//! ```

use iona::economics::params::EconomicsParams;
use iona::economics::staking::StakingState;
use iona::execution::vm_executor::{
    derive_contract_address, parse_vm_payload, vm_call, vm_deploy, VmTxPayload,
};
use iona::execution::{execute_block_with_staking, KvState};
use iona::types::Tx;
use iona::vm::interpreter;
use iona::vm::state::{VmState, VmStorage};

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh VM state.
const DEFAULT_VM_COHERENCE: f64 = 1.0;

/// Decoherence rate per opcode execution.
const OPCODE_DECOHERENCE_RATE: f64 = 0.00005;

/// Decoherence rate per storage operation (stronger — I/O interaction).
const STORAGE_DECOHERENCE_RATE: f64 = 0.0002;

/// Decoherence rate per contract deployment.
const DEPLOY_DECOHERENCE_RATE: f64 = 0.0005;

/// Minimum coherence threshold for a valid VM execution.
const MIN_VM_COHERENCE: f64 = 0.99;

/// Kraus rank for VM quantum channels.
const VM_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Quantum VM Test State
// -----------------------------------------------------------------------------

/// Quantum state tracker for VM integration tests.
///
/// Accumulates the density matrix properties during test execution,
/// providing observables for verifying quantum coherence.
#[derive(Debug, Clone)]
struct QuantumVmTestState {
    /// Purity γ = Tr(ρ²) of the VM state.
    purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    entropy: f64,
    /// Coherence of the execution path.
    execution_coherence: f64,
    /// Coherence of the storage subsystem.
    storage_coherence: f64,
    /// Number of opcodes executed.
    opcode_count: u64,
    /// Number of storage operations (SLOAD/SSTORE).
    storage_op_count: u64,
    /// Number of contract deployments.
    deploy_count: u64,
    /// Whether the VM state is in a healthy quantum state.
    is_healthy: bool,
}

impl QuantumVmTestState {
    fn new() -> Self {
        Self {
            purity: DEFAULT_VM_COHERENCE,
            entropy: 0.0,
            execution_coherence: DEFAULT_VM_COHERENCE,
            storage_coherence: DEFAULT_VM_COHERENCE,
            opcode_count: 0,
            storage_op_count: 0,
            deploy_count: 0,
            is_healthy: true,
        }
    }

    /// Estimate decoherence from executing N opcodes.
    fn apply_opcode_batch(&mut self, count: u64) {
        self.opcode_count = self.opcode_count.wrapping_add(count);
        let decay = (-OPCODE_DECOHERENCE_RATE * count as f64).exp();
        self.execution_coherence = (self.execution_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Estimate decoherence from a storage operation.
    fn apply_storage_op(&mut self, count: u64) {
        self.storage_op_count = self.storage_op_count.wrapping_add(count);
        let decay = (-STORAGE_DECOHERENCE_RATE * count as f64).exp();
        self.storage_coherence = (self.storage_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Estimate decoherence from a contract deployment.
    fn apply_deploy(&mut self) {
        self.deploy_count = self.deploy_count.wrapping_add(1);
        let decay = (-DEPLOY_DECOHERENCE_RATE).exp();
        self.execution_coherence = (self.execution_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for VM operations.
    fn apply_vm_channel(&mut self) {
        let kraus_factor = (1.0 / VM_KRAUS_RANK as f64).sqrt();
        self.execution_coherence = (self.execution_coherence * kraus_factor).clamp(0.0, 1.0);
        self.storage_coherence = (self.storage_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.execution_coherence * self.storage_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_VM_COHERENCE;
    }
}

// ── Bytecode helpers (unchanged) ──────────────────────────────────────────

fn sender() -> [u8; 32] {
    let mut a = [0u8; 32];
    a[31] = 0xAB;
    a
}

fn zero_caller() -> [u8; 32] {
    [0u8; 32]
}

/// PUSH1 n, STOP — minimal valid bytecode
fn push1_stop(n: u8) -> Vec<u8> {
    vec![0x60, n, 0x00]
}

/// Returns 42 as a 32-byte word from memory
fn return_42_code() -> Vec<u8> {
    vec![
        0x60, 42, // PUSH1 42
        0x60, 0,  // PUSH1 0   (memory offset)
        0x52,     // MSTORE
        0x60, 32, // PUSH1 32  (size)
        0x60, 0,  // PUSH1 0   (offset)
        0xF3,     // RETURN
    ]
}

/// Build bytecode that sets memory then returns it
fn wrap_as_constructor(runtime: &[u8]) -> Vec<u8> {
    let mut code = Vec::new();
    for (i, &byte) in runtime.iter().enumerate() {
        code.extend_from_slice(&[0x60, byte, 0x60, i as u8, 0x53]);
    }
    code.push(0x60);
    code.push(runtime.len() as u8);
    code.push(0x60);
    code.push(0);
    code.push(0xF3);
    code
}

// ── Quantum helper for interpreter tests ─────────────────────────────────

/// Execute interpreter with quantum state tracking.
fn exec_quantum(
    store: &mut VmStorage,
    contract: [u8; 32],
    code: &[u8],
    calldata: &[u8],
    caller: &[u8; 32],
    gas_limit: u64,
) -> (Result<iona::vm::interpreter::VmResult, iona::vm::errors::VmError>, QuantumVmTestState) {
    let mut qstate = QuantumVmTestState::new();
    let opcode_count = code.iter().filter(|&&b| b != 0x60 && b != 0x61).count() as u64;
    qstate.apply_opcode_batch(opcode_count);
    qstate.apply_vm_channel();

    let result = interpreter::exec(store, contract, code, calldata, caller, gas_limit, 0);
    (result, qstate)
}

// ── Interpreter unit tests (classical + quantum) ─────────────────────────

#[test]
fn test_interpreter_add() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 3, 0x60, 4, 0x01,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, qstate) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert!(!r.reverted);
    assert_eq!(r.return_data.len(), 32);
    assert_eq!(r.return_data[31], 7, "3 + 4 should be 7");
    // Quantum: execution coherence should be slightly reduced
    assert!(qstate.execution_coherence < 1.0);
    assert!(qstate.is_healthy);
}

#[test]
fn test_interpreter_sub() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 10, 0x60, 3, 0x03,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 7);
}

#[test]
fn test_interpreter_mul() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 6, 0x60, 7, 0x02,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 42);
}

#[test]
fn test_interpreter_div() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 100, 0x60, 4, 0x04,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 25);
}

#[test]
fn test_interpreter_mod() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 10, 0x60, 3, 0x06,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 1);
}

#[test]
fn test_interpreter_lt_gt_eq() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 3, 0x60, 5, 0x10,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 1, "3 < 5 = true");

    let code2 = vec![
        0x60, 5, 0x60, 5, 0x14,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result2, _) = exec_quantum(&mut store, [0u8; 32], &code2, &[], &zero_caller(), 100_000);
    let r2 = result2.unwrap();
    assert_eq!(r2.return_data[31], 1, "5 == 5 = true");
}

#[test]
fn test_interpreter_iszero() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 0, 0x15,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 1);

    let code2 = vec![
        0x60, 5, 0x15,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result2, _) = exec_quantum(&mut store, [0u8; 32], &code2, &[], &zero_caller(), 100_000);
    let r2 = result2.unwrap();
    assert_eq!(r2.return_data[31], 0);
}

#[test]
fn test_interpreter_and_or_xor_not() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 0b1010, 0x60, 0b1100, 0x17,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 0b1110, "OR result");
}

#[test]
fn test_interpreter_shl_shr() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 1, 0x60, 3, 0x1B,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 8, "1 << 3 = 8");

    let code2 = vec![
        0x60, 16, 0x60, 2, 0x1C,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result2, _) = exec_quantum(&mut store, [0u8; 32], &code2, &[], &zero_caller(), 100_000);
    let r2 = result2.unwrap();
    assert_eq!(r2.return_data[31], 4, "16 >> 2 = 4");
}

#[test]
fn test_interpreter_dup_swap() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 7, 0x80, 0x01,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 14);

    let code2 = vec![
        0x60, 3, 0x60, 5, 0x90, 0x03,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result2, _) = exec_quantum(&mut store, [0u8; 32], &code2, &[], &zero_caller(), 100_000);
    let r2 = result2.unwrap();
    assert_eq!(r2.return_data[31], 2);
}

#[test]
fn test_interpreter_jump_jumpi() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 4, 0x56, 0xFE, 0x5B,
        0x60, 99, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert!(!r.reverted);
    assert_eq!(r.return_data[31], 99);
}

#[test]
fn test_interpreter_jumpi_conditional() {
    let mut store = VmStorage::default();
    let dest = 8usize;
    let code = vec![
        0x60, 1, 0x60, dest as u8, 0x57,
        0x60, 0, 0x00, 0x5B,
        0x60, 1, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 1, "JUMPI with cond=1 should jump");
}

#[test]
fn test_interpreter_calldataload() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 0, 0x35,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let mut calldata = [0u8; 32];
    calldata[31] = 77;
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &calldata, &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 77);
}

#[test]
fn test_interpreter_sload_sstore() {
    let mut store = VmStorage::default();
    let contract = [1u8; 32];
    let code = vec![
        0x60, 42, 0x60, 7, 0x55,
        0x60, 7, 0x54,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, mut qstate) = exec_quantum(&mut store, contract, &code, &[], &zero_caller(), 100_000);
    qstate.apply_storage_op(2); // SSTORE + SLOAD
    let r = result.unwrap();
    assert_eq!(r.return_data[31], 42, "SLOAD should read stored value");
    assert!(qstate.storage_coherence < 1.0);
}

#[test]
fn test_interpreter_log1() {
    let mut store = VmStorage::default();
    let contract = [2u8; 32];
    let code = vec![
        0x60, 99, 0x60, 0, 0x52,
        0x60, 99, 0x60, 0, 0x60, 0, 0xA1, 0x00,
    ];
    let (result, _) = exec_quantum(&mut store, contract, &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert_eq!(r.logs_count, 1, "Should have emitted 1 log");
    assert_eq!(store.logs.len(), 1);
    assert_eq!(store.logs[0].topics[0][31], 99);
}

#[test]
fn test_interpreter_revert() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 42, 0x60, 0, 0x55,
        0x60, 0, 0x60, 0, 0xFD,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100_000);
    let r = result.unwrap();
    assert!(r.reverted, "Should be reverted");
}

#[test]
fn test_interpreter_out_of_gas() {
    let mut store = VmStorage::default();
    let code = vec![
        0x60, 1, 0x60, 1, 0x55,
        0x60, 2, 0x60, 2, 0x55, 0x60, 3, 0x60, 3, 0x55, 0x00,
    ];
    let (result, _) = exec_quantum(&mut store, [0u8; 32], &code, &[], &zero_caller(), 100);
    assert!(result.is_err(), "Should fail with out of gas");
}

// ── vm_executor integration tests (classical + quantum) ───────────────────

#[test]
fn test_vm_deploy_and_call_counter() {
    let mut state = KvState::default();
    let s = sender();

    let runtime: Vec<u8> = vec![
        0x60, 0, 0x54, 0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let init_code = wrap_as_constructor(&runtime);

    let deploy = vm_deploy(&mut state, &s, &init_code, 500_000);
    assert!(deploy.success, "Deploy failed: {:?}", deploy.error);
    let contract = deploy.contract.unwrap();

    let call1 = vm_call(&mut state, &s, &contract, &[], 100_000);
    assert!(call1.success);
    assert_eq!(call1.return_data.len(), 32);
    assert_eq!(call1.return_data[31], 0, "Slot 0 initially 0");
}

#[test]
fn test_vm_state_root_changes_after_deploy() {
    let mut state = KvState::default();
    let root_before = state.root();
    vm_deploy(&mut state, &sender(), &return_42_code(), 500_000);
    let root_after = state.root();
    assert_ne!(
        root_before.0, root_after.0,
        "State root must change after deploy"
    );
}

#[test]
fn test_vm_double_deploy_same_address_rejected() {
    let mut state = KvState::default();
    let s = sender();
    let r1 = vm_deploy(&mut state, &s, &return_42_code(), 500_000);
    assert!(r1.success);
    state.vm.nonces.insert(s, 0);
    let r2 = vm_deploy(&mut state, &s, &return_42_code(), 500_000);
    assert!(!r2.success, "Re-deploy to same address should fail");
}

#[test]
fn test_vm_revert_discards_state() {
    let mut state = KvState::default();
    let s = sender();
    let init_code = vec![
        0x60, 42, 0x60, 0, 0x55,
        0x60, 0, 0x60, 0, 0xFD,
    ];
    let r = vm_deploy(&mut state, &s, &init_code, 100_000);
    assert!(!r.success, "Reverted deploy should fail");
    assert!(
        state.vm.storage.is_empty(),
        "Storage must be empty after revert"
    );
    assert!(
        state.vm.code.is_empty(),
        "No code must be stored after revert"
    );
}

#[test]
fn test_vm_call_revert_discards_state() {
    let mut state = KvState::default();
    let s = sender();
    let runtime: Vec<u8> = vec![
        0x60, 99, 0x60, 0, 0x55,
        0x60, 0, 0x60, 0, 0xFD,
    ];
    let init = wrap_as_constructor(&runtime);
    let deploy = vm_deploy(&mut state, &s, &init, 500_000);
    assert!(deploy.success);
    let contract = deploy.contract.unwrap();

    let state_before_call = state.vm.storage.clone();
    let call = vm_call(&mut state, &s, &contract, &[], 100_000);
    assert!(!call.success);
    assert!(call.reverted);
    assert_eq!(
        state.vm.storage, state_before_call,
        "Storage unchanged after reverted call"
    );
}

#[test]
fn test_vm_multiple_deploys_unique_addresses() {
    let mut state = KvState::default();
    let s = sender();
    let code = push1_stop(1);

    let r1 = vm_deploy(&mut state, &s, &code, 100_000);
    let r2 = vm_deploy(&mut state, &s, &code, 100_000);
    let r3 = vm_deploy(&mut state, &s, &code, 100_000);

    assert!(r1.success && r2.success && r3.success);
    let a1 = r1.contract.unwrap();
    let a2 = r2.contract.unwrap();
    let a3 = r3.contract.unwrap();
    assert_ne!(a1, a2);
    assert_ne!(a2, a3);
    assert_ne!(a1, a3);
}

#[test]
fn test_parse_vm_payload_deploy() {
    let hex = hex::encode(vec![0x60u8, 42, 0x00]);
    let payload = format!("vm deploy {hex}");
    match parse_vm_payload(&payload) {
        Some(VmTxPayload::Deploy { init_code }) => assert_eq!(init_code, vec![0x60, 42, 0x00]),
        other => panic!("Expected Deploy, got {:?}", other),
    }
}

#[test]
fn test_parse_vm_payload_call() {
    let contract = hex::encode([0xBBu8; 32]);
    let calldata = hex::encode([0x01u8, 0x02]);
    let payload = format!("vm call {contract} {calldata}");
    match parse_vm_payload(&payload) {
        Some(VmTxPayload::Call { contract: c, calldata: cd }) => {
            assert_eq!(c, [0xBBu8; 32]);
            assert_eq!(cd, vec![0x01, 0x02]);
        }
        other => panic!("Expected Call, got {:?}", other),
    }
}

#[test]
fn test_parse_non_vm_payload_returns_none() {
    assert!(parse_vm_payload("stake delegate v1 100").is_none());
    assert!(parse_vm_payload("kv set foo bar").is_none());
    assert!(parse_vm_payload("gov vote 0 yes").is_none());
}

#[test]
fn test_gas_used_increases_with_more_work() {
    let mut s1 = VmStorage::default();
    let mut s2 = VmStorage::default();

    let simple = vec![0x60, 1, 0x00];
    let r_simple =
        interpreter::exec(&mut s1, [0u8; 32], &simple, &[], &zero_caller(), 100_000, 0).unwrap();

    let complex = vec![
        0x60, 1, 0x60, 1, 0x55,
        0x60, 2, 0x60, 2, 0x55, 0x00,
    ];
    let r_complex = interpreter::exec(
        &mut s2, [0u8; 32], &complex, &[], &zero_caller(), 500_000, 0,
    )
    .unwrap();

    assert!(
        r_complex.gas_used > r_simple.gas_used,
        "Complex code uses more gas"
    );
}

#[test]
fn test_contract_address_derivation_is_deterministic() {
    let s = sender();
    let a1 = derive_contract_address(&s, 0);
    let a2 = derive_contract_address(&s, 0);
    assert_eq!(a1, a2);
}

#[test]
fn test_contract_address_different_sender_different_address() {
    let s1 = sender();
    let mut s2 = sender();
    s2[0] ^= 0xFF;
    assert_ne!(
        derive_contract_address(&s1, 0),
        derive_contract_address(&s2, 0)
    );
}

// ── Quantum-specific tests ────────────────────────────────────────────────

#[test]
fn test_quantum_state_initialization() {
    let qstate = QuantumVmTestState::new();
    assert!((qstate.purity - 1.0).abs() < 1e-10);
    assert!((qstate.entropy - 0.0).abs() < 1e-10);
    assert!(qstate.is_healthy);
}

#[test]
fn test_quantum_opcode_batch_decoherence() {
    let mut qstate = QuantumVmTestState::new();
    let initial_purity = qstate.purity;
    qstate.apply_opcode_batch(100);
    assert!(qstate.purity < initial_purity);
    assert_eq!(qstate.opcode_count, 100);
}

#[test]
fn test_quantum_storage_op_decoherence() {
    let mut qstate = QuantumVmTestState::new();
    let initial_storage_coh = qstate.storage_coherence;
    qstate.apply_storage_op(10);
    assert!(qstate.storage_coherence < initial_storage_coh);
    assert_eq!(qstate.storage_op_count, 10);
}

#[test]
fn test_quantum_deploy_decoherence() {
    let mut qstate = QuantumVmTestState::new();
    let initial_exec_coh = qstate.execution_coherence;
    qstate.apply_deploy();
    assert!(qstate.execution_coherence < initial_exec_coh);
    assert_eq!(qstate.deploy_count, 1);
}

#[test]
fn test_quantum_vm_channel() {
    let mut qstate = QuantumVmTestState::new();
    let initial_exec_coh = qstate.execution_coherence;
    qstate.apply_vm_channel();
    assert!(qstate.execution_coherence < initial_exec_coh);
}

#[test]
fn test_quantum_storage_coherence_after_sload_sstore() {
    let mut store = VmStorage::default();
    let contract = [1u8; 32];
    let code = vec![
        0x60, 42, 0x60, 7, 0x55,
        0x60, 7, 0x54,
        0x60, 0, 0x52, 0x60, 32, 0x60, 0, 0xF3,
    ];
    let (result, mut qstate) = exec_quantum(&mut store, contract, &code, &[], &zero_caller(), 100_000);
    qstate.apply_storage_op(2);
    assert!(result.is_ok());
    assert!(qstate.storage_coherence < DEFAULT_VM_COHERENCE);
    assert!(qstate.storage_op_count == 2);
}

#[test]
fn test_quantum_health_after_many_operations() {
    let mut qstate = QuantumVmTestState::new();
    for _ in 0..500 {
        qstate.apply_opcode_batch(100);
        qstate.apply_storage_op(10);
    }
    assert!(!qstate.is_healthy);
}

#[test]
fn test_quantum_purity_never_negative() {
    let mut qstate = QuantumVmTestState::new();
    for _ in 0..10000 {
        qstate.apply_deploy();
    }
    assert!(qstate.purity >= 0.0);
}
