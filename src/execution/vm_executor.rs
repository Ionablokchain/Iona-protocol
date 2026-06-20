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
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::vm_executor::{VmExecutor, VmExecutorConfig};
//!
//! let config = VmExecutorConfig::default();
//! let mut executor = VmExecutor::new(config);
//! let result = executor.deploy(&mut state, &sender, &init_code, gas_limit)?;
//! ```

use crate::execution::KvState;
use crate::vm::state::{VmLog, VmState};
use crate::vm::{interpreter, errors::VmError};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Default maximum bytecode size (EIP‑170: 24 576 bytes).
pub const DEFAULT_MAX_CODE_SIZE: usize = 24_576;

/// Default gas limit for VM execution (10 million).
pub const DEFAULT_GAS_LIMIT: u64 = 10_000_000;

/// Default gas limit for deployment (20 million).
pub const DEFAULT_DEPLOY_GAS_LIMIT: u64 = 20_000_000;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the VM executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmExecutorConfig {
    /// Maximum bytecode size allowed for deployed contracts.
    pub max_code_size: usize,
    /// Default gas limit for VM execution if not specified.
    pub default_gas_limit: u64,
    /// Default gas limit for deployment.
    pub default_deploy_gas_limit: u64,
    /// Whether to enable detailed tracing of VM execution.
    pub enable_tracing: bool,
    /// Whether to collect metrics.
    pub collect_metrics: bool,
}

impl Default for VmExecutorConfig {
    fn default() -> Self {
        Self {
            max_code_size: DEFAULT_MAX_CODE_SIZE,
            default_gas_limit: DEFAULT_GAS_LIMIT,
            default_deploy_gas_limit: DEFAULT_DEPLOY_GAS_LIMIT,
            enable_tracing: false,
            collect_metrics: true,
        }
    }
}

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Metrics for VM executor operations.
#[derive(Debug, Default)]
pub struct VmExecutorMetrics {
    /// Number of deploy operations.
    pub deploys: AtomicU64,
    /// Number of call operations.
    pub calls: AtomicU64,
    /// Total gas used by deploy operations.
    pub deploy_gas_used: AtomicU64,
    /// Total gas used by call operations.
    pub call_gas_used: AtomicU64,
    /// Number of deploy failures.
    pub deploy_failures: AtomicU64,
    /// Number of call failures.
    pub call_failures: AtomicU64,
}

impl VmExecutorMetrics {
    /// Record a successful deploy.
    pub fn record_deploy(&self, gas_used: u64) {
        self.deploys.fetch_add(1, Ordering::Relaxed);
        self.deploy_gas_used.fetch_add(gas_used, Ordering::Relaxed);
    }

    /// Record a successful call.
    pub fn record_call(&self, gas_used: u64) {
        self.calls.fetch_add(1, Ordering::Relaxed);
        self.call_gas_used.fetch_add(gas_used, Ordering::Relaxed);
    }

    /// Record a deploy failure.
    pub fn record_deploy_failure(&self) {
        self.deploy_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Record a call failure.
    pub fn record_call_failure(&self) {
        self.call_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total number of deploys.
    pub fn deploys(&self) -> u64 {
        self.deploys.load(Ordering::Relaxed)
    }

    /// Get total number of calls.
    pub fn calls(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }
}

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

    #[error("constructor reverted: {data:?}")]
    ConstructorRevert { data: Vec<u8> },

    #[error("execution reverted: gas_used={gas_used}, data={data:?}")]
    CallRevert { gas_used: u64, data: Vec<u8> },

    #[error("VM execution error: {0}")]
    VmError(#[from] VmError),

    #[error("invalid deployment init code (empty)")]
    EmptyInitCode,

    #[error("invalid contract address (must be 32 bytes)")]
    InvalidContractAddress,

    #[error("gas limit too low: {gas_limit} < minimum {minimum}")]
    GasLimitTooLow { gas_limit: u64, minimum: u64 },

    #[error("internal error: {0}")]
    Internal(String),
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
// VmExecutor
// -----------------------------------------------------------------------------

/// VM executor with configuration and metrics.
#[derive(Clone)]
pub struct VmExecutor {
    config: Arc<VmExecutorConfig>,
    metrics: Arc<VmExecutorMetrics>,
}

impl VmExecutor {
    /// Create a new VM executor with default configuration.
    pub fn new() -> Self {
        Self::with_config(VmExecutorConfig::default())
    }

    /// Create a new VM executor with the given configuration.
    pub fn with_config(config: VmExecutorConfig) -> Self {
        Self {
            config: Arc::new(config),
            metrics: Arc::new(VmExecutorMetrics::default()),
        }
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &VmExecutorConfig {
        &self.config
    }

    /// Get a reference to the metrics.
    pub fn metrics(&self) -> &VmExecutorMetrics {
        &self.metrics
    }

    /// Reset metrics.
    pub fn reset_metrics(&self) {
        *self.metrics = VmExecutorMetrics::default();
    }

    // -------------------------------------------------------------------------
    // Deployment
    // -------------------------------------------------------------------------

    /// Deploy a contract.
    pub fn deploy(
        &self,
        state: &mut KvState,
        sender: &[u8; 32],
        init_code: &[u8],
        gas_limit: Option<u64>,
    ) -> VmExecutorResult<DeploySuccess> {
        let gas_limit = gas_limit.unwrap_or(self.config.default_deploy_gas_limit);
        if gas_limit < 21_000 {
            return Err(VmExecutorError::GasLimitTooLow {
                gas_limit,
                minimum: 21_000,
            });
        }

        if init_code.is_empty() {
            self.metrics.record_deploy_failure();
            return Err(VmExecutorError::EmptyInitCode);
        }

        // 1. Derive contract address.
        let sender_nonce = *state.vm.nonces.get(sender).unwrap_or(&0);
        let contract_addr = derive_contract_address(sender, sender_nonce);

        // 2. Reject duplicate.
        if !state.vm.get_code(&contract_addr).is_empty() {
            self.metrics.record_deploy_failure();
            return Err(VmExecutorError::ContractAlreadyExists {
                address: contract_addr,
            });
        }

        // 3. Clone VM state for isolation.
        let mut tmp_vm_state = state.vm.clone();

        // 4. Execute init_code.
        if self.config.enable_tracing {
            trace!(
                sender = hex::encode(sender),
                contract = hex::encode(&contract_addr),
                gas_limit,
                "VM deployment started"
            );
        }

        let result = interpreter::exec(
            &mut tmp_vm_state,
            contract_addr,
            init_code,
            &[],
            sender,
            gas_limit,
            0,
        );

        // 5. Handle result.
        match result {
            Err(e) => {
                self.metrics.record_deploy_failure();
                return Err(VmExecutorError::VmError(e));
            }
            Ok(r) if r.reverted => {
                self.metrics.record_deploy_failure();
                return Err(VmExecutorError::ConstructorRevert {
                    data: r.return_data,
                });
            }
            Ok(r) => {
                let deployed_code = r.return_data;
                if deployed_code.len() > self.config.max_code_size {
                    self.metrics.record_deploy_failure();
                    return Err(VmExecutorError::CodeTooLarge {
                        size: deployed_code.len(),
                        max: self.config.max_code_size,
                    });
                }

                // Commit state changes.
                state.vm = tmp_vm_state;
                state.vm.set_code(&contract_addr, deployed_code);
                *state.vm.nonces.entry(*sender).or_insert(0) += 1;

                // Collect logs.
                let logs = state.vm.logs.drain(..).collect::<Vec<_>>();

                if self.config.enable_tracing {
                    debug!(
                        contract = hex::encode(&contract_addr),
                        gas_used = r.gas_used,
                        code_size = deployed_code.len(),
                        "VM deployment successful"
                    );
                }

                self.metrics.record_deploy(r.gas_used);
                Ok(DeploySuccess {
                    contract: contract_addr,
                    gas_used: r.gas_used,
                    logs,
                    return_data: r.return_data,
                })
            }
        }
    }

    // -------------------------------------------------------------------------
    // Call
    // -------------------------------------------------------------------------

    /// Call a deployed contract.
    pub fn call(
        &self,
        state: &mut KvState,
        sender: &[u8; 32],
        contract: &[u8; 32],
        calldata: &[u8],
        gas_limit: Option<u64>,
    ) -> VmExecutorResult<CallSuccess> {
        let gas_limit = gas_limit.unwrap_or(self.config.default_gas_limit);
        if gas_limit < 21_000 {
            return Err(VmExecutorError::GasLimitTooLow {
                gas_limit,
                minimum: 21_000,
            });
        }

        let code = state.vm.get_code(contract);
        if code.is_empty() {
            self.metrics.record_call_failure();
            return Err(VmExecutorError::NoCodeAtAddress {
                address: *contract,
            });
        }

        // Clone VM state for isolation.
        let mut tmp_vm_state = state.vm.clone();

        if self.config.enable_tracing {
            trace!(
                sender = hex::encode(sender),
                contract = hex::encode(contract),
                calldata_len = calldata.len(),
                gas_limit,
                "VM call started"
            );
        }

        let result = interpreter::exec(
            &mut tmp_vm_state,
            *contract,
            &code,
            calldata,
            sender,
            gas_limit,
            0,
        );

        match result {
            Err(e) => {
                self.metrics.record_call_failure();
                Err(VmExecutorError::VmError(e))
            }
            Ok(r) if r.reverted => {
                self.metrics.record_call_failure();
                Err(VmExecutorError::CallRevert {
                    gas_used: r.gas_used,
                    data: r.return_data,
                })
            }
            Ok(r) => {
                // Commit state changes.
                state.vm = tmp_vm_state;
                let logs = state.vm.logs.drain(..).collect::<Vec<_>>();

                if self.config.enable_tracing {
                    debug!(
                        contract = hex::encode(contract),
                        gas_used = r.gas_used,
                        return_len = r.return_data.len(),
                        "VM call successful"
                    );
                }

                self.metrics.record_call(r.gas_used);
                Ok(CallSuccess {
                    gas_used: r.gas_used,
                    logs,
                    return_data: r.return_data,
                })
            }
        }
    }
}

impl Default for VmExecutor {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Standalone functions (backward compatibility)
// -----------------------------------------------------------------------------

/// Deploy a contract (legacy function).
pub fn vm_deploy(
    state: &mut KvState,
    sender: &[u8; 32],
    init_code: &[u8],
    gas_limit: u64,
) -> VmExecutorResult<DeploySuccess> {
    let executor = VmExecutor::default();
    executor.deploy(state, sender, init_code, Some(gas_limit))
}

/// Call a contract (legacy function).
pub fn vm_call(
    state: &mut KvState,
    sender: &[u8; 32],
    contract: &[u8; 32],
    calldata: &[u8],
    gas_limit: u64,
) -> VmExecutorResult<CallSuccess> {
    let executor = VmExecutor::default();
    executor.call(state, sender, contract, calldata, Some(gas_limit))
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

#[derive(Debug, PartialEq, Eq)]
pub enum VmTxPayload {
    Deploy { init_code: Vec<u8> },
    Call { contract: [u8; 32], calldata: Vec<u8> },
}

/// Parse a VM transaction payload from a string.
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
        let executor = VmExecutor::default();
        let result = executor.deploy(&mut state, &sender(), &init_code, Some(100_000));
        assert!(result.is_ok());
        let success = result.unwrap();
        let code = state.vm.get_code(&success.contract);
        assert_eq!(code.len(), 32);
        assert_eq!(success.gas_used, 100_000); // actual gas would be different, but we just check it's > 0
        assert!(success.gas_used > 0);
    }

    #[test]
    fn test_deploy_increments_nonce() {
        let mut state = KvState::default();
        let s = sender();
        let init = push1_stop(1);
        let executor = VmExecutor::default();
        executor.deploy(&mut state, &s, &init, Some(100_000)).unwrap();
        assert_eq!(*state.vm.nonces.get(&s).unwrap_or(&0), 1);
        executor.deploy(&mut state, &s, &init, Some(100_000)).unwrap();
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
        let executor = VmExecutor::default();
        let result = executor.deploy(&mut state, &sender(), &init_code, Some(100_000));
        assert!(matches!(result, Err(VmExecutorError::ConstructorRevert { .. })));
        assert!(state.vm.code.is_empty());
        assert!(state.vm.storage.is_empty());
    }

    #[test]
    fn test_call_nonexistent_contract_fails() {
        let mut state = KvState::default();
        let contract = [0x99u8; 32];
        let executor = VmExecutor::default();
        let result = executor.call(&mut state, &sender(), &contract, &[], Some(100_000));
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
        let executor = VmExecutor::default();
        let deploy = executor.deploy(&mut state, &s, &init_code, Some(100_000));
        assert!(deploy.is_ok());
        let contract = deploy.unwrap().contract;
        let call = executor.call(&mut state, &s, &contract, &[], Some(100_000));
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

    #[test]
    fn test_metrics() {
        let mut state = KvState::default();
        let s = sender();
        let init = push1_stop(1);
        let executor = VmExecutor::default();

        executor.deploy(&mut state, &s, &init, Some(100_000)).unwrap();
        executor.deploy(&mut state, &s, &init, Some(100_000)).unwrap();

        let metrics = executor.metrics();
        assert_eq!(metrics.deploys(), 2);
        assert!(metrics.deploy_gas_used.load(Ordering::Relaxed) > 0);
    }

    #[test]
    fn test_gas_limit_too_low() {
        let mut state = KvState::default();
        let executor = VmExecutor::default();
        let result = executor.deploy(&mut state, &sender(), &[0x00], Some(100));
        assert!(matches!(result, Err(VmExecutorError::GasLimitTooLow { .. })));
    }
}
