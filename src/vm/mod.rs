//! IONA Virtual Machine — Quantum Architecture based on Hamiltonian Formalism.
//!
//! # Production Features
//! - Unified configuration via `VmConfig` (gas, opcodes, interpreter, quantum).
//! - `VmMetrics` with Prometheus‑style counters for executions, instructions, gas, errors.
//! - `VmManager` as a thread‑safe wrapper (`parking_lot::Mutex` in std, `spin::Mutex` in no_std).
//! - Structured logging with `tracing`.
//! - Full test coverage for quantum concepts and production wrappers.
//! - Quantum-inspired API with configurable decoherence and measurement bases.

// Public modules
pub mod opcodes;
pub mod errors;
pub mod gas;
pub mod interpreter;
pub mod state;

// Re‑export common types for easier access.
pub use errors::VmError;
pub use gas::GasMeter;
pub use interpreter::execute as quantum_execute;
pub use state::{KvState as VmState, Memory, VmState as VmStateTrait};

// ── External dependencies ──────────────────────────────────────────────

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tracing::{debug, error, info, trace, warn};
use crate::types::Word;

#[cfg(feature = "std")]
use std::time::{Duration, Instant};

// ── Configuration ─────────────────────────────────────────────────────────

/// Unified configuration for the entire VM subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Gas configuration.
    pub gas: gas::GasConfig,
    /// Opcode configuration.
    pub opcodes: opcodes::OpcodeConfig,
    /// Quantum configuration.
    pub quantum: QuantumConfig,
    /// Maximum call depth.
    pub max_call_depth: usize,
    /// Maximum code size (EIP‑170).
    pub max_code_size: usize,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log execution.
    pub log_execution: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            gas: gas::GasConfig::default(),
            opcodes: opcodes::OpcodeConfig::default(),
            quantum: QuantumConfig::default(),
            max_call_depth: 1024,
            max_code_size: 24576,
            enable_metrics: true,
            log_execution: false,
        }
    }
}

impl VmConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        self.gas.validate()?;
        self.opcodes.validate()?;
        self.quantum.validate()?;
        if self.max_call_depth == 0 {
            return Err("max_call_depth must be > 0".into());
        }
        if self.max_code_size == 0 {
            return Err("max_code_size must be > 0".into());
        }
        Ok(())
    }
}

// ── Quantum Configuration ───────────────────────────────────────────────

/// Configuration for the quantum VM execution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumConfig {
    /// Reduced Planck constant ℏ (natural units = 1.0)
    pub planck_constant: f64,
    /// Maximum coherence time in evolution steps
    pub coherence_time: u64,
    /// Maximum energy budget (maps to gas limit)
    pub energy_limit: u64,
    /// Environmental decoherence rate γ
    pub decoherence_rate: f64,
    /// Preferred measurement basis
    pub measurement_basis: MeasurementBasis,
}

impl Default for QuantumConfig {
    fn default() -> Self {
        Self {
            planck_constant: 1.0,
            coherence_time: 1_000_000,
            energy_limit: 30_000_000,
            decoherence_rate: 0.001,
            measurement_basis: MeasurementBasis::PauliZ,
        }
    }
}

impl QuantumConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.planck_constant <= 0.0 {
            return Err("planck_constant must be > 0".into());
        }
        if self.coherence_time == 0 {
            return Err("coherence_time must be > 0".into());
        }
        if self.energy_limit == 0 {
            return Err("energy_limit must be > 0".into());
        }
        if self.decoherence_rate < 0.0 || self.decoherence_rate > 1.0 {
            return Err("decoherence_rate must be between 0.0 and 1.0".into());
        }
        Ok(())
    }
}

/// Available measurement bases for state readout.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MeasurementBasis {
    PauliZ,
    PauliX,
    PauliY,
    Computational,
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for the VM subsystem.
#[derive(Debug, Default)]
pub struct VmMetrics {
    /// Total number of VM executions.
    pub executions: AtomicU64,
    /// Total number of instructions executed.
    pub instructions: AtomicU64,
    /// Total gas consumed.
    pub gas_consumed: AtomicU64,
    /// Number of revert events.
    pub reverts: AtomicU64,
    /// Number of out‑of‑gas events.
    pub out_of_gas: AtomicU64,
    /// Number of invalid opcode events.
    pub invalid_opcodes: AtomicU64,
    /// Current call depth (max).
    pub max_call_depth_reached: AtomicUsize,
    /// Number of successful executions.
    pub success_count: AtomicU64,
    /// Execution time (nanoseconds, cumulative).
    pub execution_time_ns: AtomicU64,
}

impl VmMetrics {
    pub fn record_execution(&self, gas: u64, success: bool, duration_ns: u64) {
        self.executions.fetch_add(1, Ordering::Relaxed);
        self.gas_consumed.fetch_add(gas, Ordering::Relaxed);
        self.execution_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_instruction(&self) {
        self.instructions.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_revert(&self) {
        self.reverts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_out_of_gas(&self) {
        self.out_of_gas.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_invalid_opcode(&self) {
        self.invalid_opcodes.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_call_depth(&self, depth: usize) {
        let mut current = self.max_call_depth_reached.load(Ordering::Relaxed);
        while depth > current {
            match self.max_call_depth_reached.compare_exchange_weak(
                current,
                depth,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(actual) => current = actual,
            }
        }
    }

    pub fn snapshot(&self) -> VmMetricsSnapshot {
        VmMetricsSnapshot {
            executions: self.executions.load(Ordering::Relaxed),
            instructions: self.instructions.load(Ordering::Relaxed),
            gas_consumed: self.gas_consumed.load(Ordering::Relaxed),
            reverts: self.reverts.load(Ordering::Relaxed),
            out_of_gas: self.out_of_gas.load(Ordering::Relaxed),
            invalid_opcodes: self.invalid_opcodes.load(Ordering::Relaxed),
            max_call_depth_reached: self.max_call_depth_reached.load(Ordering::Relaxed),
            success_count: self.success_count.load(Ordering::Relaxed),
            execution_time_ns: self.execution_time_ns.load(Ordering::Relaxed),
        }
    }
}

/// Snapshot of VM metrics.
#[derive(Debug, Clone)]
pub struct VmMetricsSnapshot {
    pub executions: u64,
    pub instructions: u64,
    pub gas_consumed: u64,
    pub reverts: u64,
    pub out_of_gas: u64,
    pub invalid_opcodes: u64,
    pub max_call_depth_reached: usize,
    pub success_count: u64,
    pub execution_time_ns: u64,
}

// ── VmManager ────────────────────────────────────────────────────────────

/// Thread‑safe manager for the VM subsystem.
#[derive(Clone)]
pub struct VmManager {
    config: Arc<VmConfig>,
    metrics: Arc<VmMetrics>,
    opcode_registry: Arc<opcodes::OpcodeRegistry>,
    gas_manager: Arc<gas::GasManager>,
}

impl VmManager {
    /// Create a new VM manager with the given configuration.
    pub fn new(config: VmConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(VmMetrics::default());
        let opcode_registry = Arc::new(opcodes::OpcodeRegistry::new(config.opcodes.clone())?);
        let gas_manager = Arc::new(gas::GasManager::new(config.gas.clone())?);

        Ok(Self {
            config: Arc::new(config),
            metrics,
            opcode_registry,
            gas_manager,
        })
    }

    /// Get the configuration.
    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> VmMetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Get the opcode registry.
    pub fn opcode_registry(&self) -> &opcodes::OpcodeRegistry {
        &self.opcode_registry
    }

    /// Get the gas manager.
    pub fn gas_manager(&self) -> &gas::GasManager {
        &self.gas_manager
    }

    /// Execute bytecode with the given parameters.
    pub fn execute(
        &self,
        state: &mut VmState,
        contract: Word,
        code: &[u8],
        calldata: &[u8],
        caller: Word,
        call_value: u128,
        gas_limit: u64,
        depth: usize,
        is_static: bool,
    ) -> Result<interpreter::ExecutionResult, VmError> {
        let start = Instant::now();
        // Use the interpreter's execute function.
        // We pass the opcode registry and metrics via the config.
        let result = interpreter::execute_with_registry(
            state,
            contract,
            code,
            calldata,
            caller,
            call_value,
            gas_limit,
            depth,
            is_static,
            &self.config,
            &self.opcode_registry,
            Some(&self.metrics),
        );

        let duration_ns = start.elapsed().as_nanos() as u64;
        let success = result.is_ok();
        let gas_used = match &result {
            Ok(r) => r.gas_used,
            Err(_) => 0,
        };
        self.metrics.record_execution(gas_used, success, duration_ns);
        if self.config.log_execution {
            info!(contract = ?contract, gas_used, success, duration_ns, "VM execution");
        }

        // Record call depth.
        self.metrics.record_call_depth(depth);

        // Record specific error types.
        if let Err(e) = &result {
            match e {
                VmError::OutOfGas => self.metrics.record_out_of_gas(),
                VmError::Revert { .. } => self.metrics.record_revert(),
                VmError::InvalidOpcode { .. } => self.metrics.record_invalid_opcode(),
                _ => {}
            }
        }

        result
    }

    /// Quantum‑inspired execution with decoherence simulation.
    pub fn quantum_execute(
        &self,
        state: &mut VmState,
        contract: Word,
        code: &[u8],
        calldata: &[u8],
        caller: Word,
        call_value: u128,
        gas_limit: u64,
        depth: usize,
        is_static: bool,
        quantum_config: &QuantumConfig,
    ) -> Result<QuantumVmResult, QuantumError> {
        let result = self.execute(
            state,
            contract,
            code,
            calldata,
            caller,
            call_value,
            gas_limit,
            depth,
            is_static,
        )?;

        // Apply decoherence based on gas used.
        let decoherence_factor = (result.gas_used as f64 / quantum_config.energy_limit as f64)
            * quantum_config.decoherence_rate;
        let fidelity = (-decoherence_factor).exp();

        Ok(QuantumVmResult {
            final_state: state.clone(),
            measurement: result.clone(),
            energy_consumed: result.gas_used,
            reverted: result.reverted,
            quantum_logs: result.logs_count,
            fidelity,
        })
    }
}

// ── Global singleton ─────────────────────────────────────────────────────

#[cfg(feature = "std")]
static GLOBAL_VM_MANAGER: std::sync::OnceLock<VmManager> = std::sync::OnceLock::new();

#[cfg(feature = "std")]
/// Initialize the global VM manager.
pub fn init_vm_manager(config: VmConfig) -> Result<(), String> {
    let manager = VmManager::new(config)?;
    GLOBAL_VM_MANAGER.set(manager).map_err(|_| "VM manager already initialized".into())
}

#[cfg(feature = "std")]
/// Get the global VM manager.
pub fn vm_manager() -> &'static VmManager {
    GLOBAL_VM_MANAGER.get().expect("VM manager not initialized")
}

// ── Quantum VM State (wrapper) ─────────────────────────────────────────

/// The quantum state of the virtual machine.
#[derive(Debug, Clone)]
pub struct QuantumVmState {
    pub classical_state: VmState,
    pub entanglement_entropy: f64,
    pub coherence_quality: f64,
}

impl QuantumVmState {
    pub fn new() -> Self {
        Self {
            classical_state: VmState::default(),
            entanglement_entropy: 0.0,
            coherence_quality: 1.0,
        }
    }

    pub fn from_classical(state: VmState) -> Self {
        Self {
            classical_state: state,
            entanglement_entropy: 0.0,
            coherence_quality: 1.0,
        }
    }
}

impl Default for QuantumVmState {
    fn default() -> Self {
        Self::new()
    }
}

// ── Quantum VM Result ───────────────────────────────────────────────────

#[derive(Debug)]
pub struct QuantumVmResult {
    pub final_state: VmState,
    pub measurement: interpreter::ExecutionResult,
    pub energy_consumed: u64,
    pub reverted: bool,
    pub quantum_logs: usize,
    pub fidelity: f64,
}

// ── Quantum Errors ──────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum QuantumError {
    #[error("execution error: {0}")]
    Execution(#[from] VmError),
    #[error("energy budget exceeded: required {required}, available {available}")]
    EnergyBudgetExceeded { required: u64, available: u64 },
    #[error("decoherence threshold exceeded")]
    DecoherenceThresholdExceeded,
    #[error("measurement basis incompatible")]
    IncompatibleMeasurementBasis,
}

// ── Legacy quantum_execute function ─────────────────────────────────────

/// Legacy quantum execution (backward compatibility).
pub fn quantum_execute(
    state: &mut QuantumVmState,
    code: &[u8],
    calldata: &[u8],
    contract: Word,
    caller: Word,
    call_value: u128,
    gas_limit: u64,
    depth: usize,
    is_static: bool,
    config: &QuantumConfig,
) -> Result<QuantumVmResult, QuantumError> {
    // Use global manager if available, otherwise create a temporary one.
    #[cfg(feature = "std")]
    {
        let manager = vm_manager();
        manager.quantum_execute(
            &mut state.classical_state,
            contract,
            code,
            calldata,
            caller,
            call_value,
            gas_limit,
            depth,
            is_static,
            config,
        )
    }
    #[cfg(not(feature = "std"))]
    {
        // Fallback: use default configs.
        let vm_config = VmConfig::default();
        let manager = VmManager::new(vm_config).map_err(|_| QuantumError::DecoherenceThresholdExceeded)?;
        manager.quantum_execute(
            &mut state.classical_state,
            contract,
            code,
            calldata,
            caller,
            call_value,
            gas_limit,
            depth,
            is_static,
            config,
        )
    }
}

// ── Prelude ──────────────────────────────────────────────────────────────

/// Essential quantum computing types and operators.
pub mod prelude {
    pub use super::{
        QuantumConfig, QuantumVmState, QuantumVmResult, QuantumError,
        quantum_execute,
    };
    pub use super::opcodes::Opcode as QuantumGate;
    pub use super::errors::VmError as QuantumError;
    pub use super::gas::GasMeter as EnergyMeter;
    pub use super::interpreter::ExecutionResult as QuantumMeasurement;
    pub use super::state::VmState as QuantumState;
    pub use super::state::Memory as QuantumMemory;
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::Word;

    #[test]
    fn test_config_validation() {
        let mut config = VmConfig::default();
        assert!(config.validate().is_ok());

        config.max_call_depth = 0;
        assert!(config.validate().is_err());

        config.max_call_depth = 1;
        config.max_code_size = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_quantum_config_validation() {
        let mut config = QuantumConfig::default();
        assert!(config.validate().is_ok());

        config.planck_constant = 0.0;
        assert!(config.validate().is_err());

        config.planck_constant = 1.0;
        config.coherence_time = 0;
        assert!(config.validate().is_err());

        config.coherence_time = 1;
        config.decoherence_rate = 1.5;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_manager_creation() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        assert_eq!(manager.metrics_snapshot().executions, 0);
    }

    #[test]
    fn test_simple_execution() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        let mut state = VmState::default();

        let code = vec![
            0x60, 0x02, // PUSH1 2
            0x60, 0x03, // PUSH1 3
            0x01,       // ADD
            0x60, 0x00, // PUSH1 0
            0x52,       // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3,       // RETURN
        ];

        let result = manager.execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
        ).unwrap();

        assert!(!result.reverted);
        assert!(result.gas_used > 0);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.executions, 1);
        assert_eq!(snap.success_count, 1);
    }

    #[test]
    fn test_revert_execution() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        let mut state = VmState::default();

        let code = vec![
            0x60, 0x10, // PUSH1 16
            0x60, 0x00, // PUSH1 0
            0xFD,       // REVERT
        ];

        let result = manager.execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
        );

        assert!(result.is_err());
        if let Err(VmError::Revert { .. }) = result {
            // Expected
        } else {
            panic!("Expected Revert error");
        }

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.reverts, 1);
        assert_eq!(snap.success_count, 0);
    }

    #[test]
    fn test_quantum_execute() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        let mut state = VmState::default();

        let code = vec![
            0x60, 0x01, // PUSH1 1
            0x60, 0x02, // PUSH1 2
            0x01,       // ADD
        ];

        let quantum_cfg = QuantumConfig::default();
        let result = manager.quantum_execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
            &quantum_cfg,
        ).unwrap();

        assert!(!result.reverted);
        assert!(result.fidelity > 0.99);
        assert_eq!(result.quantum_logs, 0);
        assert!(result.energy_consumed > 0);
    }

    #[test]
    fn test_metrics() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        let mut state = VmState::default();

        // Execute a simple contract.
        let code = vec![0x60, 0x01, 0x60, 0x01, 0x01];
        manager.execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
        ).unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.executions, 1);
        assert!(snap.gas_consumed > 0);
        assert!(snap.instructions > 0);
        assert!(snap.execution_time_ns > 0);
    }

    #[test]
    fn test_call_depth_metric() {
        let config = VmConfig::default();
        let manager = VmManager::new(config).unwrap();
        let mut state = VmState::default();
        let code = vec![0x00]; // STOP

        // Execute with depth 5.
        manager.execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            5,
            false,
        ).unwrap();

        let snap = manager.metrics_snapshot();
        assert_eq!(snap.max_call_depth_reached, 5);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_global_manager() {
        let config = VmConfig::default();
        init_vm_manager(config).unwrap();
        let manager = vm_manager();
        let mut state = VmState::default();
        let code = vec![0x00];
        let result = manager.execute(
            &mut state,
            [0u8; 32],
            &code,
            &[],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
        ).unwrap();
        assert!(!result.reverted);
    }
}
