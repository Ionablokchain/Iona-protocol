//! IONA Virtual Machine — Quantum Architecture based on Hamiltonian Formalism.
//!
//! # Production Features
//! - Unified configuration via [`VmConfig`] (gas, opcodes, interpreter, quantum).
//! - [`VmMetrics`] with atomic counters for executions, instructions, gas,
//!   errors, and cumulative execution time.
//! - [`VmManager`] as a thread‑safe wrapper that can be shared via `Arc` and
//!   handed out to concurrent execution contexts.
//! - Structured logging with `tracing`.
//! - Quantum‑inspired API with configurable decoherence and measurement bases.
//! - Full test coverage for both classical and quantum execution paths.
//!
//! # Architectural notes
//!
//! This module previously declared `pub use interpreter::execute as
//! quantum_execute;` at the top *and* defined a local `pub fn
//! quantum_execute(...)` near the bottom. Those two names collided at the
//! crate root and prevented the module from compiling. The free function is
//! now named [`quantum_execute_legacy`] and the canonical entry point is
//! [`VmManager::quantum_execute`].
//!
//! The metrics `record_call_depth` used a `compare_exchange_weak` loop that
//! woke up on every failed CAS under contention. It now uses `fetch_max`,
//! which is a single atomic instruction.
//!
//! Every public fallible operation returns a typed error
//! ([`VmManagerError`] or [`QuantumError`]); the previous code mixed
//! `Result<_, String>` and `Result<_, VmError>` and never surfaced
//! configuration errors from the gas/opcode subsystems consistently.

pub mod errors;
pub mod gas;
pub mod interpreter;
pub mod opcodes;
pub mod state;

// ── Re-exports ────────────────────────────────────────────────────────────

pub use errors::VmError;
pub use gas::{GasConfig, GasManager, GasMeter};
pub use interpreter::{execute as execute_vm, ExecutionResult};
pub use opcodes::{Opcode as QuantumGate, OpcodeConfig, OpcodeRegistry};
pub use state::{KvState, Memory, VmState as VmStateTrait};

// ── External dependencies ────────────────────────────────────────────────

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{debug, info, warn};

use crate::types::Word;

// ── Errors ───────────────────────────────────────────────────────────────

/// Errors produced by the VM manager layer (configuration, orchestration).
///
/// Errors produced by the *interpreter* itself are [`VmError`] and are
/// returned via [`VmManagerError::Execution`].
#[derive(Debug, Error)]
pub enum VmManagerError {
    /// The VM configuration failed validation.
    #[error("invalid VM configuration: {0}")]
    Config(String),

    /// An opcode registry could not be built.
    #[error("opcode registry error: {0}")]
    OpcodeRegistry(String),

    /// The gas manager could not be built.
    #[error("gas manager error: {0}")]
    GasManager(String),

    /// The global VM manager was already installed.
    #[error("global VM manager already initialized")]
    AlreadyInitialized,

    /// The global VM manager has not been initialized yet.
    #[error("global VM manager is not initialized; call init_vm_manager first")]
    NotInitialized,

    /// A VM execution failed.
    #[error(transparent)]
    Execution(#[from] VmError),
}

pub type VmManagerResult<T> = Result<T, VmManagerError>;

// ── Configuration ────────────────────────────────────────────────────────

/// Unified configuration for the entire VM subsystem.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// Gas subsystem configuration.
    pub gas: GasConfig,
    /// Opcode registry configuration.
    pub opcodes: OpcodeConfig,
    /// Quantum emulation configuration.
    pub quantum: QuantumConfig,
    /// Maximum call depth (EIP-150 / EVM default is 1024).
    pub max_call_depth: usize,
    /// Maximum code size in bytes (EIP-170 default is 24 576).
    pub max_code_size: usize,
    /// Whether to record metrics.
    pub enable_metrics: bool,
    /// Whether to log every execution at INFO level. Off by default.
    pub log_execution: bool,
}

impl Default for VmConfig {
    fn default() -> Self {
        Self {
            gas: GasConfig::default(),
            opcodes: OpcodeConfig::default(),
            quantum: QuantumConfig::default(),
            max_call_depth: 1024,
            max_code_size: 24_576,
            enable_metrics: true,
            log_execution: false,
        }
    }
}

impl VmConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> VmManagerResult<()> {
        self.gas
            .validate()
            .map_err(|e| VmManagerError::Config(format!("gas: {e}")))?;
        self.opcodes
            .validate()
            .map_err(|e| VmManagerError::Config(format!("opcodes: {e}")))?;
        self.quantum
            .validate()
            .map_err(|e| VmManagerError::Config(format!("quantum: {e}")))?;
        if self.max_call_depth == 0 {
            return Err(VmManagerError::Config("max_call_depth must be > 0".into()));
        }
        if self.max_code_size == 0 {
            return Err(VmManagerError::Config("max_code_size must be > 0".into()));
        }
        Ok(())
    }
}

// ── Quantum configuration ────────────────────────────────────────────────

/// Configuration for the quantum emulation layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumConfig {
    /// Reduced Planck constant ℏ (natural units = 1.0).
    pub planck_constant: f64,
    /// Maximum coherence time, in evolution steps.
    pub coherence_time: u64,
    /// Maximum energy budget (maps to gas limit).
    pub energy_limit: u64,
    /// Environmental decoherence rate γ ∈ [0, 1].
    pub decoherence_rate: f64,
    /// Preferred measurement basis for readout.
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
        if !self.planck_constant.is_finite() || self.planck_constant <= 0.0 {
            return Err("planck_constant must be a positive finite number".into());
        }
        if self.coherence_time == 0 {
            return Err("coherence_time must be > 0".into());
        }
        if self.energy_limit == 0 {
            return Err("energy_limit must be > 0".into());
        }
        if !(0.0..=1.0).contains(&self.decoherence_rate) {
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

/// Atomic counters for the VM subsystem.
pub struct VmMetrics {
    pub executions: AtomicU64,
    pub instructions: AtomicU64,
    pub gas_consumed: AtomicU64,
    pub reverts: AtomicU64,
    pub out_of_gas: AtomicU64,
    pub invalid_opcodes: AtomicU64,
    pub max_call_depth_reached: AtomicUsize,
    pub success_count: AtomicU64,
    pub execution_time_ns: AtomicU64,
}

impl VmMetrics {
    pub const fn new() -> Self {
        Self {
            executions: AtomicU64::new(0),
            instructions: AtomicU64::new(0),
            gas_consumed: AtomicU64::new(0),
            reverts: AtomicU64::new(0),
            out_of_gas: AtomicU64::new(0),
            invalid_opcodes: AtomicU64::new(0),
            max_call_depth_reached: AtomicUsize::new(0),
            success_count: AtomicU64::new(0),
            execution_time_ns: AtomicU64::new(0),
        }
    }

    pub fn record_execution(&self, gas: u64, success: bool, duration: Duration) {
        self.executions.fetch_add(1, Ordering::Relaxed);
        self.gas_consumed.fetch_add(gas, Ordering::Relaxed);
        let ns = duration.as_nanos().min(u64::MAX as u128) as u64;
        self.execution_time_ns.fetch_add(ns, Ordering::Relaxed);
        if success {
            self.success_count.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_instructions(&self, n: u64) {
        if n > 0 {
            self.instructions.fetch_add(n, Ordering::Relaxed);
        }
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

    /// Update the maximum observed call depth. Uses `fetch_max` — a single
    /// atomic instruction that cannot loop under contention, unlike a
    /// `compare_exchange_weak` retry loop.
    pub fn record_call_depth(&self, depth: usize) {
        self.max_call_depth_reached.fetch_max(depth, Ordering::Relaxed);
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

    /// Reset every counter. Test-only.
    #[cfg(test)]
    pub fn reset(&self) {
        self.executions.store(0, Ordering::Relaxed);
        self.instructions.store(0, Ordering::Relaxed);
        self.gas_consumed.store(0, Ordering::Relaxed);
        self.reverts.store(0, Ordering::Relaxed);
        self.out_of_gas.store(0, Ordering::Relaxed);
        self.invalid_opcodes.store(0, Ordering::Relaxed);
        self.max_call_depth_reached.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        self.execution_time_ns.store(0, Ordering::Relaxed);
    }
}

impl Default for VmMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl core::fmt::Debug for VmMetrics {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("VmMetrics")
            .field("executions", &self.executions.load(Ordering::Relaxed))
            .field("gas_consumed", &self.gas_consumed.load(Ordering::Relaxed))
            .field("reverts", &self.reverts.load(Ordering::Relaxed))
            .finish()
    }
}

/// Snapshot of VM metrics.
#[derive(Debug, Clone, Copy, Default)]
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

// ── VmManager ───────────────────────────────────────────────────────────

/// Thread-safe facade over the VM subsystem.
///
/// `VmManager` is `Clone` and cheap to clone (everything is behind an
/// `Arc`). It owns the shared opcode registry, the shared gas manager, and
/// the shared metrics collector; callers can pass it to worker threads or
/// hand out clones to concurrent execution contexts.
#[derive(Clone)]
pub struct VmManager {
    config: Arc<VmConfig>,
    metrics: Arc<VmMetrics>,
    opcode_registry: Arc<OpcodeRegistry>,
    gas_manager: Arc<GasManager>,
}

impl VmManager {
    /// Create a new manager from `config`.
    pub fn new(config: VmConfig) -> VmManagerResult<Self> {
        config.validate()?;

        let metrics = Arc::new(VmMetrics::new());

        let opcode_registry = Arc::new(
            OpcodeRegistry::new(config.opcodes.clone())
                .map_err(|e| VmManagerError::OpcodeRegistry(e.to_string()))?,
        );

        let gas_manager = Arc::new(
            GasManager::new(config.gas.clone())
                .map_err(|e| VmManagerError::GasManager(e.to_string()))?,
        );

        Ok(Self {
            config: Arc::new(config),
            metrics,
            opcode_registry,
            gas_manager,
        })
    }

    pub fn config(&self) -> &VmConfig {
        &self.config
    }

    pub fn metrics_snapshot(&self) -> VmMetricsSnapshot {
        self.metrics.snapshot()
    }

    pub fn opcode_registry(&self) -> &OpcodeRegistry {
        &self.opcode_registry
    }

    pub fn gas_manager(&self) -> &GasManager {
        &self.gas_manager
    }

    /// Execute bytecode in the VM.
    ///
    /// This is the classical entry point. Quantum emulation is layered on
    /// top by [`Self::quantum_execute`].
    #[allow(clippy::too_many_arguments)]
    pub fn execute<S: VmStateTrait>(
        &self,
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
        if depth > self.config.max_call_depth {
            return Err(VmError::CallDepth {
                limit: self.config.max_call_depth,
            });
        }
        if code.len() > self.config.max_code_size {
            return Err(VmError::CodeTooLarge {
                size: code.len(),
                limit: self.config.max_code_size,
            });
        }

        let start = Instant::now();
        let result = interpreter::execute(
            state,
            contract,
            code,
            calldata,
            caller,
            call_value,
            gas_limit,
            depth,
            is_static,
        );
        let elapsed = start.elapsed();

        let success = result.is_ok();
        let gas_used = match &result {
            Ok(r) => r.gas_used,
            Err(_) => 0,
        };

        if self.config.enable_metrics {
            self.metrics.record_execution(gas_used, success, elapsed);
            self.metrics.record_call_depth(depth);
            if let Err(e) = &result {
                match e {
                    VmError::OutOfGas => self.metrics.record_out_of_gas(),
                    VmError::Revert { .. } => self.metrics.record_revert(),
                    VmError::InvalidOpcode { .. } => self.metrics.record_invalid_opcode(),
                    _ => {}
                }
            }
        }

        if self.config.log_execution {
            info!(
                contract = ?contract,
                gas_used,
                success,
                elapsed_ms = elapsed.as_millis(),
                "VM execution"
            );
        }

        result
    }

    /// Quantum-inspired execution with decoherence simulation.
    ///
    /// Runs the classical interpreter and then reports the measurement
    /// outcome alongside a **fidelity** value that decays exponentially
    /// with the fraction of the energy budget consumed:
    ///
    /// ```text
    /// γ  = (gas_used / energy_limit) * decoherence_rate
    /// F  = e^(-γ)
    /// ```
    ///
    /// A fidelity of `1.0` means the measurement was perfectly coherent;
    /// lower values indicate that the execution drifted toward the
    /// environment. Callers may use the fidelity to weight the outcome in
    /// consensus logic that tolerates bounded decoherence.
    #[allow(clippy::too_many_arguments)]
    pub fn quantum_execute<S: VmStateTrait>(
        &self,
        state: &mut S,
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
        quantum_config
            .validate()
            .map_err(QuantumError::InvalidConfig)?;

        let measurement = self.execute(
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

        if measurement.gas_used > quantum_config.energy_limit {
            return Err(QuantumError::EnergyBudgetExceeded {
                required: measurement.gas_used,
                available: quantum_config.energy_limit,
            });
        }

        let ratio = measurement.gas_used as f64 / quantum_config.energy_limit as f64;
        let gamma = ratio * quantum_config.decoherence_rate;
        let fidelity = (-gamma).exp().clamp(0.0, 1.0);

        Ok(QuantumVmResult {
            measurement,
            energy_consumed: measurement.gas_used,
            fidelity,
        })
    }
}

// ── Global singleton ────────────────────────────────────────────────────

static GLOBAL_VM_MANAGER: std::sync::OnceLock<VmManager> = std::sync::OnceLock::new();

/// Install the global VM manager. Idempotent-safe: a second call returns
/// [`VmManagerError::AlreadyInitialized`] rather than silently ignoring the
/// request.
pub fn init_vm_manager(config: VmConfig) -> VmManagerResult<()> {
    let manager = VmManager::new(config)?;
    GLOBAL_VM_MANAGER
        .set(manager)
        .map_err(|_| VmManagerError::AlreadyInitialized)
}

/// Access the global VM manager. Panics if [`init_vm_manager`] was never
/// called; use [`try_vm_manager`] if you want the fallible variant.
pub fn vm_manager() -> &'static VmManager {
    GLOBAL_VM_MANAGER
        .get()
        .expect("VM manager not initialized; call init_vm_manager first")
}

/// Fallible accessor for the global VM manager.
pub fn try_vm_manager() -> Option<&'static VmManager> {
    GLOBAL_VM_MANAGER.get()
}

// ── Quantum VM types ────────────────────────────────────────────────────

/// The quantum state of the VM: a classical state plus quantum observables.
#[derive(Debug, Clone)]
pub struct QuantumVmState {
    /// Underlying classical state used by the interpreter.
    pub classical_state: KvState,
    /// Entanglement entropy of the current execution branch.
    pub entanglement_entropy: f64,
    /// Coherence quality in `[0.0, 1.0]`; `1.0` is perfectly coherent.
    pub coherence_quality: f64,
}

impl QuantumVmState {
    pub fn new() -> Self {
        Self {
            classical_state: KvState::default(),
            entanglement_entropy: 0.0,
            coherence_quality: 1.0,
        }
    }

    pub fn from_classical(state: KvState) -> Self {
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

/// Result of a quantum-inspired execution.
#[derive(Debug, Clone)]
pub struct QuantumVmResult {
    /// Measurement outcome (the classical execution result).
    pub measurement: ExecutionResult,
    /// Energy consumed, equal to `measurement.gas_used`.
    pub energy_consumed: u64,
    /// Fidelity of the measurement against the ideal state.
    pub fidelity: f64,
}

/// Errors produced by the quantum emulation layer.
#[derive(Debug, Error)]
pub enum QuantumError {
    /// Classical execution failed.
    #[error(transparent)]
    Execution(#[from] VmError),

    /// The declared energy budget was exceeded.
    #[error("energy budget exceeded: required {required}, available {available}")]
    EnergyBudgetExceeded { required: u64, available: u64 },

    /// The quantum configuration failed validation.
    #[error("invalid quantum configuration: {0}")]
    InvalidConfig(String),
}

// ── Legacy free function ────────────────────────────────────────────────

/// Legacy quantum-execution entry point, retained for backward
/// compatibility.
///
/// Prefer [`VmManager::quantum_execute`] (or the global manager via
/// [`vm_manager`]) when you control the manager lifecycle. This wrapper
/// uses the global manager if installed, and otherwise constructs a
/// temporary manager from the default [`VmConfig`].
#[allow(clippy::too_many_arguments)]
pub fn quantum_execute_legacy(
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
    if let Some(manager) = try_vm_manager() {
        return manager.quantum_execute(
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
        );
    }

    let temp = VmManager::new(VmConfig::default())
        .map_err(|e| QuantumError::InvalidConfig(e.to_string()))?;
    let result = temp.quantum_execute(
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
    )?;

    // Update the wrapper's quantum observables.
    state.entanglement_entropy =
        -result.fidelity * result.fidelity.ln().max(0.0);
    state.coherence_quality = result.fidelity;

    Ok(result)
}

// ── Prelude ─────────────────────────────────────────────────────────────

/// Essential types for callers of the quantum VM.
pub mod prelude {
    pub use super::{
        execute_vm, init_vm_manager, quantum_execute_legacy, try_vm_manager,
        vm_manager, ExecutionResult, MeasurementBasis, QuantumConfig,
        QuantumError, QuantumGate, QuantumVmResult, QuantumVmState, VmConfig,
        VmError, VmManager, VmManagerError, VmManagerResult, VmMetrics,
        VmMetricsSnapshot,
    };
    pub use super::gas::GasMeter as EnergyMeter;
    pub use super::state::Memory as QuantumMemory;
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vm::state::KvState;

    fn simple_add_code() -> Vec<u8> {
        vec![
            0x60, 0x02, // PUSH1 2
            0x60, 0x03, // PUSH1 3
            0x01, // ADD
            0x60, 0x00, // PUSH1 0
            0x52, // MSTORE
            0x60, 0x20, // PUSH1 32
            0x60, 0x00, // PUSH1 0
            0xF3, // RETURN
        ]
    }

    fn simple_revert_code() -> Vec<u8> {
        vec![
            0x60, 0x10, // PUSH1 16
            0x60, 0x00, // PUSH1 0
            0xFD, // REVERT
        ]
    }

    // ── Configuration ─────────────────────────────────────────────────

    #[test]
    fn config_default_is_valid() {
        assert!(VmConfig::default().validate().is_ok());
    }

    #[test]
    fn config_rejects_zero_call_depth() {
        let mut c = VmConfig::default();
        c.max_call_depth = 0;
        assert!(matches!(c.validate(), Err(VmManagerError::Config(_))));
    }

    #[test]
    fn config_rejects_zero_code_size() {
        let mut c = VmConfig::default();
        c.max_code_size = 0;
        assert!(matches!(c.validate(), Err(VmManagerError::Config(_))));
    }

    #[test]
    fn quantum_config_default_is_valid() {
        assert!(QuantumConfig::default().validate().is_ok());
    }

    #[test]
    fn quantum_config_rejects_bad_values() {
        let mut c = QuantumConfig::default();
        c.planck_constant = 0.0;
        assert!(c.validate().is_err());

        c.planck_constant = 1.0;
        c.coherence_time = 0;
        assert!(c.validate().is_err());

        c.coherence_time = 1;
        c.decoherence_rate = 1.5;
        assert!(c.validate().is_err());

        c.decoherence_rate = 0.5;
        c.energy_limit = 0;
        assert!(c.validate().is_err());
    }

    // ── Manager ────────────────────────────────────────────────────────

    #[test]
    fn manager_creation() {
        let manager = VmManager::new(VmConfig::default()).unwrap();
        assert_eq!(manager.metrics_snapshot().executions, 0);
    }

    #[test]
    fn manager_creation_rejects_bad_config() {
        let mut c = VmConfig::default();
        c.max_call_depth = 0;
        assert!(matches!(
            VmManager::new(c),
            Err(VmManagerError::Config(_))
        ));
    }

    // ── Classical execution ────────────────────────────────────────────

    #[test]
    fn simple_execution_succeeds() {
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let code = simple_add_code();
        let result = manager
            .execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                0,
                false,
            )
            .unwrap();
        assert!(!result.reverted);
        assert!(result.gas_used > 0);
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.executions, 1);
        assert_eq!(snap.success_count, 1);
    }

    #[test]
    fn revert_is_recorded() {
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let code = simple_revert_code();
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
        assert!(matches!(result, Err(VmError::Revert { .. })));
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.executions, 1);
        assert_eq!(snap.reverts, 1);
        assert_eq!(snap.success_count, 0);
    }

    #[test]
    fn code_too_large_is_rejected_before_execution() {
        let mut c = VmConfig::default();
        c.max_code_size = 4;
        let manager = VmManager::new(c).unwrap();
        let mut state = KvState::default();
        let code = vec![0u8; 10];
        let err = manager
            .execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                0,
                false,
            )
            .unwrap_err();
        assert!(matches!(err, VmError::CodeTooLarge { .. }));
    }

    #[test]
    fn call_depth_limit_is_enforced() {
        let mut c = VmConfig::default();
        c.max_call_depth = 4;
        let manager = VmManager::new(c).unwrap();
        let mut state = KvState::default();
        let err = manager
            .execute(
                &mut state,
                [0u8; 32],
                &[0x00],
                &[],
                [0u8; 32],
                0,
                100_000,
                5,
                false,
            )
            .unwrap_err();
        assert!(matches!(err, VmError::CallDepth { .. }));
    }

    #[test]
    fn call_depth_metric_is_updated() {
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let code = vec![0x00]; // STOP
        manager
            .execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                5,
                false,
            )
            .unwrap();
        manager
            .execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                3,
                false,
            )
            .unwrap();
        let snap = manager.metrics_snapshot();
        assert_eq!(snap.max_call_depth_reached, 5);
    }

    // ── Quantum execution ──────────────────────────────────────────────

    #[test]
    fn quantum_execute_reports_fidelity() {
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let code = simple_add_code();
        let qcfg = QuantumConfig::default();
        let result = manager
            .quantum_execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                0,
                false,
                &qcfg,
            )
            .unwrap();
        assert!(!result.measurement.reverted);
        assert!(result.fidelity > 0.99);
        assert_eq!(result.energy_consumed, result.measurement.gas_used);
    }

    #[test]
    fn quantum_execute_rejects_energy_over_budget() {
        let mut qcfg = QuantumConfig::default();
        qcfg.energy_limit = 1; // Less than the intrinsic cost of any execution.
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let code = simple_add_code();
        let err = manager
            .quantum_execute(
                &mut state,
                [0u8; 32],
                &code,
                &[],
                [0u8; 32],
                0,
                100_000,
                0,
                false,
                &qcfg,
            )
            .unwrap_err();
        assert!(matches!(err, QuantumError::EnergyBudgetExceeded { .. }));
    }

    #[test]
    fn quantum_execute_rejects_invalid_config() {
        let mut qcfg = QuantumConfig::default();
        qcfg.decoherence_rate = 2.0;
        let manager = VmManager::new(VmConfig::default()).unwrap();
        let mut state = KvState::default();
        let err = manager
            .quantum_execute(
                &mut state,
                [0u8; 32],
                &[0x00],
                &[],
                [0u8; 32],
                0,
                100_000,
                0,
                false,
                &qcfg,
            )
            .unwrap_err();
        assert!(matches!(err, QuantumError::InvalidConfig(_)));
    }

    // ── Global manager ─────────────────────────────────────────────────

    #[test]
    fn legacy_quantum_execute_uses_temp_manager_when_uninitialized() {
        // No global manager is installed in the test binary (or if one is,
        // the legacy function uses it). Either path must succeed.
        let mut qstate = QuantumVmState::new();
        let result = quantum_execute_legacy(
            &mut qstate,
            &simple_add_code(),
            &[],
            [0u8; 32],
            [0u8; 32],
            0,
            100_000,
            0,
            false,
            &QuantumConfig::default(),
        );
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(!r.measurement.reverted);
    }

    #[test]
    fn metrics_reset_clears_counters() {
        let m = VmMetrics::new();
        m.record_execution(100, true, Duration::from_millis(1));
        m.record_revert();
        m.reset();
        let snap = m.snapshot();
        assert_eq!(snap.executions, 0);
        assert_eq!(snap.reverts, 0);
    }
}
