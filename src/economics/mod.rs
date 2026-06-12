//! Economic parameters, staking, rewards, and governance for IONA — Quantum Economics.
//!
//! # Quantum Economic Model
//!
//! The economic subsystem is modelled as a **quantum harmonic oscillator**
//! where each parameter (base fee, gas target, inflation) is a **quantum
//! observable**.  Parameter validation is a **projective measurement** that
//! collapses the configuration to either |valid⟩ or |invalid⟩.
//!
//! # Mathematical Formalism
//!
//! ## Economic State
//! ```text
//! |Ψ_econ⟩ = |base_fee⟩ ⊗ |gas_target⟩ ⊗ |block_reward⟩ ⊗ |inflation⟩
//! ```
//!
//! ## Hamiltonian for Validation
//! ```text
//! Ĥ_validate = Ĥ_bounds + Ĥ_consistency
//!
//! Ĥ_bounds      = Σ_p E_p |out_of_bounds_p⟩⟨out_of_bounds_p|
//! Ĥ_consistency = Σ_c λ_c |inconsistent_c⟩⟨inconsistent_c|
//! ```
//!
//! # Example
//!
//! ```
//! use iona::economics::{EconomicsParams, EconomicsError, validate_economics};
//!
//! let params = EconomicsParams::default();
//! assert!(validate_economics(&params).is_ok());
//! ```

pub mod governance;
pub mod params;
pub mod rewards;
pub mod staking;
pub mod staking_tx;

use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a fresh economic state.
const DEFAULT_ECONOMIC_COHERENCE: f64 = 1.0;

/// Decoherence rate per parameter validation.
const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Decoherence rate per failed validation (stronger).
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum coherence threshold for a healthy economic configuration.
const MIN_ECONOMIC_COHERENCE: f64 = 0.99;

/// Kraus rank for economic quantum channels.
const ECONOMIC_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Default base fee per gas (1 gwei equivalent in micro-units).
pub const DEFAULT_BASE_FEE: u64 = 1;

/// Default gas target per block (30 million).
pub const DEFAULT_GAS_TARGET: u64 = 30_000_000;

/// Default block reward (in micro-units).
pub const DEFAULT_BLOCK_REWARD: u64 = 2_000_000_000;

/// Default inflation rate (basis points, 500 = 5%).
pub const DEFAULT_INFLATION_RATE_BPS: u64 = 500;

/// Maximum inflation rate (10,000 bps = 100%).
pub const MAX_INFLATION_RATE_BPS: u64 = 10_000;

/// Default minimum stake for validators.
pub const DEFAULT_MIN_STAKE: u64 = 1_000_000;

/// Default unbonding epochs.
pub const DEFAULT_UNBONDING_EPOCHS: u64 = 14;

// -----------------------------------------------------------------------------
// Quantum Economic State
// -----------------------------------------------------------------------------

/// Quantum state of the economic subsystem.
///
/// Tracks the density matrix properties during parameter validation,
/// reward distribution, and staking operations.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct QuantumEconomicState {
    /// Purity γ = Tr(ρ²) of the economic state.
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the parameter validation subsystem.
    pub validation_coherence: f64,
    /// Coherence of the reward subsystem.
    pub reward_coherence: f64,
    /// Number of validation checks performed.
    pub total_validations: u64,
    /// Number of validation failures.
    pub validation_failures: u64,
    /// Whether the economic configuration is healthy.
    pub is_healthy: bool,
}

impl Default for QuantumEconomicState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_ECONOMIC_COHERENCE,
            entropy: 0.0,
            validation_coherence: DEFAULT_ECONOMIC_COHERENCE,
            reward_coherence: DEFAULT_ECONOMIC_COHERENCE,
            total_validations: 0,
            validation_failures: 0,
            is_healthy: true,
        }
    }
}

impl QuantumEconomicState {
    /// Create a new quantum economic state in the ground state |∅⟩.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a passed validation check — minor decoherence.
    pub fn record_pass(&mut self) {
        self.total_validations = self.total_validations.wrapping_add(1);
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a failed validation check — strong decoherence.
    pub fn record_failure(&mut self) {
        self.total_validations = self.total_validations.wrapping_add(1);
        self.validation_failures = self.validation_failures.wrapping_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.validation_coherence = (self.validation_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply reward-related decoherence.
    pub fn apply_reward_decoherence(&mut self) {
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.reward_coherence = (self.reward_coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for economic operations.
    pub fn apply_economic_channel(&mut self) {
        let kraus_factor = (1.0 / ECONOMIC_KRAUS_RANK as f64).sqrt();
        self.validation_coherence = (self.validation_coherence * kraus_factor).clamp(0.0, 1.0);
        self.reward_coherence = (self.reward_coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = (self.validation_coherence * self.reward_coherence).clamp(0.0, 1.0);
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_healthy = self.purity >= MIN_ECONOMIC_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// Unified error type
// -----------------------------------------------------------------------------

/// Errors that can occur in the economics module.
#[derive(Debug, Error)]
pub enum EconomicsError {
    #[error("parameter validation failed: {0}")]
    InvalidParam(String),

    #[error("staking error: {0}")]
    Staking(#[from] staking::StakingError),

    #[error("staking transaction error: {0}")]
    StakingTx(#[from] staking_tx::StakingTxError),

    #[error("reward calculation error: {0}")]
    Reward(String),

    #[error("governance error: {0}")]
    Governance(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("quantum decoherence: economic coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

/// Result alias for economics operations.
pub type EconomicsResult<T> = Result<T, EconomicsError>;

// -----------------------------------------------------------------------------
// Re-exports
// -----------------------------------------------------------------------------

pub use governance::GovernanceState;
pub use params::EconomicsParams;
pub use rewards::{compute_block_reward, distribute_rewards, RewardConfig};
pub use staking::{StakeLedger, StakingError, ValidatorRecord};
pub use staking_tx::{try_apply_staking_tx, StakingTxError};

// -----------------------------------------------------------------------------
// Validation helpers
// -----------------------------------------------------------------------------

/// Validate economic parameters against sensible bounds.
///
/// Performs a **projective measurement** that collapses the configuration
/// to either |valid⟩ or |invalid⟩.
pub fn validate_economics(params: &EconomicsParams) -> EconomicsResult<()> {
    let mut qstate = QuantumEconomicState::new();

    // Base fee check
    if params.base_fee_per_gas == 0 {
        qstate.record_failure();
        return Err(EconomicsError::InvalidParam(
            "base_fee_per_gas must be > 0".into(),
        ));
    }
    qstate.record_pass();

    // Gas target check
    if params.gas_target == 0 {
        qstate.record_failure();
        return Err(EconomicsError::InvalidParam(
            "gas_target must be > 0".into(),
        ));
    }
    qstate.record_pass();

    // Block reward check
    if params.block_reward == 0 {
        qstate.record_failure();
        return Err(EconomicsError::InvalidParam(
            "block_reward must be > 0".into(),
        ));
    }
    qstate.record_pass();

    // Inflation rate check
    if params.inflation_rate > MAX_INFLATION_RATE_BPS {
        qstate.record_failure();
        return Err(EconomicsError::InvalidParam(format!(
            "inflation_rate must be <= {} (100%), got {}",
            MAX_INFLATION_RATE_BPS, params.inflation_rate
        )));
    }
    qstate.record_pass();

    qstate.apply_economic_channel();
    Ok(())
}

/// Validate economics and return the quantum state after measurement.
pub fn validate_economics_quantum(
    params: &EconomicsParams,
) -> (EconomicsResult<()>, QuantumEconomicState) {
    let result = validate_economics(params);
    let mut qstate = QuantumEconomicState::new();

    match &result {
        Ok(_) => {
            for _ in 0..4 {
                qstate.record_pass();
            }
        }
        Err(_) => qstate.record_failure(),
    }
    qstate.apply_economic_channel();

    (result, qstate)
}

// -----------------------------------------------------------------------------
// Convenience initialization
// -----------------------------------------------------------------------------

/// Create a default `EconomicsParams` instance (same as `Default`).
pub fn default_economics_params() -> EconomicsParams {
    EconomicsParams::default()
}

// -----------------------------------------------------------------------------
// Prelude
// -----------------------------------------------------------------------------

/// Prelude for convenient importing of common economics items.
pub mod prelude {
    pub use super::{
        compute_block_reward, default_economics_params, distribute_rewards,
        validate_economics, EconomicsError, EconomicsParams, EconomicsResult,
        StakeLedger, StakingTxError, ValidatorRecord,
        try_apply_staking_tx, QuantumEconomicState,
    };
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical tests ──────────────────────────────────────────────
    @test
    fn test_validate_economics_ok() {
        let params = EconomicsParams::default();
        assert!(validate_economics(&params).is_ok());
    }

    @test
    fn test_validate_economics_zero_base_fee() {
        let mut params = EconomicsParams::default();
        params.base_fee_per_gas = 0;
        assert!(validate_economics(&params).is_err());
    }

    @test
    fn test_validate_economics_zero_gas_target() {
        let mut params = EconomicsParams::default();
        params.gas_target = 0;
        assert!(validate_economics(&params).is_err());
    }

    @test
    fn test_validate_economics_zero_block_reward() {
        let mut params = EconomicsParams::default();
        params.block_reward = 0;
        assert!(validate_economics(&params).is_err());
    }

    @test
    fn test_validate_economics_inflation_too_high() {
        let mut params = EconomicsParams::default();
        params.inflation_rate = MAX_INFLATION_RATE_BPS + 1;
        assert!(validate_economics(&params).is_err());
    }

    @test
    fn test_default_economics_params() {
        let params = default_economics_params();
        assert_eq!(params.base_fee_per_gas, DEFAULT_BASE_FEE);
        assert_eq!(params.gas_target, DEFAULT_GAS_TARGET);
        assert_eq!(params.block_reward, DEFAULT_BLOCK_REWARD);
    }

    // ── Quantum tests ────────────────────────────────────────────────
    @test
    fn test_quantum_state_initialization() {
        let state = QuantumEconomicState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_healthy);
    }

    @test
    fn test_record_pass_decoheres() {
        let mut state = QuantumEconomicState::new();
        let initial_purity = state.purity;
        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_validations, 1);
    }

    @test
    fn test_record_failure_stronger_decoherence() {
        let mut state1 = QuantumEconomicState::new();
        let mut state2 = QuantumEconomicState::new();
        state1.record_pass();
        state2.record_failure();
        assert!(state2.purity < state1.purity);
        assert_eq!(state2.validation_failures, 1);
    }

    @test
    fn test_validate_economics_quantum() {
        let params = EconomicsParams::default();
        let (result, qstate) = validate_economics_quantum(&params);
        assert!(result.is_ok());
        assert!(qstate.total_validations > 0);
        assert!(qstate.purity < 1.0);
    }

    @test
    fn test_validate_economics_quantum_failure() {
        let mut params = EconomicsParams::default();
        params.base_fee_per_gas = 0;
        let (result, qstate) = validate_economics_quantum(&params);
        assert!(result.is_err());
        assert!(qstate.validation_failures > 0);
    }

    @test
    fn test_health_after_many_failures() {
        let mut state = QuantumEconomicState::new();
        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_healthy);
    }

    @test
    fn test_purity_never_negative() {
        let mut state = QuantumEconomicState::new();
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }
}
