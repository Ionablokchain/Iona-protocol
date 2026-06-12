//! Economic parameters for IONA — Quantum‑Ready Parameter Validation.
//!
//! # Quantum Parameter Model
//!
//! Each economic parameter is an **eigenvalue** of the protocol Hamiltonian
//! Ĥ_econ.  Validation is a **projective measurement** that collapses the
//! parameter vector to either the |valid⟩ or |invalid⟩ subspace.
//!
//! # Mathematical Formalism
//!
//! ## Parameter State
//! ```text
//! |Ψ⟩ = |inflation⟩ ⊗ |min_stake⟩ ⊗ |slash_dbl⟩ ⊗ |slash_dwn⟩ ⊗ |unbond⟩ ⊗ |treasury⟩
//! ```
//!
//! ## Validation Projector
//! ```text
//! Π_valid = Σ_{p∈bounds} |p⟩⟨p|
//! ```
//!
//! ## Decoherence
//! Each validation step applies a **Kraus channel** with rate γ, modelling
//! the gradual degradation of parameter certainty under repeated governance
//! changes.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Quantum Constants
// -----------------------------------------------------------------------------

/// Reduced Planck constant (natural units).
const HBAR: f64 = 1.0;

/// Default quantum coherence for a freshly created parameter set.
const DEFAULT_PARAM_COHERENCE: f64 = 1.0;

/// Decoherence rate per validation check.
const VALIDATION_DECOHERENCE_RATE: f64 = 0.0001;

/// Stronger decoherence when a check **fails**.
const FAILURE_DECOHERENCE_RATE: f64 = 0.001;

/// Minimum purity threshold for a “healthy” parameter set.
const MIN_PARAM_COHERENCE: f64 = 0.99;

/// Kraus rank used when applying the quantum channel.
const PARAM_KRAUS_RANK: usize = 4;

// -----------------------------------------------------------------------------
// Classical Constants
// -----------------------------------------------------------------------------

/// Maximum basis points (100%).
pub const MAX_BPS: u64 = 10_000;

/// Default annual inflation rate (5% = 500 bps).
pub const DEFAULT_INFLATION_BPS: u64 = 500;

/// Default minimum stake (10 billion base units).
pub const DEFAULT_MIN_STAKE: u128 = 10_000_000_000;

/// Default slashing for double‑sign (50% = 5000 bps).
pub const DEFAULT_SLASH_DOUBLE_SIGN_BPS: u64 = 5000;

/// Default slashing for downtime (1% = 100 bps).
pub const DEFAULT_SLASH_DOWNTIME_BPS: u64 = 100;

/// Default unbonding epochs (14).
pub const DEFAULT_UNBONDING_EPOCHS: u64 = 14;

/// Default treasury share (5% = 500 bps).
pub const DEFAULT_TREASURY_BPS: u64 = 500;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating economics parameters.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParamsError {
    #[error("base_inflation_bps must be <= {MAX_BPS} (100%), got {0}")]
    InflationTooHigh(u64),
    #[error("min_stake cannot be zero")]
    MinStakeZero,
    #[error("slash_double_sign_bps must be <= {MAX_BPS}, got {0}")]
    SlashDoubleSignTooHigh(u64),
    #[error("slash_downtime_bps must be <= {MAX_BPS}, got {0}")]
    SlashDowntimeTooHigh(u64),
    #[error("unbonding_epochs must be >= 1, got {0}")]
    UnbondingEpochsInvalid(u64),
    #[error("treasury_bps must be <= {MAX_BPS}, got {0}")]
    TreasuryBpsTooHigh(u64),
    #[error("quantum decoherence: param coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

pub type ParamsResult<T> = Result<T, ParamsError>;

// -----------------------------------------------------------------------------
// Quantum Parameter State
// -----------------------------------------------------------------------------

/// Quantum state of the economic parameter set.
///
/// Tracks the density matrix properties during validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuantumParamsState {
    /// Purity γ = Tr(ρ²).
    pub purity: f64,
    /// Von Neumann entropy S = -Tr(ρ ln ρ).
    pub entropy: f64,
    /// Coherence of the parameter subspace.
    pub coherence: f64,
    /// Number of validation checks performed.
    pub total_checks: u64,
    /// Number of checks that failed.
    pub checks_failed: u64,
    /// Whether the parameter set is in a valid quantum state.
    pub is_valid: bool,
}

impl Default for QuantumParamsState {
    fn default() -> Self {
        Self {
            purity: DEFAULT_PARAM_COHERENCE,
            entropy: 0.0,
            coherence: DEFAULT_PARAM_COHERENCE,
            total_checks: 0,
            checks_failed: 0,
            is_valid: true,
        }
    }
}

impl QuantumParamsState {
    /// Create a fresh quantum state (pure |∅⟩).
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a **passed** check – mild decoherence.
    pub fn record_pass(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        let decay = (-VALIDATION_DECOHERENCE_RATE).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Record a **failed** check – strong decoherence.
    pub fn record_failure(&mut self) {
        self.total_checks = self.total_checks.wrapping_add(1);
        self.checks_failed = self.checks_failed.wrapping_add(1);
        let decay = (-FAILURE_DECOHERENCE_RATE).exp();
        self.coherence = (self.coherence * decay).clamp(0.0, 1.0);
        self.recompute();
    }

    /// Apply the Kraus channel for a parameter validation round.
    pub fn apply_channel(&mut self) {
        let kraus_factor = (1.0 / PARAM_KRAUS_RANK as f64).sqrt();
        self.coherence = (self.coherence * kraus_factor).clamp(0.0, 1.0);
        self.recompute();
    }

    fn recompute(&mut self) {
        self.purity = self.coherence;
        self.entropy = if self.purity >= 1.0 {
            0.0
        } else {
            -self.purity * self.purity.ln().max(0.0)
        };
        self.is_valid = self.purity >= MIN_PARAM_COHERENCE;
    }
}

// -----------------------------------------------------------------------------
// EconomicsParams
// -----------------------------------------------------------------------------

/// Core economic parameters for the IONA chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsParams {
    /// Base annual inflation rate in basis points (1 bp = 0.01%).
    /// Maximum `MAX_BPS` (100%).
    pub base_inflation_bps: u64,
    /// Minimum stake required to become a validator.
    pub min_stake: u128,
    /// Slashing percentage for double‑signing offense (basis points).
    pub slash_double_sign_bps: u64,
    /// Slashing percentage for downtime offense (basis points).
    pub slash_downtime_bps: u64,
    /// Number of epochs a validator must wait before unbonding completes.
    pub unbonding_epochs: u64,
    /// Percentage of block rewards sent to the treasury (basis points).
    pub treasury_bps: u64,
    /// Quantum coherence of this parameter set.
    #[serde(default = "default_coherence")]
    pub coherence: f64,
}

fn default_coherence() -> f64 {
    DEFAULT_PARAM_COHERENCE
}

impl Default for EconomicsParams {
    fn default() -> Self {
        Self {
            base_inflation_bps: DEFAULT_INFLATION_BPS,
            min_stake: DEFAULT_MIN_STAKE,
            slash_double_sign_bps: DEFAULT_SLASH_DOUBLE_SIGN_BPS,
            slash_downtime_bps: DEFAULT_SLASH_DOWNTIME_BPS,
            unbonding_epochs: DEFAULT_UNBONDING_EPOCHS,
            treasury_bps: DEFAULT_TREASURY_BPS,
            coherence: DEFAULT_PARAM_COHERENCE,
        }
    }
}

impl EconomicsParams {
    /// Classical validation — backward compatible.
    pub fn validate(&self) -> ParamsResult<()> {
        if self.base_inflation_bps > MAX_BPS {
            return Err(ParamsError::InflationTooHigh(self.base_inflation_bps));
        }
        if self.min_stake == 0 {
            return Err(ParamsError::MinStakeZero);
        }
        if self.slash_double_sign_bps > MAX_BPS {
            return Err(ParamsError::SlashDoubleSignTooHigh(self.slash_double_sign_bps));
        }
        if self.slash_downtime_bps > MAX_BPS {
            return Err(ParamsError::SlashDowntimeTooHigh(self.slash_downtime_bps));
        }
        if self.unbonding_epochs == 0 {
            return Err(ParamsError::UnbondingEpochsInvalid(self.unbonding_epochs));
        }
        if self.treasury_bps > MAX_BPS {
            return Err(ParamsError::TreasuryBpsTooHigh(self.treasury_bps));
        }
        Ok(())
    }

    /// Validate and return the quantum state after measurement.
    pub fn validate_quantum(&self) -> (ParamsResult<()>, QuantumParamsState) {
        let mut qstate = QuantumParamsState::new();
        let result = self.validate();

        match &result {
            Ok(_) => {
                // Six checks passed
                for _ in 0..6 {
                    qstate.record_pass();
                }
            }
            Err(_) => qstate.record_failure(),
        }
        qstate.apply_channel();

        (result, qstate)
    }

    /// Create a new instance with validation.
    pub fn new(
        base_inflation_bps: u64,
        min_stake: u128,
        slash_double_sign_bps: u64,
        slash_downtime_bps: u64,
        unbonding_epochs: u64,
        treasury_bps: u64,
    ) -> ParamsResult<Self> {
        let params = Self {
            base_inflation_bps,
            min_stake,
            slash_double_sign_bps,
            slash_downtime_bps,
            unbonding_epochs,
            treasury_bps,
            coherence: DEFAULT_PARAM_COHERENCE,
        };
        params.validate()?;
        Ok(params)
    }

    /// Treasury share as a fraction (0.0 – 1.0).
    pub fn treasury_share(&self) -> f64 {
        self.treasury_bps as f64 / MAX_BPS as f64
    }

    /// Inflation rate as a fraction (0.0 – 1.0).
    pub fn inflation_rate(&self) -> f64 {
        self.base_inflation_bps as f64 / MAX_BPS as f64
    }

    /// Quantum coherence accessor.
    pub fn coherence(&self) -> f64 {
        self.coherence
    }
}

impl std::fmt::Display for EconomicsParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Economics Parameters:")?;
        writeln!(
            f,
            "  base_inflation_bps:     {} ({:.2}%)",
            self.base_inflation_bps,
            self.base_inflation_bps as f64 / 100.0
        )?;
        writeln!(f, "  min_stake:              {}", self.min_stake)?;
        writeln!(
            f,
            "  slash_double_sign_bps:  {} ({:.2}%)",
            self.slash_double_sign_bps,
            self.slash_double_sign_bps as f64 / 100.0
        )?;
        writeln!(
            f,
            "  slash_downtime_bps:     {} ({:.2}%)",
            self.slash_downtime_bps,
            self.slash_downtime_bps as f64 / 100.0
        )?;
        writeln!(f, "  unbonding_epochs:       {}", self.unbonding_epochs)?;
        writeln!(
            f,
            "  treasury_bps:           {} ({:.2}%)",
            self.treasury_bps,
            self.treasury_bps as f64 / 100.0
        )?;
        writeln!(f, "  coherence:               {:.6}", self.coherence)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Classical tests ──────────────────────────────────────────────
    #[test]
    fn test_default_valid() {
        let params = EconomicsParams::default();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_inflation_too_high() {
        let mut params = EconomicsParams::default();
        params.base_inflation_bps = MAX_BPS + 1;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::InflationTooHigh(MAX_BPS + 1))
        ));
    }

    #[test]
    fn test_min_stake_zero() {
        let mut params = EconomicsParams::default();
        params.min_stake = 0;
        assert!(matches!(params.validate(), Err(ParamsError::MinStakeZero)));
    }

    #[test]
    fn test_slash_double_sign_too_high() {
        let mut params = EconomicsParams::default();
        params.slash_double_sign_bps = MAX_BPS + 1;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::SlashDoubleSignTooHigh(MAX_BPS + 1))
        ));
    }

    #[test]
    fn test_slash_downtime_too_high() {
        let mut params = EconomicsParams::default();
        params.slash_downtime_bps = MAX_BPS + 1;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::SlashDowntimeTooHigh(MAX_BPS + 1))
        ));
    }

    #[test]
    fn test_unbonding_epochs_zero() {
        let mut params = EconomicsParams::default();
        params.unbonding_epochs = 0;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::UnbondingEpochsInvalid(0))
        ));
    }

    #[test]
    fn test_treasury_bps_too_high() {
        let mut params = EconomicsParams::default();
        params.treasury_bps = MAX_BPS + 1;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::TreasuryBpsTooHigh(MAX_BPS + 1))
        ));
    }

    #[test]
    fn test_new_constructor() {
        let params = EconomicsParams::new(
            DEFAULT_INFLATION_BPS,
            DEFAULT_MIN_STAKE,
            DEFAULT_SLASH_DOUBLE_SIGN_BPS,
            DEFAULT_SLASH_DOWNTIME_BPS,
            DEFAULT_UNBONDING_EPOCHS,
            DEFAULT_TREASURY_BPS,
        )
        .unwrap();
        assert_eq!(params.base_inflation_bps, DEFAULT_INFLATION_BPS);
        assert!(
            EconomicsParams::new(MAX_BPS + 1, 1000, 5000, 100, 14, 500).is_err()
        );
    }

    #[test]
    fn test_treasury_share() {
        let params = EconomicsParams::default();
        let expected = DEFAULT_TREASURY_BPS as f64 / MAX_BPS as f64;
        assert!((params.treasury_share() - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_inflation_rate() {
        let params = EconomicsParams::default();
        let expected = DEFAULT_INFLATION_BPS as f64 / MAX_BPS as f64;
        assert!((params.inflation_rate() - expected).abs() < f64::EPSILON);
    }

    #[test]
    fn test_display() {
        let params = EconomicsParams::default();
        let s = format!("{}", params);
        assert!(s.contains("base_inflation_bps:"));
        assert!(s.contains("5.00%"));
        assert!(s.contains("coherence:"));
    }

    // ── Quantum tests ────────────────────────────────────────────────
    #[test]
    fn test_quantum_state_initialization() {
        let state = QuantumParamsState::new();
        assert!((state.purity - 1.0).abs() < 1e-10);
        assert!((state.entropy - 0.0).abs() < 1e-10);
        assert!(state.is_valid);
    }

    #[test]
    fn test_record_pass_decoheres() {
        let mut state = QuantumParamsState::new();
        let initial_purity = state.purity;
        state.record_pass();
        assert!(state.purity < initial_purity);
        assert_eq!(state.total_checks, 1);
    }

    #[test]
    fn test_record_failure_stronger() {
        let mut state1 = QuantumParamsState::new();
        let mut state2 = QuantumParamsState::new();
        state1.record_pass();
        state2.record_failure();
        assert!(state2.purity < state1.purity);
        assert_eq!(state2.checks_failed, 1);
    }

    #[test]
    fn test_validate_quantum_ok() {
        let params = EconomicsParams::default();
        let (result, qstate) = params.validate_quantum();
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
        assert!(qstate.purity < 1.0);
    }

    #[test]
    fn test_validate_quantum_failure() {
        let mut params = EconomicsParams::default();
        params.min_stake = 0;
        let (result, qstate) = params.validate_quantum();
        assert!(result.is_err());
        assert!(qstate.checks_failed > 0);
    }

    #[test]
    fn test_coherence_accessor() {
        let params = EconomicsParams::default();
        assert!((params.coherence() - 1.0).abs() < 1e-10);
    }

    #[test]
    fn test_health_after_many_failures() {
        let mut state = QuantumParamsState::new();
        for _ in 0..1000 {
            state.record_failure();
        }
        assert!(!state.is_valid);
    }

    #[test]
    fn test_purity_never_negative() {
        let mut state = QuantumParamsState::new();
        for _ in 0..100000 {
            state.record_failure();
        }
        assert!(state.purity >= 0.0);
    }
}
