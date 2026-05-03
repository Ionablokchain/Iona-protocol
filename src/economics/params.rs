//! Economic parameters for IONA.
//!
//! Contains inflation, staking, slashing, unbonding, and treasury configuration.
//! All values are validated at load time.

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating economics parameters.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ParamsError {
    #[error("base_inflation_bps must be <= 10_000 (100%), got {0}")]
    InflationTooHigh(u64),
    #[error("min_stake cannot be zero")]
    MinStakeZero,
    #[error("slash_double_sign_bps must be <= 10_000, got {0}")]
    SlashDoubleSignTooHigh(u64),
    #[error("slash_downtime_bps must be <= 10_000, got {0}")]
    SlashDowntimeTooHigh(u64),
    #[error("unbonding_epochs must be >= 1, got {0}")]
    UnbondingEpochsInvalid(u64),
    #[error("treasury_bps must be <= 10_000, got {0}")]
    TreasuryBpsTooHigh(u64),
}

pub type ParamsResult<T> = Result<T, ParamsError>;

// -----------------------------------------------------------------------------
// EconomicsParams
// -----------------------------------------------------------------------------

/// Core economic parameters for the IONA chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsParams {
    /// Base annual inflation rate in basis points (1 bp = 0.01%).
    /// Maximum 10 000 (100%).
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
}

impl Default for EconomicsParams {
    fn default() -> Self {
        Self {
            base_inflation_bps: 500,       // 5% annual
            min_stake: 10_000_000_000u128, // 10 billion base units (~10k tokens at 1M decimals)
            slash_double_sign_bps: 5000,   // 50%
            slash_downtime_bps: 100,       // 1%
            unbonding_epochs: 14,
            treasury_bps: 500,             // 5%
        }
    }
}

impl EconomicsParams {
    /// Validate all parameters, returning an error if any are out of bounds.
    pub fn validate(&self) -> ParamsResult<()> {
        if self.base_inflation_bps > 10_000 {
            return Err(ParamsError::InflationTooHigh(self.base_inflation_bps));
        }
        if self.min_stake == 0 {
            return Err(ParamsError::MinStakeZero);
        }
        if self.slash_double_sign_bps > 10_000 {
            return Err(ParamsError::SlashDoubleSignTooHigh(self.slash_double_sign_bps));
        }
        if self.slash_downtime_bps > 10_000 {
            return Err(ParamsError::SlashDowntimeTooHigh(self.slash_downtime_bps));
        }
        if self.unbonding_epochs == 0 {
            return Err(ParamsError::UnbondingEpochsInvalid(self.unbonding_epochs));
        }
        if self.treasury_bps > 10_000 {
            return Err(ParamsError::TreasuryBpsTooHigh(self.treasury_bps));
        }
        Ok(())
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
        };
        params.validate()?;
        Ok(params)
    }

    /// Treasury share as a fraction (0.0 – 1.0).
    pub fn treasury_share(&self) -> f64 {
        self.treasury_bps as f64 / 10_000.0
    }

    /// Inflation rate as a fraction (0.0 – 1.0).
    pub fn inflation_rate(&self) -> f64 {
        self.base_inflation_bps as f64 / 10_000.0
    }
}

impl std::fmt::Display for EconomicsParams {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "Economics Parameters:")?;
        writeln!(f, "  base_inflation_bps:     {} ({:.2}%)", self.base_inflation_bps, self.base_inflation_bps as f64 / 100.0)?;
        writeln!(f, "  min_stake:              {}", self.min_stake)?;
        writeln!(f, "  slash_double_sign_bps:  {} ({:.2}%)", self.slash_double_sign_bps, self.slash_double_sign_bps as f64 / 100.0)?;
        writeln!(f, "  slash_downtime_bps:     {} ({:.2}%)", self.slash_downtime_bps, self.slash_downtime_bps as f64 / 100.0)?;
        writeln!(f, "  unbonding_epochs:       {}", self.unbonding_epochs)?;
        writeln!(f, "  treasury_bps:           {} ({:.2}%)", self.treasury_bps, self.treasury_bps as f64 / 100.0)?;
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_valid() {
        let params = EconomicsParams::default();
        assert!(params.validate().is_ok());
    }

    #[test]
    fn test_inflation_too_high() {
        let mut params = EconomicsParams::default();
        params.base_inflation_bps = 10_001;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::InflationTooHigh(10_001))
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
        params.slash_double_sign_bps = 10_001;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::SlashDoubleSignTooHigh(10_001))
        ));
    }

    #[test]
    fn test_slash_downtime_too_high() {
        let mut params = EconomicsParams::default();
        params.slash_downtime_bps = 10_001;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::SlashDowntimeTooHigh(10_001))
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
        params.treasury_bps = 10_001;
        assert!(matches!(
            params.validate(),
            Err(ParamsError::TreasuryBpsTooHigh(10_001))
        ));
    }

    #[test]
    fn test_new_constructor() {
        let params = EconomicsParams::new(500, 1000, 5000, 100, 14, 500).unwrap();
        assert_eq!(params.base_inflation_bps, 500);
        assert!(EconomicsParams::new(10_001, 1000, 5000, 100, 14, 500).is_err());
    }

    #[test]
    fn test_treasury_share() {
        let params = EconomicsParams::default();
        assert!((params.treasury_share() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn test_inflation_rate() {
        let params = EconomicsParams::default();
        assert!((params.inflation_rate() - 0.05).abs() < f64::EPSILON);
    }

    #[test]
    fn test_display() {
        let params = EconomicsParams::default();
        let s = format!("{}", params);
        assert!(s.contains("base_inflation_bps:"));
        assert!(s.contains("5.00%"));
    }
}
