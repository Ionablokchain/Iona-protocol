use serde::{Deserialize, Serialize};

// Constants for validation limits.
const MAX_BPS: u64 = 10_000;          // 100% expressed in basis points.
const MAX_SLASH_BPS: u64 = MAX_BPS;
const MIN_STAKE_MIN: u128 = 1;        // At least 1 unit.

/// Economic parameters of the Iona protocol.
///
/// These parameters control inflation, slashing penalties, unbonding periods,
/// and treasury allocation. All percentage values are expressed in basis points (bps),
/// where 10 000 bps = 100%.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsParams {
    /// Annual inflation rate in basis points.
    /// Example: 500 bps = 5% annual inflation.
    #[serde(default = "default_base_inflation_bps")]
    pub base_inflation_bps: u64,

    /// Minimum stake required to be a validator (in base units).
    #[serde(default = "default_min_stake")]
    pub min_stake: u128,

    /// Slashing penalty for double‑signing (bps of bonded stake).
    /// Example: 5000 bps = 50% slash.
    #[serde(default = "default_slash_double_sign_bps")]
    pub slash_double_sign_bps: u64,

    /// Slashing penalty for downtime (bps of bonded stake).
    /// Example: 100 bps = 1% slash.
    #[serde(default = "default_slash_downtime_bps")]
    pub slash_downtime_bps: u64,

    /// Number of epochs a validator must wait after unbonding before funds are released.
    #[serde(default = "default_unbonding_epochs")]
    pub unbonding_epochs: u64,

    /// Portion of inflation allocated to the treasury (bps).
    /// The rest goes to validators and delegators.
    #[serde(default = "default_treasury_bps")]
    pub treasury_bps: u64,
}

impl Default for EconomicsParams {
    fn default() -> Self {
        Self {
            base_inflation_bps: default_base_inflation_bps(),
            min_stake: default_min_stake(),
            slash_double_sign_bps: default_slash_double_sign_bps(),
            slash_downtime_bps: default_slash_downtime_bps(),
            unbonding_epochs: default_unbonding_epochs(),
            treasury_bps: default_treasury_bps(),
        }
    }
}

// Default value functions (used also by serde default attributes).
fn default_base_inflation_bps() -> u64 { 500 }          // 5%
fn default_min_stake() -> u128 { 10_000_000_000 }       // 10 billion units
fn default_slash_double_sign_bps() -> u64 { 5000 }      // 50%
fn default_slash_downtime_bps() -> u64 { 100 }          // 1%
fn default_unbonding_epochs() -> u64 { 14 }
fn default_treasury_bps() -> u64 { 500 }                // 5%

impl EconomicsParams {
    /// Validates the parameters, returning `Ok(())` if they are within acceptable bounds.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.base_inflation_bps > MAX_BPS {
            return Err("base_inflation_bps must be <= 100% (10_000 bps)");
        }
        if self.slash_double_sign_bps > MAX_SLASH_BPS {
            return Err("slash_double_sign_bps must be <= 10_000 bps");
        }
        if self.slash_downtime_bps > MAX_SLASH_BPS {
            return Err("slash_downtime_bps must be <= 10_000 bps");
        }
        if self.treasury_bps > MAX_BPS {
            return Err("treasury_bps must be <= 10_000 bps");
        }
        if self.min_stake < MIN_STAKE_MIN {
            return Err("min_stake must be at least 1");
        }
        if self.unbonding_epochs == 0 {
            return Err("unbonding_epochs must be > 0");
        }
        Ok(())
    }

    /// Returns the inflation rate as a rational number (e.g., 0.05 for 5%).
    pub fn inflation_rate(&self) -> f64 {
        self.base_inflation_bps as f64 / MAX_BPS as f64
    }

    /// Returns the proportion of inflation that goes to validators/delegators (i.e., 1 - treasury_bps/10_000).
    pub fn validator_reward_share(&self) -> f64 {
        1.0 - (self.treasury_bps as f64 / MAX_BPS as f64)
    }

    /// Calculates the slash amount for a given stake, based on the double‑sign penalty.
    pub fn slash_double_sign_amount(&self, stake: u128) -> u128 {
        stake * self.slash_double_sign_bps as u128 / MAX_BPS as u128
    }

    /// Calculates the slash amount for a given stake, based on the downtime penalty.
    pub fn slash_downtime_amount(&self, stake: u128) -> u128 {
        stake * self.slash_downtime_bps as u128 / MAX_BPS as u128
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation() {
        let mut params = EconomicsParams::default();
        assert!(params.validate().is_ok());

        params.base_inflation_bps = 10_001;
        assert!(params.validate().is_err());

        params.base_inflation_bps = 5000;
        params.slash_double_sign_bps = 10_001;
        assert!(params.validate().is_err());

        params.slash_double_sign_bps = 5000;
        params.min_stake = 0;
        assert!(params.validate().is_err());
    }

    #[test]
    fn test_slash_amount() {
        let params = EconomicsParams::default();
        let stake = 1_000_000u128;
        let double_sign = params.slash_double_sign_amount(stake);
        assert_eq!(double_sign, 500_000); // 50% of 1M = 500k

        let downtime = params.slash_downtime_amount(stake);
        assert_eq!(downtime, 10_000); // 1% of 1M = 10k
    }

    #[test]
    fn test_inflation_rate() {
        let params = EconomicsParams::default();
        assert!((params.inflation_rate() - 0.05).abs() < 1e-12);
        assert!((params.validator_reward_share() - 0.95).abs() < 1e-12);
    }
}
