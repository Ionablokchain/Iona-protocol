use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsParams {
    pub base_inflation_bps: u64,
    pub min_stake: u128,
    pub slash_double_sign_bps: u64,
    pub slash_downtime_bps: u64,
    pub unbonding_epochs: u64,
    pub treasury_bps: u64,
}

impl Default for EconomicsParams {
    fn default() -> Self {
        Self {
            base_inflation_bps: 500,          // 5% annual
            min_stake: 10_000_000_000u128,    // 10 billion base units (~10k tokens at 1M decimals)
            slash_double_sign_bps: 5000,      // 50%
            slash_downtime_bps: 100,          // 1%
            unbonding_epochs: 14,
            treasury_bps: 500,                // 5%
        }
    }
}
