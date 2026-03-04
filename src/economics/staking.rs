use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Validator {
    pub operator: String,
    pub stake: u128,
    pub jailed: bool,
    pub commission_bps: u64,
}

impl Validator {
    pub fn new(operator: String, stake: u128, commission_bps: u64) -> Self {
        Self { operator, stake, jailed: false, commission_bps }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StakingState {
    pub validators: BTreeMap<String, Validator>,
    pub delegations: BTreeMap<(String, String), u128>, // (delegator, validator) -> amount
    pub unbonding: BTreeMap<(String, String), (u128, u64)>, // -> (amount, unlock_epoch)
}

/// Basic staking transitions (minimal baseline).
impl StakingState {
    pub fn delegate(&mut self, delegator: String, validator: String, amount: u128) {
        let k = (delegator, validator);
        *self.delegations.entry(k).or_insert(0) += amount;
    }

    pub fn undelegate(&mut self, delegator: String, validator: String, amount: u128, current_epoch: u64, unbonding_epochs: u64) {
        let k = (delegator.clone(), validator.clone());
        let cur = self.delegations.get(&k).copied().unwrap_or(0);
        let a = amount.min(cur);
        if a == 0 { return; }
        self.delegations.insert(k.clone(), cur - a);
        let unlock = current_epoch.saturating_add(unbonding_epochs);
        self.unbonding.insert(k, (a, unlock));
    }

    pub fn withdraw(&mut self, delegator: String, validator: String, current_epoch: u64) -> u128 {
        let k = (delegator, validator);
        match self.unbonding.get(&k).copied() {
            Some((amt, unlock)) if current_epoch >= unlock => {
                self.unbonding.remove(&k);
                amt
            }
            _ => 0,
        }
    }

    pub fn slash(&mut self, validator: &str, slash_bps: u64) {
        if let Some(v) = self.validators.get_mut(validator) {
            let slash = (v.stake.saturating_mul(slash_bps as u128)) / 10_000u128;
            v.stake = v.stake.saturating_sub(slash);
            v.jailed = true;
        }
    }
}
