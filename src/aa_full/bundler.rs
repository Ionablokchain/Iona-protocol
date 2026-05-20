//! ERC-4337 Bundler — collects UserOps, builds bundles, submits to chain.
use serde::{Deserialize, Serialize};
use crate::evm::account_abstraction::UserOperation;
use crate::aa_full::entry_point::{handle_ops, HandleOpsResult};

#[derive(Debug, Default)]
pub struct Bundler {
    pub beneficiary:   String,
    pub chain_id:      u64,
    pub bundles_built: u64,
}

impl Bundler {
    pub fn new(beneficiary: String, chain_id: u64) -> Self {
        Self { beneficiary, chain_id, ..Default::default() }
    }

    /// Simulate and validate all ops, then build a bundle.
    pub fn build_and_submit(&mut self, ops: Vec<UserOperation>) -> HandleOpsResult {
        use crate::aa_full::simulation::simulate_all;
        let valid_ops: Vec<_> = ops.into_iter()
            .filter(|op| simulate_all(op, self.chain_id).is_ok())
            .collect();
        self.bundles_built += 1;
        tracing::info!(bundle = self.bundles_built, ops = valid_ops.len(), "Bundler: submitting bundle");
        handle_ops(&valid_ops, &self.beneficiary, self.chain_id)
    }
}
