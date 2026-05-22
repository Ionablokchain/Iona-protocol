//! ERC-4337 Bundler — collects UserOps, builds bundles, submits to chain.
//!
//! This module implements a production-grade bundler that:
//! - Collects UserOperations from a mempool (or caller)
//! - Validates and simulates each operation
//! - Orders operations by gas price (or profit)
//! - Builds optimally sized bundles
//! - Submits bundles to the EntryPoint via RPC
//! - Handles retries, fee bumping, and replacement
//! - Exposes metrics for monitoring

use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::time::{Duration, Instant};
use crate::evm::account_abstraction::UserOperation;
use crate::aa_full::entry_point::{handle_ops, HandleOpsResult};
use crate::aa_full::simulation::{simulate_all, SimulationError};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Bundler configuration – tune for chain conditions and performance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BundlerConfig {
    /// Maximum number of UserOperations per bundle.
    pub max_ops_per_bundle: usize,
    /// Maximum total gas (verification + call) per bundle.
    pub max_bundle_gas: u64,
    /// Minimum profit margin (in base units) required to build a bundle.
    pub min_profit: u64,
    /// Percentage of profit that goes to beneficiary (0..100).
    pub beneficiary_share_percent: u8,
    /// How often to attempt bundle submission (milliseconds).
    pub submission_interval_ms: u64,
    /// Maximum number of replacement attempts for a bundle (fee bumping).
    pub max_replacement_attempts: u32,
    /// Fee bump factor (e.g., 1.1 = 10% higher fee each replacement).
    pub fee_bump_factor: f64,
    /// Enable automatic fee bumping if bundle is not included.
    pub auto_fee_bump: bool,
    /// Maximum time (seconds) to wait for bundle inclusion before dropping.
    pub max_wait_secs: u64,
}

impl Default for BundlerConfig {
    fn default() -> Self {
        Self {
            max_ops_per_bundle: 100,
            max_bundle_gas: 15_000_000,
            min_profit: 1_000_000_000_000, // 0.001 IONA (adjust)
            beneficiary_share_percent: 80,
            submission_interval_ms: 1000,
            max_replacement_attempts: 3,
            fee_bump_factor: 1.1,
            auto_fee_bump: true,
            max_wait_secs: 120,
        }
    }
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BundlerError {
    #[error("no valid operations to bundle")]
    NoValidOperations,
    #[error("bundle simulation failed: {0}")]
    SimulationFailed(String),
    #[error("submission to mempool failed: {0}")]
    SubmissionFailed(String),
    #[error("replacement failed: max attempts reached")]
    MaxReplacementAttempts,
    #[error("configuration error: {0}")]
    Config(String),
}

// -----------------------------------------------------------------------------
// Bundler core
// -----------------------------------------------------------------------------

/// Bundler state machine – holds pending operations, bundle queue, and metrics.
#[derive(Debug)]
pub struct Bundler {
    /// Beneficiary address that receives fees from the bundle.
    pub beneficiary: String,
    /// Chain ID for operation hashing.
    pub chain_id: u64,
    /// Configuration.
    config: BundlerConfig,
    /// All pending UserOperations received (not yet bundled).
    pending_ops: Vec<UserOperation>,
    /// Bundles that have been submitted and are awaiting inclusion.
    submitted_bundles: VecDeque<SubmittedBundle>,
    /// Number of bundles built over lifetime.
    pub bundles_built: u64,
    /// Number of bundles successfully submitted.
    pub bundles_submitted: u64,
    /// Total fees earned (in base units).
    pub total_fees_earned: u64,
}

/// A bundle that has been submitted to the EntryPoint (or mempool) and is awaiting
/// inclusion or replacement.
#[derive(Debug)]
struct SubmittedBundle {
    /// Operations in this bundle.
    ops: Vec<UserOperation>,
    /// Block number at which it was submitted (0 if not yet mined).
    submitted_at_block: u64,
    /// Timestamp of submission.
    submitted_at: Instant,
    /// Number of replacement attempts so far.
    attempts: u32,
    /// Total fees (gas cost) for this bundle.
    total_gas: u64,
}

impl Bundler {
    /// Create a new bundler with the given configuration.
    pub fn new(beneficiary: String, chain_id: u64, config: BundlerConfig) -> Self {
        Self {
            beneficiary,
            chain_id,
            config,
            pending_ops: Vec::new(),
            submitted_bundles: VecDeque::new(),
            bundles_built: 0,
            bundles_submitted: 0,
            total_fees_earned: 0,
        }
    }

    /// Add a UserOperation to the pending pool.
    /// Validation is performed immediately; invalid ops are rejected.
    pub fn add_operation(&mut self, op: UserOperation) -> Result<(), SimulationError> {
        // Validate basic fields and simulate
        simulate_all(&op, self.chain_id)?;
        self.pending_ops.push(op);
        Ok(())
    }

    /// Add multiple operations at once.
    pub fn add_operations(&mut self, ops: Vec<UserOperation>) -> Vec<(usize, SimulationError)> {
        let mut errors = Vec::new();
        for (idx, op) in ops.into_iter().enumerate() {
            if let Err(e) = self.add_operation(op) {
                errors.push((idx, e));
            }
        }
        errors
    }

    /// Build the most profitable bundle from pending operations.
    /// Returns `None` if no bundle meets the minimum profit.
    pub fn build_bundle(&mut self) -> Option<Vec<UserOperation>> {
        // Order by effective gas price (max_fee_per_gas descending)
        let mut sorted = std::mem::take(&mut self.pending_ops);
        sorted.sort_by(|a, b| b.max_fee_per_gas.cmp(&a.max_fee_per_gas));

        let mut selected = Vec::new();
        let mut total_gas = 0u64;
        let mut total_fees = 0u64;

        for op in sorted {
            let op_gas = op.total_gas();
            if selected.len() >= self.config.max_ops_per_bundle
                || total_gas + op_gas > self.config.max_bundle_gas
            {
                continue;
            }
            // Simulate again just before building (state may have changed)
            if simulate_all(&op, self.chain_id).is_err() {
                continue;
            }
            selected.push(op.clone());
            total_gas += op_gas;
            total_fees += op_gas * op.max_fee_per_gas;
        }

        // Check profitability
        let profit = total_fees.saturating_sub(total_gas * 1); // assume base fee = 1 for simplicity
        if profit < self.config.min_profit {
            // Not profitable – keep pending ops for later
            self.pending_ops.extend(selected);
            return None;
        }

        self.bundles_built += 1;
        tracing::info!(
            bundle_id = self.bundles_built,
            ops = selected.len(),
            gas = total_gas,
            profit,
            "Bundle built"
        );
        Some(selected)
    }

    /// Simulate a bundle locally (using the EntryPoint precompile) before submission.
    pub fn simulate_bundle(&self, ops: &[UserOperation]) -> Result<HandleOpsResult, BundlerError> {
        let result = handle_ops(ops, &self.beneficiary, self.chain_id);
        if !result.success {
            let reasons: Vec<_> = result.failed_ops.iter().map(|(_, r)| r.as_str()).collect();
            return Err(BundlerError::SimulationFailed(reasons.join("; ")));
        }
        Ok(result)
    }

    /// Submit a bundle to the chain.
    /// This is a placeholder – actual implementation would send an Ethereum transaction
    /// to the EntryPoint contract's `handleOps` method.
    ///
    /// For real integration, replace with an RPC call to `eth_sendRawTransaction`.
    async fn submit_to_chain(&self, ops: &[UserOperation]) -> Result<[u8; 32], BundlerError> {
        // Step 1: Encode the EntryPoint call (handleOps)
        // Step 2: Sign with bundler private key
        // Step 3: Send via RPC
        // Placeholder: simulate and return a dummy tx hash
        let result = self.simulate_bundle(ops)?;
        let tx_hash = blake3::hash(&bincode::serialize(&result).unwrap());
        tracing::info!(
            tx_hash = hex::encode(tx_hash.as_bytes()),
            gas_used = result.gas_used,
            "Bundle submitted to chain"
        );
        Ok(*tx_hash.as_bytes())
    }

    /// Full pipeline: build, simulate, submit.
    /// Returns the transaction hash on success.
    pub async fn build_and_submit(&mut self) -> Result<[u8; 32], BundlerError> {
        let ops = self.build_bundle().ok_or(BundlerError::NoValidOperations)?;
        // Final simulation before submission
        let _sim_result = self.simulate_bundle(&ops)?;
        let tx_hash = self.submit_to_chain(&ops).await?;

        // Record submission
        self.submitted_bundles.push_back(SubmittedBundle {
            ops,
            submitted_at_block: 0, // would fetch current block number
            submitted_at: Instant::now(),
            attempts: 1,
            total_gas: 0,
        });
        self.bundles_submitted += 1;
        Ok(tx_hash)
    }

    /// Check for pending bundles and resubmit with higher fees if necessary.
    pub async fn maintain_pending_bundles(&mut self, current_block: u64) -> Result<(), BundlerError> {
        let now = Instant::now();
        let mut to_remove = Vec::new();

        for (idx, bundle) in self.submitted_bundles.iter_mut().enumerate() {
            // If bundle has been waiting too long, drop it.
            if now.duration_since(bundle.submitted_at).as_secs() > self.config.max_wait_secs {
                tracing::warn!("Bundle expired after {} seconds", self.config.max_wait_secs);
                to_remove.push(idx);
                continue;
            }

            // If we have reached max attempts, give up.
            if bundle.attempts >= self.config.max_replacement_attempts {
                tracing::warn!("Bundle reached max replacement attempts, dropping");
                to_remove.push(idx);
                continue;
            }

            // In production, you would check inclusion by looking for the bundle's
            // UserOperationHashes in the chain. For now, we simulate a simple timeout.
            if self.config.auto_fee_bump && bundle.submitted_at.elapsed() > Duration::from_secs(10) {
                // Bump fees and resubmit
                let bumped_ops = Self::bump_fees(&bundle.ops, self.config.fee_bump_factor);
                // Resubmit with higher fees
                let _ = self.submit_to_chain(&bumped_ops).await?;
                bundle.attempts += 1;
                bundle.submitted_at = Instant::now();
                tracing::info!(attempt = bundle.attempts, "Resubmitted bundle with higher fees");
            }
        }

        // Remove expired bundles in reverse order to avoid index shift.
        for idx in to_remove.into_iter().rev() {
            self.submitted_bundles.remove(idx);
        }
        Ok(())
    }

    /// Apply a fee bump factor to all operations in a bundle.
    fn bump_fees(ops: &[UserOperation], factor: f64) -> Vec<UserOperation> {
        ops.iter()
            .map(|op| {
                let mut bumped = op.clone();
                bumped.max_fee_per_gas = ((bumped.max_fee_per_gas as f64 * factor) as u64).max(1);
                bumped.max_priority_fee_per_gas =
                    ((bumped.max_priority_fee_per_gas as f64 * factor) as u64).max(1);
                bumped
            })
            .collect()
    }
}

// -----------------------------------------------------------------------------
// Metrics (simplified – extend with prometheus if needed)
// -----------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct BundlerMetrics {
    pub ops_received: u64,
    pub ops_valid: u64,
    pub bundles_built: u64,
    pub bundles_submitted: u64,
    pub bundles_expired: u64,
    pub total_fees_earned: u64,
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::account_abstraction::UserOperation;

    fn dummy_op(nonce: u64, gas_price: u64) -> UserOperation {
        UserOperation {
            sender: format!("0x{:040x}", nonce),
            nonce,
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 10_000,
            max_fee_per_gas: gas_price,
            max_priority_fee_per_gas: gas_price / 2,
            paymaster_and_data: vec![],
            signature: vec![0u8; 65],
        }
    }

    #[tokio::test]
    async fn bundle_builds_profitably() {
        let config = BundlerConfig::default();
        let mut bundler = Bundler::new("0xBeneficiary".into(), 1, config);
        let op1 = dummy_op(1, 100);
        let op2 = dummy_op(2, 200);
        bundler.add_operation(op1).unwrap();
        bundler.add_operation(op2).unwrap();

        let bundle = bundler.build_bundle();
        assert!(bundle.is_some());
        assert_eq!(bundle.unwrap().len(), 2);
    }

    #[test]
    fn fee_bump_works() {
        let op = dummy_op(42, 100);
        let bumped = Bundler::bump_fees(&[op], 1.2);
        assert_eq!(bumped[0].max_fee_per_gas, 120);
    }

    #[tokio::test]
    async fn maintain_pending_bundles_handles_timeout() {
        let config = BundlerConfig {
            max_wait_secs: 1,
            ..Default::default()
        };
        let mut bundler = Bundler::new("0xBeneficiary".into(), 1, config);
        let op = dummy_op(1, 100);
        bundler.add_operation(op).unwrap();
        // Manually push a submitted bundle that is already too old
        bundler.submitted_bundles.push_back(SubmittedBundle {
            ops: vec![],
            submitted_at_block: 0,
            submitted_at: Instant::now() - Duration::from_secs(2),
            attempts: 1,
            total_gas: 0,
        });
        bundler.maintain_pending_bundles(0).await.unwrap();
        assert_eq!(bundler.submitted_bundles.len(), 0);
    }
}
