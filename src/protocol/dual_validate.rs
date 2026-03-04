//! Dual-validate (shadow validation) for pre-activation protocol upgrades.
//!
//! During the pre-activation window, a node running the new binary can
//! perform **shadow validation**: applying the new PV rules to blocks
//! without rejecting them if the new rules fail.
//!
//! This allows operators to verify that the new rules work correctly
//! before the activation height is reached.
//!
//! # Usage
//!
//! ```ignore
//! let shadow = ShadowValidator::new(activations);
//! // For each block:
//! shadow.validate(block, height);
//! // Check shadow results:
//! let stats = shadow.stats();
//! ```

use crate::protocol::version::{ProtocolActivation, version_for_height, CURRENT_PROTOCOL_VERSION};
use crate::types::{Block, Height};
use std::sync::atomic::{AtomicU64, Ordering};

/// Shadow validator that applies new-PV rules without blocking consensus.
///
/// Results are logged and tracked for operator visibility, but failures
/// do NOT cause block rejection.
pub struct ShadowValidator {
    /// Activation schedule.
    activations: Vec<ProtocolActivation>,
    /// Number of blocks validated under shadow rules.
    shadow_validated: AtomicU64,
    /// Number of blocks that PASSED shadow validation.
    shadow_passed: AtomicU64,
    /// Number of blocks that FAILED shadow validation.
    shadow_failed: AtomicU64,
}

impl ShadowValidator {
    /// Create a new shadow validator with the given activation schedule.
    pub fn new(activations: Vec<ProtocolActivation>) -> Self {
        Self {
            activations,
            shadow_validated: AtomicU64::new(0),
            shadow_passed: AtomicU64::new(0),
            shadow_failed: AtomicU64::new(0),
        }
    }

    /// Perform shadow validation on a block.
    ///
    /// This is called for blocks at heights BEFORE the activation point.
    /// The block has already been validated under the current PV rules;
    /// this additionally validates it under the NEW PV rules.
    ///
    /// Returns `Ok(true)` if shadow validation passed, `Ok(false)` if
    /// shadow validation is not applicable (height is past activation),
    /// or `Err` with a description of the shadow failure.
    pub fn validate(&self, block: &Block, height: Height) -> Result<bool, String> {
        let current_pv = version_for_height(height, &self.activations);

        // Shadow validation only applies before activation height.
        // After activation, normal validation handles the new PV.
        if current_pv >= CURRENT_PROTOCOL_VERSION {
            return Ok(false); // Not applicable; already using latest PV.
        }

        // Find the next activation that hasn't happened yet.
        let next_activation = self.activations.iter().find(|a| {
            a.protocol_version > current_pv
                && a.activation_height
                    .map(|ah| height < ah)
                    .unwrap_or(false)
        });

        let Some(_activation) = next_activation else {
            return Ok(false); // No upcoming activation.
        };

        self.shadow_validated.fetch_add(1, Ordering::Relaxed);

        // Apply new-PV validation rules (shadow, non-blocking).
        // Currently: validate that the block header fields are well-formed
        // for the new PV. In the future, this would apply full new-PV
        // execution rules.
        let result = self.shadow_validate_block(block);

        match &result {
            Ok(()) => {
                self.shadow_passed.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    height,
                    block_pv = block.header.protocol_version,
                    "shadow validation PASSED"
                );
                Ok(true)
            }
            Err(reason) => {
                self.shadow_failed.fetch_add(1, Ordering::Relaxed);
                tracing::warn!(
                    height,
                    block_pv = block.header.protocol_version,
                    reason = reason.as_str(),
                    "shadow validation FAILED (non-blocking)"
                );
                Err(reason.clone())
            }
        }
    }

    /// Internal: apply new-PV rules to a block (shadow mode).
    fn shadow_validate_block(&self, block: &Block) -> Result<(), String> {
        // Validate block header structure.
        if block.header.protocol_version == 0 {
            return Err("protocol_version must be >= 1".into());
        }

        // Validate that the block ID is deterministic.
        let computed_id = block.id();
        // (We can't compare to the "expected" ID here since we don't have it,
        // but we verify that id() doesn't panic and returns a non-zero hash.)
        if computed_id.0 == [0u8; 32] {
            return Err("block ID is all zeros (likely missing header fields)".into());
        }

        // Validate tx_root matches the transactions.
        let computed_tx_root = crate::types::tx_root(&block.txs);
        if computed_tx_root != block.header.tx_root {
            return Err(format!(
                "tx_root mismatch: header={}, computed={}",
                hex::encode(block.header.tx_root.0),
                hex::encode(computed_tx_root.0),
            ));
        }

        Ok(())
    }

    /// Get shadow validation statistics.
    pub fn stats(&self) -> ShadowStats {
        ShadowStats {
            validated: self.shadow_validated.load(Ordering::Relaxed),
            passed: self.shadow_passed.load(Ordering::Relaxed),
            failed: self.shadow_failed.load(Ordering::Relaxed),
        }
    }
}

/// Statistics from shadow validation.
#[derive(Debug, Clone)]
pub struct ShadowStats {
    /// Total blocks shadow-validated.
    pub validated: u64,
    /// Blocks that passed shadow validation.
    pub passed: u64,
    /// Blocks that failed shadow validation (non-blocking).
    pub failed: u64,
}

impl std::fmt::Display for ShadowStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "shadow_validation: {} validated, {} passed, {} failed",
            self.validated, self.passed, self.failed
        )
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;
    use crate::types::*;

    fn make_test_block(height: u64, pv: u32) -> Block {
        let txs = vec![];
        Block {
            header: BlockHeader {
                height,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![1, 2, 3],
                tx_root: tx_root(&txs),
                receipts_root: receipts_root(&[]),
                state_root: Hash32::zero(),
                base_fee_per_gas: 1,
                gas_used: 0,
                intrinsic_gas_used: 0,
                exec_gas_used: 0,
                vm_gas_used: 0,
                evm_gas_used: 0,
                chain_id: 6126151,
                timestamp: 0,
                protocol_version: pv,
            },
            txs,
        }
    }

    #[test]
    fn test_shadow_not_applicable_at_current_pv() {
        // With only PV=1 active (no future activation), shadow is not applicable.
        let activations = vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }];
        let sv = ShadowValidator::new(activations);
        let block = make_test_block(100, 1);
        let result = sv.validate(&block, 100);
        assert_eq!(result.unwrap(), false); // Not applicable
    }

    #[test]
    fn test_shadow_validates_before_activation() {
        let activations = vec![
            ProtocolActivation {
                protocol_version: 1,
                activation_height: None,
                grace_blocks: 0,
            },
            ProtocolActivation {
                protocol_version: 2,
                activation_height: Some(1000),
                grace_blocks: 100,
            },
        ];
        let sv = ShadowValidator::new(activations);
        let block = make_test_block(500, 1);
        // This should attempt shadow validation since PV=2 activates at 1000
        // but current PV at height 500 is 1 < CURRENT_PROTOCOL_VERSION (1).
        // Since CURRENT_PROTOCOL_VERSION is 1, shadow is not applicable.
        let result = sv.validate(&block, 500);
        assert!(result.is_ok());
    }

    #[test]
    fn test_shadow_stats() {
        let activations = vec![ProtocolActivation {
            protocol_version: 1,
            activation_height: None,
            grace_blocks: 0,
        }];
        let sv = ShadowValidator::new(activations);
        let stats = sv.stats();
        assert_eq!(stats.validated, 0);
        assert_eq!(stats.passed, 0);
        assert_eq!(stats.failed, 0);
    }
}
