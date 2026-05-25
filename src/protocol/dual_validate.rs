//! Dual-validate (shadow validation) for pre‑activation protocol upgrades.
//!
//! During the pre‑activation window, a node running a binary that already
//! supports the **next** protocol version can perform **shadow validation**:
//! applying the new PV rules to blocks without rejecting them if the new
//! rules fail.
//!
//! This allows operators to verify that the new rules work correctly
//! **before** the activation height is reached.  Failures are logged and
//! counted but never block consensus.
//!
//! # How it works
//!
//! 1. The node is built with `CURRENT_PROTOCOL_VERSION = N+1` (it knows the
//!    future rules).
//! 2. The chain is still running at protocol version `N`.
//! 3. For every block at height `< activation_height(N+1)`, the node runs
//!    the new validation rules in a shadow thread.
//! 4. Results are recorded; if a block would be invalid under the new rules,
//!    a warning is logged.
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::protocol::dual_validate::{ShadowValidator, ShadowValidatorConfig};
//! use iona::protocol::version::default_activations;
//!
//! let config = ShadowValidatorConfig::default();
//! let shadow = ShadowValidator::new(default_activations(), config);
//! // For each block:
//! shadow.validate(block, height);
//! // Check shadow results:
//! let stats = shadow.stats();
//! ```

use crate::protocol::version::{version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION};
use crate::types::{Block, Height};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the shadow validator.
#[derive(Debug, Clone)]
pub struct ShadowValidatorConfig {
    /// Enable shadow validation (default: `true`).
    pub enabled: bool,
    /// If `true`, log every shadow validation result (default: `false`).
    pub verbose_logging: bool,
}

impl Default for ShadowValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            verbose_logging: false,
        }
    }
}

// -----------------------------------------------------------------------------
// ShadowValidator
// -----------------------------------------------------------------------------

/// Shadow validator that applies new‑PV rules without blocking consensus.
///
/// Results are logged and tracked for operator visibility, but failures
/// do **not** cause block rejection.
#[derive(Debug)]
pub struct ShadowValidator {
    /// Activation schedule.
    activations: Vec<ProtocolActivation>,
    /// Configuration.
    config: ShadowValidatorConfig,
    /// Number of blocks validated under shadow rules.
    shadow_validated: AtomicU64,
    /// Number of blocks that **passed** shadow validation.
    shadow_passed: AtomicU64,
    /// Number of blocks that **failed** shadow validation.
    shadow_failed: AtomicU64,
}

impl ShadowValidator {
    /// Create a new shadow validator with the given activation schedule and configuration.
    #[must_use]
    pub fn new(activations: Vec<ProtocolActivation>, config: ShadowValidatorConfig) -> Self {
        info!(enabled = config.enabled, "shadow validator created");
        Self {
            activations,
            config,
            shadow_validated: AtomicU64::new(0),
            shadow_passed: AtomicU64::new(0),
            shadow_failed: AtomicU64::new(0),
        }
    }

    /// Create a shadow validator with default configuration.
    #[must_use]
    pub fn with_defaults(activations: Vec<ProtocolActivation>) -> Self {
        Self::new(activations, ShadowValidatorConfig::default())
    }

    /// Perform shadow validation on a block.
    ///
    /// This is called for blocks at heights **before** the activation point
    /// of a newer protocol version that this binary already supports.
    /// The block has already been validated under the current PV rules;
    /// this method additionally validates it under the **new** PV rules.
    ///
    /// # Returns
    ///
    /// - `Ok(true)` if shadow validation was performed and passed.
    /// - `Ok(false)` if shadow validation was not applicable (e.g., disabled,
    ///   no future activation, or already at the latest PV).
    /// - `Err(reason)` if shadow validation was performed but failed (non‑blocking).
    ///
    /// The caller should **never** reject a block based on this error.
    pub fn validate(&self, block: &Block, height: Height) -> Result<bool, String> {
        if !self.config.enabled {
            debug!("shadow validation disabled");
            return Ok(false);
        }

        let current_pv = version_for_height(height, &self.activations);

        // Shadow validation only makes sense when this binary already supports
        // a *higher* protocol version than the one currently active on the chain.
        if current_pv >= CURRENT_PROTOCOL_VERSION {
            debug!(
                height,
                current_pv,
                binary_pv = CURRENT_PROTOCOL_VERSION,
                "shadow validation not applicable (binary version not ahead of chain)"
            );
            return Ok(false);
        }

        // Find the activation for the protocol version that this binary produces
        // (i.e., `CURRENT_PROTOCOL_VERSION`). If it's not found, there is no
        // scheduled upgrade to that version – shadow validation is irrelevant.
        let Some(activation) = self.activations.iter().find(|a| {
            a.protocol_version == CURRENT_PROTOCOL_VERSION
        }) else {
            debug!(
                height,
                binary_pv = CURRENT_PROTOCOL_VERSION,
                "no activation entry for the binary's protocol version"
            );
            return Ok(false);
        };

        // If the activation height is not yet set, the upgrade is not scheduled.
        let Some(activation_height) = activation.activation_height else {
            debug!(
                height,
                binary_pv = CURRENT_PROTOCOL_VERSION,
                "activation height is None (upgrade not scheduled)"
            );
            return Ok(false);
        };

        // Only run shadow validation for blocks **strictly before** activation.
        if height >= activation_height {
            debug!(
                height,
                activation_height,
                "shadow validation not applicable (already at or past activation)"
            );
            return Ok(false);
        }

        self.shadow_validated.fetch_add(1, Ordering::Relaxed);

        // Apply the new‑PV validation rules (shadow, non‑blocking).
        let result = self.shadow_validate_block(block, activation);

        match &result {
            Ok(()) => {
                self.shadow_passed.fetch_add(1, Ordering::Relaxed);
                if self.config.verbose_logging {
                    debug!(
                        height,
                        block_pv = block.header.protocol_version,
                        target_pv = activation.protocol_version,
                        activation_height,
                        "shadow validation PASSED"
                    );
                } else {
                    debug!(height, "shadow validation passed");
                }
                Ok(true)
            }
            Err(reason) => {
                self.shadow_failed.fetch_add(1, Ordering::Relaxed);
                warn!(
                    height,
                    block_pv = block.header.protocol_version,
                    target_pv = activation.protocol_version,
                    activation_height,
                    reason = reason.as_str(),
                    "shadow validation FAILED (non‑blocking)"
                );
                Err(reason.clone())
            }
        }
    }

    /// Internal: apply the new‑PV validation rules to a block (shadow mode).
    ///
    /// This is the place where additional checks for future protocol versions
    /// should be added.  The base implementation verifies:
    ///
    /// - `protocol_version` is not zero.
    /// - Block ID is non‑zero (deterministic).
    /// - Transaction root matches the transactions.
    ///
    /// More checks can be added as new PVs are introduced.
    fn shadow_validate_block(&self, block: &Block, activation: &ProtocolActivation) -> Result<(), String> {
        // Check that the block's protocol version is at least 1.
        if block.header.protocol_version == 0 {
            return Err("protocol_version must be >= 1".into());
        }

        // Verify that the block ID is deterministic (not all zeros).
        let computed_id = block.id();
        if computed_id.0 == [0u8; 32] {
            return Err("block ID is all zeros (likely missing header fields)".into());
        }

        // Validate transaction root.
        let computed_tx_root = crate::types::tx_root(&block.txs);
        if computed_tx_root != block.header.tx_root {
            return Err(format!(
                "tx_root mismatch: header={}, computed={}",
                hex::encode(block.header.tx_root.0),
                hex::encode(computed_tx_root.0),
            ));
        }

        // Additional PV‑specific checks can be inserted here.
        // Example: future PV 2 may require a new header field, etc.

        Ok(())
    }

    /// Get shadow validation statistics.
    #[must_use]
    pub fn stats(&self) -> ShadowStats {
        ShadowStats {
            validated: self.shadow_validated.load(Ordering::Relaxed),
            passed: self.shadow_passed.load(Ordering::Relaxed),
            failed: self.shadow_failed.load(Ordering::Relaxed),
        }
    }

    /// Reset statistics (useful for tests or after a long period).
    pub fn reset_stats(&self) {
        self.shadow_validated.store(0, Ordering::Relaxed);
        self.shadow_passed.store(0, Ordering::Relaxed);
        self.shadow_failed.store(0, Ordering::Relaxed);
        debug!("shadow validation stats reset");
    }
}

// -----------------------------------------------------------------------------
// ShadowStats
// -----------------------------------------------------------------------------

/// Statistics from shadow validation.
#[derive(Debug, Clone)]
pub struct ShadowStats {
    /// Total blocks shadow‑validated.
    pub validated: u64,
    /// Blocks that passed shadow validation.
    pub passed: u64,
    /// Blocks that failed shadow validation (non‑blocking).
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;
    use crate::types::*;

    // Test helpers
    fn make_test_block(height: u64, pv: u32, tx_root_override: Option<Hash32>) -> Block {
        let txs = vec![];
        let tx_root = tx_root_override.unwrap_or_else(|| tx_root(&txs));
        Block {
            header: BlockHeader {
                height,
                round: 0,
                prev: Hash32::zero(),
                proposer_pk: vec![1, 2, 3],
                tx_root,
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

    // This test simulates a binary that already supports PV 2 (CURRENT_PROTOCOL_VERSION = 2)
    // while the chain is still on PV 1. In this test environment we cannot change the
    // const, but we can create a helper that mocks the condition. For the purpose of
    // this test, we use the real `CURRENT_PROTOCOL_VERSION` (which is 1 as of this writing).
    // Therefore, shadow validation will not be triggered because the binary does not
    // support a newer version. To keep the tests meaningful, we will only test the
    // internal `shadow_validate_block` directly and check the conditions.

    #[test]
    fn test_shadow_validate_block_passes() {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let sv = ShadowValidator::with_defaults(vec![]); // activations not used internally
        let block = make_test_block(500, 1, None);
        let result = sv.shadow_validate_block(&block, &activation);
        assert!(result.is_ok());
    }

    #[test]
    fn test_shadow_validate_block_fails_bad_tx_root() {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let sv = ShadowValidator::with_defaults(vec![]);
        let bad_hash = Hash32([0xDE; 32]);
        let block = make_test_block(500, 1, Some(bad_hash));
        let result = sv.shadow_validate_block(&block, &activation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("tx_root mismatch"));
    }

    #[test]
    fn test_shadow_validate_block_fails_zero_pv() {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let sv = ShadowValidator::with_defaults(vec![]);
        let mut block = make_test_block(500, 1, None);
        block.header.protocol_version = 0;
        let result = sv.shadow_validate_block(&block, &activation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("protocol_version must be >= 1"));
    }

    #[test]
    fn test_stats() {
        let sv = ShadowValidator::with_defaults(vec![]);
        let stats = sv.stats();
        assert_eq!(stats.validated, 0);
        assert_eq!(stats.passed, 0);
        assert_eq!(stats.failed, 0);
        sv.reset_stats();
        let stats2 = sv.stats();
        assert_eq!(stats2.validated, 0);
    }
}
