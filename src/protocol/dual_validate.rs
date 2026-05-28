//! Dual-validate (shadow validation) for pre‑activation protocol upgrades.
//!
//! During the pre‑activation window, a node running a binary that already
//! supports the **next** protocol version can perform **shadow validation**:
//! applying the new PV rules to blocks without rejecting them if the new
//! rules fail.
//!
//! This allows operators to verify that the new rules work correctly
//! **before** the activation height is reached. Failures are logged and
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
use crate::types::{Block, Height, Hash32};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, info, warn, error};

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
    /// If `true`, collect detailed timing metrics (default: `false`).
    pub collect_timing: bool,
    /// Maximum number of shadow validation failures to log (default: 100).
    pub max_failures_logged: usize,
}

impl Default for ShadowValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            verbose_logging: false,
            collect_timing: false,
            max_failures_logged: 100,
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
    /// Number of failures logged (to avoid flooding logs).
    failures_logged: AtomicU64,
    /// Total time spent in shadow validation (nanoseconds).
    total_time_ns: AtomicU64,
}

impl ShadowValidator {
    /// Create a new shadow validator with the given activation schedule and configuration.
    #[must_use]
    pub fn new(activations: Vec<ProtocolActivation>, config: ShadowValidatorConfig) -> Self {
        info!(
            enabled = config.enabled,
            verbose = config.verbose_logging,
            collect_timing = config.collect_timing,
            "shadow validator created"
        );
        Self {
            activations,
            config,
            shadow_validated: AtomicU64::new(0),
            shadow_passed: AtomicU64::new(0),
            shadow_failed: AtomicU64::new(0),
            failures_logged: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
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

        let start = if self.config.collect_timing { Some(Instant::now()) } else { None };
        let result = self.shadow_validate_block(block, activation);
        if let Some(start_time) = start {
            let elapsed = start_time.elapsed().as_nanos() as u64;
            self.total_time_ns.fetch_add(elapsed, Ordering::Relaxed);
        }

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
                let failures = self.failures_logged.fetch_add(1, Ordering::Relaxed);
                if failures < self.config.max_failures_logged {
                    warn!(
                        height,
                        block_pv = block.header.protocol_version,
                        target_pv = activation.protocol_version,
                        activation_height,
                        reason = reason.as_str(),
                        "shadow validation FAILED (non‑blocking)"
                    );
                } else if failures == self.config.max_failures_logged {
                    warn!(
                        "shadow validation failures exceeded limit ({}), suppressing further logs",
                        self.config.max_failures_logged
                    );
                }
                Err(reason.clone())
            }
        }
    }

    /// Internal: apply the new‑PV validation rules to a block (shadow mode).
    ///
    /// This is the place where additional checks for future protocol versions
    /// should be added. The base implementation verifies:
    ///
    /// - `protocol_version` is not zero.
    /// - Block ID is non‑zero (deterministic).
    /// - Transaction root matches the transactions.
    /// - Receipts root matches (if receipts are available).
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

        // Validate receipts root (if receipts are available in the block).
        // For blocks without receipts, this check is skipped.
        if !block.receipts.is_empty() {
            let computed_receipts_root = crate::types::receipts_root(&block.receipts);
            if computed_receipts_root != block.header.receipts_root {
                return Err(format!(
                    "receipts_root mismatch: header={}, computed={}",
                    hex::encode(block.header.receipts_root.0),
                    hex::encode(computed_receipts_root.0),
                ));
            }
        }

        // Validate state root (basic sanity – non-zero).
        if block.header.state_root.0 == [0u8; 32] {
            return Err("state_root is all zeros".into());
        }

        // Additional PV‑specific checks can be inserted here.
        // Example: future PV 2 may require a new header field.
        if activation.protocol_version >= 2 {
            // PV2: validate that block height is within reasonable bounds
            if block.header.height == 0 {
                return Err("PV2: block height cannot be zero".into());
            }
        }

        if activation.protocol_version >= 3 {
            // PV3: validate that timestamp is reasonable (not in the far future)
            let now = crate::arch::x86_64::timer::uptime_ms() / 1000;
            if block.header.timestamp > now + 3600 {
                return Err(format!(
                    "PV3: block timestamp too far in the future: {} > {} + 3600",
                    block.header.timestamp, now
                ));
            }
        }

        Ok(())
    }

    /// Get shadow validation statistics.
    #[must_use]
    pub fn stats(&self) -> ShadowStats {
        ShadowStats {
            validated: self.shadow_validated.load(Ordering::Relaxed),
            passed: self.shadow_passed.load(Ordering::Relaxed),
            failed: self.shadow_failed.load(Ordering::Relaxed),
            total_time_ns: self.total_time_ns.load(Ordering::Relaxed),
            avg_time_ns: if self.shadow_validated.load(Ordering::Relaxed) > 0 {
                self.total_time_ns.load(Ordering::Relaxed) / self.shadow_validated.load(Ordering::Relaxed)
            } else {
                0
            },
        }
    }

    /// Reset statistics (useful for tests or after a long period).
    pub fn reset_stats(&self) {
        self.shadow_validated.store(0, Ordering::Relaxed);
        self.shadow_passed.store(0, Ordering::Relaxed);
        self.shadow_failed.store(0, Ordering::Relaxed);
        self.failures_logged.store(0, Ordering::Relaxed);
        self.total_time_ns.store(0, Ordering::Relaxed);
        debug!("shadow validation stats reset");
    }

    /// Get the current failure rate (failed / validated).
    #[must_use]
    pub fn failure_rate(&self) -> f64 {
        let validated = self.shadow_validated.load(Ordering::Relaxed);
        let failed = self.shadow_failed.load(Ordering::Relaxed);
        if validated == 0 {
            0.0
        } else {
            failed as f64 / validated as f64
        }
    }

    /// Get the current pass rate (passed / validated).
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        let validated = self.shadow_validated.load(Ordering::Relaxed);
        let passed = self.shadow_passed.load(Ordering::Relaxed);
        if validated == 0 {
            0.0
        } else {
            passed as f64 / validated as f64
        }
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
    /// Total time spent in shadow validation (nanoseconds).
    pub total_time_ns: u64,
    /// Average time per validation (nanoseconds).
    pub avg_time_ns: u64,
}

impl std::fmt::Display for ShadowStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let pass_rate = if self.validated > 0 {
            (self.passed as f64 / self.validated as f64) * 100.0
        } else {
            0.0
        };
        let fail_rate = if self.validated > 0 {
            (self.failed as f64 / self.validated as f64) * 100.0
        } else {
            0.0
        };
        write!(
            f,
            "shadow_validation: {} validated, {} passed ({:.1}%), {} failed ({:.1}%), avg={}ns",
            self.validated, self.passed, pass_rate, self.failed, fail_rate, self.avg_time_ns
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
                timestamp: height * 1000,
                protocol_version: pv,
            },
            txs,
            receipts: vec![],
        }
    }

    #[test]
    fn test_shadow_validate_block_passes() {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let sv = ShadowValidator::with_defaults(vec![]);
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
    fn test_shadow_validate_block_fails_zero_state_root() {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let sv = ShadowValidator::with_defaults(vec![]);
        let mut block = make_test_block(500, 1, None);
        block.header.state_root = Hash32([0u8; 32]);
        let result = sv.shadow_validate_block(&block, &activation);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("state_root is all zeros"));
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

    #[test]
    fn test_failure_rate() {
        // We need to actually validate blocks to see failure rate.
        // This test just checks the method exists and returns a value.
        let sv = ShadowValidator::with_defaults(vec![]);
        let rate = sv.failure_rate();
        assert_eq!(rate, 0.0);
    }

    #[test]
    fn test_pass_rate() {
        let sv = ShadowValidator::with_defaults(vec![]);
        let rate = sv.pass_rate();
        assert_eq!(rate, 0.0);
    }
}
