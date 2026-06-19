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
//! use iona::protocol::dual_validate::{ShadowValidator, ShadowValidatorConfig, ShadowValidationFn};
//! use iona::protocol::version::default_activations;
//!
//! let config = ShadowValidatorConfig::default();
//! let mut validator = ShadowValidator::new(default_activations(), config);
//! // For each block:
//! validator.validate(block, height, &default_shadow_validation)?;
//! // Check shadow results:
//! let stats = validator.stats();
//! ```

use crate::protocol::version::{version_for_height, ProtocolActivation, CURRENT_PROTOCOL_VERSION};
use crate::types::{Block, Height, Hash32};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, warn};

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during shadow validation.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ShadowError {
    #[error("shadow validation disabled")]
    Disabled,

    #[error("not applicable (binary not ahead of chain)")]
    NotApplicable,

    #[error("activation not found for protocol version {0}")]
    ActivationNotFound(u32),

    #[error("activation height not set for protocol version {0}")]
    ActivationHeightNotSet(u32),

    #[error("already at or past activation height")]
    AlreadyPastActivation,

    #[error("validation failed: {0}")]
    ValidationFailed(String),
}

pub type ShadowResult<T> = Result<T, ShadowError>;

// -----------------------------------------------------------------------------
// Shadow validation function type
// -----------------------------------------------------------------------------

/// Type alias for a shadow validation function.
///
/// The function receives a block and the target protocol version (the one being
/// shadow-validated), and returns `Ok(())` if the block is valid under the new
/// rules, or an error describing the failure.
///
/// The validation must be **non‑blocking** – any error should be logged but
/// must not prevent the block from being accepted by consensus.
pub type ShadowValidationFn = dyn Fn(&Block, u32) -> Result<(), String> + Send + Sync;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the shadow validator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowValidatorConfig {
    /// Enable shadow validation (default: `true`).
    pub enabled: bool,
    /// If `true`, log every shadow validation result (default: `false`).
    pub verbose_logging: bool,
    /// If `true`, collect detailed timing metrics (default: `false`).
    pub collect_timing: bool,
    /// Maximum number of shadow validation failures to log (default: 100).
    pub max_failures_logged: usize,
    /// Sample rate for shadow validation (0.0 = none, 1.0 = all).
    /// This can be used to reduce CPU overhead during high traffic.
    pub sample_rate: f64,
    /// Minimum number of blocks between shadow validation attempts.
    pub min_interval_blocks: u64,
}

impl Default for ShadowValidatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            verbose_logging: false,
            collect_timing: false,
            max_failures_logged: 100,
            sample_rate: 1.0,
            min_interval_blocks: 0,
        }
    }
}

impl ShadowValidatorConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if !(0.0..=1.0).contains(&self.sample_rate) {
            return Err(format!("sample_rate must be between 0.0 and 1.0, got {}", self.sample_rate));
        }
        if self.max_failures_logged == 0 {
            return Err("max_failures_logged must be > 0".into());
        }
        Ok(())
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
    /// Minimum time spent (nanoseconds).
    min_time_ns: AtomicU64,
    /// Maximum time spent (nanoseconds).
    max_time_ns: AtomicU64,
    /// Last shadow-validated height.
    last_validated_height: AtomicU64,
    /// Counter for sample rate decisions.
    sample_counter: AtomicU64,
    /// Failure categories (counts).
    failure_counts: Mutex<BTreeMap<String, u64>>,
}

impl ShadowValidator {
    /// Create a new shadow validator with the given activation schedule and configuration.
    pub fn new(activations: Vec<ProtocolActivation>, config: ShadowValidatorConfig) -> Result<Self, String> {
        config.validate()?;
        info!(
            enabled = config.enabled,
            verbose = config.verbose_logging,
            collect_timing = config.collect_timing,
            sample_rate = config.sample_rate,
            "shadow validator created"
        );
        Ok(Self {
            activations,
            config,
            shadow_validated: AtomicU64::new(0),
            shadow_passed: AtomicU64::new(0),
            shadow_failed: AtomicU64::new(0),
            failures_logged: AtomicU64::new(0),
            total_time_ns: AtomicU64::new(0),
            min_time_ns: AtomicU64::new(u64::MAX),
            max_time_ns: AtomicU64::new(0),
            last_validated_height: AtomicU64::new(0),
            sample_counter: AtomicU64::new(0),
            failure_counts: Mutex::new(BTreeMap::new()),
        })
    }

    /// Create a shadow validator with default configuration.
    pub fn with_defaults(activations: Vec<ProtocolActivation>) -> Result<Self, String> {
        Self::new(activations, ShadowValidatorConfig::default())
    }

    /// Perform shadow validation on a block using the provided validation function.
    ///
    /// This is called for blocks at heights **before** the activation point
    /// of a newer protocol version that this binary already supports.
    /// The block has already been validated under the current PV rules;
    /// this method additionally validates it under the **new** PV rules.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if shadow validation was performed.
    /// - `Err(ShadowError)` if shadow validation was not applicable or failed.
    pub fn validate<F>(
        &self,
        block: &Block,
        height: Height,
        validation_fn: F,
    ) -> ShadowResult<()>
    where
        F: Fn(&Block, u32) -> Result<(), String>,
    {
        if !self.config.enabled {
            debug!("shadow validation disabled");
            return Err(ShadowError::Disabled);
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
            return Err(ShadowError::NotApplicable);
        }

        // Find the activation for the protocol version that this binary produces.
        let Some(activation) = self.activations.iter().find(|a| {
            a.protocol_version == CURRENT_PROTOCOL_VERSION
        }) else {
            debug!(
                height,
                binary_pv = CURRENT_PROTOCOL_VERSION,
                "no activation entry for the binary's protocol version"
            );
            return Err(ShadowError::ActivationNotFound(CURRENT_PROTOCOL_VERSION));
        };

        let Some(activation_height) = activation.activation_height else {
            debug!(
                height,
                binary_pv = CURRENT_PROTOCOL_VERSION,
                "activation height is None (upgrade not scheduled)"
            );
            return Err(ShadowError::ActivationHeightNotSet(CURRENT_PROTOCOL_VERSION));
        };

        if height >= activation_height {
            debug!(
                height,
                activation_height,
                "shadow validation not applicable (already at or past activation)"
            );
            return Err(ShadowError::AlreadyPastActivation);
        }

        // Sample rate check.
        if self.config.sample_rate < 1.0 {
            let counter = self.sample_counter.fetch_add(1, Ordering::Relaxed);
            if (counter as f64) % (1.0 / self.config.sample_rate) != 0.0 {
                debug!(height, "shadow validation skipped (sampling)");
                return Ok(());
            }
        }

        // Minimum interval check.
        if self.config.min_interval_blocks > 0 {
            let last = self.last_validated_height.load(Ordering::Acquire);
            if height < last + self.config.min_interval_blocks {
                debug!(
                    height,
                    last,
                    min_interval = self.config.min_interval_blocks,
                    "shadow validation skipped (min interval)"
                );
                return Ok(());
            }
            self.last_validated_height.store(height, Ordering::Release);
        }

        self.shadow_validated.fetch_add(1, Ordering::Relaxed);

        let start = if self.config.collect_timing { Some(Instant::now()) } else { None };
        let result = self.shadow_validate(block, activation, validation_fn);
        if let Some(start_time) = start {
            let elapsed = start_time.elapsed().as_nanos() as u64;
            self.total_time_ns.fetch_add(elapsed, Ordering::Relaxed);
            self.update_min_max_time(elapsed);
        }

        match result {
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
                }
                Ok(())
            }
            Err(err) => {
                self.shadow_failed.fetch_add(1, Ordering::Relaxed);
                // Record failure category
                let category = err.split(':').next().unwrap_or("unknown").trim().to_string();
                self.record_failure(&category);

                let failures = self.failures_logged.fetch_add(1, Ordering::Relaxed);
                if failures < self.config.max_failures_logged {
                    warn!(
                        height,
                        block_pv = block.header.protocol_version,
                        target_pv = activation.protocol_version,
                        activation_height,
                        reason = %err,
                        "shadow validation FAILED (non‑blocking)"
                    );
                } else if failures == self.config.max_failures_logged {
                    warn!(
                        "shadow validation failures exceeded limit ({}), suppressing further logs",
                        self.config.max_failures_logged
                    );
                }
                Err(ShadowError::ValidationFailed(err))
            }
        }
    }

    /// Internal: apply the validation function to the block.
    fn shadow_validate<F>(
        &self,
        block: &Block,
        activation: &ProtocolActivation,
        validation_fn: F,
    ) -> Result<(), String>
    where
        F: Fn(&Block, u32) -> Result<(), String>,
    {
        validation_fn(block, activation.protocol_version)
    }

    /// Update min/max timing metrics.
    fn update_min_max_time(&self, elapsed_ns: u64) {
        let mut min = self.min_time_ns.load(Ordering::Relaxed);
        while elapsed_ns < min && self.min_time_ns.compare_exchange(min, elapsed_ns, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            min = self.min_time_ns.load(Ordering::Relaxed);
        }
        let mut max = self.max_time_ns.load(Ordering::Relaxed);
        while elapsed_ns > max && self.max_time_ns.compare_exchange(max, elapsed_ns, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            max = self.max_time_ns.load(Ordering::Relaxed);
        }
    }

    /// Record a failure category.
    fn record_failure(&self, category: &str) {
        let mut counts = self.failure_counts.lock().unwrap();
        *counts.entry(category.to_string()).or_insert(0) += 1;
    }

    /// Get shadow validation statistics.
    pub fn stats(&self) -> ShadowStats {
        let validated = self.shadow_validated.load(Ordering::Relaxed);
        let passed = self.shadow_passed.load(Ordering::Relaxed);
        let failed = self.shadow_failed.load(Ordering::Relaxed);
        let total_time_ns = self.total_time_ns.load(Ordering::Relaxed);
        let min_time_ns = if self.min_time_ns.load(Ordering::Relaxed) == u64::MAX {
            0
        } else {
            self.min_time_ns.load(Ordering::Relaxed)
        };
        let max_time_ns = self.max_time_ns.load(Ordering::Relaxed);
        let avg_time_ns = if validated > 0 {
            total_time_ns / validated
        } else {
            0
        };
        let failure_counts = self.failure_counts.lock().unwrap().clone();

        ShadowStats {
            validated,
            passed,
            failed,
            total_time_ns,
            avg_time_ns,
            min_time_ns,
            max_time_ns,
            failure_counts,
        }
    }

    /// Reset statistics (useful for tests or after a long period).
    pub fn reset_stats(&self) {
        self.shadow_validated.store(0, Ordering::Relaxed);
        self.shadow_passed.store(0, Ordering::Relaxed);
        self.shadow_failed.store(0, Ordering::Relaxed);
        self.failures_logged.store(0, Ordering::Relaxed);
        self.total_time_ns.store(0, Ordering::Relaxed);
        self.min_time_ns.store(u64::MAX, Ordering::Relaxed);
        self.max_time_ns.store(0, Ordering::Relaxed);
        self.last_validated_height.store(0, Ordering::Relaxed);
        self.sample_counter.store(0, Ordering::Relaxed);
        self.failure_counts.lock().unwrap().clear();
        debug!("shadow validation stats reset");
    }

    /// Get the current failure rate (failed / validated).
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
    pub fn pass_rate(&self) -> f64 {
        let validated = self.shadow_validated.load(Ordering::Relaxed);
        let passed = self.shadow_passed.load(Ordering::Relaxed);
        if validated == 0 {
            0.0
        } else {
            passed as f64 / validated as f64
        }
    }

    /// Check if shadow validation is enabled.
    pub fn is_enabled(&self) -> bool {
        self.config.enabled
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &ShadowValidatorConfig {
        &self.config
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
    /// Minimum time per validation (nanoseconds).
    pub min_time_ns: u64,
    /// Maximum time per validation (nanoseconds).
    pub max_time_ns: u64,
    /// Failure categories and their counts.
    pub failure_counts: BTreeMap<String, u64>,
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
        writeln!(
            f,
            "shadow_validation: {} validated, {} passed ({:.1}%), {} failed ({:.1}%)",
            self.validated, self.passed, pass_rate, self.failed, fail_rate
        )?;
        writeln!(
            f,
            "  time: avg={}ns, min={}ns, max={}ns",
            self.avg_time_ns, self.min_time_ns, self.max_time_ns
        )?;
        if !self.failure_counts.is_empty() {
            writeln!(f, "  failure categories:")?;
            for (cat, count) in &self.failure_counts {
                writeln!(f, "    {}: {}", cat, count)?;
            }
        }
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Default shadow validation function
// -----------------------------------------------------------------------------

/// Default shadow validation logic.
///
/// This function applies a set of standard checks that are expected to
/// be valid across protocol versions. It can be extended with PV‑specific
/// checks by passing a custom closure.
pub fn default_shadow_validation(block: &Block, target_pv: u32) -> Result<(), String> {
    // Basic checks.
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

    // Validate receipts root (if receipts are available).
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

    // PV‑specific checks.
    if target_pv >= 2 {
        // PV2: block height must be > 0.
        if block.header.height == 0 {
            return Err("PV2: block height cannot be zero".into());
        }
        // PV2: chain ID must match.
        if block.header.chain_id != 6126151 {
            return Err(format!(
                "PV2: chain ID mismatch: expected 6126151, got {}",
                block.header.chain_id
            ));
        }
    }

    if target_pv >= 3 {
        // PV3: timestamp not too far in the future.
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

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::version::ProtocolActivation;
    use crate::types::*;

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
                state_root: Hash32([1u8; 32]),
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
    fn test_shadow_validate_passes() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        let result = validator.validate(&block, 500, default_shadow_validation);
        assert!(result.is_ok());
        let stats = validator.stats();
        assert_eq!(stats.validated, 1);
        assert_eq!(stats.passed, 1);
        assert_eq!(stats.failed, 0);
        Ok(())
    }

    #[test]
    fn test_shadow_validate_fails_bad_tx_root() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let bad_hash = Hash32([0xDE; 32]);
        let block = make_test_block(500, 1, Some(bad_hash));
        let result = validator.validate(&block, 500, default_shadow_validation);
        assert!(result.is_err());
        let stats = validator.stats();
        assert_eq!(stats.validated, 1);
        assert_eq!(stats.passed, 0);
        assert_eq!(stats.failed, 1);
        Ok(())
    }

    #[test]
    fn test_shadow_validate_disabled() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let mut config = ShadowValidatorConfig::default();
        config.enabled = false;
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        let result = validator.validate(&block, 500, default_shadow_validation);
        assert!(matches!(result, Err(ShadowError::Disabled)));
        let stats = validator.stats();
        assert_eq!(stats.validated, 0);
        Ok(())
    }

    #[test]
    fn test_shadow_validate_not_applicable() -> Result<(), String> {
        // This test assumes CURRENT_PROTOCOL_VERSION is 1 (or higher).
        // We'll skip if CURRENT_PROTOCOL_VERSION > 1.
        if CURRENT_PROTOCOL_VERSION > 1 {
            return Ok(());
        }
        let activation = ProtocolActivation {
            protocol_version: 1,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        let result = validator.validate(&block, 500, default_shadow_validation);
        assert!(matches!(result, Err(ShadowError::NotApplicable)));
        Ok(())
    }

    #[test]
    fn test_shadow_validate_sampling() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let mut config = ShadowValidatorConfig::default();
        config.sample_rate = 0.5;
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        // Run twice; should sample about half.
        let mut validated = 0;
        for _ in 0..10 {
            if validator.validate(&block, 500, default_shadow_validation).is_ok() {
                validated += 1;
            }
        }
        assert!(validated >= 2 && validated <= 8);
        Ok(())
    }

    #[test]
    fn test_stats_display() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        validator.validate(&block, 500, default_shadow_validation)?;
        let stats = validator.stats();
        let s = format!("{}", stats);
        assert!(s.contains("validated"));
        assert!(s.contains("passed"));
        Ok(())
    }

    #[test]
    fn test_reset_stats() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block = make_test_block(500, 1, None);
        validator.validate(&block, 500, default_shadow_validation)?;
        assert_eq!(validator.stats().validated, 1);
        validator.reset_stats();
        assert_eq!(validator.stats().validated, 0);
        Ok(())
    }

    #[test]
    fn test_failure_rate_and_pass_rate() -> Result<(), String> {
        let activation = ProtocolActivation {
            protocol_version: 2,
            activation_height: Some(1000),
            grace_blocks: 100,
        };
        let config = ShadowValidatorConfig::default();
        let validator = ShadowValidator::new(vec![activation], config)?;
        let block1 = make_test_block(500, 1, None);
        let bad_hash = Hash32([0xDE; 32]);
        let block2 = make_test_block(501, 1, Some(bad_hash));
        validator.validate(&block1, 500, default_shadow_validation)?;
        let _ = validator.validate(&block2, 501, default_shadow_validation);
        assert_eq!(validator.failure_rate(), 0.5);
        assert_eq!(validator.pass_rate(), 0.5);
        Ok(())
    }
}
