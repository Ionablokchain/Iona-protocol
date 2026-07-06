//! VM transaction types for the IONA custom VM — Quantum-Ready.
//!
//! # Production Features
//! - Configurable via `VmTxConfig` (gas limits, sizes, caching).
//! - `VmTxMetrics` with Prometheus counters for validations, passes, failures, cache hits/misses.
//! - `VmTxManager` with thread‑safe LRU cache for validation results.
//! - Configurable validation with limits.
//! - Extended error types.
//! - Structured logging with `tracing`.
//! - Full test coverage.

use crate::types::vm_tx::{QuantumVmTxState, VmTx, VmTxError, VmTxResult};
use lru::LruCache;
use parking_lot::Mutex;
use prometheus::{
    register_counter, register_counter_vec, register_gauge, Counter, CounterVec, Gauge,
};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Keccak256};
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{debug, error, info, trace, warn};

// ── Re‑export types from the original module ─────────────────────────────

pub use crate::types::vm_tx::{
    ContractAddr, QuantumVmTxState, VmTx, VmTxError, VmTxResult, default_coherence, vm_tx_fidelity,
};

// ── Configuration ─────────────────────────────────────────────────────────

/// Configuration for VM transaction handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmTxConfig {
    /// Minimum gas limit required.
    pub min_gas_limit: u64,
    /// Maximum gas limit allowed.
    pub max_gas_limit: u64,
    /// Maximum size of init code (deploy).
    pub max_init_code_size: usize,
    /// Maximum size of calldata (call).
    pub max_calldata_size: usize,
    /// Whether to enable validation caching.
    pub enable_cache: bool,
    /// Maximum number of entries in the validation cache.
    pub cache_size: usize,
    /// Cache TTL in seconds.
    pub cache_ttl_secs: u64,
    /// Whether to enable metrics.
    pub enable_metrics: bool,
    /// Whether to log validation events.
    pub log_validation: bool,
}

impl Default for VmTxConfig {
    fn default() -> Self {
        Self {
            min_gas_limit: 21_000,
            max_gas_limit: 30_000_000,
            max_init_code_size: 256 * 1024, // 256 KiB
            max_calldata_size: 128 * 1024,  // 128 KiB
            enable_cache: true,
            cache_size: 1024,
            cache_ttl_secs: 300,
            enable_metrics: true,
            log_validation: true,
        }
    }
}

impl VmTxConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), String> {
        if self.min_gas_limit == 0 {
            return Err("min_gas_limit must be > 0".into());
        }
        if self.max_gas_limit == 0 {
            return Err("max_gas_limit must be > 0".into());
        }
        if self.min_gas_limit > self.max_gas_limit {
            return Err("min_gas_limit must be <= max_gas_limit".into());
        }
        if self.max_init_code_size == 0 {
            return Err("max_init_code_size must be > 0".into());
        }
        if self.max_calldata_size == 0 {
            return Err("max_calldata_size must be > 0".into());
        }
        if self.cache_size == 0 {
            return Err("cache_size must be > 0".into());
        }
        if self.cache_ttl_secs == 0 {
            return Err("cache_ttl_secs must be > 0".into());
        }
        Ok(())
    }
}

// ── Metrics ──────────────────────────────────────────────────────────────

/// Metrics for VM transaction handling.
#[derive(Clone)]
pub struct VmTxMetrics {
    pub validations: Counter,
    pub passes: Counter,
    pub failures: CounterVec,
    pub cache_hits: Counter,
    pub cache_misses: Counter,
    pub gas_estimates: Counter,
}

impl VmTxMetrics {
    pub fn new() -> Result<Self, prometheus::Error> {
        let validations = register_counter!(
            "iona_vmtx_validations_total",
            "Total VM transaction validations"
        )?;
        let passes = register_counter!(
            "iona_vmtx_passes_total",
            "Validations that passed"
        )?;
        let failures = register_counter_vec!(
            "iona_vmtx_failures_total",
            "Validations that failed",
            &["reason"]
        )?;
        let cache_hits = register_counter!(
            "iona_vmtx_cache_hits_total",
            "Validation cache hits"
        )?;
        let cache_misses = register_counter!(
            "iona_vmtx_cache_misses_total",
            "Validation cache misses"
        )?;
        let gas_estimates = register_counter!(
            "iona_vmtx_gas_estimates_total",
            "Total gas estimates"
        )?;
        Ok(Self {
            validations,
            passes,
            failures,
            cache_hits,
            cache_misses,
            gas_estimates,
        })
    }

    pub fn record_validation(&self) {
        self.validations.inc();
    }

    pub fn record_pass(&self) {
        self.passes.inc();
    }

    pub fn record_failure(&self, reason: &str) {
        self.failures.with_label_values(&[reason]).inc();
    }

    pub fn record_cache_hit(&self) {
        self.cache_hits.inc();
    }

    pub fn record_cache_miss(&self) {
        self.cache_misses.inc();
    }

    pub fn record_gas_estimate(&self) {
        self.gas_estimates.inc();
    }
}

impl Default for VmTxMetrics {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            validations: Counter::new("iona_vmtx_validations_total", "Validations").unwrap(),
            passes: Counter::new("iona_vmtx_passes_total", "Passes").unwrap(),
            failures: CounterVec::new(
                prometheus::Opts::new("iona_vmtx_failures_total", "Failures"),
                &["reason"],
            ).unwrap(),
            cache_hits: Counter::new("iona_vmtx_cache_hits_total", "Cache hits").unwrap(),
            cache_misses: Counter::new("iona_vmtx_cache_misses_total", "Cache misses").unwrap(),
            gas_estimates: Counter::new("iona_vmtx_gas_estimates_total", "Gas estimates").unwrap(),
        })
    }
}

// ── Cache Entry ──────────────────────────────────────────────────────────

#[derive(Clone)]
struct ValidationCacheEntry {
    result: VmTxResult<()>,
    expires_at: Instant,
}

// ── VmTxManager ─────────────────────────────────────────────────────────

/// Thread‑safe manager for VM transaction validation, caching, and metrics.
#[derive(Clone)]
pub struct VmTxManager {
    config: Arc<VmTxConfig>,
    metrics: Arc<VmTxMetrics>,
    cache: Arc<Mutex<Option<LruCache<Vec<u8>, ValidationCacheEntry>>>>,
}

impl VmTxManager {
    /// Create a new manager with the given configuration.
    pub fn new(config: VmTxConfig) -> Result<Self, String> {
        config.validate()?;
        let metrics = Arc::new(VmTxMetrics::default());
        let cache = if config.enable_cache {
            let size = NonZeroUsize::new(config.cache_size).ok_or("cache_size must be > 0")?;
            Some(LruCache::new(size))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            metrics,
            cache: Arc::new(Mutex::new(cache)),
        })
    }

    /// Validate a transaction using the configured limits.
    pub fn validate(&self, tx: &VmTx) -> VmTxResult<()> {
        self.metrics.record_validation();

        // Compute cache key from serialized transaction (excluding coherence).
        let key = self.compute_cache_key(tx);

        // Check cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                if let Some(entry) = cache.get(&key) {
                    if entry.expires_at > Instant::now() {
                        self.metrics.record_cache_hit();
                        trace!("validation cache hit");
                        return entry.result.clone();
                    } else {
                        cache.pop(&key);
                    }
                }
                self.metrics.record_cache_miss();
            }
        }

        // Perform validation.
        let result = self.validate_internal(tx);

        // Store in cache.
        if self.config.enable_cache {
            let mut cache_guard = self.cache.lock();
            if let Some(cache) = cache_guard.as_mut() {
                let entry = ValidationCacheEntry {
                    result: result.clone(),
                    expires_at: Instant::now() + Duration::from_secs(self.config.cache_ttl_secs),
                };
                cache.put(key, entry);
            }
        }

        result
    }

    /// Internal validation with configuration limits.
    fn validate_internal(&self, tx: &VmTx) -> VmTxResult<()> {
        // Gas limit bounds.
        let gas = tx.gas_limit();
        if gas == 0 {
            self.metrics.record_failure("zero_gas_limit");
            return Err(VmTxError::ZeroGasLimit(gas));
        }
        if gas > self.config.max_gas_limit {
            self.metrics.record_failure("gas_limit_too_high");
            return Err(VmTxError::GasLimitTooHigh {
                limit: gas,
                max: self.config.max_gas_limit,
            });
        }
        if gas < self.config.min_gas_limit {
            self.metrics.record_failure("gas_limit_too_low");
            return Err(VmTxError::GasLimitTooLow {
                limit: gas,
                min: self.config.min_gas_limit,
            });
        }

        // Sender check.
        if tx.sender().is_empty() {
            self.metrics.record_failure("empty_sender");
            return Err(VmTxError::EmptySender);
        }

        // Payload checks.
        match tx {
            VmTx::Deploy { init_code, .. } => {
                if init_code.is_empty() {
                    self.metrics.record_failure("empty_init_code");
                    return Err(VmTxError::EmptyInitCode);
                }
                if init_code.len() > self.config.max_init_code_size {
                    self.metrics.record_failure("init_code_too_large");
                    return Err(VmTxError::InitCodeTooLarge {
                        size: init_code.len(),
                        max: self.config.max_init_code_size,
                    });
                }
            }
            VmTx::Call { contract, calldata, .. } => {
                if contract.iter().all(|&b| b == 0) {
                    self.metrics.record_failure("zero_contract_address");
                    return Err(VmTxError::ZeroContractAddress);
                }
                if calldata.len() > self.config.max_calldata_size {
                    self.metrics.record_failure("calldata_too_large");
                    return Err(VmTxError::CalldataTooLarge {
                        size: calldata.len(),
                        max: self.config.max_calldata_size,
                    });
                }
            }
        }

        // All checks passed.
        self.metrics.record_pass();
        if self.config.log_validation {
            trace!("validation passed for {:?}", tx);
        }
        Ok(())
    }

    /// Validate with quantum state tracking.
    pub fn validate_quantum(&self, tx: &VmTx) -> (VmTxResult<()>, QuantumVmTxState) {
        let result = self.validate(tx);
        let mut qstate = QuantumVmTxState::new();
        match &result {
            Ok(_) => {
                qstate.record_pass();
                qstate.record_pass();
                qstate.record_pass();
                qstate.apply_payload_decoherence(tx.payload_size());
            }
            Err(_) => {
                qstate.record_failure();
            }
        }
        qstate.apply_vm_tx_channel();
        (result, qstate)
    }

    /// Compute a cache key from the transaction.
    fn compute_cache_key(&self, tx: &VmTx) -> Vec<u8> {
        let mut bytes = Vec::new();
        match tx {
            VmTx::Deploy { sender, init_code, gas_limit, .. } => {
                bytes.extend_from_slice(&[0u8]); // type marker
                bytes.extend_from_slice(sender.as_bytes());
                bytes.extend_from_slice(&gas_limit.to_le_bytes());
                bytes.extend_from_slice(init_code);
            }
            VmTx::Call { sender, contract, calldata, gas_limit, .. } => {
                bytes.extend_from_slice(&[1u8]);
                bytes.extend_from_slice(sender.as_bytes());
                bytes.extend_from_slice(contract);
                bytes.extend_from_slice(&gas_limit.to_le_bytes());
                bytes.extend_from_slice(calldata);
            }
        }
        // Hash the bytes to get a fixed-size key.
        let hash = Keccak256::digest(&bytes);
        hash.to_vec()
    }

    /// Estimate gas for the transaction (intrinsic + overhead).
    pub fn estimate_gas(&self, tx: &VmTx) -> u64 {
        self.metrics.record_gas_estimate();
        // Base gas: 21,000 + 4 per byte of payload (simplified).
        let payload_size = tx.payload_size();
        let base = 21_000 + 4 * payload_size;
        // For deploy, add extra for creation.
        let extra = if tx.is_deploy() { 32_000 } else { 0 };
        base + extra
    }

    /// Get metrics snapshot.
    pub fn metrics_snapshot(&self) -> VmTxMetricsSnapshot {
        VmTxMetricsSnapshot {
            validations: self.metrics.validations.get(),
            passes: self.metrics.passes.get(),
            failures: self.metrics.failures.clone(),
            cache_hits: self.metrics.cache_hits.get(),
            cache_misses: self.metrics.cache_misses.get(),
            gas_estimates: self.metrics.gas_estimates.get(),
        }
    }

    /// Get configuration.
    pub fn config(&self) -> &VmTxConfig {
        &self.config
    }

    /// Clear the cache.
    pub fn clear_cache(&self) {
        if let Some(cache) = self.cache.lock().as_mut() {
            cache.clear();
            trace!("VM tx cache cleared");
        }
    }

    /// Get cache size.
    pub fn cache_size(&self) -> usize {
        if let Some(cache) = self.cache.lock().as_ref() {
            cache.len()
        } else {
            0
        }
    }
}

/// Snapshot of VM transaction metrics.
#[derive(Debug, Clone)]
pub struct VmTxMetricsSnapshot {
    pub validations: u64,
    pub passes: u64,
    pub failures: CounterVec,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub gas_estimates: u64,
}

// ── Extended Error Types ─────────────────────────────────────────────────

/// Extended error types for VM transaction validation.
#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum VmTxErrorExt {
    #[error("gas limit {limit} exceeds max {max}")]
    GasLimitTooHigh { limit: u64, max: u64 },

    #[error("gas limit {limit} below minimum {min}")]
    GasLimitTooLow { limit: u64, min: u64 },

    #[error("init code size {size} exceeds max {max}")]
    InitCodeTooLarge { size: usize, max: usize },

    #[error("calldata size {size} exceeds max {max}")]
    CalldataTooLarge { size: usize, max: usize },

    #[error("gas limit must be > 0, got {0}")]
    ZeroGasLimit(u64),

    #[error("init code cannot be empty for deployment")]
    EmptyInitCode,

    #[error("sender address cannot be empty")]
    EmptySender,

    #[error("contract address cannot be all zeroes")]
    ZeroContractAddress,

    #[error("quantum decoherence: vm tx coherence {coherence} below threshold {threshold}")]
    Decoherence { coherence: f64, threshold: f64 },
}

// ── Standalone functions ────────────────────────────────────────────────

/// Validate a VM transaction with default configuration.
pub fn validate_vm_tx(tx: &VmTx) -> VmTxResult<()> {
    let config = VmTxConfig::default();
    let manager = VmTxManager::new(config).map_err(|e| VmTxError::Decoherence {
        coherence: 0.0,
        threshold: 0.0,
    })?;
    manager.validate(tx)
}

/// Estimate gas for a VM transaction with default config.
pub fn estimate_vm_gas(tx: &VmTx) -> u64 {
    let config = VmTxConfig::default();
    let manager = VmTxManager::new(config).unwrap();
    manager.estimate_gas(tx)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_deploy() -> VmTx {
        VmTx::Deploy {
            sender: "alice".into(),
            init_code: vec![0x60, 0x00, 0x00],
            gas_limit: 100_000,
            coherence: 1.0,
        }
    }

    fn valid_call() -> VmTx {
        VmTx::Call {
            sender: "bob".into(),
            contract: [1u8; 32],
            calldata: vec![0x01, 0x02],
            gas_limit: 200_000,
            coherence: 1.0,
        }
    }

    #[test]
    fn test_manager_validate_ok() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        assert!(manager.validate(&valid_deploy()).is_ok());
        assert!(manager.validate(&valid_call()).is_ok());
    }

    #[test]
    fn test_manager_validate_gas_limit_too_high() {
        let config = VmTxConfig {
            max_gas_limit: 50_000,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        let result = manager.validate(&tx);
        assert!(matches!(
            result,
            Err(VmTxError::GasLimitTooHigh { .. })
        ));
    }

    #[test]
    fn test_manager_validate_gas_limit_too_low() {
        let config = VmTxConfig {
            min_gas_limit: 200_000,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        let result = manager.validate(&tx);
        assert!(matches!(
            result,
            Err(VmTxError::GasLimitTooLow { .. })
        ));
    }

    #[test]
    fn test_manager_validate_init_code_too_large() {
        let config = VmTxConfig {
            max_init_code_size: 2,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        let result = manager.validate(&tx);
        assert!(matches!(
            result,
            Err(VmTxError::InitCodeTooLarge { .. })
        ));
    }

    #[test]
    fn test_manager_validate_calldata_too_large() {
        let config = VmTxConfig {
            max_calldata_size: 1,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_call();
        let result = manager.validate(&tx);
        assert!(matches!(
            result,
            Err(VmTxError::CalldataTooLarge { .. })
        ));
    }

    #[test]
    fn test_manager_validate_empty_sender() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        let mut tx = valid_deploy();
        if let VmTx::Deploy { sender, .. } = &mut tx {
            sender.clear();
        }
        let result = manager.validate(&tx);
        assert!(matches!(result, Err(VmTxError::EmptySender)));
    }

    #[test]
    fn test_manager_validate_empty_init_code() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        let result = manager.validate(&tx);
        assert!(matches!(result, Err(VmTxError::EmptyInitCode)));
    }

    #[test]
    fn test_manager_validate_zero_contract() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        let mut tx = valid_call();
        if let VmTx::Call { contract, .. } = &mut tx {
            *contract = [0u8; 32];
        }
        let result = manager.validate(&tx);
        assert!(matches!(result, Err(VmTxError::ZeroContractAddress)));
    }

    #[test]
    fn test_manager_validate_quantum() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        let (result, qstate) = manager.validate_quantum(&tx);
        assert!(result.is_ok());
        assert!(qstate.total_checks > 0);
        assert!(qstate.purity < 1.0);
    }

    #[test]
    fn test_manager_estimate_gas() {
        let config = VmTxConfig::default();
        let manager = VmTxManager::new(config).unwrap();
        let deploy = valid_deploy();
        let gas = manager.estimate_gas(&deploy);
        assert!(gas >= 21_000 + 3 * 4 + 32_000);
        let call = valid_call();
        let gas = manager.estimate_gas(&call);
        assert!(gas >= 21_000 + 2 * 4);
    }

    #[test]
    fn test_manager_cache() {
        let config = VmTxConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        manager.validate(&tx).unwrap();
        manager.validate(&tx).unwrap();
        assert!(manager.cache_size() > 0);
        let snap = manager.metrics_snapshot();
        assert!(snap.cache_hits > 0);
        assert!(snap.cache_misses > 0);
    }

    #[test]
    fn test_manager_clear_cache() {
        let config = VmTxConfig {
            enable_cache: true,
            cache_size: 10,
            ..Default::default()
        };
        let manager = VmTxManager::new(config).unwrap();
        let tx = valid_deploy();
        manager.validate(&tx).unwrap();
        assert!(manager.cache_size() > 0);
        manager.clear_cache();
        assert_eq!(manager.cache_size(), 0);
    }

    #[test]
    fn test_config_validation() {
        let mut config = VmTxConfig::default();
        assert!(config.validate().is_ok());
        config.min_gas_limit = 0;
        assert!(config.validate().is_err());
        config.min_gas_limit = 10;
        config.max_gas_limit = 5;
        assert!(config.validate().is_err());
        config.max_gas_limit = 10;
        config.max_init_code_size = 0;
        assert!(config.validate().is_err());
        config.max_init_code_size = 1024;
        config.max_calldata_size = 0;
        assert!(config.validate().is_err());
        config.max_calldata_size = 1024;
        config.cache_size = 0;
        assert!(config.validate().is_err());
        config.cache_size = 10;
        config.cache_ttl_secs = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_standalone_validate() {
        assert!(validate_vm_tx(&valid_deploy()).is_ok());
        let mut tx = valid_deploy();
        if let VmTx::Deploy { init_code, .. } = &mut tx {
            init_code.clear();
        }
        assert!(validate_vm_tx(&tx).is_err());
    }

    #[test]
    fn test_standalone_estimate_gas() {
        let deploy = valid_deploy();
        let gas = estimate_vm_gas(&deploy);
        assert!(gas > 0);
    }

    #[test]
    fn test_error_extension() {
        let err = VmTxErrorExt::GasLimitTooHigh { limit: 100, max: 50 };
        assert_eq!(err.to_string(), "gas limit 100 exceeds max 50");
        let err = VmTxErrorExt::InitCodeTooLarge { size: 1000, max: 500 };
        assert_eq!(err.to_string(), "init code size 1000 exceeds max 500");
    }
}
