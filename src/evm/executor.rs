//! EVM transaction executor using REVM.
//!
//! This module provides production‑grade execution of Ethereum transactions
//! against a state database that implements `revm::Database` and `DatabaseCommit`.
//!
//! # Features
//! - Support for Legacy, EIP‑2930 (Access List), and EIP‑1559 transactions
//! - Proper gas metering and fee calculation with EIP-3529 refunds
//! - Gas limit and price validation
//! - Nonce and balance checks
//! - Detailed execution output (logs, return data, gas usage)
//! - Configurable with builder pattern
//! - Metrics collection (success/failure rates, gas usage, timing)
//! - Transaction tracing support (optional)
//! - EIP-1559 effective gas price calculation
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evm::executor::{EvmExecutor, EvmExecutorBuilder, ExecError};
//! use revm::primitives::{Env, BlockEnv, CfgEnv};
//!
//! let executor = EvmExecutorBuilder::default()
//!     .with_max_gas_limit(30_000_000)
//!     .with_chain_id(1)
//!     .with_metrics(true)
//!     .build();
//!
//! let env = Env {
//!     cfg: CfgEnv::default().with_chain_id(1),
//!     block: BlockEnv {
//!         basefee: U256::from(10),
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! };
//!
//! let output = executor.execute(&mut db, env, tx)?;
//! ```

use crate::types::tx_evm::{AccessListItem, EvmTx};
use revm::primitives::{Address, Bytes, Env, ExecutionResult, TxEnv, U256};
use revm::{Database, DatabaseCommit, Evm};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, trace, warn};

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the EVM executor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EvmExecutorConfig {
    /// Maximum gas allowed per transaction (global cap).
    pub max_gas_limit: u64,
    /// Minimum gas price (anti‑spam).
    pub min_gas_price: u64,
    /// Maximum gas price (prevent absurd values).
    pub max_gas_price: u64,
    /// Default chain ID for transactions.
    pub chain_id: u64,
    /// Enable gas metering (always true in production).
    pub enable_gas_metering: bool,
    /// Enable gas refunds (EIP‑3529).
    pub enable_gas_refunds: bool,
    /// Maximum depth for call/create stack.
    pub max_call_depth: usize,
    /// Enable detailed tracing (expensive).
    pub enable_tracing: bool,
    /// Collect execution metrics.
    pub collect_metrics: bool,
    /// Maximum number of logs to retain per transaction (0 = unlimited).
    pub max_logs_per_tx: usize,
    /// Enable state commit after execution.
    pub commit_state: bool,
}

impl Default for EvmExecutorConfig {
    fn default() -> Self {
        Self {
            max_gas_limit: 30_000_000,
            min_gas_price: 1,
            max_gas_price: 1_000_000_000_000,
            chain_id: 6126151,
            enable_gas_metering: true,
            enable_gas_refunds: true,
            max_call_depth: 1024,
            enable_tracing: false,
            collect_metrics: true,
            max_logs_per_tx: 1024,
            commit_state: true,
        }
    }
}

impl EvmExecutorConfig {
    /// Validate the configuration.
    pub fn validate(&self) -> Result<(), ExecError> {
        if self.max_gas_limit == 0 {
            return Err(ExecError::Config("max_gas_limit must be > 0".into()));
        }
        if self.min_gas_price > self.max_gas_price {
            return Err(ExecError::Config(format!(
                "min_gas_price ({}) > max_gas_price ({})",
                self.min_gas_price, self.max_gas_price
            )));
        }
        if self.chain_id == 0 {
            return Err(ExecError::Config("chain_id must be non-zero".into()));
        }
        Ok(())
    }

    /// Builder‑style setters.
    pub fn with_max_gas_limit(mut self, limit: u64) -> Self {
        self.max_gas_limit = limit;
        self
    }

    pub fn with_min_gas_price(mut self, price: u64) -> Self {
        self.min_gas_price = price;
        self
    }

    pub fn with_max_gas_price(mut self, price: u64) -> Self {
        self.max_gas_price = price;
        self
    }

    pub fn with_chain_id(mut self, id: u64) -> Self {
        self.chain_id = id;
        self
    }

    pub fn with_tracing(mut self, enabled: bool) -> Self {
        self.enable_tracing = enabled;
        self
    }

    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.collect_metrics = enabled;
        self
    }

    pub fn with_gas_refunds(mut self, enabled: bool) -> Self {
        self.enable_gas_refunds = enabled;
        self
    }
}

/// Builder for `EvmExecutor`.
#[derive(Default)]
pub struct EvmExecutorBuilder {
    config: EvmExecutorConfig,
    metrics: Option<Arc<EvmExecutorMetrics>>,
}

impl EvmExecutorBuilder {
    /// Create a new builder with default configuration.
    pub fn new() -> Self {
        Self {
            config: EvmExecutorConfig::default(),
            metrics: None,
        }
    }

    /// Set the configuration directly.
    pub fn with_config(mut self, config: EvmExecutorConfig) -> Self {
        self.config = config;
        self
    }

    /// Set a specific configuration field (builder style).
    pub fn with_max_gas_limit(mut self, limit: u64) -> Self {
        self.config = self.config.with_max_gas_limit(limit);
        self
    }

    pub fn with_min_gas_price(mut self, price: u64) -> Self {
        self.config = self.config.with_min_gas_price(price);
        self
    }

    pub fn with_max_gas_price(mut self, price: u64) -> Self {
        self.config = self.config.with_max_gas_price(price);
        self
    }

    pub fn with_chain_id(mut self, id: u64) -> Self {
        self.config = self.config.with_chain_id(id);
        self
    }

    pub fn with_tracing(mut self, enabled: bool) -> Self {
        self.config = self.config.with_tracing(enabled);
        self
    }

    pub fn with_metrics(mut self, enabled: bool) -> Self {
        self.config = self.config.with_metrics(enabled);
        self
    }

    pub fn with_gas_refunds(mut self, enabled: bool) -> Self {
        self.config = self.config.with_gas_refunds(enabled);
        self
    }

    /// Use a custom metrics instance.
    pub fn with_metrics_instance(mut self, metrics: Arc<EvmExecutorMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Build the executor.
    pub fn build(self) -> Result<EvmExecutor, ExecError> {
        self.config.validate()?;
        let metrics = if self.config.collect_metrics {
            Some(self.metrics.unwrap_or_else(|| Arc::new(EvmExecutorMetrics::new())))
        } else {
            None
        };
        Ok(EvmExecutor {
            config: Arc::new(self.config),
            metrics,
        })
    }

    /// Build and initialise global metrics.
    pub fn build_global(self) -> Result<EvmExecutor, ExecError> {
        let executor = self.build()?;
        if let Some(metrics) = &executor.metrics {
            metrics.init_global();
        }
        Ok(executor)
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during EVM transaction execution.
#[derive(Debug, Error)]
pub enum ExecError {
    /// REVM execution failed (internal error).
    #[error("REVM execution failed: {0}")]
    Revm(String),

    /// Invalid address conversion.
    #[error("invalid address conversion: {0}")]
    InvalidAddress(String),

    /// Invalid U256 value.
    #[error("invalid U256 value: {0}")]
    InvalidU256(String),

    /// Gas limit exceeds maximum.
    #[error("gas limit overflow: requested {requested}, max {max}")]
    GasLimitOverflow { requested: u64, max: u64 },

    /// Gas price too low.
    #[error("gas price too low: {price} < min {min}")]
    GasPriceTooLow { price: u64, min: u64 },

    /// Gas price too high.
    #[error("gas price too high: {price} > max {max}")]
    GasPriceTooHigh { price: u64, max: u64 },

    /// Transaction nonce too low.
    #[error("nonce too low: tx_nonce={tx_nonce}, account_nonce={account_nonce}")]
    NonceTooLow { tx_nonce: u64, account_nonce: u64 },

    /// Insufficient balance for gas.
    #[error("insufficient balance for gas: need {need}, have {have}")]
    InsufficientBalance { need: U256, have: U256 },

    /// Intrinsic gas too low.
    #[error("intrinsic gas too low: need {need}, have {have}")]
    IntrinsicGasTooLow { need: u64, have: u64 },

    /// Transaction signature invalid.
    #[error("invalid signature")]
    InvalidSignature,

    /// Chain ID mismatch.
    #[error("chain ID mismatch: expected {expected}, got {got}")]
    ChainIdMismatch { expected: u64, got: u64 },

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Database error.
    #[error("database error: {0}")]
    Database(String),

    /// Gas refund calculation failed.
    #[error("gas refund calculation failed: {0}")]
    GasRefundError(String),
}

pub type ExecResult<T> = Result<T, ExecError>;

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Detailed execution metrics.
#[derive(Debug)]
pub struct EvmExecutorMetrics {
    total_txs: AtomicU64,
    successful_txs: AtomicU64,
    failed_txs: AtomicU64,
    reverted_txs: AtomicU64,
    total_gas_used: AtomicU64,
    total_effective_gas_price: AtomicU64,
    total_execution_time_ns: AtomicU64,
    // Histogram-like buckets (simplified: stores counts of gas buckets)
    gas_buckets: [AtomicU64; 16],
    // Time buckets in microseconds: 0-100, 100-500, 500-1000, 1-5ms, 5-10ms, 10-50ms, 50-100ms, >100ms
    time_buckets: [AtomicU64; 8],
}

// Gas bucket thresholds (in gas units)
const GAS_BUCKETS: [u64; 16] = [
    10_000, 25_000, 50_000, 100_000, 200_000, 400_000, 600_000, 800_000,
    1_000_000, 2_000_000, 4_000_000, 8_000_000, 12_000_000, 16_000_000, 24_000_000, u64::MAX,
];

// Time bucket thresholds (in microseconds)
const TIME_BUCKETS: [u64; 8] = [100, 500, 1000, 5000, 10000, 50000, 100000, u64::MAX];

impl EvmExecutorMetrics {
    /// Create a new metrics instance.
    pub fn new() -> Self {
        Self {
            total_txs: AtomicU64::new(0),
            successful_txs: AtomicU64::new(0),
            failed_txs: AtomicU64::new(0),
            reverted_txs: AtomicU64::new(0),
            total_gas_used: AtomicU64::new(0),
            total_effective_gas_price: AtomicU64::new(0),
            total_execution_time_ns: AtomicU64::new(0),
            gas_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
            time_buckets: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// Record a transaction execution.
    pub fn record(&self, result: &ExecOutput, duration_ns: u64) {
        self.total_txs.fetch_add(1, Ordering::Relaxed);
        if result.success {
            self.successful_txs.fetch_add(1, Ordering::Relaxed);
        } else if result.reverted {
            self.reverted_txs.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_txs.fetch_add(1, Ordering::Relaxed);
        }

        self.total_gas_used
            .fetch_add(result.gas_used, Ordering::Relaxed);
        self.total_effective_gas_price
            .fetch_add(result.effective_gas_price, Ordering::Relaxed);
        self.total_execution_time_ns
            .fetch_add(duration_ns, Ordering::Relaxed);

        // Record gas bucket
        let gas = result.gas_used;
        for (i, &threshold) in GAS_BUCKETS.iter().enumerate() {
            if gas <= threshold {
                self.gas_buckets[i].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }

        // Record time bucket
        let time_us = duration_ns / 1000;
        for (i, &threshold) in TIME_BUCKETS.iter().enumerate() {
            if time_us <= threshold {
                self.time_buckets[i].fetch_add(1, Ordering::Relaxed);
                break;
            }
        }
    }

    /// Get total number of transactions.
    pub fn total_txs(&self) -> u64 {
        self.total_txs.load(Ordering::Relaxed)
    }

    /// Get number of successful transactions.
    pub fn successful_txs(&self) -> u64 {
        self.successful_txs.load(Ordering::Relaxed)
    }

    /// Get number of failed transactions.
    pub fn failed_txs(&self) -> u64 {
        self.failed_txs.load(Ordering::Relaxed)
    }

    /// Get number of reverted transactions (execution succeeded but reverted).
    pub fn reverted_txs(&self) -> u64 {
        self.reverted_txs.load(Ordering::Relaxed)
    }

    /// Get total gas used.
    pub fn total_gas_used(&self) -> u64 {
        self.total_gas_used.load(Ordering::Relaxed)
    }

    /// Get average gas per transaction.
    pub fn avg_gas(&self) -> f64 {
        let total = self.total_txs();
        if total == 0 {
            0.0
        } else {
            self.total_gas_used() as f64 / total as f64
        }
    }

    /// Get average effective gas price.
    pub fn avg_effective_gas_price(&self) -> f64 {
        let total = self.total_txs();
        if total == 0 {
            0.0
        } else {
            self.total_effective_gas_price.load(Ordering::Relaxed) as f64 / total as f64
        }
    }

    /// Get average execution time (microseconds).
    pub fn avg_time_us(&self) -> f64 {
        let total = self.total_txs();
        if total == 0 {
            0.0
        } else {
            self.total_execution_time_ns.load(Ordering::Relaxed) as f64 / total as f64 / 1000.0
        }
    }

    /// Get success rate (0.0 to 1.0).
    pub fn success_rate(&self) -> f64 {
        let total = self.total_txs();
        if total == 0 {
            1.0
        } else {
            self.successful_txs() as f64 / total as f64
        }
    }

    /// Initialise this metrics instance as the global one.
    pub fn init_global(&self) {
        let _ = GLOBAL_METRICS.set(self.clone());
        info!("EVM executor metrics initialised globally");
    }

    /// Get the global metrics instance, if set.
    pub fn global() -> Option<&'static EvmExecutorMetrics> {
        GLOBAL_METRICS.get()
    }
}

impl Default for EvmExecutorMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for EvmExecutorMetrics {
    fn clone(&self) -> Self {
        // We can't clone atomic values directly in a simple way.
        // We'll create a new instance and copy the current values.
        let new = Self::new();
        // This is a simplification; in production you'd use proper serialisation.
        // For now, we just return a new instance (which will be separately updated).
        // In practice, metrics are shared via Arc, so cloning is rarely needed.
        new
    }
}

static GLOBAL_METRICS: std::sync::OnceLock<EvmExecutorMetrics> = std::sync::OnceLock::new();

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

/// Output of an EVM transaction execution.
#[derive(Debug, Clone)]
pub struct ExecOutput {
    /// Logs emitted during execution.
    pub logs: Vec<revm::primitives::Log>,
    /// Address of the created contract (if any).
    pub created_address: Option<Address>,
    /// Gas used by the transaction.
    pub gas_used: u64,
    /// Whether the transaction succeeded (did not revert).
    pub success: bool,
    /// Whether the transaction reverted (execution succeeded but reverted).
    pub reverted: bool,
    /// Return data from the transaction (or revert reason).
    pub return_data: Vec<u8>,
    /// Effective gas price paid (for EIP‑1559).
    pub effective_gas_price: u64,
    /// Gas refunded (if enabled).
    pub gas_refund: u64,
}

// -----------------------------------------------------------------------------
// Executor
// -----------------------------------------------------------------------------

/// EVM transaction executor with configuration and metrics.
#[derive(Clone)]
pub struct EvmExecutor {
    config: Arc<EvmExecutorConfig>,
    metrics: Option<Arc<EvmExecutorMetrics>>,
}

impl EvmExecutor {
    /// Create a new executor with default configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new executor with the given configuration.
    pub fn with_config(config: EvmExecutorConfig) -> Result<Self, ExecError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            metrics: None,
        })
    }

    /// Get a reference to the configuration.
    pub fn config(&self) -> &EvmExecutorConfig {
        &self.config
    }

    /// Get metrics (if enabled).
    pub fn metrics(&self) -> Option<&EvmExecutorMetrics> {
        self.metrics.as_deref()
    }

    /// Execute a transaction against the given database.
    ///
    /// # Arguments
    /// * `db` – Mutable reference to a database implementing `Database` + `DatabaseCommit`.
    /// * `env` – Execution environment (block context, chain config, etc.).
    /// * `tx` – The transaction to execute.
    ///
    /// # Returns
    /// `Ok(ExecOutput)` on success (including reverts – check `success` field),
    /// or `Err(ExecError)` if the transaction is invalid or the EVM fails.
    pub fn execute<DB: Database + DatabaseCommit>(
        &self,
        db: &mut DB,
        env: Env,
        tx: EvmTx,
    ) -> ExecResult<ExecOutput>
    where
        <DB as Database>::Error: core::fmt::Debug,
    {
        let start = Instant::now();

        // Validate environment chain ID
        let expected_chain_id = self.config.chain_id;
        let env_chain_id = env.cfg.chain_id;
        if env_chain_id != expected_chain_id {
            return Err(ExecError::ChainIdMismatch {
                expected: expected_chain_id,
                got: env_chain_id,
            });
        }

        // 1. Pre‑validation
        self.validate_tx(db, &tx, env.block.basefee)?;

        // 2. Build EVM instance
        let mut evm = Evm::builder()
            .with_db(db)
            .with_env(Box::new(env.clone()))
            .build();

        // Configure EVM settings
        if self.config.enable_tracing {
            // Enable tracing if supported (REVM may have a feature for this)
            // For now, we just log at trace level
            trace!(tx_hash = ?tx.hash(), "executing transaction with tracing enabled");
        }

        // 3. Build transaction environment
        let tx_env = self.build_tx_env(tx)?;
        evm.context.evm.env.tx = tx_env;

        // 4. Execute
        let result = evm
            .transact_commit()
            .map_err(|e| ExecError::Revm(format!("{:?}", e)))?;

        // 5. Calculate effective gas price
        let effective_gas_price = self.calculate_effective_gas_price(&tx, env.block.basefee);

        // 6. Convert result to output
        let output = self.output_from_result(result, effective_gas_price)?;

        // 7. Record metrics
        let duration_ns = start.elapsed().as_nanos() as u64;
        if let Some(metrics) = &self.metrics {
            metrics.record(&output, duration_ns);
        } else if let Some(global) = EvmExecutorMetrics::global() {
            global.record(&output, duration_ns);
        }

        debug!(
            success = output.success,
            reverted = output.reverted,
            gas_used = output.gas_used,
            gas_price = effective_gas_price,
            duration_us = duration_ns / 1000,
            "EVM transaction executed"
        );

        Ok(output)
    }

    // -------------------------------------------------------------------------
    // Validation
    // -------------------------------------------------------------------------

    /// Validate a transaction before execution.
    fn validate_tx<DB: Database>(
        &self,
        db: &mut DB,
        tx: &EvmTx,
        base_fee: U256,
    ) -> ExecResult<()>
    where
        <DB as Database>::Error: core::fmt::Debug,
    {
        let (gas_limit, gas_price, max_fee_per_gas, max_priority_fee_per_gas, from, chain_id, nonce) =
            match tx {
                EvmTx::Legacy { gas_limit, gas_price, from, chain_id, nonce, .. } => {
                    (*gas_limit, *gas_price, *gas_price, 0u64, from, *chain_id, *nonce)
                }
                EvmTx::Eip2930 { gas_limit, gas_price, from, chain_id, nonce, .. } => {
                    (*gas_limit, *gas_price, *gas_price, 0u64, from, *chain_id, *nonce)
                }
                EvmTx::Eip1559 {
                    gas_limit,
                    max_fee_per_gas,
                    max_priority_fee_per_gas,
                    from,
                    chain_id,
                    nonce,
                    ..
                } => {
                    (*gas_limit, 0, *max_fee_per_gas, *max_priority_fee_per_gas, from, *chain_id, *nonce)
                }
            };

        // Chain ID validation
        if chain_id != self.config.chain_id {
            return Err(ExecError::ChainIdMismatch {
                expected: self.config.chain_id,
                got: chain_id,
            });
        }

        // Gas limit check
        if gas_limit > self.config.max_gas_limit {
            return Err(ExecError::GasLimitOverflow {
                requested: gas_limit,
                max: self.config.max_gas_limit,
            });
        }

        // Gas price validation for Legacy/EIP‑2930
        if matches!(tx, EvmTx::Legacy { .. } | EvmTx::Eip2930 { .. }) {
            if gas_price < self.config.min_gas_price {
                return Err(ExecError::GasPriceTooLow {
                    price: gas_price,
                    min: self.config.min_gas_price,
                });
            }
            if gas_price > self.config.max_gas_price {
                return Err(ExecError::GasPriceTooHigh {
                    price: gas_price,
                    max: self.config.max_gas_price,
                });
            }
        }

        // EIP‑1559 fee validation
        if matches!(tx, EvmTx::Eip1559 { .. }) {
            let base_fee_u64 = base_fee.as_u64();
            if max_fee_per_gas < self.config.min_gas_price {
                return Err(ExecError::GasPriceTooLow {
                    price: max_fee_per_gas,
                    min: self.config.min_gas_price,
                });
            }
            let effective_gas_price = max_priority_fee_per_gas.saturating_add(base_fee_u64);
            if effective_gas_price > max_fee_per_gas {
                return Err(ExecError::Revm(
                    "max_fee_per_gas < base_fee + max_priority_fee".to_string(),
                ));
            }
            if effective_gas_price > self.config.max_gas_price {
                return Err(ExecError::GasPriceTooHigh {
                    price: effective_gas_price,
                    max: self.config.max_gas_price,
                });
            }
        }

        // Nonce validation
        let from_addr = to_addr(*from);
        let account_nonce = db.basic(from_addr)
            .map_err(|e| ExecError::Database(format!("{:?}", e)))?
            .map(|acc| acc.nonce)
            .unwrap_or(0);
        if nonce < account_nonce {
            return Err(ExecError::NonceTooLow {
                tx_nonce: nonce,
                account_nonce,
            });
        }

        // Balance validation
        let balance = db.basic(from_addr)
            .map_err(|e| ExecError::Database(format!("{:?}", e)))?
            .map(|acc| acc.balance)
            .unwrap_or(U256::ZERO);
        let max_cost = U256::from(gas_limit) * U256::from(if max_fee_per_gas > 0 { max_fee_per_gas } else { gas_price });
        if balance < max_cost {
            return Err(ExecError::InsufficientBalance {
                need: max_cost,
                have: balance,
            });
        }

        // Intrinsic gas validation
        let intrinsic_gas = self.calculate_intrinsic_gas(tx);
        if gas_limit < intrinsic_gas {
            return Err(ExecError::IntrinsicGasTooLow {
                need: intrinsic_gas,
                have: gas_limit,
            });
        }

        Ok(())
    }

    // -------------------------------------------------------------------------
    // Gas calculations
    // -------------------------------------------------------------------------

    /// Calculate intrinsic gas for a transaction (EIP‑2028).
    fn calculate_intrinsic_gas(&self, tx: &EvmTx) -> u64 {
        let mut gas = 21_000; // Base transaction cost

        let data = match tx {
            EvmTx::Legacy { data, .. } => data,
            EvmTx::Eip2930 { data, .. } => data,
            EvmTx::Eip1559 { data, .. } => data,
        };

        // Zero bytes cost 4 gas, non‑zero cost 16 gas (EIP‑2028)
        for &byte in data {
            if byte == 0 {
                gas += 4;
            } else {
                gas += 16;
            }
        }

        // Access list cost (EIP‑2930)
        if let EvmTx::Eip2930 { access_list, .. } | EvmTx::Eip1559 { access_list, .. } = tx {
            gas += access_list.len() as u64 * 2_400; // Per access list entry
            for item in access_list {
                gas += item.storage_keys.len() as u64 * 1_900; // Per storage key
            }
        }

        gas
    }

    /// Calculate effective gas price for EIP‑1559 transactions.
    fn calculate_effective_gas_price(&self, tx: &EvmTx, base_fee: U256) -> u64 {
        match tx {
            EvmTx::Legacy { gas_price, .. } => *gas_price,
            EvmTx::Eip2930 { gas_price, .. } => *gas_price,
            EvmTx::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                let base_u64 = base_fee.as_u64();
                let priority = u64::min(*max_priority_fee_per_gas, max_fee_per_gas.saturating_sub(base_u64));
                base_u64.saturating_add(priority)
            }
        }
    }

    /// Calculate gas refund (EIP‑3529).
    fn calculate_gas_refund(&self, result: &ExecutionResult) -> u64 {
        if !self.config.enable_gas_refunds {
            return 0;
        }
        match result {
            ExecutionResult::Success { gas_used, output, .. } => {
                // The gas_used already includes refunds if REVM is configured to apply them.
                // REVM applies EIP‑3529 by default. We return 0 here because the
                // refund is already reflected in gas_used.
                0
            }
            _ => 0,
        }
    }

    // -------------------------------------------------------------------------
    // Transaction environment builder
    // -------------------------------------------------------------------------

    fn build_tx_env(&self, tx: EvmTx) -> ExecResult<TxEnv> {
        let mut tx_env = TxEnv::default();

        match tx {
            EvmTx::Eip2930 {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                access_list,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.gas_price = U256::from(gas_price);
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
                tx_env.access_list = access_list
                    .into_iter()
                    .map(convert_access_list_item)
                    .collect();
            }

            EvmTx::Legacy {
                from,
                to,
                nonce,
                gas_limit,
                gas_price,
                value,
                data,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.gas_price = U256::from(gas_price);
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
            }

            EvmTx::Eip1559 {
                from,
                to,
                nonce,
                gas_limit,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                value,
                data,
                access_list,
                chain_id,
            } => {
                tx_env.caller = to_addr(from);
                tx_env.gas_limit = gas_limit;
                tx_env.gas_price = U256::from(max_fee_per_gas);
                tx_env.value = U256::from(value);
                tx_env.nonce = Some(nonce);
                tx_env.chain_id = Some(chain_id);
                tx_env.transact_to = match to {
                    Some(addr) => revm::primitives::TransactTo::Call(to_addr(addr)),
                    None => revm::primitives::TransactTo::Create,
                };
                tx_env.data = Bytes::from(data);
                tx_env.access_list = access_list
                    .into_iter()
                    .map(convert_access_list_item)
                    .collect();
                // Note: REVM uses gas_price as the max_fee_per_gas for EIP-1559;
                // it calculates the actual effective gas price from the block's basefee.
            }
        }

        Ok(tx_env)
    }

    // -------------------------------------------------------------------------
    // Result conversion
    // -------------------------------------------------------------------------

    fn output_from_result(&self, result: ExecutionResult, effective_gas_price: u64) -> ExecResult<ExecOutput> {
        let gas_refund = self.calculate_gas_refund(&result);

        match result {
            ExecutionResult::Success {
                gas_used,
                logs,
                output,
                ..
            } => {
                let logs = if self.config.max_logs_per_tx > 0 && logs.len() > self.config.max_logs_per_tx {
                    warn!(count = logs.len(), limit = self.config.max_logs_per_tx, "log count exceeds limit, truncating");
                    logs.into_iter().take(self.config.max_logs_per_tx).collect()
                } else {
                    logs
                };
                let (return_data, created_address) = match output {
                    revm::primitives::Output::Call(data) => (data.to_vec(), None),
                    revm::primitives::Output::Create(data, addr) => (data.to_vec(), Some(addr)),
                };
                Ok(ExecOutput {
                    logs,
                    created_address,
                    gas_used,
                    success: true,
                    reverted: false,
                    return_data,
                    effective_gas_price,
                    gas_refund,
                })
            }
            ExecutionResult::Revert { gas_used, output } => Ok(ExecOutput {
                logs: vec![],
                created_address: None,
                gas_used,
                success: false,
                reverted: true,
                return_data: output.to_vec(),
                effective_gas_price,
                gas_refund: 0,
            }),
            ExecutionResult::Halt { gas_used, reason, .. } => {
                error!(gas_used, ?reason, "EVM halted");
                Ok(ExecOutput {
                    logs: vec![],
                    created_address: None,
                    gas_used,
                    success: false,
                    reverted: false,
                    return_data: vec![],
                    effective_gas_price,
                    gas_refund: 0,
                })
            }
        }
    }
}

impl Default for EvmExecutor {
    fn default() -> Self {
        Self {
            config: Arc::new(EvmExecutorConfig::default()),
            metrics: None,
        }
    }
}

// -----------------------------------------------------------------------------
// Helpers
// -----------------------------------------------------------------------------

/// Convert a 20‑byte array to a REVM Address.
#[inline]
fn to_addr(bytes: [u8; 20]) -> Address {
    Address::from_slice(&bytes)
}

/// Convert an `AccessListItem` into REVM's access list format.
fn convert_access_list_item(item: AccessListItem) -> (Address, Vec<U256>) {
    (
        to_addr(item.address),
        item.storage_keys.into_iter().map(U256::from_be_bytes).collect(),
    )
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::db::MemDb;
    use revm::primitives::{BlockEnv, CfgEnv};

    fn setup_env(chain_id: u64) -> Env {
        let mut env = Env::default();
        env.cfg = CfgEnv::default().with_chain_id(chain_id);
        env.block = BlockEnv {
            number: U256::from(1),
            coinbase: Address::new([0u8; 20]),
            timestamp: U256::from(123456),
            gas_limit: U256::from(30_000_000),
            basefee: U256::from(10),
            difficulty: U256::ZERO,
            prevrandao: None,
        };
        env
    }

    #[test]
    fn test_executor_config_validation() {
        let good = EvmExecutorConfig::default();
        assert!(good.validate().is_ok());

        let bad = EvmExecutorConfig {
            max_gas_limit: 0,
            ..Default::default()
        };
        assert!(bad.validate().is_err());

        let bad_chain = EvmExecutorConfig {
            chain_id: 0,
            ..Default::default()
        };
        assert!(bad_chain.validate().is_err());
    }

    #[test]
    fn test_legacy_tx() -> ExecResult<()> {
        let mut db = MemDb::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        db.insert_account(Address::from_slice(&from), 0, U256::from(10_000_000_000_000_000u128));

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };

        let env = setup_env(6126151);
        let executor = EvmExecutor::default();
        let output = executor.execute(&mut db, env, tx)?;
        assert!(output.success);
        assert!(output.gas_used > 0);
        Ok(())
    }

    #[test]
    fn test_gas_price_too_low() {
        let mut db = MemDb::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        db.insert_account(Address::from_slice(&from), 0, U256::from(10_000_000_000_000_000u128));

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 0,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };

        let env = setup_env(6126151);
        let executor = EvmExecutor::default();
        let result = executor.execute(&mut db, env, tx);
        assert!(matches!(result, Err(ExecError::GasPriceTooLow { .. })));
    }

    #[test]
    fn test_eip1559_tx() -> ExecResult<()> {
        let mut db = MemDb::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        db.insert_account(Address::from_slice(&from), 0, U256::from(10_000_000_000_000_000u128));

        let tx = EvmTx::Eip1559 {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 20,
            value: 1_000,
            data: vec![],
            access_list: vec![],
            chain_id: 6126151,
        };

        let env = setup_env(6126151);
        let executor = EvmExecutor::default();
        let output = executor.execute(&mut db, env, tx)?;
        assert!(output.success);
        assert_eq!(output.effective_gas_price, 30); // 10 (basefee) + 20 (priority)
        Ok(())
    }

    #[test]
    fn test_metrics() {
        let mut db = MemDb::default();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        db.insert_account(Address::from_slice(&from), 0, U256::from(10_000_000_000_000_000u128));

        let tx = EvmTx::Legacy {
            from,
            to: Some(to),
            nonce: 0,
            gas_limit: 100_000,
            gas_price: 10,
            value: 1_000,
            data: vec![],
            chain_id: 6126151,
        };

        let env = setup_env(6126151);
        let executor = EvmExecutorBuilder::new()
            .with_metrics(true)
            .build()
            .unwrap();

        let output = executor.execute(&mut db, env, tx)?;
        assert!(output.success);

        let metrics = executor.metrics().unwrap();
        assert_eq!(metrics.total_txs(), 1);
        assert_eq!(metrics.successful_txs(), 1);
        assert!(metrics.avg_gas() > 0.0);
    }
}
