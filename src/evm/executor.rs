//! EVM transaction executor using REVM.
//!
//! This module provides production‑grade execution of Ethereum transactions
//! against a state database that implements `revm::Database` and `DatabaseCommit`.
//!
//! # Features
//! - Support for Legacy, EIP‑2930 (Access List), and EIP‑1559 transactions
//! - Proper gas metering and fee calculation
//! - Gas refunds (EIP‑3529) and gas limits
//! - Detailed execution output (logs, return data, gas usage)
//! - Gas price validation
//! - Metrics collection
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::evm::executor::{execute_evm_tx, EvmExecutorConfig};
//! use revm::primitives::{Env, BlockEnv, CfgEnv};
//!
//! let config = EvmExecutorConfig::default();
//! let env = Env {
//!     cfg: CfgEnv::default().with_chain_id(1),
//!     block: BlockEnv {
//!         basefee: U256::from(10),
//!         ..Default::default()
//!     },
//!     ..Default::default()
//! };
//! let output = execute_evm_tx(&mut db, env, tx, &config)?;
//! ```

use crate::types::tx_evm::{AccessListItem, EvmTx};
use revm::primitives::{Address, Bytes, Env, ExecutionResult, TxEnv, U256};
use revm::{Database, DatabaseCommit, Evm};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tracing::{debug, error, info, warn};

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
    /// Enable gas metering (always true in production).
    pub enable_gas_metering: bool,
    /// Enable gas refunds (EIP‑3529).
    pub enable_gas_refunds: bool,
    /// Maximum depth for call/create stack.
    pub max_call_depth: usize,
    /// Enable detailed tracing (expensive).
    pub enable_tracing: bool,
}

impl Default for EvmExecutorConfig {
    fn default() -> Self {
        Self {
            max_gas_limit: 30_000_000,
            min_gas_price: 1,
            max_gas_price: 1_000_000_000_000,
            enable_gas_metering: true,
            enable_gas_refunds: true,
            max_call_depth: 1024,
            enable_tracing: false,
        }
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur during EVM transaction execution.
#[derive(Debug, Error)]
pub enum EvmExecutorError {
    /// REVM execution failed (internal error).
    #[error("REVM execution failed: {0}")]
    Revm(String),

    /// Invalid address conversion.
    #[error("invalid address conversion: {0}")]
    InvalidAddress(String),

    /// Invalid U256 value.
    #[error("invalid U256 value: {0}")]
    InvalidU256(String),

    /// Gas limit overflow.
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
}

pub type EvmExecutorResult<T> = Result<T, EvmExecutorError>;

// -----------------------------------------------------------------------------
// Metrics
// -----------------------------------------------------------------------------

/// Execution metrics.
#[derive(Debug, Default)]
pub struct EvmExecutorMetrics {
    /// Total number of transactions executed.
    pub total_txs: AtomicU64,
    /// Number of successful transactions.
    pub successful_txs: AtomicU64,
    /// Number of failed transactions.
    pub failed_txs: AtomicU64,
    /// Total gas used.
    pub total_gas_used: AtomicU64,
    /// Total execution time (nanoseconds).
    pub total_execution_time_ns: AtomicU64,
}

impl EvmExecutorMetrics {
    /// Record a transaction execution.
    pub fn record(&self, success: bool, gas_used: u64, duration_ns: u64) {
        self.total_txs.fetch_add(1, Ordering::Relaxed);
        if success {
            self.successful_txs.fetch_add(1, Ordering::Relaxed);
        } else {
            self.failed_txs.fetch_add(1, Ordering::Relaxed);
        }
        self.total_gas_used.fetch_add(gas_used, Ordering::Relaxed);
        self.total_execution_time_ns.fetch_add(duration_ns, Ordering::Relaxed);
    }

    /// Get average gas per transaction.
    pub fn avg_gas(&self) -> f64 {
        let total = self.total_txs.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            self.total_gas_used.load(Ordering::Relaxed) as f64 / total as f64
        }
    }

    /// Get average execution time (microseconds).
    pub fn avg_time_us(&self) -> f64 {
        let total = self.total_txs.load(Ordering::Relaxed);
        if total == 0 {
            0.0
        } else {
            self.total_execution_time_ns.load(Ordering::Relaxed) as f64 / total as f64 / 1000.0
        }
    }
}

// -----------------------------------------------------------------------------
// Output
// -----------------------------------------------------------------------------

/// Output of an EVM transaction execution.
#[derive(Debug, Clone)]
pub struct EvmExecOutput {
    /// Logs emitted during execution.
    pub logs: Vec<revm::primitives::Log>,
    /// Address of the created contract (if any).
    pub created_address: Option<Address>,
    /// Gas used by the transaction.
    pub gas_used: u64,
    /// Whether the transaction succeeded (did not revert).
    pub success: bool,
    /// Return data from the transaction (or revert reason).
    pub return_data: Vec<u8>,
    /// Effective gas price paid (for EIP‑1559).
    pub effective_gas_price: u64,
}

// -----------------------------------------------------------------------------
// Helper: convert 20‑byte array to REVM Address
// -----------------------------------------------------------------------------

#[inline]
fn to_addr(bytes: [u8; 20]) -> Address {
    Address::from_slice(&bytes)
}

// -----------------------------------------------------------------------------
// Transaction execution
// -----------------------------------------------------------------------------

/// Execute an EVM transaction against the given database.
///
/// # Arguments
/// * `db` – Mutable reference to a database implementing `Database` + `DatabaseCommit`.
/// * `env` – Execution environment (block context, chain config, etc.).
/// * `tx` – The transaction to execute.
/// * `config` – Executor configuration.
///
/// # Returns
/// `Ok(EvmExecOutput)` on success (including reverts – check `success` field),
/// or `Err(EvmExecutorError)` if the transaction is invalid or the EVM fails.
pub fn execute_evm_tx<DB: Database + DatabaseCommit>(
    db: &mut DB,
    env: Env,
    tx: EvmTx,
    config: &EvmExecutorConfig,
) -> EvmExecutorResult<EvmExecOutput>
where
    <DB as Database>::Error: core::fmt::Debug,
{
    let start = Instant::now();

    // 1. Pre‑validation
    validate_tx(&tx, db, env.block.basefee, config)?;

    // 2. Build EVM instance
    let mut evm = Evm::builder()
        .with_db(db)
        .with_env(Box::new(env.clone()))
        .build();

    // 3. Build transaction environment
    let tx_env = build_tx_env(tx.clone())?;
    evm.context.evm.env.tx = tx_env;

    // 4. Execute and commit changes
    let result = evm
        .transact_commit()
        .map_err(|e| EvmExecutorError::Revm(format!("{:?}", e)))?;

    // 5. Calculate effective gas price (for EIP‑1559)
    let effective_gas_price = calculate_effective_gas_price(&tx, env.block.basefee);

    // 6. Convert result to output
    let output = output_from_result(result, effective_gas_price)?;

    // 7. Record metrics
    let duration_ns = start.elapsed().as_nanos() as u64;
    if let Some(metrics) = get_global_metrics() {
        metrics.record(output.success, output.gas_used, duration_ns);
    }

    debug!(
        success = output.success,
        gas_used = output.gas_used,
        gas_price = effective_gas_price,
        duration_us = duration_ns / 1000,
        "EVM transaction executed"
    );

    Ok(output)
}

// -----------------------------------------------------------------------------
// Transaction validation
// -----------------------------------------------------------------------------

/// Validate a transaction before execution.
fn validate_tx<DB: Database>(
    tx: &EvmTx,
    db: &mut DB,
    base_fee: U256,
    config: &EvmExecutorConfig,
) -> EvmExecutorResult<()>
where
    <DB as Database>::Error: core::fmt::Debug,
{
    let (gas_limit, gas_price, max_fee_per_gas, max_priority_fee_per_gas, from, chain_id, nonce) =
        match tx {
            EvmTx::Legacy { gas_limit, gas_price, from, chain_id, nonce, .. } => {
                (*gas_limit, *gas_price, *gas_price, *gas_price, from, *chain_id, *nonce)
            }
            EvmTx::Eip2930 { gas_limit, gas_price, from, chain_id, nonce, .. } => {
                (*gas_limit, *gas_price, *gas_price, *gas_price, from, *chain_id, *nonce)
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

    // Gas limit check
    if gas_limit > config.max_gas_limit {
        return Err(EvmExecutorError::GasLimitOverflow {
            requested: gas_limit,
            max: config.max_gas_limit,
        });
    }

    // Gas price validation for Legacy/EIP‑2930
    if matches!(tx, EvmTx::Legacy { .. } | EvmTx::Eip2930 { .. }) {
        if gas_price < config.min_gas_price {
            return Err(EvmExecutorError::GasPriceTooLow {
                price: gas_price,
                min: config.min_gas_price,
            });
        }
        if gas_price > config.max_gas_price {
            return Err(EvmExecutorError::GasPriceTooHigh {
                price: gas_price,
                max: config.max_gas_price,
            });
        }
    }

    // EIP‑1559 fee validation
    if matches!(tx, EvmTx::Eip1559 { .. }) {
        if max_fee_per_gas < config.min_gas_price {
            return Err(EvmExecutorError::GasPriceTooLow {
                price: max_fee_per_gas,
                min: config.min_gas_price,
            });
        }
        let effective_gas_price = max_priority_fee_per_gas + base_fee;
        if effective_gas_price > max_fee_per_gas {
            return Err(EvmExecutorError::Revm(
                "max_fee_per_gas < base_fee + max_priority_fee".to_string(),
            ));
        }
        if effective_gas_price > config.max_gas_price {
            return Err(EvmExecutorError::GasPriceTooHigh {
                price: effective_gas_price,
                max: config.max_gas_price,
            });
        }
    }

    // Chain ID validation
    let expected_chain_id = env_chain_id();
    if chain_id != expected_chain_id {
        return Err(EvmExecutorError::Revm(format!(
            "chain ID mismatch: expected {}, got {}",
            expected_chain_id, chain_id
        )));
    }

    // Nonce validation
    let from_addr = to_addr(*from);
    let account_nonce = db.basic(from_addr)
        .map_err(|e| EvmExecutorError::Revm(format!("{:?}", e)))?
        .map(|acc| acc.nonce)
        .unwrap_or(0);
    if nonce < account_nonce {
        return Err(EvmExecutorError::NonceTooLow {
            tx_nonce: nonce,
            account_nonce,
        });
    }

    // Balance validation
    let balance = db.basic(from_addr)
        .map_err(|e| EvmExecutorError::Revm(format!("{:?}", e)))?
        .map(|acc| acc.balance)
        .unwrap_or(U256::ZERO);
    let max_cost = U256::from(gas_limit) * U256::from(gas_price);
    if balance < max_cost {
        return Err(EvmExecutorError::InsufficientBalance {
            need: max_cost,
            have: balance,
        });
    }

    // Intrinsic gas validation
    let intrinsic_gas = calculate_intrinsic_gas(tx);
    if gas_limit < intrinsic_gas {
        return Err(EvmExecutorError::IntrinsicGasTooLow {
            need: intrinsic_gas,
            have: gas_limit,
        });
    }

    Ok(())
}

/// Calculate intrinsic gas for a transaction.
fn calculate_intrinsic_gas(tx: &EvmTx) -> u64 {
    let mut gas = 21_000; // Base transaction cost

    let data_len = match tx {
        EvmTx::Legacy { data, .. } => data.len(),
        EvmTx::Eip2930 { data, .. } => data.len(),
        EvmTx::Eip1559 { data, .. } => data.len(),
    };

    // Zero bytes cost 4 gas, non‑zero cost 16 gas (EIP‑2028)
    for &byte in data_len.iter() {
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
fn calculate_effective_gas_price(tx: &EvmTx, base_fee: U256) -> u64 {
    match tx {
        EvmTx::Legacy { gas_price, .. } => *gas_price,
        EvmTx::Eip2930 { gas_price, .. } => *gas_price,
        EvmTx::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..
        } => {
            let priority = u64::min(*max_priority_fee_per_gas, *max_fee_per_gas - base_fee.as_u64());
            base_fee.as_u64() + priority
        }
    }
}

/// Get the current chain ID from the environment.
fn env_chain_id() -> u64 {
    // In production, this should come from the node config.
    // For now, we use a default or read from environment.
    std::env::var("IONA_CHAIN_ID")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(6126151)
}

// -----------------------------------------------------------------------------
// Helper: build TxEnv from EvmTx
// -----------------------------------------------------------------------------

fn build_tx_env(tx: EvmTx) -> EvmExecutorResult<TxEnv> {
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
            // REVM uses `gas_price` as the effective price. For EIP‑1559, we set
            // it to `max_fee_per_gas`; the actual effective price is determined
            // by the block's base fee and the priority fee.
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
        }
    }

    Ok(tx_env)
}

/// Convert an `AccessListItem` into REVM's access list format.
fn convert_access_list_item(item: AccessListItem) -> (Address, Vec<U256>) {
    (
        to_addr(item.address),
        item.storage_keys.into_iter().map(U256::from_be_bytes).collect(),
    )
}

/// Convert REVM `ExecutionResult` into `EvmExecOutput`.
fn output_from_result(result: ExecutionResult, effective_gas_price: u64) -> EvmExecutorResult<EvmExecOutput> {
    match result {
        ExecutionResult::Success {
            gas_used,
            logs,
            output,
            ..
        } => {
            let (return_data, created_address) = match output {
                revm::primitives::Output::Call(data) => (data.to_vec(), None),
                revm::primitives::Output::Create(data, addr) => (data.to_vec(), Some(addr)),
            };
            Ok(EvmExecOutput {
                logs,
                created_address,
                gas_used,
                success: true,
                return_data,
                effective_gas_price,
            })
        }
        ExecutionResult::Revert { gas_used, output } => Ok(EvmExecOutput {
            logs: vec![],
            created_address: None,
            gas_used,
            success: false,
            return_data: output.to_vec(),
            effective_gas_price,
        }),
        ExecutionResult::Halt { gas_used, reason, .. } => {
            error!(gas_used, ?reason, "EVM halted");
            Ok(EvmExecOutput {
                logs: vec![],
                created_address: None,
                gas_used,
                success: false,
                return_data: vec![],
                effective_gas_price,
            })
        }
    }
}

// -----------------------------------------------------------------------------
// Global metrics (optional)
// -----------------------------------------------------------------------------

static GLOBAL_METRICS: std::sync::OnceLock<EvmExecutorMetrics> = std::sync::OnceLock::new();

/// Initialise global metrics collection.
pub fn init_global_metrics() {
    GLOBAL_METRICS.get_or_init(EvmExecutorMetrics::default);
    info!("EVM executor global metrics initialised");
}

/// Get global metrics (if initialised).
pub fn get_global_metrics() -> Option<&'static EvmExecutorMetrics> {
    GLOBAL_METRICS.get()
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
        Env {
            cfg: CfgEnv::default().with_chain_id(chain_id),
            block: BlockEnv {
                number: U256::from(1),
                coinbase: Address::new([0u8; 20]),
                timestamp: U256::from(123456),
                gas_limit: U256::from(30_000_000),
                basefee: U256::from(10),
                difficulty: U256::ZERO,
                prevrandao: None,
            },
            tx: TxEnv::default(),
        }
    }

    #[test]
    fn test_legacy_tx() -> EvmExecutorResult<()> {
        let mut db = MemDb::new();
        let from = [0xAB; 20];
        let to = [0xCD; 20];
        // Fund sender
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
        let config = EvmExecutorConfig::default();
        let output = execute_evm_tx(&mut db, env, tx, &config)?;
        // Simple transfer should succeed
        assert!(output.success);
        assert!(output.gas_used > 0);
        Ok(())
    }

    #[test]
    fn test_gas_price_too_low() {
        let mut db = MemDb::new();
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
        let config = EvmExecutorConfig::default();
        let result = execute_evm_tx(&mut db, env, tx, &config);
        assert!(matches!(result, Err(EvmExecutorError::GasPriceTooLow { .. })));
    }

    #[test]
    fn test_non_revert() {
        let mut db = MemDb::new();
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
        let config = EvmExecutorConfig::default();
        let output = execute_evm_tx(&mut db, env, tx, &config)?;
        assert!(output.success);
        assert!(output.gas_used > 0);
        assert_eq!(output.effective_gas_price, 30); // 10 (basefee) + 20 (priority)
        Ok(())
    }
}
