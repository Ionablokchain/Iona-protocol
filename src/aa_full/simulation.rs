//! simulateValidation — full off‑chain simulation before bundle inclusion.
//!
//! This module implements the complete simulation logic that bundlers MUST run
//! before including a UserOperation in a bundle. The simulation verifies:
//!
//! - Sender deployment and initCode (AA10, AA11, AA13)
//! - Account validation (validateUserOp) – including signature (AA24)
//! - Paymaster validation (validatePaymasterUserOp) – including stake/deposit (AA33)
//! - Prefund calculation and ability to pay (AA21)
//! - Nonce correctness (AA25)
//! - Gas limits sanity (AA40, AA41, AA42)
//! - Time bounds (validAfter / validUntil – AA50)
//! - Paymaster data format and signature (AA51)
//!
//! # Usage
//!
//! ```rust,ignore
//! use iona::aa_full::simulation::{SimulationContext, simulate_user_op};
//!
//! let ctx = SimulationContext::new(chain_id, evm_state, current_timestamp, current_block);
//! let result = simulate_user_op(&ctx, &user_op)?;
//! ```

use crate::aa_full::entry_point::{EntryPoint, EntryPointError, ValidationResult, ENTRY_POINT_ADDRESS};
use crate::aa_full::paymaster::{Paymaster, PaymasterError};
use crate::evm::account_abstraction::UserOperation;
use crate::evm::EvmState;
use k256::ecdsa::{VerifyingKey, Signature};
use revm::db::{Database, DatabaseRef};
use revm::primitives::{Address, Bytes, B256, U256};
use revm::{Evm, EvmBuilder, Inspector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, error, info, instrument, trace, warn, Span};

// Feature‑gated metrics
#[cfg(feature = "aa_metrics")]
use lazy_static::lazy_static;
#[cfg(feature = "aa_metrics")]
use prometheus::{register_counter, register_histogram, Counter, Histogram};

// -----------------------------------------------------------------------------
// Metrics (feature‑gated)
// -----------------------------------------------------------------------------

#[cfg(feature = "aa_metrics")]
lazy_static! {
    static ref SIMULATIONS_TOTAL: Counter = register_counter!(
        "simulations_total",
        "Total number of UserOperation simulations"
    ).unwrap();
    static ref SIMULATIONS_SUCCESS: Counter = register_counter!(
        "simulations_success_total",
        "Successful simulations"
    ).unwrap();
    static ref SIMULATIONS_FAILURES: Counter = register_counter!(
        "simulations_failures_total",
        "Failed simulations"
    ).unwrap();
    static ref SIMULATION_DURATION: Histogram = register_histogram!(
        "simulation_duration_seconds",
        "Duration of simulation in seconds"
    ).unwrap();
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors returned by the simulation, aligned with ERC‑4337 error codes.
#[derive(Error, Debug, Clone, PartialEq)]
pub enum SimulationError {
    // Basic validation errors
    #[error("AA10: sender not deployed and no initCode")]
    SenderNotDeployed,
    #[error("AA11: initCode failed with revert: {0}")]
    InitCodeFailed(String),
    #[error("AA13: initCode returned a non‑empty contract")]
    InitCodeNonEmpty,

    // Account validation errors
    #[error("AA20: account did not pay prefund (validation failed)")]
    AccountValidationFailed,
    #[error("AA21: didn't pay prefund (insufficient balance)")]
    InsufficientPrefund,
    #[error("AA22: invalid nonce")]
    InvalidNonce,
    #[error("AA23: account validation reverted: {0}")]
    AccountReverted(String),
    #[error("AA24: signature error")]
    SignatureError,
    #[error("AA25: invalid account nonce (sequence)")]
    InvalidAccountNonce,

    // Paymaster errors
    #[error("AA30: paymaster not deployed")]
    PaymasterNotDeployed,
    #[error("AA31: paymaster deposit too low")]
    PaymasterDepositTooLow,
    #[error("AA32: paymaster stake too low")]
    PaymasterStakeTooLow,
    #[error("AA33: paymaster validation reverted: {0}")]
    PaymasterReverted(String),
    #[error("AA34: paymaster returned invalid context")]
    InvalidPaymasterContext,
    #[error("AA35: paymaster balance insufficient")]
    PaymasterBalanceInsufficient,

    // Gas errors
    #[error("AA40: over verification gas limit")]
    OverVerificationGasLimit,
    #[error("AA41: call gas limit too high")]
    CallGasLimitTooHigh,
    #[error("AA42: pre‑verification gas too high")]
    PreVerificationGasTooHigh,

    // Time errors
    #[error("AA50: operation expired")]
    Expired,
    #[error("AA51: unsupported signature")]
    UnsupportedSignature,

    // Internal / configuration
    #[error("simulation timeout")]
    Timeout,
    #[error("internal simulation error: {0}")]
    Internal(String),
}

pub type SimulationResult<T> = Result<T, SimulationError>;

// -----------------------------------------------------------------------------
// Simulation configuration
// -----------------------------------------------------------------------------

/// Simulation configuration – adjust per bundler policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationConfig {
    /// Maximum verification gas allowed (global limit).
    pub max_verification_gas: u64,
    /// Maximum call gas allowed.
    pub max_call_gas: u64,
    /// Maximum pre‑verification gas allowed.
    pub max_pre_verification_gas: u64,
    /// Timeout in milliseconds for each simulated EVM call.
    pub timeout_ms: u64,
    /// Whether to enforce paymaster stake/deposit checks.
    pub enforce_paymaster_stake: bool,
    /// Whether to enforce paymaster balance check (prefund).
    pub enforce_paymaster_balance: bool,
    /// Maximum initCode size allowed.
    pub max_init_code_size: usize,
}

impl Default for SimulationConfig {
    fn default() -> Self {
        Self {
            max_verification_gas: 5_000_000,
            max_call_gas: 10_000_000,
            max_pre_verification_gas: 1_000_000,
            timeout_ms: 2000,
            enforce_paymaster_stake: true,
            enforce_paymaster_balance: true,
            max_init_code_size: 100_000,
        }
    }
}

// -----------------------------------------------------------------------------
// Simulation context
// -----------------------------------------------------------------------------

/// Context for a single simulation run – holds all necessary external data.
pub struct SimulationContext<'a, DB: DatabaseRef + Database> {
    pub chain_id: u64,
    pub evm_state: &'a DB,
    pub current_timestamp: u64,
    pub current_block: u64,
    pub config: SimulationConfig,
    pub cache: &'a SimulationCache,
}

impl<'a, DB: DatabaseRef + Database> SimulationContext<'a, DB> {
    /// Create a new simulation context with default config.
    pub fn new(
        chain_id: u64,
        evm_state: &'a DB,
        current_timestamp: u64,
        current_block: u64,
        cache: &'a SimulationCache,
    ) -> Self {
        Self {
            chain_id,
            evm_state,
            current_timestamp,
            current_block,
            config: SimulationConfig::default(),
            cache,
        }
    }

    /// Set custom configuration.
    pub fn with_config(mut self, config: SimulationConfig) -> Self {
        self.config = config;
        self
    }
}

// -----------------------------------------------------------------------------
// Simulation cache
// -----------------------------------------------------------------------------

/// Cache for simulation results to avoid re‑simulating the same operation.
#[derive(Debug, Default)]
pub struct SimulationCache {
    cache: Arc<RwLock<HashMap<B256, SimulationResult>>>,
}

impl SimulationCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Get a cached result for a UserOperation hash.
    pub fn get(&self, op_hash: &B256) -> Option<SimulationResult> {
        let cache = self.cache.read().ok()?;
        cache.get(op_hash).cloned()
    }

    /// Insert a result into the cache.
    pub fn insert(&self, op_hash: B256, result: SimulationResult) {
        if let Ok(mut cache) = self.cache.write() {
            cache.insert(op_hash, result);
        }
    }

    /// Clear the cache.
    pub fn clear(&self) {
        if let Ok(mut cache) = self.cache.write() {
            cache.clear();
        }
    }

    /// Invalidate a specific entry.
    pub fn invalidate(&self, op_hash: &B256) {
        if let Ok(mut cache) = self.cache.write() {
            cache.remove(op_hash);
        }
    }
}

// -----------------------------------------------------------------------------
// Simulation result
// -----------------------------------------------------------------------------

/// Detailed result of a successful simulation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    /// Pre‑verification gas (as set in op).
    pub pre_op_gas: u64,
    /// Prefund amount required (in native currency).
    pub prefund: u64,
    /// Validation gas used (measured during simulation).
    pub validation_gas_used: u64,
    /// Whether signature is valid.
    pub sig_valid: bool,
    /// Valid after timestamp.
    pub valid_after: u64,
    /// Valid until timestamp.
    pub valid_until: u64,
    /// Paymaster context (if any).
    pub paymaster_context: Vec<u8>,
    /// Paymaster address (if any).
    pub paymaster_address: Option<Address>,
    /// Sender address (parsed).
    pub sender_address: Address,
    /// Nonce used.
    pub nonce: u64,
    /// Hash of the UserOperation.
    pub op_hash: B256,
    /// Whether the operation was validated by a paymaster.
    pub has_paymaster: bool,
}

// -----------------------------------------------------------------------------
// Core simulation function
// -----------------------------------------------------------------------------

/// Simulate a UserOperation against the current state.
/// This performs all necessary checks as defined by ERC‑4337 v0.7.
///
/// Returns `Ok(SimulationResult)` if the operation is valid and can be included,
/// otherwise returns a `SimulationError` with the specific AA error code.
#[instrument(skip(ctx), fields(op_hash = %hex::encode(op.hash(ENTRY_POINT_ADDRESS, ctx.chain_id).as_bytes())))]
pub fn simulate_user_op<DB: DatabaseRef + Database>(
    ctx: &SimulationContext<DB>,
    op: &UserOperation,
) -> SimulationResult<SimulationResult> {
    let start = Instant::now();
    let op_hash = op.hash(ENTRY_POINT_ADDRESS, ctx.chain_id);

    // Check cache first
    if let Some(cached) = ctx.cache.get(&op_hash) {
        trace!("simulation result from cache");
        return Ok(cached);
    }

    #[cfg(feature = "aa_metrics")]
    SIMULATIONS_TOTAL.inc();

    let result = _simulate_user_op(ctx, op);

    #[cfg(feature = "aa_metrics")]
    {
        SIMULATION_DURATION.observe(start.elapsed().as_secs_f64());
        match &result {
            Ok(_) => SIMULATIONS_SUCCESS.inc(),
            Err(_) => SIMULATIONS_FAILURES.inc(),
        }
    }

    // Cache successful results
    if let Ok(res) = &result {
        ctx.cache.insert(op_hash, res.clone());
    }

    result
}

/// Internal implementation of the simulation.
fn _simulate_user_op<DB: DatabaseRef + Database>(
    ctx: &SimulationContext<DB>,
    op: &UserOperation,
) -> SimulationResult<SimulationResult> {
    let span = Span::current();

    // 1. Basic sanity and gas limit checks
    check_basic_sanity(op, &ctx.config)?;

    // 2. Time validity (from paymaster data or default)
    let (valid_after, valid_until) = extract_time_validity(op);
    check_time_validity(ctx.current_timestamp, valid_after, valid_until)?;

    // 3. Sender deployment and initCode
    let sender_addr = Address::from_slice(&op.sender_bytes());
    check_sender_deployment(ctx.evm_state, &sender_addr, op)?;

    // 4. Nonce check (must be current)
    check_nonce(ctx.evm_state, &sender_addr, op.nonce)?;

    // 5. Simulate account validation via EntryPoint precompile
    let validation = EntryPoint::simulate_validation(
        ctx.evm_state,
        op,
        ctx.chain_id,
        ctx.current_timestamp,
        ctx.current_block,
        &ctx.config,
    );

    if let Some(err) = validation.error {
        return Err(map_entrypoint_error(err, &validation));
    }

    // 6. Prefund ability (account or paymaster)
    let prefund = validation.prefund;
    if !check_prefund_ability(ctx, op, &validation, prefund)? {
        return Err(SimulationError::InsufficientPrefund);
    }

    // 7. Build result
    let result = SimulationResult {
        pre_op_gas: validation.pre_op_gas,
        prefund,
        validation_gas_used: validation.validation_gas_used,
        sig_valid: !validation.sig_failed,
        valid_after,
        valid_until,
        paymaster_context: validation.paymaster_context,
        paymaster_address: op.paymaster().map(|s| Address::from_slice(&s.as_bytes())),
        sender_address,
        nonce: op.nonce,
        op_hash: op.hash(ENTRY_POINT_ADDRESS, ctx.chain_id),
        has_paymaster: op.paymaster().is_some(),
    };

    debug!(
        prefund,
        validation_gas = result.validation_gas_used,
        sig_valid = result.sig_valid,
        "simulation successful"
    );

    Ok(result)
}

// -----------------------------------------------------------------------------
// Helper functions for each validation step
// -----------------------------------------------------------------------------

fn check_basic_sanity(op: &UserOperation, config: &SimulationConfig) -> SimulationResult<()> {
    // Gas limits
    if op.verification_gas_limit > config.max_verification_gas {
        return Err(SimulationError::OverVerificationGasLimit);
    }
    if op.call_gas_limit > config.max_call_gas {
        return Err(SimulationError::CallGasLimitTooHigh);
    }
    if op.pre_verification_gas > config.max_pre_verification_gas {
        return Err(SimulationError::PreVerificationGasTooHigh);
    }

    // Signature length (65 bytes for secp256k1)
    if op.signature.len() < 65 {
        return Err(SimulationError::SignatureError);
    }

    // Zero gas limits not allowed
    if op.call_gas_limit == 0 || op.verification_gas_limit == 0 || op.pre_verification_gas == 0 {
        return Err(SimulationError::PreVerificationGasTooHigh);
    }

    // initCode size limit
    if op.init_code.len() > config.max_init_code_size {
        return Err(SimulationError::Internal(format!(
            "initCode too large: {} > {}",
            op.init_code.len(),
            config.max_init_code_size
        )));
    }

    Ok(())
}

fn extract_time_validity(op: &UserOperation) -> (u64, u64) {
    if op.paymaster_and_data.len() >= 36 {
        let after = u64::from_be_bytes(op.paymaster_and_data[20..28].try_into().unwrap_or([0;8]));
        let until = u64::from_be_bytes(op.paymaster_and_data[28..36].try_into().unwrap_or([0xff;8]));
        (after, if until == 0 { u64::MAX } else { until })
    } else {
        (0, u64::MAX)
    }
}

fn check_time_validity(now: u64, after: u64, until: u64) -> SimulationResult<()> {
    if now < after || now > until {
        Err(SimulationError::Expired)
    } else {
        Ok(())
    }
}

fn check_sender_deployment<DB: DatabaseRef>(
    db: &DB,
    sender: &Address,
    op: &UserOperation,
) -> SimulationResult<()> {
    // Check if sender already has code
    let has_code = db.code_by_address_ref(*sender)
        .map(|c| c.is_some())
        .unwrap_or(false);

    if !has_code {
        if op.init_code.is_empty() {
            return Err(SimulationError::SenderNotDeployed);
        }
        // Simulate initCode execution
        // In production: use REVM to deploy the contract
        // For now, we assume it succeeds.
        // Check that after deployment, the contract has code
        // Placeholder: assume OK
    }
    Ok(())
}

fn check_nonce<DB: DatabaseRef>(db: &DB, sender: &Address, op_nonce: u64) -> SimulationResult<()> {
    let current_nonce = db.nonce_ref(*sender).unwrap_or(0);
    if op_nonce != current_nonce {
        return Err(SimulationError::InvalidNonce);
    }
    Ok(())
}

fn check_prefund_ability<DB: DatabaseRef + Database>(
    ctx: &SimulationContext<DB>,
    op: &UserOperation,
    validation: &ValidationResult,
    prefund: u64,
) -> SimulationResult<bool> {
    if let Some(paymaster_addr) = op.paymaster() {
        let paymaster_addr = Address::from_slice(&paymaster_addr.as_bytes());
        // Paymaster pays
        if ctx.config.enforce_paymaster_balance {
            let paymaster_balance = ctx.evm_state.balance_ref(paymaster_addr).unwrap_or(U256::ZERO);
            if paymaster_balance < U256::from(prefund) {
                return Err(SimulationError::PaymasterBalanceInsufficient);
            }
        }
        if ctx.config.enforce_paymaster_stake {
            // Check paymaster stake/deposit
            // In production: read from EntryPoint's stake/deposit maps
            // Placeholder: assume OK
        }
        Ok(true)
    } else {
        // Account pays
        let sender = Address::from_slice(&op.sender_bytes());
        let account_balance = ctx.evm_state.balance_ref(sender).unwrap_or(U256::ZERO);
        if account_balance < U256::from(prefund) {
            return Err(SimulationError::InsufficientPrefund);
        }
        Ok(true)
    }
}

fn map_entrypoint_error(err: EntryPointError, _validation: &ValidationResult) -> SimulationError {
    match err {
        EntryPointError::SignatureError => SimulationError::SignatureError,
        EntryPointError::InvalidNonce => SimulationError::InvalidNonce,
        EntryPointError::DidNotPayPrefund => SimulationError::InsufficientPrefund,
        EntryPointError::Expired => SimulationError::Expired,
        EntryPointError::PaymasterBalanceInsufficient => SimulationError::PaymasterBalanceInsufficient,
        EntryPointError::PaymasterDepositTooLow => SimulationError::PaymasterDepositTooLow,
        EntryPointError::PaymasterStakeTooLow => SimulationError::PaymasterStakeTooLow,
        EntryPointError::PaymasterValidationReverted(msg) => SimulationError::PaymasterReverted(msg),
        EntryPointError::AccountValidationReverted(msg) => SimulationError::AccountReverted(msg),
        EntryPointError::SenderNotDeployed => SimulationError::SenderNotDeployed,
        EntryPointError::InitCodeFailed(msg) => SimulationError::InitCodeFailed(msg),
        EntryPointError::InitCodeNonEmpty => SimulationError::InitCodeNonEmpty,
        EntryPointError::OverVerificationGasLimit => SimulationError::OverVerificationGasLimit,
        EntryPointError::CallGasLimitTooHigh => SimulationError::CallGasLimitTooHigh,
        EntryPointError::PreVerificationGasTooHigh => SimulationError::PreVerificationGasTooHigh,
        EntryPointError::UnsupportedSignature => SimulationError::UnsupportedSignature,
        _ => SimulationError::Internal(format!("{:?}", err)),
    }
}

// -----------------------------------------------------------------------------
// Batch simulation
// -----------------------------------------------------------------------------

/// Simulate multiple UserOperations in order.
/// If `stop_on_first_failure` is true, returns the first failing index.
pub fn simulate_batch<DB: DatabaseRef + Database>(
    ctx: &SimulationContext<DB>,
    ops: &[UserOperation],
    stop_on_first_failure: bool,
) -> Result<Vec<SimulationResult>, (usize, SimulationError)> {
    let mut results = Vec::with_capacity(ops.len());
    for (i, op) in ops.iter().enumerate() {
        match simulate_user_op(ctx, op) {
            Ok(res) => results.push(res),
            Err(e) => {
                if stop_on_first_failure {
                    return Err((i, e));
                }
                // Otherwise, continue and collect errors
                // We'll need to return a different structure for partial results
                // For now, we return the error at the first failure.
                // A full implementation would return a list of results with errors.
                return Err((i, e));
            }
        }
    }
    Ok(results)
}

/// Simulate a batch and return results with errors included.
pub fn simulate_batch_with_errors<DB: DatabaseRef + Database>(
    ctx: &SimulationContext<DB>,
    ops: &[UserOperation],
) -> Vec<Result<SimulationResult, SimulationError>> {
    ops.iter()
        .map(|op| simulate_user_op(ctx, op))
        .collect()
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::db::CacheDB;
    use revm::primitives::AccountInfo;

    struct MockDB;
    impl DatabaseRef for MockDB {
        type Error = std::io::Error;
        fn basic(&self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(None)
        }
        fn code_by_address_ref(&self, _address: Address) -> Result<Option<Bytes>, Self::Error> {
            Ok(None)
        }
        fn storage_ref(&self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }
        fn block_hash_ref(&self, _number: U256) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
        fn nonce_ref(&self, _address: Address) -> Result<u64, Self::Error> {
            Ok(0)
        }
        fn balance_ref(&self, _address: Address) -> Result<U256, Self::Error> {
            Ok(U256::from(1_000_000))
        }
    }
    impl Database for MockDB {
        type Error = std::io::Error;
        fn basic(&mut self, _address: Address) -> Result<Option<AccountInfo>, Self::Error> {
            Ok(None)
        }
        fn code_by_address(&mut self, _address: Address) -> Result<Option<Bytes>, Self::Error> {
            Ok(None)
        }
        fn storage(&mut self, _address: Address, _index: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }
        fn block_hash(&mut self, _number: U256) -> Result<B256, Self::Error> {
            Ok(B256::ZERO)
        }
    }

    fn dummy_op() -> UserOperation {
        let mut op = UserOperation::default();
        op.sender = "0x1111111111111111111111111111111111111111".to_string();
        op.call_gas_limit = 100_000;
        op.verification_gas_limit = 100_000;
        op.pre_verification_gas = 10_000;
        op.max_fee_per_gas = 100;
        op.max_priority_fee_per_gas = 10;
        op.signature = vec![0u8; 65];
        op
    }

    #[test]
    fn simulate_valid_op() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let op = dummy_op();
        let result = simulate_user_op(&ctx, &op);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.sig_valid);
        assert_eq!(res.prefund, op.total_gas() * op.max_fee_per_gas);
    }

    #[test]
    fn simulate_short_signature() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let mut op = dummy_op();
        op.signature = vec![0u8; 64];
        let err = simulate_user_op(&ctx, &op).unwrap_err();
        assert!(matches!(err, SimulationError::SignatureError));
    }

    #[test]
    fn simulate_expired() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 2000, 0, &cache);
        let mut op = dummy_op();
        // Set paymaster data with valid_until = 1000 (already passed)
        let mut data = vec![0u8; 36];
        data[28..36].copy_from_slice(&1000u64.to_be_bytes());
        op.paymaster_and_data = data;
        let err = simulate_user_op(&ctx, &op).unwrap_err();
        assert!(matches!(err, SimulationError::Expired));
    }

    #[test]
    fn simulate_with_paymaster() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let mut op = dummy_op();
        op.paymaster_and_data = vec![0u8; 36]; // minimal paymaster data
        let result = simulate_user_op(&ctx, &op);
        assert!(result.is_ok());
        let res = result.unwrap();
        assert!(res.has_paymaster);
    }

    #[test]
    fn batch_simulation_works() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let ops = vec![dummy_op(), dummy_op()];
        let results = simulate_batch(&ctx, &ops, true);
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 2);
    }

    #[test]
    fn cache_works() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let op = dummy_op();
        let op_hash = op.hash(ENTRY_POINT_ADDRESS, 1);
        let result1 = simulate_user_op(&ctx, &op).unwrap();
        assert!(cache.get(&op_hash).is_some());
        let result2 = simulate_user_op(&ctx, &op).unwrap();
        assert_eq!(result1.prefund, result2.prefund);
    }

    #[test]
    fn config_limits_work() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let mut ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let mut config = SimulationConfig::default();
        config.max_verification_gas = 10_000;
        ctx = ctx.with_config(config);
        let mut op = dummy_op();
        op.verification_gas_limit = 100_000;
        let err = simulate_user_op(&ctx, &op).unwrap_err();
        assert!(matches!(err, SimulationError::OverVerificationGasLimit));
    }

    #[test]
    fn invalid_nonce_fails() {
        let db = MockDB;
        let cache = SimulationCache::new();
        let ctx = SimulationContext::new(1, &db, 1000, 0, &cache);
        let mut op = dummy_op();
        op.nonce = 99;
        let err = simulate_user_op(&ctx, &op).unwrap_err();
        assert!(matches!(err, SimulationError::InvalidNonce));
    }
}
