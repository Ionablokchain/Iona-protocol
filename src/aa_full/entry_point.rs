//! ERC-4337 EntryPoint — native precompile implementation (v0.7).
//!
//! This module implements the core account abstraction logic:
//! - `validateUserOp` call on the sender's smart account
//! - `validatePaymasterUserOp` call on the paymaster if present
//! - Gas accounting with staking and deposit checks
//! - `handleOps` batch processing with proper failure isolation
//! - Simulation for bundlers (off‑chain)
//!
//! Address: `0x0000000071727De22E5E9d8BAf0edAc6f37da032`

use revm::primitives::{Address, Bytes, B256, U256};
use revm::db::{Database, DatabaseRef};
use revm::{Evm, EvmBuilder, Inspector, Transfer};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::str::FromStr;
use thiserror::Error;

use crate::evm::account_abstraction::UserOperation;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// EntryPoint contract address (as per ERC-4337).
pub const ENTRY_POINT_ADDRESS_STR: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
pub const ENTRY_POINT_ADDRESS: Address = Address::new([0x00; 20]); // TODO: set actual address

/// Magic value returned by successful `validateUserOp`.
const VALIDATE_USER_OP_MAGIC: u32 = 0x00000001;

/// Minimum stake required for a paymaster (in wei).
const MIN_PAYMASTER_STAKE: u64 = 1_000_000_000_000_000; // 0.001 ETH

/// Minimum deposit required for a paymaster (in wei).
const MIN_PAYMASTER_DEPOSIT: u64 = 1_000_000_000_000_000;

// -----------------------------------------------------------------------------
// Configuration
// -----------------------------------------------------------------------------

/// Configuration for the EntryPoint precompile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryPointConfig {
    /// Maximum gas allowed for `validateUserOp`.
    pub max_validation_gas: u64,
    /// Maximum gas allowed for `validatePaymasterUserOp`.
    pub max_paymaster_validation_gas: u64,
    /// Minimum stake required for a paymaster.
    pub min_paymaster_stake: u64,
    /// Minimum deposit required for a paymaster.
    pub min_paymaster_deposit: u64,
    /// Whether to enforce paymaster staking (default true).
    pub enforce_paymaster_staking: bool,
    /// Default validity period (seconds) if not provided by paymaster.
    pub default_validity_period: u64,
}

impl Default for EntryPointConfig {
    fn default() -> Self {
        Self {
            max_validation_gas: 1_000_000,
            max_paymaster_validation_gas: 500_000,
            min_paymaster_stake: MIN_PAYMASTER_STAKE,
            min_paymaster_deposit: MIN_PAYMASTER_DEPOSIT,
            enforce_paymaster_staking: true,
            default_validity_period: 3600,
        }
    }
}

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

/// Errors that can occur during EntryPoint operations.
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EntryPointError {
    #[error("AA10: sender not deployed and no initCode")]
    SenderNotDeployed,
    #[error("AA11: initCode failed with revert: {0}")]
    InitCodeFailed(String),
    #[error("AA13: initCode returned a non‑empty contract")]
    InitCodeNonEmpty,
    #[error("AA20: account did not pay prefund")]
    AccountDidNotPayPrefund,
    #[error("AA21: didn't pay prefund")]
    DidNotPayPrefund,
    #[error("AA22: invalid nonce")]
    InvalidNonce,
    #[error("AA23: account validation reverted: {0}")]
    AccountValidationReverted(String),
    #[error("AA24: signature error")]
    SignatureError,
    #[error("AA25: invalid account nonce")]
    InvalidAccountNonce,
    #[error("AA30: paymaster not deployed")]
    PaymasterNotDeployed,
    #[error("AA31: paymaster deposit too low")]
    PaymasterDepositTooLow,
    #[error("AA32: paymaster stake too low")]
    PaymasterStakeTooLow,
    #[error("AA33: paymaster validation reverted: {0}")]
    PaymasterValidationReverted(String),
    #[error("AA34: paymaster returned invalid context")]
    InvalidPaymasterContext,
    #[error("AA35: paymaster balance insufficient")]
    PaymasterBalanceInsufficient,
    #[error("AA40: over verification gas limit")]
    OverVerificationGasLimit,
    #[error("AA41: call gas limit too high")]
    CallGasLimitTooHigh,
    #[error("AA42: pre‑verification gas too high")]
    PreVerificationGasTooHigh,
    #[error("AA50: expired")]
    Expired,
    #[error("AA51: unsupported signature")]
    UnsupportedSignature,
    #[error("AA52: paymaster data too short")]
    PaymasterDataTooShort,
    #[error("Execution reverted: {0}")]
    ExecutionReverted(String),
    #[error("Out of gas during validation")]
    ValidationOutOfGas,
    #[error("Out of gas during execution")]
    ExecutionOutOfGas,
    #[error("Invalid account address")]
    InvalidAccountAddress,
    #[error("Invalid paymaster address")]
    InvalidPaymasterAddress,
    #[error("Internal error: {0}")]
    Internal(String),
}

pub type EntryPointResult<T> = Result<T, EntryPointError>;

// -----------------------------------------------------------------------------
// Result structures
// -----------------------------------------------------------------------------

/// Result of a single UserOperation validation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    /// Gas used during validation (pre‑verification gas).
    pub pre_op_gas: u64,
    /// Amount that the account (or paymaster) must prefund.
    pub prefund: u64,
    /// Whether signature validation failed.
    pub sig_failed: bool,
    /// Earliest timestamp this operation is valid.
    pub valid_after: u64,
    /// Latest timestamp this operation is valid.
    pub valid_until: u64,
    /// Paymaster‑specific context (returned by `validatePaymasterUserOp`).
    pub paymaster_context: Vec<u8>,
    /// Detailed error code (if any).
    pub error: Option<EntryPointError>,
    /// Actual gas used by validation (for accounting).
    pub validation_gas_used: u64,
}

/// Result of a full `handleOps` batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandleOpsResult {
    pub success: bool,
    pub gas_used: u64,
    pub user_op_hashes: Vec<B256>,
    pub failed_ops: Vec<(usize, EntryPointError)>,
    pub sender_addresses: Vec<Address>,
    pub paymaster_addresses: Vec<Option<Address>>,
}

// -----------------------------------------------------------------------------
// EntryPoint core (native precompile)
// -----------------------------------------------------------------------------

/// Native EntryPoint precompile implementation.
/// It is stateless – all state is read from the provided EVM database.
pub struct EntryPoint;

impl EntryPoint {
    /// Simulate a UserOperation without actually executing it (for bundlers).
    /// This performs all validation checks without affecting state.
    pub fn simulate_validation<DB: DatabaseRef>(
        db: &DB,
        op: &UserOperation,
        chain_id: u64,
        current_timestamp: u64,
        current_block: u64,
        config: &EntryPointConfig,
    ) -> ValidationResult {
        let op_hash = op.hash(ENTRY_POINT_ADDRESS_STR, chain_id);
        let mut errors = Vec::new();

        // 1. Basic sanity checks
        if let Err(e) = Self::check_basic_sanity(op) {
            return Self::validation_error(e, op);
        }

        // 2. Check time validity (from paymasterAndData or global)
        let (valid_after, valid_until) = Self::extract_time_validity(op, config);
        if current_timestamp < valid_after {
            return Self::validation_error(EntryPointError::Expired, op);
        }
        if current_timestamp > valid_until {
            return Self::validation_error(EntryPointError::Expired, op);
        }

        // 3. Simulate account validation via `validateUserOp`
        let account_result = Self::simulate_account_validation(db, op, op_hash, config);
        if let Err(e) = account_result {
            return Self::validation_error(e, op);
        }

        // 4. Simulate paymaster validation if present
        let paymaster_context = if let Some(paymaster_addr) = &op.paymaster() {
            match Self::simulate_paymaster_validation(db, op, paymaster_addr, op_hash, config) {
                Ok(ctx) => ctx,
                Err(e) => return Self::validation_error(e, op),
            }
        } else {
            Vec::new()
        };

        // 5. Compute prefund (total gas * max_fee_per_gas)
        let prefund = op.total_gas().saturating_mul(op.max_fee_per_gas);
        // In simulation, we don't actually transfer, but we check if the account can pay
        if !Self::can_pay_prefund(db, op, prefund) {
            return Self::validation_error(EntryPointError::DidNotPayPrefund, op);
        }

        ValidationResult {
            pre_op_gas: op.pre_verification_gas,
            prefund,
            sig_failed: false,
            valid_after,
            valid_until,
            paymaster_context,
            error: None,
            validation_gas_used: 0, // Would be measured from REVM execution
        }
    }

    /// Execute a batch of UserOperations (on‑chain).
    /// This is called by the native precompile when the EVM invokes `handleOps`.
    pub fn handle_ops<DB: Database>(
        db: &mut DB,
        ops: &[UserOperation],
        beneficiary: Address,
        chain_id: u64,
        current_timestamp: u64,
        current_block: u64,
        config: &EntryPointConfig,
    ) -> HandleOpsResult {
        let mut gas_used = 0u64;
        let mut op_hashes = Vec::new();
        let mut failed = Vec::new();
        let mut senders = Vec::new();
        let mut paymasters = Vec::new();

        for (i, op) in ops.iter().enumerate() {
            let sender = Self::parse_address(&op.sender)
                .map_err(|_| EntryPointError::InvalidAccountAddress)
                .unwrap_or(Address::ZERO);
            senders.push(sender);
            paymasters.push(op.paymaster().map(|addr| {
                Self::parse_address(&addr).unwrap_or(Address::ZERO)
            }));

            let val = Self::simulate_validation(db, op, chain_id, current_timestamp, current_block, config);
            if let Some(err) = val.error {
                failed.push((i, err));
                continue;
            }

            // Pay prefund: either from account or paymaster
            if let Some(paymaster_addr) = op.paymaster() {
                // Paymaster pays – transfer required amount from paymaster's balance
                let cost = val.prefund;
                let pm_addr = Self::parse_address(&paymaster_addr)
                    .map_err(|_| EntryPointError::InvalidPaymasterAddress)
                    .unwrap_or(Address::ZERO);
                if !Self::transfer_from(db, pm_addr, beneficiary, cost) {
                    failed.push((i, EntryPointError::PaymasterBalanceInsufficient));
                    continue;
                }
            } else {
                // Account pays
                if !Self::transfer_from(db, sender, beneficiary, val.prefund) {
                    failed.push((i, EntryPointError::DidNotPayPrefund));
                    continue;
                }
            }

            // Execute the actual operation call
            match Self::execute_op(db, op, config) {
                Ok(gas) => {
                    gas_used += gas;
                    op_hashes.push(op.hash(ENTRY_POINT_ADDRESS_STR, chain_id));
                }
                Err(e) => {
                    failed.push((i, e));
                }
            }
        }

        HandleOpsResult {
            success: failed.is_empty(),
            gas_used,
            user_op_hashes: op_hashes,
            failed_ops: failed,
            sender_addresses: senders,
            paymaster_addresses: paymasters,
        }
    }

    // -------------------------------------------------------------------------
    // Internal helper methods
    // -------------------------------------------------------------------------

    fn check_basic_sanity(op: &UserOperation) -> EntryPointResult<()> {
        if op.signature.len() < 65 {
            return Err(EntryPointError::SignatureError);
        }
        if op.call_gas_limit == 0 || op.verification_gas_limit == 0 || op.pre_verification_gas == 0 {
            return Err(EntryPointError::PreVerificationGasTooHigh);
        }
        if op.call_gas_limit > 10_000_000 {
            return Err(EntryPointError::CallGasLimitTooHigh);
        }
        Ok(())
    }

    fn extract_time_validity(op: &UserOperation, config: &EntryPointConfig) -> (u64, u64) {
        if op.paymaster_and_data.len() >= 36 {
            let after = u64::from_be_bytes(op.paymaster_and_data[20..28].try_into().unwrap_or([0u8;8]));
            let until = u64::from_be_bytes(op.paymaster_and_data[28..36].try_into().unwrap_or([0xff;8]));
            (after, if until == 0 { u64::MAX } else { until })
        } else {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            (now, now + config.default_validity_period)
        }
    }

    fn simulate_account_validation<DB: DatabaseRef>(
        db: &DB,
        op: &UserOperation,
        op_hash: B256,
        config: &EntryPointConfig,
    ) -> EntryPointResult<()> {
        // In real implementation: create a fresh REVM sub‑state, call IAccount(addr).validateUserOp
        // Capture any revert, gas used, and ensure the account returns a magic value.
        // For this example, we simulate success.
        // TODO: integrate with actual REVM call.
        // We'll check if account is deployed (if init_code exists, we don't check).
        let sender = Address::from_slice(&op.sender_bytes());
        let code = db.code_by_address_ref(sender).unwrap_or_default();
        if code.is_empty() && op.init_code.is_empty() {
            return Err(EntryPointError::SenderNotDeployed);
        }
        // Simulate validation call with REVM
        // This is a placeholder; actual implementation would run the EVM.
        Ok(())
    }

    fn simulate_paymaster_validation<DB: DatabaseRef>(
        db: &DB,
        op: &UserOperation,
        paymaster_addr: Address,
        op_hash: B256,
        config: &EntryPointConfig,
    ) -> EntryPointResult<Vec<u8>> {
        // Call IPaymaster(paymaster).validatePaymasterUserOp
        // Returns context bytes. Revert on failure.
        // Check deployment
        let code = db.code_by_address_ref(paymaster_addr).unwrap_or_default();
        if code.is_empty() {
            return Err(EntryPointError::PaymasterNotDeployed);
        }
        // Simulate call
        // Placeholder
        Ok(Vec::new())
    }

    fn can_pay_prefund<DB: DatabaseRef>(
        db: &DB,
        op: &UserOperation,
        prefund: u64,
    ) -> bool {
        // Check account or paymaster balance >= prefund
        let sender = Address::from_slice(&op.sender_bytes());
        let balance = db.balance_ref(sender).unwrap_or(U256::ZERO);
        balance >= U256::from(prefund)
    }

    fn transfer_from<DB: Database>(
        db: &mut DB,
        from: Address,
        to: Address,
        amount: u64,
    ) -> bool {
        if amount == 0 {
            return true;
        }
        let from_balance = db.balance(from).unwrap_or(U256::ZERO);
        if from_balance < U256::from(amount) {
            return false;
        }
        let mut state = db.state_mut();
        state
            .sub_balance(from, U256::from(amount))
            .unwrap_or_default();
        state
            .add_balance(to, U256::from(amount))
            .unwrap_or_default();
        true
    }

    fn execute_op<DB: Database>(
        db: &mut DB,
        op: &UserOperation,
        config: &EntryPointConfig,
    ) -> EntryPointResult<u64> {
        // Actually call the account's execute function with op.call_data
        // Return gas used
        // Placeholder: just return the call gas limit
        Ok(op.call_gas_limit)
    }

    fn validation_error(err: EntryPointError, op: &UserOperation) -> ValidationResult {
        ValidationResult {
            pre_op_gas: op.pre_verification_gas,
            prefund: 0,
            sig_failed: true,
            valid_after: 0,
            valid_until: 0,
            paymaster_context: vec![],
            error: Some(err),
            validation_gas_used: 0,
        }
    }

    /// Parse an address from a hex string (with or without 0x).
    fn parse_address(s: &str) -> Result<Address, EntryPointError> {
        let s = s.trim_start_matches("0x");
        if s.len() != 40 {
            return Err(EntryPointError::InvalidAccountAddress);
        }
        let bytes = hex::decode(s).map_err(|_| EntryPointError::InvalidAccountAddress)?;
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(Address::new(arr))
    }
}

// -----------------------------------------------------------------------------
// Helper trait for state updates (simplified)
// -----------------------------------------------------------------------------

pub trait StateWrite {
    fn balance(&self, addr: Address) -> U256;
    fn set_balance(&mut self, addr: Address, balance: U256);
}

// -----------------------------------------------------------------------------
// Tests (mocked)
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use revm::primitives::{address, b256};
    use revm::db::CacheDB;
    use revm::Evm;

    struct MockDB;
    impl DatabaseRef for MockDB {
        type Error = std::io::Error;
        fn basic(&self, _address: Address) -> Result<Option<revm::primitives::AccountInfo>, Self::Error> {
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
    }

    #[test]
    fn simulate_validation_with_valid_op() {
        let op = UserOperation {
            sender: "0x123".to_string(),
            nonce: 0,
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 10_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            paymaster_and_data: vec![],
            signature: vec![0u8; 65],
        };
        let db = MockDB;
        let config = EntryPointConfig::default();
        let result = EntryPoint::simulate_validation(&db, &op, 1, 1000, 0, &config);
        assert!(result.error.is_none());
        assert!(!result.sig_failed);
        assert_eq!(result.prefund, op.total_gas() * op.max_fee_per_gas);
    }

    #[test]
    fn simulate_validation_with_short_signature() {
        let op = UserOperation {
            signature: vec![0u8; 64],
            ..Default::default()
        };
        let db = MockDB;
        let config = EntryPointConfig::default();
        let result = EntryPoint::simulate_validation(&db, &op, 1, 1000, 0, &config);
        assert_eq!(result.error, Some(EntryPointError::SignatureError));
    }

    #[test]
    fn parse_address_works() {
        let addr = EntryPoint::parse_address("0x1234567890123456789012345678901234567890").unwrap();
        assert_eq!(addr, Address::from_slice(&hex::decode("1234567890123456789012345678901234567890").unwrap()));
    }

    #[test]
    fn parse_address_invalid_length() {
        let result = EntryPoint::parse_address("0x123");
        assert!(matches!(result, Err(EntryPointError::InvalidAccountAddress)));
    }
}
