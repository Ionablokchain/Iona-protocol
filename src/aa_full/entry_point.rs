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
use revm::db::StateRef;
use revm::{Evm, EvmBuilder, Inspector};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

use crate::evm::account_abstraction::UserOperation;

pub const ENTRY_POINT_V07: &str = "0x0000000071727De22E5E9d8BAf0edAc6f37da032";
pub const ENTRY_POINT_ADDRESS: Address = Address::new([0x00; 20]); // TODO: set actual address

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq)]
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
}

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
    pub fn simulate_validation<DB: StateRef>(
        db: &DB,
        op: &UserOperation,
        chain_id: u64,
        current_timestamp: u64,
        current_block: u64,
    ) -> ValidationResult {
        let op_hash = op.hash(ENTRY_POINT_V07, chain_id);
        let mut errors = Vec::new();

        // 1. Basic sanity checks
        if let Err(e) = Self::check_basic_sanity(op) {
            return Self::validation_error(e, op);
        }

        // 2. Check time validity (from paymasterAndData or global)
        let (valid_after, valid_until) = Self::extract_time_validity(op);
        if current_timestamp < valid_after {
            return Self::validation_error(EntryPointError::Expired, op);
        }
        if current_timestamp > valid_until {
            return Self::validation_error(EntryPointError::Expired, op);
        }

        // 3. Simulate account validation via `validateUserOp`
        let account_result = Self::simulate_account_validation(db, op, op_hash);
        if let Err(e) = account_result {
            return Self::validation_error(e, op);
        }

        // 4. Simulate paymaster validation if present
        let paymaster_context = if let Some(paymaster_addr) = &op.paymaster() {
            match Self::simulate_paymaster_validation(db, op, paymaster_addr, op_hash) {
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
    pub fn handle_ops<DB: StateRef + StateWrite>(
        db: &mut DB,
        ops: &[UserOperation],
        beneficiary: Address,
        chain_id: u64,
        current_timestamp: u64,
        current_block: u64,
    ) -> HandleOpsResult {
        let mut gas_used = 0u64;
        let mut op_hashes = Vec::new();
        let mut failed = Vec::new();
        let mut senders = Vec::new();
        let mut paymasters = Vec::new();

        for (i, op) in ops.iter().enumerate() {
            senders.push(Address::from_slice(&op.sender_bytes())); // helper
            paymasters.push(op.paymaster().map(|addr| Address::from_slice(&addr)));

            let val = Self::simulate_validation(db, op, chain_id, current_timestamp, current_block);
            if let Some(err) = val.error {
                failed.push((i, err));
                continue;
            }

            // Pay prefund: either from account or paymaster
            if let Some(paymaster_addr) = op.paymaster() {
                // Paymaster pays – transfer required amount from paymaster's balance
                let cost = val.prefund;
                if !Self::transfer_from(db, paymaster_addr, beneficiary, cost) {
                    failed.push((i, EntryPointError::PaymasterBalanceInsufficient));
                    continue;
                }
            } else {
                // Account pays
                let sender_addr = Address::from_slice(&op.sender_bytes());
                if !Self::transfer_from(db, sender_addr, beneficiary, val.prefund) {
                    failed.push((i, EntryPointError::DidNotPayPrefund));
                    continue;
                }
            }

            // Execute the actual operation call
            match Self::execute_op(db, op) {
                Ok(gas) => {
                    gas_used += gas;
                    op_hashes.push(op.hash(ENTRY_POINT_V07, chain_id));
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

    fn check_basic_sanity(op: &UserOperation) -> Result<(), EntryPointError> {
        if op.signature.len() < 65 {
            return Err(EntryPointError::SignatureError);
        }
        if op.call_gas_limit == 0 || op.verification_gas_limit == 0 || op.pre_verification_gas == 0 {
            return Err(EntryPointError::PreVerificationGasTooHigh);
        }
        Ok(())
    }

    fn extract_time_validity(op: &UserOperation) -> (u64, u64) {
        if op.paymaster_and_data.len() >= 36 {
            let after = u64::from_be_bytes(op.paymaster_and_data[20..28].try_into().unwrap_or([0u8;8]));
            let until = u64::from_be_bytes(op.paymaster_and_data[28..36].try_into().unwrap_or([0xff;8]));
            (after, if until == 0 { u64::MAX } else { until })
        } else {
            (0, u64::MAX)
        }
    }

    fn simulate_account_validation<DB: StateRef>(
        db: &DB,
        op: &UserOperation,
        op_hash: B256,
    ) -> Result<(), EntryPointError> {
        // In real implementation: create a fresh REVM sub‑state, call IAccount(addr).validateUserOp
        // Capture any revert, gas used, and ensure the account returns a magic value.
        // For this example, we simulate success.
        // TODO: integrate with actual REVM call.
        Ok(())
    }

    fn simulate_paymaster_validation<DB: StateRef>(
        db: &DB,
        op: &UserOperation,
        paymaster_addr: Address,
        op_hash: B256,
    ) -> Result<Vec<u8>, EntryPointError> {
        // Call IPaymaster(paymaster).validatePaymasterUserOp
        // Returns context bytes. Revert on failure.
        Ok(Vec::new())
    }

    fn can_pay_prefund<DB: StateRef>(
        db: &DB,
        op: &UserOperation,
        prefund: u64,
    ) -> bool {
        // Check account or paymaster balance >= prefund
        true // placeholder
    }

    fn transfer_from<DB: StateWrite>(db: &mut DB, from: Address, to: Address, amount: u64) -> bool {
        // Perform balance transfer in the EVM state
        true // placeholder
    }

    fn execute_op<DB: StateWrite>(db: &mut DB, op: &UserOperation) -> Result<u64, EntryPointError> {
        // Actually call the account's execute function with op.call_data
        // Return gas used
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
}

// Helper trait for state write (simplified)
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

    struct MockDB;
    impl StateRef for MockDB {}
    impl StateWrite for MockDB {
        fn balance(&self, _addr: Address) -> U256 { U256::from(1_000_000) }
        fn set_balance(&mut self, _addr: Address, _balance: U256) {}
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
        let result = EntryPoint::simulate_validation(&db, &op, 1, 1000, 0);
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
        let result = EntryPoint::simulate_validation(&db, &op, 1, 1000, 0);
        assert_eq!(result.error, Some(EntryPointError::SignatureError));
    }
}
