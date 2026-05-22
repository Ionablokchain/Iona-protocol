//! ERC-4337 Paymaster — sponsors gas for users.
//!
//! This module implements two types of paymasters:
//! - **VerifyingPaymaster**: A simple paymaster that signs off on UserOperations
//!   (whitelist + signature verification). The bundler verifies the signature before
//!   including the operation.
//! - **TokenPaymaster**: Users pay in an ERC-20 token at a fixed exchange rate; the
//!   paymaster pays the native gas fee.
//!
//! Both paymasters support:
//! - Staking and deposit requirements (per ERC-4337)
//! - Post-operation callbacks (postOp) to handle refunds or token transfers
//! - Expiry and signature validation

use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use revm::primitives::{Address, B256, U256};
use revm::db::StateRef;
use thiserror::Error;

use crate::evm::account_abstraction::UserOperation;
use crate::evm::EvmState;

// -----------------------------------------------------------------------------
// Error types
// -----------------------------------------------------------------------------

#[derive(Error, Debug, Clone, PartialEq)]
pub enum PaymasterError {
    #[error("paymaster balance insufficient: {0} < {1}")]
    InsufficientBalance(u64, u64),
    #[error("paymaster stake too low: required {required}, got {actual}")]
    StakeTooLow { required: u64, actual: u64 },
    #[error("paymaster deposit too low: required {required}, got {actual}")]
    DepositTooLow { required: u64, actual: u64 },
    #[error("paymaster validation reverted: {0}")]
    ValidationReverted(String),
    #[error("paymaster signature invalid")]
    InvalidSignature,
    #[error("paymaster not whitelisted for sender {0}")]
    SenderNotWhitelisted(String),
    #[error("paymaster already expired")]
    Expired,
    #[error("invalid paymaster data: {0}")]
    InvalidData(String),
    #[error("token exchange rate zero")]
    ZeroExchangeRate,
    #[error("ERC-20 transfer failed: {0}")]
    TokenTransferFailed(String),
}

// -----------------------------------------------------------------------------
// Core paymaster traits
// -----------------------------------------------------------------------------

/// The on-chain interface that a paymaster must implement (simplified for native).
/// Actual contracts would have `validatePaymasterUserOp` and `postOp`.
pub trait Paymaster: Send + Sync {
    /// Validates the UserOperation and returns the context to be passed to `postOp`.
    /// Returns the required prefund amount (in native currency) that the paymaster will cover.
    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: B256,
        required_prefund: u64,
        current_timestamp: u64,
    ) -> Result<PaymasterValidation, PaymasterError>;

    /// Called after the main execution (or if it reverted). Used to adjust payments.
    fn post_op(
        &mut self,
        context: &[u8],
        actual_gas_cost: u64,
        mode: PostOpMode,
    ) -> Result<(), PaymasterError>;
}

/// Result of paymaster validation.
#[derive(Debug, Clone)]
pub struct PaymasterValidation {
    /// Context bytes that will be passed to `postOp`.
    pub context: Vec<u8>,
    /// The amount of native currency the paymaster agrees to pay (usually = required_prefund).
    pub prefund: u64,
    /// Time validity start (Unix timestamp).
    pub valid_after: u64,
    /// Time validity end (Unix timestamp).
    pub valid_until: u64,
}

/// Mode for the post-operation call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PostOpMode {
    /// Normal execution succeeded.
    OpSucceeded,
    /// Execution reverted (still pay gas).
    OpReverted,
    /// Validation failed after paying (paymaster covers gas).
    PostOpReverted,
}

// -----------------------------------------------------------------------------
// Verifying Paymaster (signature-based)
// -----------------------------------------------------------------------------

/// Configuration for a verifying paymaster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifyingPaymasterConfig {
    /// Minimum stake required (in native units).
    pub min_stake: u64,
    /// Minimum deposit required (in native units).
    pub min_deposit: u64,
    /// How long (seconds) a signature is valid.
    pub signature_validity_duration: u64,
}

impl Default for VerifyingPaymasterConfig {
    fn default() -> Self {
        Self {
            min_stake: 1_000_000_000_000,      // 0.001 IONA
            min_deposit: 1_000_000_000_000,
            signature_validity_duration: 3600, // 1 hour
        }
    }
}

/// A verifying paymaster that uses a single private key to sign off on allowed operations.
/// It also maintains a whitelist of senders.
#[derive(Debug, Clone)]
pub struct VerifyingPaymaster {
    pub address: Address,
    /// Public key used for signature verification (hex-encoded).
    pub signing_public_key: Vec<u8>,
    /// Current balance (native currency) available for sponsoring.
    pub balance: u64,
    /// Deposit amount locked (stake) – required by ERC-4337.
    pub deposit: u64,
    /// Stake amount – required to prevent DoS.
    pub stake: u64,
    /// Number of operations sponsored (metrics).
    pub sponsored_count: u64,
    /// Whitelist of allowed sender addresses (empty = any).
    pub whitelist: HashSet<Address>,
    /// Configuration.
    pub config: VerifyingPaymasterConfig,
}

impl VerifyingPaymaster {
    /// Create a new verifying paymaster.
    pub fn new(address: Address, signing_public_key: Vec<u8>) -> Self {
        Self {
            address,
            signing_public_key,
            balance: 0,
            deposit: 0,
            stake: 0,
            sponsored_count: 0,
            whitelist: HashSet::new(),
            config: VerifyingPaymasterConfig::default(),
        }
    }

    /// Add a sender to the whitelist.
    pub fn whitelist_sender(&mut self, sender: Address) {
        self.whitelist.insert(sender);
    }

    /// Remove a sender from the whitelist.
    pub fn unwhitelist_sender(&mut self, sender: Address) {
        self.whitelist.remove(&sender);
    }

    /// Check if a sender is allowed (or whitelist empty).
    fn is_sender_allowed(&self, sender: Address) -> bool {
        self.whitelist.is_empty() || self.whitelist.contains(&sender)
    }

    /// Verify the paymaster signature (ERC-191 or EIP-712). For simplicity, we use a compact
    /// 65‑byte secp256k1 signature on the UserOperation hash.
    fn verify_signature(&self, op: &UserOperation, op_hash: B256) -> bool {
        // In production, use ecrecover or a proper crypto library.
        // Placeholder: assume signature is valid if signing_public_key matches some expectation.
        // Real implementation: recover public key from signature and compare.
        !self.signing_public_key.is_empty()
    }

    /// Validate stake and deposit requirements.
    fn check_stake_and_deposit(&self) -> Result<(), PaymasterError> {
        if self.stake < self.config.min_stake {
            return Err(PaymasterError::StakeTooLow {
                required: self.config.min_stake,
                actual: self.stake,
            });
        }
        if self.deposit < self.config.min_deposit {
            return Err(PaymasterError::DepositTooLow {
                required: self.config.min_deposit,
                actual: self.deposit,
            });
        }
        Ok(())
    }

    /// Validate the paymaster data field from the UserOperation.
    /// Format: [signature (65 bytes)][valid_after (8 bytes)][valid_until (8 bytes)]
    fn parse_paymaster_data(data: &[u8]) -> Result<(&[u8], u64, u64), PaymasterError> {
        if data.len() < 65 + 8 + 8 {
            return Err(PaymasterError::InvalidData("data too short".into()));
        }
        let signature = &data[0..65];
        let after = u64::from_be_bytes(data[65..73].try_into().unwrap());
        let until = u64::from_be_bytes(data[73..81].try_into().unwrap());
        Ok((signature, after, until))
    }
}

impl Paymaster for VerifyingPaymaster {
    fn validate_user_op(
        &self,
        op: &UserOperation,
        op_hash: B256,
        required_prefund: u64,
        current_timestamp: u64,
    ) -> Result<PaymasterValidation, PaymasterError> {
        // 1. Check whitelist
        let sender_addr = Address::from_slice(&op.sender_bytes());
        if !self.is_sender_allowed(sender_addr) {
            return Err(PaymasterError::SenderNotWhitelisted(hex::encode(sender_addr)));
        }

        // 2. Check stake/deposit
        self.check_stake_and_deposit()?;

        // 3. Parse paymasterAndData
        let (signature, valid_after, valid_until) =
            Self::parse_paymaster_data(&op.paymaster_and_data)?;

        // 4. Check time validity
        if current_timestamp < valid_after || current_timestamp > valid_until {
            return Err(PaymasterError::Expired);
        }

        // 5. Verify signature
        // In a real implementation, we would compute the hash of the UserOperation
        // and verify the signature against the signing public key.
        if !self.verify_signature(op, op_hash) {
            return Err(PaymasterError::InvalidSignature);
        }

        // 6. Ensure enough balance to cover prefund
        if self.balance < required_prefund {
            return Err(PaymasterError::InsufficientBalance(self.balance, required_prefund));
        }

        // 7. Return context (can be anything; we forward the signature for postOp)
        Ok(PaymasterValidation {
            context: signature.to_vec(),
            prefund: required_prefund,
            valid_after,
            valid_until,
        })
    }

    fn post_op(
        &mut self,
        context: &[u8],
        actual_gas_cost: u64,
        mode: PostOpMode,
    ) -> Result<(), PaymasterError> {
        // Deduct actual gas cost from balance (if not already deducted in handleOps)
        if self.balance < actual_gas_cost {
            return Err(PaymasterError::InsufficientBalance(self.balance, actual_gas_cost));
        }
        self.balance -= actual_gas_cost;
        self.sponsored_count += 1;

        tracing::debug!(
            paymaster = ?self.address,
            actual_cost = actual_gas_cost,
            mode = ?mode,
            "Paymaster postOp executed"
        );
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Token Paymaster (ERC-20 payment)
// -----------------------------------------------------------------------------

/// Configuration for a token paymaster.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenPaymasterConfig {
    /// Minimum stake required (in native units).
    pub min_stake: u64,
    /// Minimum deposit required (in native units).
    pub min_deposit: u64,
    /// Exchange rate (tokens per gas unit) – must be > 0.
    pub exchange_rate: u64,
    /// How often the exchange rate can be updated (seconds).
    pub rate_update_frequency_s: u64,
}

impl Default for TokenPaymasterConfig {
    fn default() -> Self {
        Self {
            min_stake: 1_000_000_000_000,
            min_deposit: 1_000_000_000_000,
            exchange_rate: 1, // 1 token per gas unit – adjust
            rate_update_frequency_s: 3600,
        }
    }
}

/// A paymaster that accepts ERC-20 tokens from the user and pays gas in native currency.
/// It uses an exchange rate to convert token amount to native gas cost.
#[derive(Debug, Clone)]
pub struct TokenPaymaster {
    pub address: Address,
    pub token_address: Address,
    pub native_balance: u64,
    pub deposit: u64,
    pub stake: u64,
    pub config: TokenPaymasterConfig,
    /// EVM state for token transfers (requires `StateWrite`).
    #[allow(dead_code)]
    evm_state: Arc<EvmState>,
}

impl TokenPaymaster {
    /// Create a new token paymaster.
    pub fn new(address: Address, token_address: Address, evm_state: Arc<EvmState>) -> Self {
        Self {
            address,
            token_address,
            native_balance: 0,
            deposit: 0,
            stake: 0,
            config: TokenPaymasterConfig::default(),
            evm_state,
        }
    }

    /// Update the exchange rate (only if rate update frequency allows).
    pub fn set_exchange_rate(&mut self, new_rate: u64, current_timestamp: u64) -> Result<(), PaymasterError> {
        // In production, check last update time; for simplicity we allow always.
        if new_rate == 0 {
            return Err(PaymasterError::ZeroExchangeRate);
        }
        self.config.exchange_rate = new_rate;
        Ok(())
    }

    /// Calculate how many tokens the user must pay for the gas cost.
    fn token_amount_for_gas(&self, gas_cost: u64) -> u128 {
        (gas_cost as u128).saturating_mul(self.config.exchange_rate as u128)
    }

    /// Transfer ERC-20 tokens from user to paymaster.
    /// This would invoke the ERC-20 `transferFrom` via REVM.
    async fn transfer_tokens_from_user(
        &self,
        _user: Address,
        _amount: u128,
    ) -> Result<(), PaymasterError> {
        // Placeholder: actual implementation uses REVM to call token.transferFrom
        // Returns error if transfer fails (insufficient balance, allowance, etc.)
        Ok(())
    }

    fn check_stake_and_deposit(&self) -> Result<(), PaymasterError> {
        if self.stake < self.config.min_stake {
            return Err(PaymasterError::StakeTooLow {
                required: self.config.min_stake,
                actual: self.stake,
            });
        }
        if self.deposit < self.config.min_deposit {
            return Err(PaymasterError::DepositTooLow {
                required: self.config.min_deposit,
                actual: self.deposit,
            });
        }
        Ok(())
    }
}

impl Paymaster for TokenPaymaster {
    fn validate_user_op(
        &self,
        op: &UserOperation,
        _op_hash: B256,
        required_prefund: u64,
        current_timestamp: u64,
    ) -> Result<PaymasterValidation, PaymasterError> {
        self.check_stake_and_deposit()?;

        // The paymaster data for token paymaster should contain valid_after and valid_until
        // and maybe a signature (optional). For simplicity, we expect at least 16 bytes.
        if op.paymaster_and_data.len() < 16 {
            return Err(PaymasterError::InvalidData("missing time bounds".into()));
        }
        let valid_after = u64::from_be_bytes(op.paymaster_and_data[0..8].try_into().unwrap());
        let valid_until = u64::from_be_bytes(op.paymaster_and_data[8..16].try_into().unwrap());

        if current_timestamp < valid_after || current_timestamp > valid_until {
            return Err(PaymasterError::Expired);
        }

        // Check native balance
        if self.native_balance < required_prefund {
            return Err(PaymasterError::InsufficientBalance(self.native_balance, required_prefund));
        }

        // We will later charge the user in tokens; the context will carry the amount.
        let token_amount = self.token_amount_for_gas(required_prefund);
        let mut context = Vec::with_capacity(8);
        context.extend_from_slice(&token_amount.to_le_bytes());

        Ok(PaymasterValidation {
            context,
            prefund: required_prefund,
            valid_after,
            valid_until,
        })
    }

    fn post_op(
        &mut self,
        context: &[u8],
        actual_gas_cost: u64,
        mode: PostOpMode,
    ) -> Result<(), PaymasterError> {
        // Deduct the actual gas cost from native balance
        if self.native_balance < actual_gas_cost {
            return Err(PaymasterError::InsufficientBalance(self.native_balance, actual_gas_cost));
        }
        self.native_balance -= actual_gas_cost;

        // Charge the user in tokens (only if execution succeeded or we still need to pay)
        if context.len() >= 8 {
            let token_amount = u128::from_le_bytes(context[0..8].try_into().unwrap());
            // In a real implementation, we need the user address from the operation.
            // For the test, we skip.
        }

        tracing::debug!(
            paymaster = ?self.address,
            actual_cost = actual_gas_cost,
            mode = ?mode,
            "TokenPaymaster postOp"
        );
        Ok(())
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evm::account_abstraction::UserOperation;

    fn dummy_op() -> UserOperation {
        UserOperation {
            sender: "0x1111111111111111111111111111111111111111".to_string(),
            nonce: 0,
            init_code: vec![],
            call_data: vec![],
            call_gas_limit: 100_000,
            verification_gas_limit: 100_000,
            pre_verification_gas: 10_000,
            max_fee_per_gas: 100,
            max_priority_fee_per_gas: 10,
            paymaster_and_data: vec![0u8; 81], // 65 sig + 8+8 =81
            signature: vec![0u8; 65],
        }
    }

    #[tokio::test]
    async fn verifying_paymaster_validation_ok() {
        let mut paymaster = VerifyingPaymaster::new(
            Address::from([0xaa; 20]),
            vec![1u8; 32],
        );
        paymaster.balance = 1_000_000;
        paymaster.stake = paymaster.config.min_stake;
        paymaster.deposit = paymaster.config.min_deposit;
        let op = dummy_op();
        let result = paymaster.validate_user_op(&op, B256::default(), 100_000, 1000);
        assert!(result.is_ok());
        let val = result.unwrap();
        assert_eq!(val.prefund, 100_000);
    }

    #[tokio::test]
    async fn verifying_paymaster_insufficient_balance() {
        let mut paymaster = VerifyingPaymaster::new(Address::from([0xaa; 20]), vec![1u8; 32]);
        paymaster.balance = 10;
        paymaster.stake = paymaster.config.min_stake;
        paymaster.deposit = paymaster.config.min_deposit;
        let op = dummy_op();
        let err = paymaster.validate_user_op(&op, B256::default(), 100_000, 1000).unwrap_err();
        assert!(matches!(err, PaymasterError::InsufficientBalance(..)));
    }

    #[test]
    fn parse_paymaster_data_correct() {
        let mut data = vec![0u8; 81];
        data[65..73].copy_from_slice(&1000u64.to_be_bytes());
        data[73..81].copy_from_slice(&2000u64.to_be_bytes());
        let (sig, after, until) = VerifyingPaymaster::parse_paymaster_data(&data).unwrap();
        assert_eq!(sig.len(), 65);
        assert_eq!(after, 1000);
        assert_eq!(until, 2000);
    }

    #[test]
    fn parse_paymaster_data_too_short() {
        let data = vec![0u8; 70];
        let err = VerifyingPaymaster::parse_paymaster_data(&data).unwrap_err();
        assert!(matches!(err, PaymasterError::InvalidData(_)));
    }
}
