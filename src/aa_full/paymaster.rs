//! ERC-4337 Paymaster — sponsors gas for users.
use serde::{Deserialize, Serialize};
use crate::evm::account_abstraction::UserOperation;

/// A Verifying Paymaster that sponsors gas for whitelisted operations.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct VerifyingPaymaster {
    pub address:         String,
    pub signer_pk:       Vec<u8>,
    pub balance:         u64,
    pub sponsored_count: u64,
    /// Whitelist of allowed senders (empty = sponsor all).
    pub whitelist:       Vec<String>,
}

impl VerifyingPaymaster {
    pub fn can_sponsor(&self, op: &UserOperation) -> bool {
        if self.balance == 0 { return false; }
        if self.whitelist.is_empty() { return true; }
        self.whitelist.iter().any(|a| a.eq_ignore_ascii_case(&op.sender))
    }
    pub fn sponsor(&mut self, op: &UserOperation, max_cost: u64) -> Option<Vec<u8>> {
        if !self.can_sponsor(op) { return None; }
        if self.balance < max_cost { return None; }
        self.balance -= max_cost;
        self.sponsored_count += 1;
        // Return paymaster context (passed to postOp)
        Some(op.sender.as_bytes().to_vec())
    }
}

/// Token Paymaster — user pays in ERC-20, paymaster pays gas in native token.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TokenPaymaster {
    pub address:       String,
    pub token_address: String,
    pub exchange_rate: u64, // tokens per gas unit
    pub native_balance: u64,
}
