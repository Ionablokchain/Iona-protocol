//! EVM transaction types (Legacy, EIP‑2930, EIP‑1559).
//!
//! This module defines the transaction formats accepted by the IONA EVM
//! (`iona-evm-rpc` and the unified `evm_unified` transaction payload).

use serde::{Deserialize, Serialize};
use thiserror::Error;

// -----------------------------------------------------------------------------
// Type aliases for EVM compatibility
// -----------------------------------------------------------------------------

/// 20‑byte Ethereum address.
pub type Address20 = [u8; 20];

/// 32‑byte hash (used for storage keys).
pub type H256 = [u8; 32];

// -----------------------------------------------------------------------------
// Access list item (EIP‑2930 and EIP‑1559)
// -----------------------------------------------------------------------------

/// A single entry in an EIP‑2930 access list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: Address20,
    pub storage_keys: Vec<H256>,
}

impl AccessListItem {
    /// Create a new access list item.
    pub fn new(address: Address20, storage_keys: Vec<H256>) -> Self {
        Self { address, storage_keys }
    }

    /// Check if the access list item is empty (no storage keys).
    pub fn is_empty(&self) -> bool {
        self.storage_keys.is_empty()
    }

    /// Number of storage keys.
    pub fn len(&self) -> usize {
        self.storage_keys.len()
    }
}

// -----------------------------------------------------------------------------
// Errors
// -----------------------------------------------------------------------------

/// Errors that can occur when validating an EVM transaction.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum EvmTxError {
    #[error("chain ID mismatch: expected {expected}, got {actual}")]
    ChainIdMismatch { expected: u64, actual: u64 },

    #[error("gas limit must be > 0, got {0}")]
    ZeroGasLimit(u64),

    #[error("gas price must be > 0, got {0}")]
    ZeroGasPrice(u128),

    #[error("gas fee cap cannot be zero (EIP‑1559)")]
    ZeroMaxFeePerGas,

    #[error("priority fee cannot exceed max fee per gas (EIP‑1559)")]
    PriorityFeeExceedsMaxFee,

    #[error("nonce overflow (max 2^64-1)")]
    NonceOverflow,

    #[error("value overflow (max 2^128-1)")]
    ValueOverflow,
}

pub type EvmTxResult<T> = Result<T, EvmTxError>;

// -----------------------------------------------------------------------------
// EVM transaction enum
// -----------------------------------------------------------------------------

/// EVM transaction types supported by IONA.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EvmTx {
    /// Legacy transaction (pre‑EIP‑1559).
    Legacy {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        chain_id: u64,
    },
    /// EIP‑2930 transaction with access list.
    Eip2930 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        gas_price: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
    },
    /// EIP‑1559 transaction with fee caps.
    Eip1559 {
        from: Address20,
        to: Option<Address20>,
        nonce: u64,
        gas_limit: u64,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        value: u128,
        data: Vec<u8>,
        access_list: Vec<AccessListItem>,
        chain_id: u64,
    },
}

impl EvmTx {
    /// Returns the chain ID of the transaction.
    pub fn chain_id(&self) -> u64 {
        match self {
            EvmTx::Legacy { chain_id, .. } => *chain_id,
            EvmTx::Eip2930 { chain_id, .. } => *chain_id,
            EvmTx::Eip1559 { chain_id, .. } => *chain_id,
        }
    }

    /// Returns the sender address (already recovered and filled).
    pub fn from(&self) -> &Address20 {
        match self {
            EvmTx::Legacy { from, .. } => from,
            EvmTx::Eip2930 { from, .. } => from,
            EvmTx::Eip1559 { from, .. } => from,
        }
    }

    /// Returns the recipient address (None for contract creation).
    pub fn to(&self) -> Option<&Address20> {
        match self {
            EvmTx::Legacy { to, .. } => to.as_ref(),
            EvmTx::Eip2930 { to, .. } => to.as_ref(),
            EvmTx::Eip1559 { to, .. } => to.as_ref(),
        }
    }

    /// Returns the transaction nonce.
    pub fn nonce(&self) -> u64 {
        match self {
            EvmTx::Legacy { nonce, .. } => *nonce,
            EvmTx::Eip2930 { nonce, .. } => *nonce,
            EvmTx::Eip1559 { nonce, .. } => *nonce,
        }
    }

    /// Returns the gas limit.
    pub fn gas_limit(&self) -> u64 {
        match self {
            EvmTx::Legacy { gas_limit, .. } => *gas_limit,
            EvmTx::Eip2930 { gas_limit, .. } => *gas_limit,
            EvmTx::Eip1559 { gas_limit, .. } => *gas_limit,
        }
    }

    /// Returns the value transferred (in wei).
    pub fn value(&self) -> u128 {
        match self {
            EvmTx::Legacy { value, .. } => *value,
            EvmTx::Eip2930 { value, .. } => *value,
            EvmTx::Eip1559 { value, .. } => *value,
        }
    }

    /// Returns the call data.
    pub fn data(&self) -> &[u8] {
        match self {
            EvmTx::Legacy { data, .. } => data,
            EvmTx::Eip2930 { data, .. } => data,
            EvmTx::Eip1559 { data, .. } => data,
        }
    }

    /// Returns `true` if this is a contract creation transaction (`to` is `None`).
    pub fn is_create(&self) -> bool {
        self.to().is_none()
    }

    /// For legacy and EIP‑2930: gas price. For EIP‑1559: returns `None`.
    pub fn gas_price(&self) -> Option<u128> {
        match self {
            EvmTx::Legacy { gas_price, .. } => Some(*gas_price),
            EvmTx::Eip2930 { gas_price, .. } => Some(*gas_price),
            EvmTx::Eip1559 { .. } => None,
        }
    }

    /// For EIP‑1559: max fee per gas.
    pub fn max_fee_per_gas(&self) -> Option<u128> {
        match self {
            EvmTx::Eip1559 { max_fee_per_gas, .. } => Some(*max_fee_per_gas),
            _ => None,
        }
    }

    /// For EIP‑1559: max priority fee per gas.
    pub fn max_priority_fee_per_gas(&self) -> Option<u128> {
        match self {
            EvmTx::Eip1559 { max_priority_fee_per_gas, .. } => Some(*max_priority_fee_per_gas),
            _ => None,
        }
    }

    /// For EIP‑2930 and EIP‑1559: access list (empty for legacy).
    pub fn access_list(&self) -> &[AccessListItem] {
        match self {
            EvmTx::Legacy { .. } => &[],
            EvmTx::Eip2930 { access_list, .. } => access_list,
            EvmTx::Eip1559 { access_list, .. } => access_list,
        }
    }

    /// Validate the transaction against a given expected chain ID.
    ///
    /// Checks:
    /// - Chain ID matches.
    /// - Gas limit > 0.
    /// - Gas price > 0 (legacy/2930) or fee caps are valid (1559).
    /// - Priority fee ≤ max fee (1559).
    pub fn validate(&self, expected_chain_id: u64) -> EvmTxResult<()> {
        if self.chain_id() != expected_chain_id {
            return Err(EvmTxError::ChainIdMismatch {
                expected: expected_chain_id,
                actual: self.chain_id(),
            });
        }
        if self.gas_limit() == 0 {
            return Err(EvmTxError::ZeroGasLimit(self.gas_limit()));
        }
        match self {
            EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => {
                if *gas_price == 0 {
                    return Err(EvmTxError::ZeroGasPrice(*gas_price));
                }
            }
            EvmTx::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                if *max_fee_per_gas == 0 {
                    return Err(EvmTxError::ZeroMaxFeePerGas);
                }
                if *max_priority_fee_per_gas > *max_fee_per_gas {
                    return Err(EvmTxError::PriorityFeeExceedsMaxFee);
                }
            }
        }
        Ok(())
    }

    /// Compute the effective gas price given the block base fee (EIP‑1559).
    /// For legacy/2930 transactions, this is simply the gas price.
    pub fn effective_gas_price(&self, base_fee_per_gas: u64) -> u128 {
        match self {
            EvmTx::Legacy { gas_price, .. } | EvmTx::Eip2930 { gas_price, .. } => *gas_price,
            EvmTx::Eip1559 {
                max_fee_per_gas,
                max_priority_fee_per_gas,
                ..
            } => {
                let base = base_fee_per_gas as u128;
                let tip = (*max_priority_fee_per_gas).min(max_fee_per_gas.saturating_sub(base));
                base.saturating_add(tip).min(*max_fee_per_gas)
            }
        }
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_legacy() -> EvmTx {
        EvmTx::Legacy {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            gas_price: 10_000_000_000,
            value: 0,
            data: vec![],
            chain_id: 1,
        }
    }

    fn dummy_eip1559() -> EvmTx {
        EvmTx::Eip1559 {
            from: [0xAA; 20],
            to: Some([0xBB; 20]),
            nonce: 1,
            gas_limit: 100_000,
            max_fee_per_gas: 100_000_000_000,
            max_priority_fee_per_gas: 1_000_000_000,
            value: 0,
            data: vec![],
            access_list: vec![],
            chain_id: 1,
        }
    }

    #[test]
    fn test_validate_ok() {
        let tx = dummy_legacy();
        assert!(tx.validate(1).is_ok());
        let tx1559 = dummy_eip1559();
        assert!(tx1559.validate(1).is_ok());
    }

    #[test]
    fn test_validate_wrong_chain() {
        let tx = dummy_legacy();
        assert!(matches!(
            tx.validate(2),
            Err(EvmTxError::ChainIdMismatch { expected: 2, actual: 1 })
        ));
    }

    #[test]
    fn test_validate_zero_gas_limit() {
        let mut tx = dummy_legacy();
        if let EvmTx::Legacy { gas_limit, .. } = &mut tx {
            *gas_limit = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroGasLimit(0))));
    }

    #[test]
    fn test_validate_zero_gas_price() {
        let mut tx = dummy_legacy();
        if let EvmTx::Legacy { gas_price, .. } = &mut tx {
            *gas_price = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroGasPrice(0))));
    }

    #[test]
    fn test_validate_eip1559_fee_caps() {
        let mut tx = dummy_eip1559();
        if let EvmTx::Eip1559 { max_fee_per_gas, .. } = &mut tx {
            *max_fee_per_gas = 0;
        }
        assert!(matches!(tx.validate(1), Err(EvmTxError::ZeroMaxFeePerGas)));

        let mut tx = dummy_eip1559();
        if let EvmTx::Eip1559 {
            max_fee_per_gas,
            max_priority_fee_per_gas,
            ..
        } = &mut tx
        {
            *max_priority_fee_per_gas = *max_fee_per_gas + 1;
        }
        assert!(matches!(
            tx.validate(1),
            Err(EvmTxError::PriorityFeeExceedsMaxFee)
        ));
    }

    #[test]
    fn test_effective_gas_price_legacy() {
        let tx = dummy_legacy();
        let base = 5_000_000_000;
        assert_eq!(tx.effective_gas_price(base), 10_000_000_000);
    }

    #[test]
    fn test_effective_gas_price_eip1559() {
        let tx = dummy_eip1559();
        let base = 50_000_000_000;
        let expected = base as u128
            + tx.max_priority_fee_per_gas().unwrap().min(
                tx.max_fee_per_gas().unwrap().saturating_sub(base as u128),
            );
        assert_eq!(tx.effective_gas_price(base), expected);
    }

    #[test]
    fn test_accessors() {
        let tx = dummy_legacy();
        assert_eq!(tx.chain_id(), 1);
        assert_eq!(tx.from(), &[0xAA; 20]);
        assert_eq!(tx.to(), Some(&[0xBB; 20]));
        assert_eq!(tx.nonce(), 1);
        assert_eq!(tx.gas_limit(), 100_000);
        assert_eq!(tx.value(), 0);
        assert!(tx.data().is_empty());
        assert!(!tx.is_create());
        assert_eq!(tx.gas_price(), Some(10_000_000_000));
        assert_eq!(tx.max_fee_per_gas(), None);
        assert!(tx.access_list().is_empty());
    }
}
