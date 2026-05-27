//! EVM primitive types re‑exported from `revm::primitives`.
//!
//! This module provides the core types used by the EVM integration,
//! re‑exported from the `revm` crate for convenience, along with
//! additional helper functions and constants.
//!
//! # Example
//!
//! ```
//! use iona::evm::types::{Address, U256, B256, Bytes, ZERO_ADDRESS, hex_to_address};
//!
//! let addr = ZERO_ADDRESS;
//! let value = U256::from(1_000_000);
//! let hash = B256::zero();
//! let data = Bytes::from(vec![0x60, 0x00]);
//!
//! // Convert hex string to address
//! let addr = hex_to_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28").unwrap();
//! ```

use revm::primitives::{Address, Bytes, B256, U256};
use std::str::FromStr;

// -----------------------------------------------------------------------------
// Core re‑exports
// -----------------------------------------------------------------------------

pub use revm::primitives::{
    // Core types
    Address, Bytes, B256, U256,
    // Environment types
    BlockEnv, CfgEnv, Env, ExecutionResult, Log, Output, TxEnv,
    // Transaction types
    TransactTo,
    // Gas constants
    GAS_REFUND_DENOMINATOR, GAS_REFUND_NUMERATOR,
};

// -----------------------------------------------------------------------------
// Convenience constants
// -----------------------------------------------------------------------------

/// Zero address (all zeroes, 20 bytes).
pub const ZERO_ADDRESS: Address = Address::new([0u8; 20]);

/// Empty byte array.
pub const EMPTY_BYTES: Bytes = Bytes::new();

/// Zero hash (32 bytes of zeroes).
pub const ZERO_HASH: B256 = B256::new([0u8; 32]);

/// One as U256.
pub const U256_ONE: U256 = U256::from(1);

/// Zero as U256.
pub const U256_ZERO: U256 = U256::ZERO;

// -----------------------------------------------------------------------------
// Helper functions
// -----------------------------------------------------------------------------

/// Convert a hex string (with or without `0x` prefix) to an `Address`.
///
/// # Arguments
/// * `s` – Hex string, e.g., `"0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28"`
///
/// # Returns
/// `Ok(Address)` if the string is valid and exactly 40 hex characters (20 bytes),
/// otherwise `Err(String)`.
///
/// # Example
/// ```
/// use iona::evm::types::hex_to_address;
///
/// let addr = hex_to_address("0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28").unwrap();
/// ```
pub fn hex_to_address(s: &str) -> Result<Address, String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 40 {
        return Err(format!("invalid address length: expected 40 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    Ok(Address::from_slice(&bytes))
}

/// Convert an `Address` to a hex string with `0x` prefix.
///
/// # Example
/// ```
/// use iona::evm::types::{Address, address_to_hex};
///
/// let addr = Address::new([0xAB; 20]);
/// let hex = address_to_hex(&addr);
/// assert!(hex.starts_with("0x"));
/// ```
pub fn address_to_hex(addr: &Address) -> String {
    format!("0x{}", hex::encode(addr.as_slice()))
}

/// Convert a hex string (with or without `0x` prefix) to `B256` (32 bytes).
///
/// # Arguments
/// * `s` – Hex string, e.g., `"0x1234..."`
///
/// # Returns
/// `Ok(B256)` if the string is valid and exactly 64 hex characters (32 bytes).
pub fn hex_to_b256(s: &str) -> Result<B256, String> {
    let s = s.trim_start_matches("0x");
    if s.len() != 64 {
        return Err(format!("invalid hash length: expected 64 hex chars, got {}", s.len()));
    }
    let bytes = hex::decode(s).map_err(|e| format!("invalid hex: {}", e))?;
    Ok(B256::from_slice(&bytes))
}

/// Convert a `B256` to a hex string with `0x` prefix.
pub fn b256_to_hex(hash: &B256) -> String {
    format!("0x{}", hex::encode(hash.as_bytes()))
}

/// Convert a `U256` to a hex string with `0x` prefix.
pub fn u256_to_hex(value: &U256) -> String {
    format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
}

/// Convert a hex string to `U256`.
pub fn hex_to_u256(s: &str) -> Result<U256, String> {
    let s = s.trim_start_matches("0x");
    U256::from_str(s).map_err(|e| format!("invalid U256: {}", e))
}

/// Check if an address is zero.
pub fn is_zero_address(addr: &Address) -> bool {
    *addr == ZERO_ADDRESS
}

/// Check if a hash is zero.
pub fn is_zero_hash(hash: &B256) -> bool {
    *hash == ZERO_HASH
}

// -----------------------------------------------------------------------------
// Formatting helpers (for logging)
// -----------------------------------------------------------------------------

/// Format an address for logging (shortened).
pub fn fmt_address(addr: &Address) -> String {
    let hex = hex::encode(&addr.as_slice()[..4]);
    format!("0x{}...", hex)
}

/// Format a hash for logging (shortened).
pub fn fmt_hash(hash: &B256) -> String {
    let hex = hex::encode(&hash.as_bytes()[..4]);
    format!("0x{}...", hex)
}

/// Format a U256 for logging (shortened).
pub fn fmt_u256(value: &U256) -> String {
    if *value < U256::from(1_000_000) {
        format!("{}", value)
    } else {
        format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zero_address() {
        let addr = ZERO_ADDRESS;
        assert_eq!(addr.as_slice(), &[0u8; 20]);
        assert!(is_zero_address(&addr));
    }

    #[test]
    fn test_empty_bytes() {
        assert!(EMPTY_BYTES.is_empty());
    }

    #[test]
    fn test_zero_hash() {
        let hash = ZERO_HASH;
        assert_eq!(hash.as_bytes(), &[0u8; 32]);
        assert!(is_zero_hash(&hash));
    }

    #[test]
    fn test_hex_to_address() {
        let hex = "0x742d35Cc6634C0532925a3b844Bc9e7595f2bD28";
        let addr = hex_to_address(hex).unwrap();
        assert_eq!(address_to_hex(&addr).to_lowercase(), hex.to_lowercase());
    }

    #[test]
    fn test_hex_to_address_no_prefix() {
        let hex = "742d35Cc6634C0532925a3b844Bc9e7595f2bD28";
        let addr = hex_to_address(hex).unwrap();
        assert_eq!(address_to_hex(&addr).to_lowercase(), format!("0x{}", hex.to_lowercase()));
    }

    #[test]
    fn test_hex_to_address_invalid_length() {
        assert!(hex_to_address("0x1234").is_err());
    }

    #[test]
    fn test_hex_to_b256() {
        let hex = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        let hash = hex_to_b256(hex).unwrap();
        assert_eq!(b256_to_hex(&hash).to_lowercase(), hex.to_lowercase());
    }

    #[test]
    fn test_u256_conversion() {
        let value = U256::from(42);
        let hex = u256_to_hex(&value);
        assert_eq!(hex_to_u256(&hex).unwrap(), value);
    }

    #[test]
    fn test_fmt_address() {
        let addr = Address::new([0xAB; 20]);
        let fmt = fmt_address(&addr);
        assert!(fmt.starts_with("0x"));
        assert!(fmt.len() <= 10);
    }

    #[test]
    fn test_fmt_hash() {
        let hash = B256::new([0xCD; 32]);
        let fmt = fmt_hash(&hash);
        assert!(fmt.starts_with("0x"));
        assert!(fmt.len() <= 10);
    }
}
