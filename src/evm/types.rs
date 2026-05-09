//! EVM primitive types re‑exported from `revm::primitives`.
//!
//! This module provides the core types used by the EVM integration,
//! re‑exported from the `revm` crate for convenience.
//!
//! # Example
//!
//! ```
//! use iona::evm::types::{Address, U256, B256, Bytes};
//!
//! let addr = Address::new([0u8; 20]);
//! let value = U256::from(1_000_000);
//! ```

pub use revm::primitives::{Address, Bytes, B256, U256};

// -----------------------------------------------------------------------------
// Constants (additional for convenience)
// -----------------------------------------------------------------------------

/// Zero address (all zeroes).
pub const ZERO_ADDRESS: Address = Address::new([0u8; 20]);

/// Empty bytes.
pub const EMPTY_BYTES: Bytes = Bytes::new();

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
    }

    #[test]
    fn test_empty_bytes() {
        assert!(EMPTY_BYTES.is_empty());
    }
}
