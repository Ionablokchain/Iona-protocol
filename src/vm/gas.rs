//! Gas meter for the IONA VM.
//!
//! Tracks gas consumption during execution, supports refunds,
//! and provides helpers for memory expansion costs.
//!
//! # Design
//!
//! - Gas consumption is **monotonic** — `used` never decreases during
//!   execution (refunds are applied only at the end via [`apply_refund`]).
//! - Refunds are capped at **half of gas used** per EIP-3529, preventing
//!   refund abuse while still incentivizing state cleanup.
//! - Memory expansion cost follows the Ethereum formula: `3 gas per word`
//!   plus a quadratic term for large expansions (EIP-150).
//!
//! # Example
//!
//! ```
//! use iona::vm::gas::{GasMeter, GasError};
//!
//! let mut meter = GasMeter::new(1000);
//! meter.charge(500)?;
//! meter.add_refund(100)?;
//! let net_used = meter.apply_refund();
//! assert_eq!(net_used, 400);
//! # Ok::<(), GasError>(())
//! ```

use thiserror::Error;

// -----------------------------------------------------------------------------
// Constants
// -----------------------------------------------------------------------------

/// Base gas cost per memory word (32 bytes).
pub const MEMORY_WORD_GAS: u64 = 3;

/// Minimum gas for any transaction (covers base overhead).
pub const MINIMUM_GAS: u64 = 21_000;

/// Maximum gas allowed in a single block (adjust per chain config).
pub const MAX_BLOCK_GAS: u64 = 30_000_000;

// -----------------------------------------------------------------------------
// Gas error
// -----------------------------------------------------------------------------

/// Errors that can occur during gas metering.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GasError {
    /// Insufficient gas to perform the operation.
    #[error("out of gas: needed {needed}, remaining {remaining}")]
    OutOfGas { needed: u64, remaining: u64 },

    /// Refund would exceed the maximum allowed (capped at half of gas used).
    #[error("refund capped: attempted {attempted}, current refund {current}, max allowed {max_allowed}")]
    RefundCapped {
        attempted: u64,
        current: u64,
        max_allowed: u64,
    },

    /// Gas limit exceeds block gas limit.
    #[error("gas limit {limit} exceeds block gas limit {block_limit}")]
    GasLimitTooHigh { limit: u64, block_limit: u64 },

    /// Gas limit below the minimum required.
    #[error("gas limit {limit} below minimum {minimum}")]
    GasLimitTooLow { limit: u64, minimum: u64 },

    /// Arithmetic overflow in gas calculation (should never happen).
    #[error("gas calculation overflow")]
    Overflow,
}

// -----------------------------------------------------------------------------
// Gas meter
// -----------------------------------------------------------------------------

/// Gas meter tracks consumption and refunds during VM execution.
///
/// The meter enforces that gas usage never exceeds the specified limit.
/// Refunds are accumulated separately and applied only at the end of
/// execution via [`apply_refund`], ensuring that execution never sees
/// a decreasing gas balance.
#[derive(Debug, Clone, Copy)]
pub struct GasMeter {
    /// Maximum gas allowed for this execution context.
    limit: u64,
    /// Gas consumed so far (monotonically increasing).
    used: u64,
    /// Gas to be refunded after execution (capped at `used / 2`).
    refund: u64,
}

impl GasMeter {
    /// Creates a new gas meter with the given limit.
    ///
    /// # Panics
    /// Panics in debug mode if `limit` is 0 or exceeds `MAX_BLOCK_GAS`.
    /// In release mode, the limit is silently clamped.
    pub fn new(limit: u64) -> Self {
        debug_assert!(limit > 0, "Gas limit must be > 0");
        debug_assert!(
            limit <= MAX_BLOCK_GAS,
            "Gas limit {limit} exceeds block limit {MAX_BLOCK_GAS}"
        );
        Self {
            limit: limit.min(MAX_BLOCK_GAS).max(1),
            used: 0,
            refund: 0,
        }
    }

    /// Creates a gas meter from a block context, validating the limit.
    pub fn new_with_validation(limit: u64, block_gas_limit: u64) -> Result<Self, GasError> {
        if limit < MINIMUM_GAS {
            return Err(GasError::GasLimitTooLow {
                limit,
                minimum: MINIMUM_GAS,
            });
        }
        if limit > block_gas_limit {
            return Err(GasError::GasLimitTooHigh {
                limit,
                block_limit: block_gas_limit,
            });
        }
        Ok(Self {
            limit,
            used: 0,
            refund: 0,
        })
    }

    // ── Getters ─────────────────────────────────────────────────────────

    /// Returns the gas limit.
    #[inline]
    pub fn limit(&self) -> u64 {
        self.limit
    }

    /// Returns the gas used so far.
    #[inline]
    pub fn used(&self) -> u64 {
        self.used
    }

    /// Returns the current refundable gas (before applying).
    #[inline]
    pub fn refundable(&self) -> u64 {
        self.refund
    }

    /// Returns the remaining gas.
    #[inline]
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Returns the maximum refund allowed under current usage (half of used).
    #[inline]
    pub fn max_refund_allowed(&self) -> u64 {
        self.used / 2
    }

    /// Returns the fraction of gas used (0.0 – 1.0).
    #[inline]
    pub fn fraction_used(&self) -> f64 {
        if self.limit == 0 {
            return 1.0;
        }
        (self.used as f64 / self.limit as f64).min(1.0)
    }

    /// Returns the net gas used after applying the refund (without mutating).
    #[inline]
    pub fn net_used(&self) -> u64 {
        let effective_refund = self.refund.min(self.used);
        self.used.saturating_sub(effective_refund)
    }

    // ── Charging ────────────────────────────────────────────────────────

    /// Charges `amount` gas.
    ///
    /// Returns `Err(OutOfGas)` if the charge would exceed the limit.
    /// On failure, `used` is set to `limit` (gas is fully consumed).
    #[inline]
    pub fn charge(&mut self, amount: u64) -> Result<(), GasError> {
        let new_used = self
            .used
            .checked_add(amount)
            .ok_or(GasError::Overflow)?;

        if new_used > self.limit {
            self.used = self.limit; // consume all remaining gas
            return Err(GasError::OutOfGas {
                needed: amount,
                remaining: self.limit.saturating_sub(self.used),
            });
        }

        self.used = new_used;
        Ok(())
    }

    /// Checks if `amount` gas can be charged without actually charging.
    #[inline]
    pub fn can_charge(&self, amount: u64) -> bool {
        self.used.saturating_add(amount) <= self.limit
    }

    /// Charges gas only if `condition` is true (e.g., for conditional costs).
    ///
    /// Returns `Ok(charged_amount)` on success, where `charged_amount` is
    /// 0 if the condition was false, or `amount` if the charge succeeded.
    #[inline]
    pub fn charge_if(&mut self, condition: bool, amount: u64) -> Result<u64, GasError> {
        if condition {
            self.charge(amount)?;
            Ok(amount)
        } else {
            Ok(0)
        }
    }

    // ── Refunds ─────────────────────────────────────────────────────────

    /// Adds a refund amount (e.g., for clearing storage slots).
    ///
    /// The total refund is capped at `used / 2` per EIP-3529. If the
    /// refund would exceed the cap, the amount is silently reduced to
    /// the maximum allowed. This matches the Ethereum behaviour where
    /// refunds are clamped rather than rejected.
    #[inline]
    pub fn add_refund(&mut self, amount: u64) -> Result<(), GasError> {
        if amount == 0 {
            return Ok(());
        }

        let new_refund = self
            .refund
            .checked_add(amount)
            .ok_or(GasError::Overflow)?;

        let max_refund = self.max_refund_allowed();
        if new_refund > max_refund {
            // Clamp to max rather than failing
            self.refund = max_refund;
        } else {
            self.refund = new_refund;
        }

        Ok(())
    }

    /// Applies the refund, reducing `used` gas.
    ///
    /// Returns the net gas used after the refund.
    /// This should be called exactly once, at the end of execution.
    #[inline]
    pub fn apply_refund(&mut self) -> u64 {
        let effective_refund = self.refund.min(self.used);
        self.used = self.used.saturating_sub(effective_refund);
        self.refund = 0;
        self.used
    }

    // ── Memory expansion ────────────────────────────────────────────────

    /// Charges gas for memory expansion.
    ///
    /// Computes the cost of expanding memory from `current_words` to
    /// `new_words` (both in 32‑byte words). Uses the Ethereum formula:
    ///
    /// ```text
    /// memory_cost(word) = 3 * word + floor(word^2 / 512)
    /// ```
    ///
    /// Only the *additional* cost (new minus current) is charged.
    ///
    /// Returns the gas cost charged, or `Err` if insufficient gas.
    #[inline]
    pub fn charge_memory_expansion(
        &mut self,
        current_words: usize,
        new_words: usize,
    ) -> Result<u64, GasError> {
        if new_words <= current_words {
            return Ok(0);
        }

        let current_cost = memory_cost_words(current_words);
        let new_cost = memory_cost_words(new_words);
        let additional = new_cost
            .checked_sub(current_cost)
            .ok_or(GasError::Overflow)?;

        if additional > 0 {
            self.charge(additional)?;
        }

        Ok(additional)
    }
}

// -----------------------------------------------------------------------------
// Memory cost function
// -----------------------------------------------------------------------------

/// Computes the gas cost for `words` of memory (EIP-150 quadratic formula).
///
/// ```text
/// Cmem(w) = 3 * w + floor(w^2 / 512)
/// ```
#[inline]
pub fn memory_cost_words(words: usize) -> u64 {
    let w = words as u64;
    // 3 * w + w^2 / 512
    let linear = w.saturating_mul(3);
    let quadratic = w.saturating_mul(w).saturating_div(512);
    linear.saturating_add(quadratic)
}

/// Computes the gas cost for `bytes` of memory, rounding up to the next word.
#[inline]
pub fn memory_cost_bytes(bytes: usize) -> u64 {
    let words = (bytes + 31) / 32;
    memory_cost_words(words)
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Constructor tests ───────────────────────────────────────────────
    #[test]
    fn test_new_normal() {
        let g = GasMeter::new(1000);
        assert_eq!(g.limit(), 1000);
        assert_eq!(g.used(), 0);
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn test_new_zero_clamped() {
        let g = GasMeter::new(0);
        assert_eq!(g.limit(), 1); // clamped to minimum
    }

    #[test]
    fn test_new_exceeds_block_limit() {
        let g = GasMeter::new(MAX_BLOCK_GAS + 1);
        assert_eq!(g.limit(), MAX_BLOCK_GAS);
    }

    #[test]
    fn test_new_with_validation() {
        let g = GasMeter::new_with_validation(50_000, MAX_BLOCK_GAS).unwrap();
        assert_eq!(g.limit(), 50_000);
    }

    #[test]
    fn test_new_with_validation_too_low() {
        let err = GasMeter::new_with_validation(100, MAX_BLOCK_GAS).unwrap_err();
        assert!(matches!(err, GasError::GasLimitTooLow { .. }));
    }

    #[test]
    fn test_new_with_validation_too_high() {
        let err = GasMeter::new_with_validation(MAX_BLOCK_GAS + 1, MAX_BLOCK_GAS).unwrap_err();
        assert!(matches!(err, GasError::GasLimitTooHigh { .. }));
    }

    // ── Charge tests ────────────────────────────────────────────────────
    #[test]
    fn test_charge_ok() {
        let mut g = GasMeter::new(1000);
        assert!(g.charge(500).is_ok());
        assert_eq!(g.used(), 500);
        assert_eq!(g.remaining(), 500);
    }

    #[test]
    fn test_charge_exact_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(100).is_ok());
        assert_eq!(g.remaining(), 0);
        let err = g.charge(1).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
        assert_eq!(g.used(), 100); // saturated at limit
    }

    #[test]
    fn test_charge_exceeds_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(50).is_ok());
        let err = g.charge(60).unwrap_err();
        assert!(matches!(
            err,
            GasError::OutOfGas { needed: 60, remaining: 50 }
        ));
    }

    #[test]
    fn test_charge_overflow() {
        let mut g = GasMeter::new(u64::MAX);
        g.charge(1).unwrap();
        let err = g.charge(u64::MAX).unwrap_err();
        assert!(matches!(err, GasError::Overflow));
    }

    #[test]
    fn test_charge_if() {
        let mut g = GasMeter::new(100);
        let cost = g.charge_if(true, 30).unwrap();
        assert_eq!(cost, 30);
        let cost = g.charge_if(false, 70).unwrap();
        assert_eq!(cost, 0);
        assert_eq!(g.used(), 30);
    }

    #[test]
    fn test_can_charge() {
        let g = GasMeter::new(100);
        assert!(g.can_charge(50));
        assert!(g.can_charge(100));
        assert!(!g.can_charge(101));
    }

    // ── Refund tests ────────────────────────────────────────────────────
    #[test]
    fn test_refund_basic() {
        let mut g = GasMeter::new(1000);
        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        assert_eq!(g.refundable(), 100);
        assert_eq!(g.max_refund_allowed(), 250);
        let net = g.apply_refund();
        assert_eq!(net, 400);
        assert_eq!(g.used(), 400);
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn test_refund_capped_at_half_used() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        // max refund = 100
        g.add_refund(80).unwrap();
        g.add_refund(50).unwrap(); // would be 130, but capped at 100
        assert_eq!(g.refundable(), 100); // silently clamped
    }

    #[test]
    fn test_refund_zero_amount() {
        let mut g = GasMeter::new(1000);
        g.charge(100).unwrap();
        g.add_refund(0).unwrap();
        assert_eq!(g.refundable(), 0);
    }

    #[test]
    fn test_refund_overflow() {
        let mut g = GasMeter::new(1000);
        g.charge(100).unwrap();
        g.refund = u64::MAX; // simulate corruption
        let err = g.add_refund(1).unwrap_err();
        assert!(matches!(err, GasError::Overflow));
    }

    #[test]
    fn test_net_used() {
        let mut g = GasMeter::new(1000);
        g.charge(500).unwrap();
        g.add_refund(100).unwrap();
        assert_eq!(g.net_used(), 400);
        // State unchanged
        assert_eq!(g.used(), 500);
        assert_eq!(g.refundable(), 100);
    }

    #[test]
    fn test_apply_refund_zero() {
        let mut g = GasMeter::new(1000);
        g.charge(300).unwrap();
        let net = g.apply_refund();
        assert_eq!(net, 300);
    }

    // ── Memory expansion tests ──────────────────────────────────────────
    #[test]
    fn test_memory_cost_words() {
        assert_eq!(memory_cost_words(0), 0);
        assert_eq!(memory_cost_words(1), 3);
        assert_eq!(memory_cost_words(10), 30);
        assert_eq!(memory_cost_words(100), 3 * 100 + 10000 / 512);
    }

    #[test]
    fn test_memory_cost_bytes() {
        assert_eq!(memory_cost_bytes(0), 0);
        assert_eq!(memory_cost_bytes(32), 3);
        assert_eq!(memory_cost_bytes(33), memory_cost_words(2)); // rounds up
    }

    #[test]
    fn test_charge_memory_expansion() {
        let mut g = GasMeter::new(1000);
        let cost = g.charge_memory_expansion(0, 10).unwrap();
        assert_eq!(cost, memory_cost_words(10));
        assert_eq!(g.used(), memory_cost_words(10));
    }

    #[test]
    fn test_charge_memory_no_expansion() {
        let mut g = GasMeter::new(1000);
        let cost = g.charge_memory_expansion(10, 10).unwrap();
        assert_eq!(cost, 0);
        let cost = g.charge_memory_expansion(10, 5).unwrap();
        assert_eq!(cost, 0);
    }

    #[test]
    fn test_charge_memory_insufficient_gas() {
        let mut g = GasMeter::new(10);
        let err = g.charge_memory_expansion(0, 100).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
    }

    // ── Fraction tests ──────────────────────────────────────────────────
    #[test]
    fn test_fraction_used() {
        let mut g = GasMeter::new(200);
        assert!((g.fraction_used() - 0.0).abs() < f64::EPSILON);
        g.charge(50).unwrap();
        assert!((g.fraction_used() - 0.25).abs() < f64::EPSILON);
        g.charge(150).unwrap();
        assert!((g.fraction_used() - 1.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_fraction_used_zero_limit() {
        let mut g = GasMeter::new(0);
        assert!((g.fraction_used() - 1.0).abs() < f64::EPSILON);
    }

    // ── Getters ─────────────────────────────────────────────────────────
    #[test]
    fn test_getters() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        g.add_refund(50).unwrap();

        assert_eq!(g.limit(), 1000);
        assert_eq!(g.used(), 200);
        assert_eq!(g.refundable(), 50);
        assert_eq!(g.remaining(), 800);
        assert_eq!(g.max_refund_allowed(), 100);
        assert_eq!(g.net_used(), 150);
    }

    #[test]
    fn test_integration_flow() {
        // Simulate a full execution
        let mut g = GasMeter::new(100_000);

        // Base transaction cost
        g.charge(21_000).unwrap();

        // Memory expansion
        g.charge_memory_expansion(0, 100).unwrap();

        // Storage operations
        g.charge(5_000).unwrap(); // SSTORE
        g.add_refund(15_000).unwrap(); // clearing storage

        // Arithmetic
        g.charge(3).unwrap();

        let net = g.apply_refund();
        assert!(net > 0);
        assert_eq!(g.refundable(), 0);
    }
}
