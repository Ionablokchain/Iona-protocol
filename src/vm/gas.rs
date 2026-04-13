//! Gas meter for the IONA VM.
//!
//! Tracks gas consumption during execution, supports refunds,
//! and provides helpers for memory expansion costs.

use thiserror::Error;

// -----------------------------------------------------------------------------
// Gas error
// -----------------------------------------------------------------------------

/// Errors that can occur during gas metering.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum GasError {
    /// Insufficient gas to perform the operation.
    #[error("out of gas: needed {needed}, remaining {remaining}")]
    OutOfGas { needed: u64, remaining: u64 },
    /// Refund would exceed the maximum allowed (should not happen).
    #[error("refund overflow: attempted to refund {amount}, current refund {current}")]
    RefundOverflow { amount: u64, current: u64 },
}

// -----------------------------------------------------------------------------
// Gas meter
// -----------------------------------------------------------------------------

/// Gas meter tracks consumption and refunds during VM execution.
#[derive(Debug, Clone, Copy)]
pub struct GasMeter {
    /// Maximum gas allowed for the transaction.
    pub limit: u64,
    /// Gas used so far.
    pub used: u64,
    /// Gas to be refunded after execution (max half of used).
    pub refund: u64,
}

impl GasMeter {
    /// Create a new gas meter with the given limit.
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            refund: 0,
        }
    }

    /// Charge `amount` gas. Returns `Err` if limit would be exceeded.
    pub fn charge(&mut self, amount: u64) -> Result<(), GasError> {
        let new_used = self.used.saturating_add(amount);
        if new_used > self.limit {
            return Err(GasError::OutOfGas {
                needed: amount,
                remaining: self.remaining(),
            });
        }
        self.used = new_used;
        Ok(())
    }

    /// Add a refund amount (e.g., for clearing storage).
    /// The refund is capped at half of the gas used (EIP-3529).
    pub fn add_refund(&mut self, amount: u64) -> Result<(), GasError> {
        let new_refund = self.refund.saturating_add(amount);
        let max_refund = self.used / 2;
        if new_refund > max_refund {
            return Err(GasError::RefundOverflow {
                amount,
                current: self.refund,
            });
        }
        self.refund = new_refund;
        Ok(())
    }

    /// Apply the refund, reducing gas used.
    /// Returns the net gas used after refund.
    pub fn apply_refund(&mut self) -> u64 {
        let refund = std::cmp::min(self.refund, self.used);
        self.used -= refund;
        self.refund = 0;
        self.used
    }

    /// Gas remaining.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Fraction of gas used (0.0 – 1.0).
    pub fn fraction_used(&self) -> f64 {
        if self.limit == 0 {
            return 1.0;
        }
        self.used as f64 / self.limit as f64
    }

    /// Check if there is enough gas for an operation without charging.
    pub fn can_charge(&self, amount: u64) -> bool {
        self.used.saturating_add(amount) <= self.limit
    }

    /// Charge for memory expansion.
    ///
    /// `current_words` – current memory size in 32‑byte words.
    /// `new_words` – new memory size in 32‑byte words.
    /// Returns the additional gas cost (3 gas per word).
    pub fn charge_memory_expansion(&mut self, current_words: usize, new_words: usize) -> Result<u64, GasError> {
        if new_words <= current_words {
            return Ok(0);
        }
        let additional = (new_words - current_words) as u64;
        let cost = additional * 3;
        self.charge(cost)?;
        Ok(cost)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_charge_ok() {
        let mut g = GasMeter::new(1000);
        assert!(g.charge(500).is_ok());
        assert_eq!(g.used, 500);
        assert_eq!(g.remaining(), 500);
    }

    #[test]
    fn test_charge_exceeds_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(50).is_ok());
        let err = g.charge(60).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { needed: 60, remaining: 50 }));
        assert_eq!(g.used, 100); // used becomes limit
        assert_eq!(g.remaining(), 0);
    }

    #[test]
    fn test_exact_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(100).is_ok());
        assert_eq!(g.remaining(), 0);
        let err = g.charge(1).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
    }

    #[test]
    fn test_refund_within_limit() {
        let mut g = GasMeter::new(1000);
        g.charge(500).unwrap();
        assert!(g.add_refund(100).is_ok());
        assert_eq!(g.refund, 100);
        let net = g.apply_refund();
        assert_eq!(net, 400);
        assert_eq!(g.used, 400);
        assert_eq!(g.refund, 0);
    }

    #[test]
    fn test_refund_capped_at_half_used() {
        let mut g = GasMeter::new(1000);
        g.charge(200).unwrap();
        // Max refund = 100
        assert!(g.add_refund(80).is_ok());
        let err = g.add_refund(30).unwrap_err();
        assert!(matches!(err, GasError::RefundOverflow { amount: 30, current: 80 }));
        assert_eq!(g.refund, 80);
    }

    #[test]
    fn test_memory_expansion() {
        let mut g = GasMeter::new(1000);
        let cost = g.charge_memory_expansion(0, 10).unwrap();
        assert_eq!(cost, 30); // 10 words * 3
        assert_eq!(g.used, 30);

        // No expansion
        let cost = g.charge_memory_expansion(10, 10).unwrap();
        assert_eq!(cost, 0);
        assert_eq!(g.used, 30);
    }

    #[test]
    fn test_memory_expansion_insufficient_gas() {
        let mut g = GasMeter::new(10);
        let err = g.charge_memory_expansion(0, 10).unwrap_err();
        assert!(matches!(err, GasError::OutOfGas { .. }));
    }

    #[test]
    fn test_can_charge() {
        let g = GasMeter::new(100);
        assert!(g.can_charge(50));
        assert!(g.can_charge(100));
        assert!(!g.can_charge(101));
    }

    #[test]
    fn test_fraction_used() {
        let mut g = GasMeter::new(200);
        assert_eq!(g.fraction_used(), 0.0);
        g.charge(50).unwrap();
        assert!((g.fraction_used() - 0.25).abs() < f64::EPSILON);
        g.charge(150).unwrap();
        assert!((g.fraction_used() - 1.0).abs() < f64::EPSILON);
    }
}
