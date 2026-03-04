//! Gas meter for the IONA VM.

#[derive(Debug, Clone, Copy)]
pub struct GasMeter {
    pub limit: u64,
    pub used:  u64,
}

impl GasMeter {
    pub fn new(limit: u64) -> Self {
        Self { limit, used: 0 }
    }

    /// Charge `amount` gas. Returns Err if limit exceeded.
    pub fn charge(&mut self, amount: u64) -> Result<(), ()> {
        let new = self.used.saturating_add(amount);
        if new > self.limit {
            self.used = self.limit;
            return Err(());
        }
        self.used = new;
        Ok(())
    }

    /// Gas remaining.
    pub fn remaining(&self) -> u64 {
        self.limit.saturating_sub(self.used)
    }

    /// Fraction of gas used (0.0 – 1.0).
    pub fn fraction_used(&self) -> f64 {
        if self.limit == 0 { return 1.0; }
        self.used as f64 / self.limit as f64
    }
}

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
        assert!(g.charge(60).is_err()); // 50 + 60 > 100
    }

    #[test]
    fn test_exact_limit() {
        let mut g = GasMeter::new(100);
        assert!(g.charge(100).is_ok());
        assert_eq!(g.remaining(), 0);
        assert!(g.charge(1).is_err());
    }
}
