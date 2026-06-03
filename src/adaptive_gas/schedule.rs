//! Gas schedule – maps VM operations to resource costs.
//!
//! Each opcode / operation has a predefined cost vector across the four
//! resource dimensions. The total gas is computed as the dot product
//! between the cost vector and the current resource prices.

use super::pricing::ResourcePrices;
use super::resource_meter::{Resource, ResourceUsage};
use std::collections::HashMap;

// -----------------------------------------------------------------------------
// Operation cost
// -----------------------------------------------------------------------------

/// Cost of a single operation across all resource dimensions.
#[derive(Debug, Clone, Copy)]
pub struct OperationCost {
    pub cpu: u64,
    pub io: u64,
    pub net: u64,
    pub storage: u64,
}

impl OperationCost {
    /// Create a new operation cost. Use `0` for dimensions not consumed.
    pub const fn new(cpu: u64, io: u64, net: u64, storage: u64) -> Self {
        Self { cpu, io, net, storage }
    }

    /// Convert to a ResourceUsage (for accumulation).
    pub fn to_usage(&self) -> ResourceUsage {
        ResourceUsage {
            cpu: self.cpu,
            io: self.io,
            net: self.net,
            storage: self.storage,
        }
    }

    /// Compute the gas cost given current resource prices.
    pub fn gas_cost(&self, prices: &ResourcePrices) -> u64 {
        self.cpu.saturating_mul(prices.cpu)
            .saturating_add(self.io.saturating_mul(prices.io))
            .saturating_add(self.net.saturating_mul(prices.net))
            .saturating_add(self.storage.saturating_mul(prices.storage))
    }
}

// -----------------------------------------------------------------------------
// Gas schedule
// -----------------------------------------------------------------------------

/// Holds predefined costs for all VM operations.
#[derive(Debug, Clone)]
pub struct GasSchedule {
    costs: HashMap<String, OperationCost>,
}

impl GasSchedule {
    /// Create a new schedule with default EVM‑compatible costs.
    pub fn new() -> Self {
        let mut costs = HashMap::new();

        // ---- Arithmetic ----
        costs.insert("ADD".into(), OperationCost::new(3, 0, 0, 0));
        costs.insert("MUL".into(), OperationCost::new(5, 0, 0, 0));
        costs.insert("SUB".into(), OperationCost::new(3, 0, 0, 0));
        costs.insert("DIV".into(), OperationCost::new(5, 0, 0, 0));
        costs.insert("MOD".into(), OperationCost::new(5, 0, 0, 0));
        costs.insert("EXP".into(), OperationCost::new(10, 0, 0, 0));

        // ---- Memory ----
        costs.insert("MLOAD".into(), OperationCost::new(3, 0, 0, 0));
        costs.insert("MSTORE".into(), OperationCost::new(3, 0, 0, 0));
        costs.insert("MSTORE8".into(), OperationCost::new(3, 0, 0, 0));

        // ---- Storage (IO + persistent) ----
        costs.insert("SLOAD".into(), OperationCost::new(0, 100, 0, 0));
        costs.insert("SSTORE".into(), OperationCost::new(0, 200, 0, 100));

        // ---- Control flow ----
        costs.insert("JUMP".into(), OperationCost::new(8, 0, 0, 0));
        costs.insert("JUMPI".into(), OperationCost::new(10, 0, 0, 0));
        costs.insert("PC".into(), OperationCost::new(2, 0, 0, 0));

        // ---- Environment ----
        costs.insert("BALANCE".into(), OperationCost::new(0, 100, 0, 0));
        costs.insert("CALLER".into(), OperationCost::new(2, 0, 0, 0));

        // ---- Network (calldata, logs) ----
        costs.insert("CALLDATALOAD".into(), OperationCost::new(3, 0, 0, 0));
        costs.insert("LOG0".into(), OperationCost::new(0, 0, 375, 0));
        costs.insert("LOG1".into(), OperationCost::new(0, 0, 750, 0));
        costs.insert("LOG2".into(), OperationCost::new(0, 0, 1125, 0));
        costs.insert("LOG3".into(), OperationCost::new(0, 0, 1500, 0));
        costs.insert("LOG4".into(), OperationCost::new(0, 0, 1875, 0));

        // ---- System ----
        costs.insert("CREATE".into(), OperationCost::new(32000, 0, 0, 200));
        costs.insert("CALL".into(), OperationCost::new(700, 0, 0, 0));
        costs.insert("RETURN".into(), OperationCost::new(0, 0, 0, 0));
        costs.insert("REVERT".into(), OperationCost::new(0, 0, 0, 0));

        Self { costs }
    }

    /// Look up the cost of an operation by name.
    pub fn get(&self, op: &str) -> Option<&OperationCost> {
        self.costs.get(op)
    }

    /// Compute the gas cost for an operation given current prices.
    pub fn gas_cost(&self, op: &str, prices: &ResourcePrices) -> Option<u64> {
        self.get(op).map(|c| c.gas_cost(prices))
    }

    /// Total number of defined operations.
    pub fn len(&self) -> usize {
        self.costs.len()
    }
}

impl Default for GasSchedule {
    fn default() -> Self {
        Self::new()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schedule_lookup() {
        let schedule = GasSchedule::new();
        let add = schedule.get("ADD").unwrap();
        assert_eq!(add.cpu, 3);
        let prices = ResourcePrices::default();
        let gas = schedule.gas_cost("ADD", &prices).unwrap();
        assert_eq!(gas, 3 * prices.cpu);
    }

    #[test]
    fn test_missing_opcode() {
        let schedule = GasSchedule::new();
        assert!(schedule.get("MISSING").is_none());
    }
}
