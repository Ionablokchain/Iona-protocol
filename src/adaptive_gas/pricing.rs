//! Multi-dimensional gas pricing with EIP-1559 per dimension.
use serde::{Deserialize, Serialize};
use crate::adaptive_gas::resource_meter::ResourceUsage;

/// Per-resource base fees (adjusted each block like EIP-1559).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceBaseFees {
    pub cpu_per_op:       u64,   // gwei per CPU op
    pub io_read_per_op:   u64,   // gwei per storage read
    pub io_write_per_op:  u64,   // gwei per storage write
    pub network_per_byte: u64,   // gwei per network byte
    pub memory_per_kb:    u64,   // gwei per KB memory
    pub precompile_per_op: u64,  // gwei per precompile op
}

impl Default for ResourceBaseFees {
    fn default() -> Self {
        Self {
            cpu_per_op:        1,
            io_read_per_op:    100,
            io_write_per_op:   2_000,
            network_per_byte:  1,
            memory_per_kb:     10,
            precompile_per_op: 10,
        }
    }
}

impl ResourceBaseFees {
    /// Calculate the total fee for a transaction's resource usage.
    pub fn calculate_fee(&self, usage: &ResourceUsage) -> u64 {
        let cpu    = usage.cpu_ops        * self.cpu_per_op;
        let io_r   = usage.io_reads       * self.io_read_per_op;
        let io_w   = usage.io_writes      * self.io_write_per_op;
        let net    = usage.network_bytes  * self.network_per_byte;
        let mem    = (usage.memory_bytes / 1024).saturating_add(1) * self.memory_per_kb;
        let pre    = usage.precompile_ops * self.precompile_per_op;
        cpu + io_r + io_w + net + mem + pre
    }

    /// Update base fees based on actual vs target utilization (EIP-1559 per dimension).
    pub fn update(&mut self, actual: &ResourceUsage, target: &ResourceUsage) {
        const MAX_CHANGE_BPS: u64 = 125; // 12.5% max change per block (like EIP-1559)
        let adjust = |fee: u64, actual: u64, target: u64| -> u64 {
            if target == 0 { return fee; }
            let delta = (fee * MAX_CHANGE_BPS / 1000) as i64;
            if actual > target { (fee as i64 + delta).max(1) as u64 }
            else if actual < target { (fee as i64 - delta).max(1) as u64 }
            else { fee }
        };
        self.cpu_per_op       = adjust(self.cpu_per_op,       actual.cpu_ops,       target.cpu_ops);
        self.io_read_per_op   = adjust(self.io_read_per_op,   actual.io_reads,      target.io_reads);
        self.io_write_per_op  = adjust(self.io_write_per_op,  actual.io_writes,     target.io_writes);
        self.network_per_byte = adjust(self.network_per_byte, actual.network_bytes, target.network_bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fee_calculation() {
        let fees = ResourceBaseFees::default();
        let usage = ResourceUsage::evm_transfer();
        let fee = fees.calculate_fee(&usage);
        assert!(fee > 0);
        // Contract call should cost more than transfer
        let contract_usage = ResourceUsage::evm_contract_call(256, 10);
        assert!(fees.calculate_fee(&contract_usage) > fee);
    }
}
