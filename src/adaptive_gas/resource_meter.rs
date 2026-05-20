//! Per-operation resource consumption measurement.
use serde::{Deserialize, Serialize};

/// Resources consumed by a single transaction.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_ops:        u64,   // arithmetic, logic, hashing
    pub io_reads:       u64,   // storage reads
    pub io_writes:      u64,   // storage writes (more expensive)
    pub network_bytes:  u64,   // bytes propagated over P2P
    pub memory_bytes:   u64,   // peak memory used
    pub precompile_ops: u64,   // expensive crypto ops (bn128, kzg)
}

impl ResourceUsage {
    pub fn evm_transfer() -> Self {
        Self { cpu_ops: 100, io_reads: 2, io_writes: 2, network_bytes: 200, memory_bytes: 0, precompile_ops: 0 }
    }
    pub fn evm_contract_call(calldata_len: usize, storage_ops: usize) -> Self {
        Self {
            cpu_ops:        1_000 + calldata_len as u64 * 3,
            io_reads:       storage_ops as u64,
            io_writes:      (storage_ops / 2) as u64,
            network_bytes:  calldata_len as u64 + 200,
            memory_bytes:   calldata_len as u64 * 4,
            precompile_ops: 0,
        }
    }
    pub fn evm_precompile(precompile_addr: u64) -> Self {
        let precompile_cost = match precompile_addr {
            1 => 100,    // ecrecover
            5 => 5_000,  // modexp
            6 => 5_000,  // bn128 add
            8 => 50_000, // bn128 pairing
            _ => 500,
        };
        Self { cpu_ops: 0, io_reads: 0, io_writes: 0, network_bytes: 0, memory_bytes: 0, precompile_ops: precompile_cost }
    }
}
