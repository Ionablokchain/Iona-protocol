//! Gas schedule — maps EVM opcodes to resource usage.
use crate::adaptive_gas::resource_meter::ResourceUsage;

pub fn opcode_resources(opcode: u8) -> ResourceUsage {
    match opcode {
        // Arithmetic (cheap CPU, no IO)
        0x01..=0x0B => ResourceUsage { cpu_ops: 3, ..Default::default() },
        // Comparison
        0x10..=0x1D => ResourceUsage { cpu_ops: 3, ..Default::default() },
        // SHA3 (expensive CPU)
        0x20 => ResourceUsage { cpu_ops: 30, memory_bytes: 32, ..Default::default() },
        // Storage read (expensive IO)
        0x54 => ResourceUsage { cpu_ops: 5, io_reads: 1, ..Default::default() },
        // Storage write (very expensive IO)
        0x55 => ResourceUsage { cpu_ops: 5, io_writes: 1, ..Default::default() },
        // CALL (network + IO)
        0xF1 | 0xF4 => ResourceUsage { cpu_ops: 100, io_reads: 2, network_bytes: 50, ..Default::default() },
        // LOG (network + IO)
        0xA0..=0xA4 => ResourceUsage { cpu_ops: 20, io_writes: 1, network_bytes: 50, ..Default::default() },
        // Default
        _ => ResourceUsage { cpu_ops: 1, ..Default::default() },
    }
}
