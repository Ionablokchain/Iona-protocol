//! Resource metering for IONA gas pricing.
//!
//! Tracks usage of CPU, I/O, network, and storage resources.

use serde::{Deserialize, Serialize};

/// Types of resources that can be metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Cpu,
    Io,
    Network,
    Storage,
}

impl ResourceType {
    pub fn to_string(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Io => "io",
            Self::Network => "network",
            Self::Storage => "storage",
        }
    }
}

impl std::fmt::Display for ResourceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_string())
    }
}

/// Resource usage data for a block or transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub cpu_used: u64,
    pub io_used: u64,
    pub network_used: u64,
    pub storage_used: u64,
    pub target_cpu: u64,
    pub target_io: u64,
    pub target_network: u64,
    pub target_storage: u64,
}

impl ResourceUsage {
    /// Create a new usage with zeros.
    pub fn zero() -> Self {
        Self {
            cpu_used: 0,
            io_used: 0,
            network_used: 0,
            storage_used: 0,
            target_cpu: 0,
            target_io: 0,
            target_network: 0,
            target_storage: 0,
        }
    }

    /// Compute the ratio of used to target for a given resource.
    pub fn ratio(&self, resource: ResourceType) -> f64 {
        match resource {
            ResourceType::Cpu => {
                if self.target_cpu == 0 {
                    return 1.0;
                }
                self.cpu_used as f64 / self.target_cpu as f64
            }
            ResourceType::Io => {
                if self.target_io == 0 {
                    return 1.0;
                }
                self.io_used as f64 / self.target_io as f64
            }
            ResourceType::Network => {
                if self.target_network == 0 {
                    return 1.0;
                }
                self.network_used as f64 / self.target_network as f64
            }
            ResourceType::Storage => {
                if self.target_storage == 0 {
                    return 1.0;
                }
                self.storage_used as f64 / self.target_storage as f64
            }
        }
    }
}

/// Meter that tracks resource usage during execution.
#[derive(Debug, Clone, Default)]
pub struct ResourceMeter {
    pub cpu: u64,
    pub io: u64,
    pub network: u64,
    pub storage: u64,
}

impl ResourceMeter {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_cpu(&mut self, amount: u64) {
        self.cpu = self.cpu.saturating_add(amount);
    }

    pub fn record_io(&mut self, amount: u64) {
        self.io = self.io.saturating_add(amount);
    }

    pub fn record_network(&mut self, amount: u64) {
        self.network = self.network.saturating_add(amount);
    }

    pub fn record_storage(&mut self, amount: u64) {
        self.storage = self.storage.saturating_add(amount);
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }

    pub fn snapshot(&self) -> ResourceUsage {
        ResourceUsage {
            cpu_used: self.cpu,
            io_used: self.io,
            network_used: self.network,
            storage_used: self.storage,
            target_cpu: 0,
            target_io: 0,
            target_network: 0,
            target_storage: 0,
        }
    }
}
