//! Resource metering for IONA gas pricing.
//!
//! Tracks usage of CPU, I/O, network, and storage resources.
//! Provides validation, metrics, and snapshot capabilities.

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// Types of resources that can be metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Cpu,
    Io,
    Network,
    Storage,
}

impl ResourceType {
    /// Returns a string representation for logging and metrics.
    pub fn as_str(&self) -> &'static str {
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
        write!(f, "{}", self.as_str())
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

    /// Validate that all usage and target values are within reasonable bounds.
    /// Usage values must be ≤ 100 (percent), targets can be any positive value.
    pub fn validate(&self) -> Result<(), String> {
        let fields = [
            (self.cpu_used, "cpu_used"),
            (self.io_used, "io_used"),
            (self.network_used, "network_used"),
            (self.storage_used, "storage_used"),
        ];
        for (val, name) in fields {
            if val > 100 {
                return Err(format!("{} cannot exceed 100", name));
            }
        }
        // Targets can be zero (meaning no limit), but if > 0 they should be reasonable.
        // We don't enforce upper bound, but we can check that they're not absurdly large.
        let targets = [
            (self.target_cpu, "target_cpu"),
            (self.target_io, "target_io"),
            (self.target_network, "target_network"),
            (self.target_storage, "target_storage"),
        ];
        for (val, name) in targets {
            if val > 10_000_000 {
                return Err(format!("{} is unreasonably large (> 10M)", name));
            }
        }
        Ok(())
    }

    /// Compute the ratio of used to target for a given resource.
    /// If target is 0, returns 1.0 (neutral).
    pub fn ratio(&self, resource: ResourceType) -> f64 {
        match resource {
            ResourceType::Cpu => self.ratio_for(self.cpu_used, self.target_cpu),
            ResourceType::Io => self.ratio_for(self.io_used, self.target_io),
            ResourceType::Network => self.ratio_for(self.network_used, self.target_network),
            ResourceType::Storage => self.ratio_for(self.storage_used, self.target_storage),
        }
    }

    fn ratio_for(&self, used: u64, target: u64) -> f64 {
        if target == 0 {
            1.0
        } else {
            used as f64 / target as f64
        }
    }

    /// Get the used value for a resource.
    pub fn used(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_used,
            ResourceType::Io => self.io_used,
            ResourceType::Network => self.network_used,
            ResourceType::Storage => self.storage_used,
        }
    }

    /// Get the target value for a resource.
    pub fn target(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.target_cpu,
            ResourceType::Io => self.target_io,
            ResourceType::Network => self.target_network,
            ResourceType::Storage => self.target_storage,
        }
    }

    /// Set the used value for a resource.
    pub fn set_used(&mut self, resource: ResourceType, value: u64) {
        match resource {
            ResourceType::Cpu => self.cpu_used = value,
            ResourceType::Io => self.io_used = value,
            ResourceType::Network => self.network_used = value,
            ResourceType::Storage => self.storage_used = value,
        }
    }

    /// Set the target value for a resource.
    pub fn set_target(&mut self, resource: ResourceType, value: u64) {
        match resource {
            ResourceType::Cpu => self.target_cpu = value,
            ResourceType::Io => self.target_io = value,
            ResourceType::Network => self.target_network = value,
            ResourceType::Storage => self.target_storage = value,
        }
    }
}

/// Meter that tracks resource usage during execution.
#[derive(Debug, Clone, Default)]
pub struct ResourceMeter {
    cpu: u64,
    io: u64,
    network: u64,
    storage: u64,
    /// Optional timestamp of last reset.
    last_reset: Option<u64>,
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

    /// Record usage for a specific resource type.
    pub fn record(&mut self, resource: ResourceType, amount: u64) {
        match resource {
            ResourceType::Cpu => self.record_cpu(amount),
            ResourceType::Io => self.record_io(amount),
            ResourceType::Network => self.record_network(amount),
            ResourceType::Storage => self.record_storage(amount),
        }
    }

    /// Reset all counters to zero and update last_reset.
    pub fn reset(&mut self) {
        *self = Self::new();
        self.last_reset = Some(current_timestamp());
    }

    /// Reset only a specific resource counter.
    pub fn reset_resource(&mut self, resource: ResourceType) {
        match resource {
            ResourceType::Cpu => self.cpu = 0,
            ResourceType::Io => self.io = 0,
            ResourceType::Network => self.network = 0,
            ResourceType::Storage => self.storage = 0,
        }
    }

    /// Get the current usage for a resource.
    pub fn get(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu,
            ResourceType::Io => self.io,
            ResourceType::Network => self.network,
            ResourceType::Storage => self.storage,
        }
    }

    /// Take a snapshot of current usage (without targets).
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

    /// Take a snapshot with provided targets.
    pub fn snapshot_with_targets(&self, targets: &ResourceUsage) -> ResourceUsage {
        ResourceUsage {
            cpu_used: self.cpu,
            io_used: self.io,
            network_used: self.network,
            storage_used: self.storage,
            target_cpu: targets.target_cpu,
            target_io: targets.target_io,
            target_network: targets.target_network,
            target_storage: targets.target_storage,
        }
    }

    /// Get the time since last reset in seconds.
    pub fn seconds_since_reset(&self) -> Option<u64> {
        self.last_reset.map(|ts| current_timestamp().saturating_sub(ts))
    }
}

/// Helper to get current timestamp in seconds.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_usage_validation() {
        let mut usage = ResourceUsage {
            cpu_used: 50,
            io_used: 30,
            network_used: 20,
            storage_used: 10,
            target_cpu: 100,
            target_io: 100,
            target_network: 100,
            target_storage: 100,
        };
        assert!(usage.validate().is_ok());

        usage.cpu_used = 101;
        assert!(usage.validate().is_err());

        usage.cpu_used = 50;
        usage.target_cpu = 10_000_001;
        assert!(usage.validate().is_err());

        usage.target_cpu = 10_000_000;
        assert!(usage.validate().is_ok());
    }

    #[test]
    fn test_resource_usage_ratio() {
        let usage = ResourceUsage {
            cpu_used: 80,
            io_used: 40,
            network_used: 20,
            storage_used: 5,
            target_cpu: 100,
            target_io: 50,
            target_network: 100,
            target_storage: 10,
        };
        assert_eq!(usage.ratio(ResourceType::Cpu), 0.8);
        assert_eq!(usage.ratio(ResourceType::Io), 0.8);
        assert_eq!(usage.ratio(ResourceType::Network), 0.2);
        assert_eq!(usage.ratio(ResourceType::Storage), 0.5);
    }

    #[test]
    fn test_resource_usage_ratio_zero_target() {
        let usage = ResourceUsage {
            cpu_used: 100,
            io_used: 0,
            network_used: 0,
            storage_used: 0,
            target_cpu: 0,
            target_io: 0,
            target_network: 0,
            target_storage: 0,
        };
        assert_eq!(usage.ratio(ResourceType::Cpu), 1.0);
        assert_eq!(usage.ratio(ResourceType::Io), 1.0);
    }

    #[test]
    fn test_resource_meter_record_and_get() {
        let mut meter = ResourceMeter::new();
        meter.record_cpu(10);
        meter.record_io(20);
        meter.record_network(30);
        meter.record_storage(40);

        assert_eq!(meter.get(ResourceType::Cpu), 10);
        assert_eq!(meter.get(ResourceType::Io), 20);
        assert_eq!(meter.get(ResourceType::Network), 30);
        assert_eq!(meter.get(ResourceType::Storage), 40);

        meter.record(ResourceType::Cpu, 5);
        assert_eq!(meter.get(ResourceType::Cpu), 15);
    }

    #[test]
    fn test_resource_meter_reset() {
        let mut meter = ResourceMeter::new();
        meter.record_cpu(100);
        meter.reset();
        assert_eq!(meter.get(ResourceType::Cpu), 0);
        assert!(meter.seconds_since_reset().unwrap_or(0) < 2);
    }

    #[test]
    fn test_resource_meter_reset_resource() {
        let mut meter = ResourceMeter::new();
        meter.record_cpu(100);
        meter.record_io(200);
        meter.reset_resource(ResourceType::Cpu);
        assert_eq!(meter.get(ResourceType::Cpu), 0);
        assert_eq!(meter.get(ResourceType::Io), 200);
    }

    #[test]
    fn test_snapshot_with_targets() {
        let mut meter = ResourceMeter::new();
        meter.record_cpu(50);
        meter.record_io(25);

        let targets = ResourceUsage {
            cpu_used: 0,
            io_used: 0,
            network_used: 0,
            storage_used: 0,
            target_cpu: 100,
            target_io: 50,
            target_network: 100,
            target_storage: 100,
        };

        let snapshot = meter.snapshot_with_targets(&targets);
        assert_eq!(snapshot.cpu_used, 50);
        assert_eq!(snapshot.io_used, 25);
        assert_eq!(snapshot.target_cpu, 100);
        assert_eq!(snapshot.target_io, 50);
    }
}
