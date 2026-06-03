//! Resource meter – tracks CPU, IO, NET, and STORAGE consumption.
//!
//! Each resource has a configurable limit per transaction / block,
//! and the meter accumulates usage linearly. On overflow or exceeding
//! a limit, it returns a dedicated error.

use std::cmp;
use thiserror::Error;

// -----------------------------------------------------------------------------
// Resource dimensions
// -----------------------------------------------------------------------------

/// Enum representing the four resource dimensions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Resource {
    Cpu,
    Io,
    Net,
    Storage,
}

impl Resource {
    /// Iterator over all resource types.
    pub const ALL: [Resource; 4] = [Resource::Cpu, Resource::Io, Resource::Net, Resource::Storage];
}

// -----------------------------------------------------------------------------
// Resource usage
// -----------------------------------------------------------------------------

/// Accumulated resource usage for a single execution context (transaction).
#[derive(Debug, Clone, Default)]
pub struct ResourceUsage {
    /// CPU usage in abstract "gas‑equivalent" units (already scaled to gas).
    pub cpu: u64,
    /// IO usage (state reads / writes) in gas‑equivalent units.
    pub io: u64,
    /// Network usage (bytes transferred) in gas‑equivalent units.
    pub net: u64,
    /// Storage usage (bytes written permanently) in gas‑equivalent units.
    pub storage: u64,
}

impl ResourceUsage {
    /// Create a new empty usage.
    pub fn new() -> Self {
        Self::default()
    }

    /// Total gas across all resources.
    pub fn total(&self) -> u64 {
        self.cpu
            .saturating_add(self.io)
            .saturating_add(self.net)
            .saturating_add(self.storage)
    }

    /// Add another usage into this one (for block‑level aggregation).
    pub fn add(&mut self, other: &ResourceUsage) {
        self.cpu = self.cpu.saturating_add(other.cpu);
        self.io = self.io.saturating_add(other.io);
        self.net = self.net.saturating_add(other.net);
        self.storage = self.storage.saturating_add(other.storage);
    }

    /// Charge a specific resource with the given amount.
    pub fn charge(&mut self, resource: Resource, amount: u64) -> Result<(), ResourceError> {
        let target = match resource {
            Resource::Cpu => &mut self.cpu,
            Resource::Io => &mut self.io,
            Resource::Net => &mut self.net,
            Resource::Storage => &mut self.storage,
        };
        *target = target.checked_add(amount).ok_or(ResourceError::Overflow {
            resource,
            current: *target,
            amount,
        })?;
        Ok(())
    }

    /// Check if any dimension exceeds a given per‑transaction limit.
    pub fn exceeds(&self, limits: &ResourceLimits) -> Option<Resource> {
        if self.cpu > limits.max_cpu {
            return Some(Resource::Cpu);
        }
        if self.io > limits.max_io {
            return Some(Resource::Io);
        }
        if self.net > limits.max_net {
            return Some(Resource::Net);
        }
        if self.storage > limits.max_storage {
            return Some(Resource::Storage);
        }
        None
    }
}

// -----------------------------------------------------------------------------
// Resource limits
// -----------------------------------------------------------------------------

/// Per‑transaction resource limits.
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_cpu: u64,
    pub max_io: u64,
    pub max_net: u64,
    pub max_storage: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_cpu: 30_000_000,
            max_io: 10_000_000,
            max_net: 5_000_000,
            max_storage: 20_000_000,
        }
    }
}

// -----------------------------------------------------------------------------
// Resource errors
// -----------------------------------------------------------------------------

/// Errors that can occur during resource metering.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResourceError {
    #[error("resource limit exceeded: {resource:?} used {used} > max {max}")]
    LimitExceeded {
        resource: Resource,
        used: u64,
        max: u64,
    },
    #[error("resource overflow: {resource:?} at {current}, adding {amount}")]
    Overflow {
        resource: Resource,
        current: u64,
        amount: u64,
    },
}

// -----------------------------------------------------------------------------
// Resource meter
// -----------------------------------------------------------------------------

/// Tracks resource usage during VM execution and enforces limits.
#[derive(Debug, Clone)]
pub struct ResourceMeter {
    /// Current usage for this execution context.
    pub usage: ResourceUsage,
    /// Per‑transaction limits.
    pub limits: ResourceLimits,
    /// Block‑level accumulated usage (for price adjustment).
    pub block_usage: ResourceUsage,
}

impl ResourceMeter {
    /// Create a new meter with the given limits.
    pub fn new(limits: ResourceLimits) -> Self {
        Self {
            usage: ResourceUsage::new(),
            limits,
            block_usage: ResourceUsage::new(),
        }
    }

    /// Charge a specific resource. Returns an error if the limit is exceeded.
    pub fn charge(&mut self, resource: Resource, amount: u64) -> Result<(), ResourceError> {
        self.usage.charge(resource, amount)?;
        if let Some(exceeded) = self.usage.exceeds(&self.limits) {
            let used = match exceeded {
                Resource::Cpu => self.usage.cpu,
                Resource::Io => self.usage.io,
                Resource::Net => self.usage.net,
                Resource::Storage => self.usage.storage,
            };
            let max = match exceeded {
                Resource::Cpu => self.limits.max_cpu,
                Resource::Io => self.limits.max_io,
                Resource::Net => self.limits.max_net,
                Resource::Storage => self.limits.max_storage,
            };
            return Err(ResourceError::LimitExceeded {
                resource: exceeded,
                used,
                max,
            });
        }
        Ok(())
    }

    /// Consume the current usage into the block accumulator and reset.
    pub fn flush_to_block(&mut self) {
        self.block_usage.add(&self.usage);
        self.usage = ResourceUsage::new();
    }

    /// Reset block accumulator (call at the beginning of a new block).
    pub fn reset_block(&mut self) {
        self.block_usage = ResourceUsage::new();
    }

    /// Get the fraction of block capacity used for a specific resource.
    pub fn block_utilization(&self, resource: Resource, block_limits: &ResourceLimits) -> f64 {
        let used = match resource {
            Resource::Cpu => self.block_usage.cpu,
            Resource::Io => self.block_usage.io,
            Resource::Net => self.block_usage.net,
            Resource::Storage => self.block_usage.storage,
        };
        let limit = match resource {
            Resource::Cpu => block_limits.max_cpu,
            Resource::Io => block_limits.max_io,
            Resource::Net => block_limits.max_net,
            Resource::Storage => block_limits.max_storage,
        };
        if limit == 0 {
            return 1.0;
        }
        cmp::min(used, limit) as f64 / limit as f64
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_charge() {
        let limits = ResourceLimits::default();
        let mut meter = ResourceMeter::new(limits);
        meter.charge(Resource::Cpu, 100).unwrap();
        assert_eq!(meter.usage.cpu, 100);
    }

    #[test]
    fn test_resource_limit_exceeded() {
        let limits = ResourceLimits {
            max_cpu: 50,
            ..Default::default()
        };
        let mut meter = ResourceMeter::new(limits);
        meter.charge(Resource::Cpu, 60).unwrap_err();
    }

    #[test]
    fn test_block_accumulation() {
        let limits = ResourceLimits::default();
        let mut meter = ResourceMeter::new(limits.clone());
        meter.charge(Resource::Io, 200).unwrap();
        meter.flush_to_block();
        assert_eq!(meter.usage.io, 0);
        assert_eq!(meter.block_usage.io, 200);
    }
}
