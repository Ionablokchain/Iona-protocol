//! Dynamic resource pricing – adjusts prices based on recent block utilization.
//!
//! Each resource has a base price and an elasticity factor.
//! After every block, the price is updated proportionally to how close
//! the block usage was to the target.

use super::resource_meter::{Resource, ResourceUsage, ResourceLimits};

// -----------------------------------------------------------------------------
// Resource prices
// -----------------------------------------------------------------------------

/// Current prices for each resource dimension (in wei per gas‑equivalent unit).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourcePrices {
    pub cpu: u64,
    pub io: u64,
    pub net: u64,
    pub storage: u64,
}

impl Default for ResourcePrices {
    fn default() -> Self {
        Self {
            cpu: 1,
            io: 2,
            net: 3,
            storage: 5,
        }
    }
}

impl ResourcePrices {
    /// Price for a specific resource.
    pub fn get(&self, resource: Resource) -> u64 {
        match resource {
            Resource::Cpu => self.cpu,
            Resource::Io => self.io,
            Resource::Net => self.net,
            Resource::Storage => self.storage,
        }
    }

    /// Compute the cost of a resource usage given current prices.
    pub fn compute_cost(&self, usage: &ResourceUsage) -> u64 {
        usage.cpu.saturating_mul(self.cpu)
            .saturating_add(usage.io.saturating_mul(self.io))
            .saturating_add(usage.net.saturating_mul(self.net))
            .saturating_add(usage.storage.saturating_mul(self.storage))
    }
}

// -----------------------------------------------------------------------------
// Price adjuster
// -----------------------------------------------------------------------------

/// Configuration for the multi‑dimensional price adjuster.
#[derive(Debug, Clone)]
pub struct PriceAdjusterConfig {
    /// Target utilization per resource (0.0 – 1.0).
    pub target_utilization: f64,
    /// Maximum price change per block (as a fraction, e.g. 0.125 = 12.5%).
    pub max_change_per_block: f64,
    /// Minimum price floor for each resource.
    pub min_price: u64,
}

impl Default for PriceAdjusterConfig {
    fn default() -> Self {
        Self {
            target_utilization: 0.5,
            max_change_per_block: 0.125,
            min_price: 1,
        }
    }
}

/// Adjusts resource prices after each block.
#[derive(Debug, Clone)]
pub struct PriceAdjuster {
    pub config: PriceAdjusterConfig,
    pub prices: ResourcePrices,
}

impl PriceAdjuster {
    /// Create a new adjuster with the given configuration and initial prices.
    pub fn new(config: PriceAdjusterConfig, initial_prices: ResourcePrices) -> Self {
        Self {
            config,
            prices: initial_prices,
        }
    }

    /// Update prices based on the block usage and block limits.
    ///
    /// For each resource, the new price is:
    /// ```text
    /// new_price = old_price * (1 + elasticity * (utilization - target))
    /// ```
    /// where elasticity is derived from `max_change_per_block` and the
    /// change is clamped to `±max_change_per_block`.
    pub fn update(&mut self, block_usage: &ResourceUsage, block_limits: &ResourceLimits) {
        for &resource in &Resource::ALL {
            let utilization = self.utilization(resource, block_usage, block_limits);
            let target = self.config.target_utilization;
            let delta = utilization - target;
            let change = delta * self.config.max_change_per_block * 2.0; // scale so that at util=1.0 change=+max
            let factor = 1.0 + change.clamp(
                -self.config.max_change_per_block,
                self.config.max_change_per_block,
            );

            let old_price = self.prices.get(resource);
            let new_price = (old_price as f64 * factor).round() as u64;
            let new_price = new_price.max(self.config.min_price);
            match resource {
                Resource::Cpu => self.prices.cpu = new_price,
                Resource::Io => self.prices.io = new_price,
                Resource::Net => self.prices.net = new_price,
                Resource::Storage => self.prices.storage = new_price,
            }
        }
    }

    /// Compute utilization of a single resource from block usage.
    fn utilization(
        &self,
        resource: Resource,
        block_usage: &ResourceUsage,
        block_limits: &ResourceLimits,
    ) -> f64 {
        let used = match resource {
            Resource::Cpu => block_usage.cpu,
            Resource::Io => block_usage.io,
            Resource::Net => block_usage.net,
            Resource::Storage => block_usage.storage,
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
        (used as f64 / limit as f64).clamp(0.0, 1.0)
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_price_increase_on_high_utilization() {
        let config = PriceAdjusterConfig::default();
        let initial = ResourcePrices::default();
        let mut adjuster = PriceAdjuster::new(config, initial);
        let usage = ResourceUsage {
            cpu: 8_000_000,
            ..Default::default()
        };
        let limits = ResourceLimits {
            max_cpu: 10_000_000,
            ..Default::default()
        };
        adjuster.update(&usage, &limits);
        assert!(adjuster.prices.cpu > initial.cpu);
    }

    #[test]
    fn test_price_never_below_floor() {
        let config = PriceAdjusterConfig::default();
        let initial = ResourcePrices::default();
        let mut adjuster = PriceAdjuster::new(config, initial);
        let usage = ResourceUsage::default();
        let limits = ResourceLimits::default();
        // Apply many blocks of zero usage
        for _ in 0..100 {
            adjuster.update(&usage, &limits);
        }
        assert!(adjuster.prices.cpu >= config.min_price);
    }
}
