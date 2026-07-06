//! Gas pricing formulas and adjustments.

use crate::gas::{GasPricingConfig, ResourceType, ResourceUsage};
use serde::{Deserialize, Serialize};

/// Current price for a resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePrice {
    pub resource: ResourceType,
    pub price: u64,
    pub timestamp: u64,
}

/// Pricing formula trait.
pub trait PricingFormula {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64;
}

/// Simple linear adjustment: price = base * (1 + rate * (ratio - 1)).
pub struct LinearPricing;

impl PricingFormula for LinearPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let adjustment = 1.0 + config.adjustment_rate * (ratio - 1.0);
        let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
        (base as f64 * multiplier).round() as u64
    }
}

/// Core pricing state.
#[derive(Debug)]
pub struct GasPricing {
    cpu_price: u64,
    io_price: u64,
    network_price: u64,
    storage_price: u64,
    formula: Box<dyn PricingFormula + Send + Sync>,
}

impl GasPricing {
    pub fn new(config: &GasPricingConfig) -> Self {
        Self {
            cpu_price: config.cpu_base_price,
            io_price: config.io_base_price,
            network_price: config.network_base_price,
            storage_price: config.storage_base_price,
            formula: Box::new(LinearPricing),
        }
    }

    pub fn price_for(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_price,
            ResourceType::Io => self.io_price,
            ResourceType::Network => self.network_price,
            ResourceType::Storage => self.storage_price,
        }
    }

    pub fn adjust(
        &mut self,
        demand: &ResourceUsage,
        config: &GasPricingConfig,
    ) -> Vec<(ResourceType, u64, u64)> {
        let mut adjustments = Vec::new();

        // CPU
        let ratio = demand.ratio(ResourceType::Cpu);
        let new_cpu = self.formula.compute_price(config.cpu_base_price, ratio, config);
        if new_cpu != self.cpu_price {
            adjustments.push((ResourceType::Cpu, self.cpu_price, new_cpu));
            self.cpu_price = new_cpu;
        }

        // I/O
        let ratio = demand.ratio(ResourceType::Io);
        let new_io = self.formula.compute_price(config.io_base_price, ratio, config);
        if new_io != self.io_price {
            adjustments.push((ResourceType::Io, self.io_price, new_io));
            self.io_price = new_io;
        }

        // Network
        let ratio = demand.ratio(ResourceType::Network);
        let new_network = self.formula.compute_price(config.network_base_price, ratio, config);
        if new_network != self.network_price {
            adjustments.push((ResourceType::Network, self.network_price, new_network));
            self.network_price = new_network;
        }

        // Storage
        let ratio = demand.ratio(ResourceType::Storage);
        let new_storage = self.formula.compute_price(config.storage_base_price, ratio, config);
        if new_storage != self.storage_price {
            adjustments.push((ResourceType::Storage, self.storage_price, new_storage));
            self.storage_price = new_storage;
        }

        adjustments
    }
}
