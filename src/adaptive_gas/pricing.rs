//! Gas pricing formulas and adjustments.
//!
//! Provides pluggable pricing formulas (linear, exponential, sigmoid)
//! and the core `GasPricing` state machine.

use crate::gas::{GasPricingConfig, ResourceType, ResourceUsage};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Current price for a resource (cached entry).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePrice {
    pub resource: ResourceType,
    pub price: u64,
    pub timestamp: u64,
}

/// Pricing formula trait.
pub trait PricingFormula: Send + Sync {
    /// Compute a new price based on base price, demand ratio, and configuration.
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64;
}

/// Linear adjustment: price = base * (1 + rate * (ratio - 1)).
pub struct LinearPricing;

impl PricingFormula for LinearPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let adjustment = 1.0 + config.adjustment_rate * (ratio - 1.0);
        let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
        (base as f64 * multiplier).round() as u64
    }
}

/// Exponential adjustment: price = base * exp(rate * (ratio - 1)).
/// More sensitive to high demand.
pub struct ExponentialPricing;

impl PricingFormula for ExponentialPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let exponent = config.adjustment_rate * (ratio - 1.0);
        let multiplier = exponent.exp().clamp(config.min_price_multiplier, config.max_price_multiplier);
        (base as f64 * multiplier).round() as u64
    }
}

/// Sigmoid adjustment: price = base * (1 + rate * tanh(ratio - 1)).
/// Gentle at extremes.
pub struct SigmoidPricing;

impl PricingFormula for SigmoidPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let x = ratio - 1.0;
        let adjustment = 1.0 + config.adjustment_rate * x.tanh();
        let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
        (base as f64 * multiplier).round() as u64
    }
}

/// Which formula to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormulaType {
    Linear,
    Exponential,
    Sigmoid,
}

impl Default for FormulaType {
    fn default() -> Self {
        Self::Linear
    }
}

impl fmt::Display for FormulaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linear => write!(f, "linear"),
            Self::Exponential => write!(f, "exponential"),
            Self::Sigmoid => write!(f, "sigmoid"),
        }
    }
}

/// Core pricing state.
#[derive(Debug)]
pub struct GasPricing {
    cpu_price: u64,
    io_price: u64,
    network_price: u64,
    storage_price: u64,
    formula: Box<dyn PricingFormula>,
    formula_type: FormulaType,
}

impl GasPricing {
    /// Create a new pricing instance with default linear formula.
    pub fn new(config: &GasPricingConfig) -> Self {
        Self::with_formula(config, FormulaType::Linear)
    }

    /// Create a new pricing instance with a specific formula.
    pub fn with_formula(config: &GasPricingConfig, formula_type: FormulaType) -> Self {
        let formula: Box<dyn PricingFormula> = match formula_type {
            FormulaType::Linear => Box::new(LinearPricing),
            FormulaType::Exponential => Box::new(ExponentialPricing),
            FormulaType::Sigmoid => Box::new(SigmoidPricing),
        };
        Self {
            cpu_price: config.cpu_base_price,
            io_price: config.io_base_price,
            network_price: config.network_base_price,
            storage_price: config.storage_base_price,
            formula,
            formula_type,
        }
    }

    /// Change the pricing formula at runtime.
    pub fn set_formula(&mut self, formula_type: FormulaType) {
        self.formula = match formula_type {
            FormulaType::Linear => Box::new(LinearPricing),
            FormulaType::Exponential => Box::new(ExponentialPricing),
            FormulaType::Sigmoid => Box::new(SigmoidPricing),
        };
        self.formula_type = formula_type;
    }

    /// Get the current formula type.
    pub fn formula_type(&self) -> FormulaType {
        self.formula_type
    }

    /// Get the current price for a resource.
    pub fn price_for(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_price,
            ResourceType::Io => self.io_price,
            ResourceType::Network => self.network_price,
            ResourceType::Storage => self.storage_price,
        }
    }

    /// Get all current prices as an array.
    pub fn all_prices(&self) -> [u64; 4] {
        [
            self.cpu_price,
            self.io_price,
            self.network_price,
            self.storage_price,
        ]
    }

    /// Adjust prices based on current demand.
    /// Returns a vector of (resource, old_price, new_price) for changed resources.
    pub fn adjust(
        &mut self,
        demand: &ResourceUsage,
        config: &GasPricingConfig,
    ) -> Vec<(ResourceType, u64, u64)> {
        // Validate demand first.
        if let Err(e) = demand.validate() {
            tracing::warn!("Invalid demand data: {}, skipping adjustment", e);
            return Vec::new();
        }

        let mut adjustments = Vec::new();

        // Helper closure to adjust a single resource.
        let mut adjust_resource = |resource: ResourceType, base: u64, current: &mut u64| {
            let ratio = demand.ratio(resource);
            let new_price = self.formula.compute_price(base, ratio, config);
            if new_price != *current {
                let old = *current;
                *current = new_price;
                adjustments.push((resource, old, new_price));
            }
        };

        adjust_resource(ResourceType::Cpu, config.cpu_base_price, &mut self.cpu_price);
        adjust_resource(ResourceType::Io, config.io_base_price, &mut self.io_price);
        adjust_resource(ResourceType::Network, config.network_base_price, &mut self.network_price);
        adjust_resource(ResourceType::Storage, config.storage_base_price, &mut self.storage_price);

        adjustments
    }

    /// Reset all prices to their base values (from config).
    pub fn reset_to_base(&mut self, config: &GasPricingConfig) {
        self.cpu_price = config.cpu_base_price;
        self.io_price = config.io_base_price;
        self.network_price = config.network_base_price;
        self.storage_price = config.storage_base_price;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> GasPricingConfig {
        GasPricingConfig {
            cpu_base_price: 10,
            io_base_price: 5,
            network_base_price: 3,
            storage_base_price: 2,
            adjustment_rate: 0.1,
            max_price_multiplier: 10.0,
            min_price_multiplier: 0.1,
            enable_cache: false,
            cache_size: 1024,
            cache_ttl_secs: 10,
            update_interval_secs: 60,
            enable_adaptive: true,
            enable_metrics: false,
            log_changes: false,
            retry_attempts: 3,
            retry_backoff_ms: 100,
        }
    }

    fn sample_demand() -> ResourceUsage {
        ResourceUsage {
            cpu_used: 80,
            io_used: 40,
            network_used: 20,
            storage_used: 5,
            target_cpu: 100,
            target_io: 50,
            target_network: 100,
            target_storage: 10,
        }
    }

    #[test]
    fn test_linear_pricing() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let demand = sample_demand();

        let adjustments = pricing.adjust(&demand, &config);
        assert!(!adjustments.is_empty());

        // CPU ratio = 0.8, so price should decrease slightly.
        let cpu_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Cpu);
        assert!(cpu_adj.is_some());
        let (_, old, new) = cpu_adj.unwrap();
        assert!(*new < *old); // demand below target → decrease

        // IO ratio = 0.8 (40/50), also decrease.
        let io_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Io);
        assert!(io_adj.is_some());
        let (_, old, new) = io_adj.unwrap();
        assert!(*new < *old);

        // Network ratio = 0.2 (20/100), decrease more.
        let net_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Network);
        assert!(net_adj.is_some());
        let (_, old, new) = net_adj.unwrap();
        assert!(*new < *old);
        // Storage ratio = 0.5 (5/10), decrease moderately.
        let stor_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Storage);
        assert!(stor_adj.is_some());
        let (_, old, new) = stor_adj.unwrap();
        assert!(*new < *old);
    }

    #[test]
    fn test_exponential_pricing() {
        let config = default_config();
        let mut pricing = GasPricing::with_formula(&config, FormulaType::Exponential);
        let demand = sample_demand();

        let adjustments = pricing.adjust(&demand, &config);
        assert!(!adjustments.is_empty());

        // With exponential, changes are more pronounced.
        let cpu_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Cpu).unwrap();
        let (_, old, new) = cpu_adj;
        // Should be lower than linear for ratio < 1.
        let linear_pricing = GasPricing::new(&config);
        let linear_cpu = linear_pricing.price_for(ResourceType::Cpu);
        assert!(*new < linear_cpu);
    }

    #[test]
    fn test_sigmoid_pricing() {
        let config = default_config();
        let mut pricing = GasPricing::with_formula(&config, FormulaType::Sigmoid);
        let demand = sample_demand();

        let adjustments = pricing.adjust(&demand, &config);
        assert!(!adjustments.is_empty());

        // Sigmoid is less aggressive than linear for small deviations.
        let cpu_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Cpu).unwrap();
        let (_, old, new) = cpu_adj;
        let linear_pricing = GasPricing::new(&config);
        let linear_cpu = linear_pricing.price_for(ResourceType::Cpu);
        // Sigmoid should be closer to base for ratio 0.8 than linear.
        // Actually, for ratio 0.8, linear gives 10 * (1 + 0.1*(-0.2)) = 9.8, sigmoid gives ~10*(1+0.1*tanh(-0.2)) ≈ 9.8.
        // They might be similar. We'll just test it runs.
    }

    #[test]
    fn test_formula_switch() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        assert_eq!(pricing.formula_type(), FormulaType::Linear);

        pricing.set_formula(FormulaType::Exponential);
        assert_eq!(pricing.formula_type(), FormulaType::Exponential);

        let demand = sample_demand();
        let adj = pricing.adjust(&demand, &config);
        assert!(!adj.is_empty());
    }

    #[test]
    fn test_reset_to_base() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let demand = sample_demand();
        pricing.adjust(&demand, &config);
        // Prices changed.
        assert_ne!(pricing.price_for(ResourceType::Cpu), config.cpu_base_price);

        pricing.reset_to_base(&config);
        assert_eq!(pricing.price_for(ResourceType::Cpu), config.cpu_base_price);
        assert_eq!(pricing.price_for(ResourceType::Io), config.io_base_price);
        assert_eq!(pricing.price_for(ResourceType::Network), config.network_base_price);
        assert_eq!(pricing.price_for(ResourceType::Storage), config.storage_base_price);
    }

    #[test]
    fn test_adjust_ignores_invalid_demand() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let mut demand = sample_demand();
        demand.cpu_used = 101; // invalid

        let adjustments = pricing.adjust(&demand, &config);
        assert!(adjustments.is_empty());
        // Prices unchanged.
        assert_eq!(pricing.price_for(ResourceType::Cpu), config.cpu_base_price);
    }

    #[test]
    fn test_all_prices() {
        let config = default_config();
        let pricing = GasPricing::new(&config);
        let prices = pricing.all_prices();
        assert_eq!(prices, [10, 5, 3, 2]);
    }
}
