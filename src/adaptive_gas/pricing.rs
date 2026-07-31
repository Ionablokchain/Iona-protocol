//! Gas pricing formulas and adjustments.
//!
//! Provides the core pricing logic with pluggable formulas,
//! demand‑based adjustments, and configurable bounds.

use crate::gas::{GasPricingConfig, ResourceType, ResourceUsage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{debug, trace, warn};

// ── Re‑exports ─────────────────────────────────────────────────────────────

pub use linear::LinearPricing;
pub use exponential::ExponentialPricing;
pub use adaptive::AdaptivePricing;

// ── Resource Price ───────────────────────────────────────────────────────

/// Current price for a resource (includes timestamp).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePrice {
    pub resource: ResourceType,
    pub price: u64,
    pub timestamp: u64,
}

/// Adjustment result: (resource, old_price, new_price)
pub type Adjustment = (ResourceType, u64, u64);

// ── Pricing Formula Trait ──────────────────────────────────────────────

/// Pricing formula trait.
pub trait PricingFormula: Send + Sync {
    /// Compute price based on base price and demand ratio.
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64;

    /// Name of the formula (for logging/metrics).
    fn name(&self) -> &'static str;
}

// ── Built‑in Formulas ──────────────────────────────────────────────────

mod linear {
    use super::*;

    /// Simple linear adjustment: price = base * (1 + rate * (ratio - 1)).
    pub struct LinearPricing;

    impl PricingFormula for LinearPricing {
        fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
            let adjustment = 1.0 + config.adjustment_rate * (ratio - 1.0);
            let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
            (base as f64 * multiplier).round() as u64
        }

        fn name(&self) -> &'static str {
            "linear"
        }
    }
}

mod exponential {
    use super::*;

    /// Exponential adjustment: price = base * exp(rate * (ratio - 1)).
    /// More aggressive than linear for high demand.
    pub struct ExponentialPricing;

    impl PricingFormula for ExponentialPricing {
        fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
            let exponent = config.adjustment_rate * (ratio - 1.0);
            let adjustment = exponent.exp();
            let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
            (base as f64 * multiplier).round() as u64
        }

        fn name(&self) -> &'static str {
            "exponential"
        }
    }
}

mod adaptive {
    use super::*;

    /// Adaptive formula that uses a moving average of recent ratios.
    /// (In a real implementation, you'd store historical data.)
    pub struct AdaptivePricing {
        // Placeholder for state (e.g., moving average).
        // For now, it delegates to linear.
    }

    impl AdaptivePricing {
        pub fn new() -> Self {
            Self
        }
    }

    impl PricingFormula for AdaptivePricing {
        fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
            // For demonstration, we use linear with a slight smoothing.
            // In production, you would maintain a window of ratios.
            let adjustment = 1.0 + config.adjustment_rate * (ratio - 1.0);
            let multiplier = adjustment.clamp(config.min_price_multiplier, config.max_price_multiplier);
            (base as f64 * multiplier).round() as u64
        }

        fn name(&self) -> &'static str {
            "adaptive"
        }
    }
}

// ── Formula Registry ───────────────────────────────────────────────────

/// Registry for pricing formulas (singleton pattern).
#[derive(Default)]
pub struct FormulaRegistry {
    formulas: HashMap<String, Arc<dyn PricingFormula>>,
}

impl FormulaRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            formulas: HashMap::new(),
        };
        // Register built‑in formulas.
        registry.register(Arc::new(LinearPricing));
        registry.register(Arc::new(ExponentialPricing));
        registry.register(Arc::new(AdaptivePricing::new()));
        registry
    }

    pub fn register(&mut self, formula: Arc<dyn PricingFormula>) {
        let name = formula.name().to_string();
        if self.formulas.insert(name.clone(), formula).is_some() {
            warn!("Formula '{}' was overwritten", name);
        } else {
            debug!("Registered pricing formula: {}", name);
        }
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn PricingFormula>> {
        self.formulas.get(name).cloned()
    }

    pub fn list(&self) -> Vec<&'static str> {
        self.formulas.keys().map(|s| s.as_str()).collect()
    }
}

// ── Core Pricing State ─────────────────────────────────────────────────

/// Core pricing state.
pub struct GasPricing {
    cpu_price: u64,
    io_price: u64,
    network_price: u64,
    storage_price: u64,
    formula: Arc<dyn PricingFormula>,
    // Historical ratios for adaptive formulas (optional).
    // In a full implementation you'd store a ring buffer here.
}

impl GasPricing {
    /// Create a new instance with default (linear) formula.
    pub fn new(config: &GasPricingConfig) -> Self {
        Self::with_formula(config, Arc::new(LinearPricing))
    }

    /// Create a new instance with a custom formula.
    pub fn with_formula(config: &GasPricingConfig, formula: Arc<dyn PricingFormula>) -> Self {
        Self {
            cpu_price: config.cpu_base_price,
            io_price: config.io_base_price,
            network_price: config.network_base_price,
            storage_price: config.storage_base_price,
            formula,
        }
    }

    /// Get price for a resource.
    pub fn price_for(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_price,
            ResourceType::Io => self.io_price,
            ResourceType::Network => self.network_price,
            ResourceType::Storage => self.storage_price,
        }
    }

    /// Set a new formula (dynamic switching).
    pub fn set_formula(&mut self, formula: Arc<dyn PricingFormula>) {
        let old_name = self.formula.name();
        self.formula = formula;
        debug!("Switched pricing formula from '{}' to '{}'", old_name, self.formula.name());
    }

    /// Adjust prices based on demand.
    pub fn adjust(
        &mut self,
        demand: &ResourceUsage,
        config: &GasPricingConfig,
    ) -> Vec<Adjustment> {
        let mut adjustments = Vec::with_capacity(4);

        // Compute demand ratios (clamped to avoid extreme values).
        let cpu_ratio = demand.ratio(ResourceType::Cpu).clamp(0.0, 10.0);
        let io_ratio = demand.ratio(ResourceType::Io).clamp(0.0, 10.0);
        let net_ratio = demand.ratio(ResourceType::Network).clamp(0.0, 10.0);
        let stor_ratio = demand.ratio(ResourceType::Storage).clamp(0.0, 10.0);

        // Apply formula to each resource.
        let new_cpu = self.formula.compute_price(config.cpu_base_price, cpu_ratio, config);
        if new_cpu != self.cpu_price {
            adjustments.push((ResourceType::Cpu, self.cpu_price, new_cpu));
            self.cpu_price = new_cpu;
        }

        let new_io = self.formula.compute_price(config.io_base_price, io_ratio, config);
        if new_io != self.io_price {
            adjustments.push((ResourceType::Io, self.io_price, new_io));
            self.io_price = new_io;
        }

        let new_network = self.formula.compute_price(config.network_base_price, net_ratio, config);
        if new_network != self.network_price {
            adjustments.push((ResourceType::Network, self.network_price, new_network));
            self.network_price = new_network;
        }

        let new_storage = self.formula.compute_price(config.storage_base_price, stor_ratio, config);
        if new_storage != self.storage_price {
            adjustments.push((ResourceType::Storage, self.storage_price, new_storage));
            self.storage_price = new_storage;
        }

        trace!(
            formula = self.formula.name(),
            adjustments = adjustments.len(),
            "Prices adjusted"
        );

        adjustments
    }

    /// Get current prices as a slice.
    pub fn all_prices(&self) -> [u64; 4] {
        [
            self.cpu_price,
            self.io_price,
            self.network_price,
            self.storage_price,
        ]
    }
}

// ── Standalone functions ──────────────────────────────────────────────

/// Compute price using a specific formula by name (from registry).
pub fn compute_with_formula(
    name: &str,
    base: u64,
    ratio: f64,
    config: &GasPricingConfig,
) -> Option<u64> {
    let registry = FormulaRegistry::new();
    registry.get(name).map(|formula| {
        formula.compute_price(base, ratio.clamp(0.0, 10.0), config)
    })
}

// ── Tests ──────────────────────────────────────────────────────────────

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
            enable_cache: true,
            cache_size: 100,
            cache_ttl_secs: 60,
            update_interval_secs: 60,
            enable_adaptive: true,
            enable_metrics: true,
            log_changes: true,
            retry_attempts: 3,
            retry_backoff_ms: 100,
        }
    }

    fn sample_demand() -> ResourceUsage {
        ResourceUsage {
            cpu_used: 80,
            io_used: 50,
            network_used: 40,
            storage_used: 20,
            target_cpu: 50,
            target_io: 30,
            target_network: 20,
            target_storage: 10,
        }
    }

    #[test]
    fn test_linear_pricing() {
        let config = default_config();
        let formula = LinearPricing;
        // ratio = 1.0 (target met) -> price should equal base.
        let price = formula.compute_price(10, 1.0, &config);
        assert_eq!(price, 10);
        // ratio > 1.0 (demand > target) -> price increases.
        let price = formula.compute_price(10, 2.0, &config);
        assert!(price > 10);
        // ratio < 1.0 (demand < target) -> price decreases.
        let price = formula.compute_price(10, 0.5, &config);
        assert!(price < 10);
    }

    #[test]
    fn test_exponential_pricing() {
        let config = default_config();
        let formula = ExponentialPricing;
        // ratio = 1.0 -> price = base.
        let price = formula.compute_price(10, 1.0, &config);
        assert_eq!(price, 10);
        // High demand should be more aggressive than linear.
        let linear = LinearPricing.compute_price(10, 2.0, &config);
        let exp = formula.compute_price(10, 2.0, &config);
        assert!(exp > linear);
    }

    #[test]
    fn test_gas_pricing_adjust() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let demand = sample_demand();
        let adjustments = pricing.adjust(&demand, &config);
        assert!(!adjustments.is_empty());
        // CPU should increase.
        let cpu_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Cpu);
        assert!(cpu_adj.is_some());
        let (_, old, new) = cpu_adj.unwrap();
        assert!(new > old);
    }

    #[test]
    fn test_set_formula() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let old_name = pricing.formula.name();
        assert_eq!(old_name, "linear");

        pricing.set_formula(Arc::new(ExponentialPricing));
        assert_eq!(pricing.formula.name(), "exponential");
    }

    #[test]
    fn test_formula_registry() {
        let registry = FormulaRegistry::new();
        assert!(registry.get("linear").is_some());
        assert!(registry.get("exponential").is_some());
        assert!(registry.get("adaptive").is_some());
        assert!(registry.get("unknown").is_none());
        assert_eq!(registry.list().len(), 3);
    }

    #[test]
    fn test_compute_with_formula() {
        let config = default_config();
        let price = compute_with_formula("linear", 10, 1.5, &config);
        assert!(price.is_some());
        assert!(price.unwrap() > 10);
        let price = compute_with_formula("unknown", 10, 1.5, &config);
        assert!(price.is_none());
    }

    #[test]
    fn test_ratio_clamping() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let mut demand = sample_demand();
        // Extreme ratio (should be clamped to 10.0).
        demand.cpu_used = 500; // ratio = 500/50 = 10.0
        demand.target_cpu = 50;
        let adjustments = pricing.adjust(&demand, &config);
        let cpu_adj = adjustments.iter().find(|(r, _, _)| *r == ResourceType::Cpu);
        if let Some((_, _, new)) = cpu_adj {
            // Should not exceed max multiplier.
            let max_price = (config.cpu_base_price as f64 * config.max_price_multiplier).round() as u64;
            assert!(*new <= max_price);
        }
    }

    #[test]
    fn test_all_prices() {
        let config = default_config();
        let pricing = GasPricing::new(&config);
        let prices = pricing.all_prices();
        assert_eq!(prices, [10, 5, 3, 2]);
    }

    #[test]
    fn test_adjustment_no_change() {
        let config = default_config();
        let mut pricing = GasPricing::new(&config);
        let demand = ResourceUsage {
            cpu_used: 50,
            io_used: 30,
            network_used: 20,
            storage_used: 10,
            target_cpu: 50,
            target_io: 30,
            target_network: 20,
            target_storage: 10,
        };
        let adjustments = pricing.adjust(&demand, &config);
        assert!(adjustments.is_empty());
    }

    #[test]
    fn test_linear_pricing_bounds() {
        let config = default_config();
        let formula = LinearPricing;
        // Very low demand.
        let price = formula.compute_price(10, 0.01, &config);
        let min_price = (10.0 * config.min_price_multiplier).round() as u64;
        assert_eq!(price, min_price);
        // Very high demand.
        let price = formula.compute_price(10, 100.0, &config);
        let max_price = (10.0 * config.max_price_multiplier).round() as u64;
        assert_eq!(price, max_price);
    }
}
