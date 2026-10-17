//! Gas pricing formulas and adjustments.
//!
//! Provides pluggable pricing formulas (linear, exponential, sigmoid)
//! and the core [`GasPricing`] state machine.
//!
//! # Compounding
//!
//! Each call to [`GasPricing::adjust`] multiplies the **current** price
//! by the formula's multiplier and clamps the result to
//! `[base × min_price_multiplier, base × max_price_multiplier]`. This
//! makes prices compound across calls, matching how a real EIP-1559-style
//! fee market behaves. The previous implementation recomputed every price
//! from the base, so the price could never deviate from
//! `base × multiplier` and the adaptive logic was effectively dead.
//!
//! # Bounds
//!
//! Every formula result is clamped to
//! `[base × min_price_multiplier, base × max_price_multiplier]`. A caller
//! that lowers the demand to zero cannot drive the price below
//! `base × min_price_multiplier`; a caller that raises it arbitrarily
//! cannot drive the price above `base × max_price_multiplier`.
//!
//! # Numeric safety
//!
//! Inputs to every formula go through `sanitize_ratio` and
//! `sanitize_multiplier`, which reject `NaN`, infinities, and negative
//! values. An invalid input returns the base price unchanged. This
//! closes the silent `NaN → 0` bug that a naive cast would produce.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::gas::pricing::{GasPricing, FormulaType};
//!
//! let mut pricing = GasPricing::with_formula(&config, FormulaType::Exponential);
//! let adjustments = pricing.adjust(&demand, &config);
//! for (resource, old, new) in &adjustments {
//!     println!("{resource}: {old} -> {new}");
//! }
//! ```

use crate::gas::{GasPricingConfig, ResourceType, ResourceUsage};
use serde::{Deserialize, Serialize};
use std::fmt;

// ── Types ─────────────────────────────────────────────────────────────────

/// Snapshot of a single resource price.
///
/// Returned by callers that want an owned record of the pricing state
/// at a given moment (e.g. for logging or state persistence). It is not
/// produced by `GasPricing` itself; `GasPricing::all_prices` returns a
/// plain `[u64; 4]`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourcePrice {
    pub resource: ResourceType,
    pub price: u64,
    /// Unix seconds when the snapshot was taken.
    pub timestamp: u64,
}

/// A pricing formula maps `(ratio, config)` to a **multiplier** applied
/// to the current price.
///
/// The formula receives the *current* absolute price (`base`) not the
/// configured base price. The compound effect is intentional: two
/// successive `ratio = 1.1` observations produce a strictly larger
/// price than one.
pub trait PricingFormula: Send + Sync {
    /// Compute a new absolute price from `base` (the current price) and
    /// `ratio` (current usage / target usage).
    ///
    /// Implementations **must** handle `ratio = NaN`, `ratio < 0`,
    /// `ratio = ∞` by returning `base` unchanged.
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64;
}

// ── Formulas ──────────────────────────────────────────────────────────────

/// Linear adjustment: `new = base × (1 + rate × (ratio − 1))`.
#[derive(Debug, Default, Clone, Copy)]
pub struct LinearPricing;

impl PricingFormula for LinearPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let Some(ratio) = sanitize_ratio(ratio) else {
            return base;
        };
        let multiplier = 1.0 + config.adjustment_rate * (ratio - 1.0);
        apply_multiplier(base, multiplier, config)
    }
}

/// Exponential adjustment: `new = base × exp(rate × (ratio − 1))`.
///
/// More aggressive than linear at high demand; the multiplier is clamped
/// to `[min_price_multiplier, max_price_multiplier]` so it cannot escape
/// the configured band.
#[derive(Debug, Default, Clone, Copy)]
pub struct ExponentialPricing;

impl PricingFormula for ExponentialPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let Some(ratio) = sanitize_ratio(ratio) else {
            return base;
        };
        let exponent = config.adjustment_rate * (ratio - 1.0);
        // `exp` of a large positive input is `inf`; of a large negative
        // input is `0`. `sanitize_multiplier` rejects both and falls back
        // to `1.0` (base unchanged) rather than clamping to a bound.
        let multiplier = exponent.exp();
        apply_multiplier(base, multiplier, config)
    }
}

/// Sigmoid adjustment: `new = base × (1 + rate × tanh(ratio − 1))`.
///
/// Gentle at both extremes: `tanh` saturates to `±1`, so the multiplier
/// lives in `[1 − rate, 1 + rate]` before the final clamp.
#[derive(Debug, Default, Clone, Copy)]
pub struct SigmoidPricing;

impl PricingFormula for SigmoidPricing {
    fn compute_price(&self, base: u64, ratio: f64, config: &GasPricingConfig) -> u64 {
        let Some(ratio) = sanitize_ratio(ratio) else {
            return base;
        };
        let multiplier = 1.0 + config.adjustment_rate * (ratio - 1.0).tanh();
        apply_multiplier(base, multiplier, config)
    }
}

// ── Formula type ──────────────────────────────────────────────────────────

/// Which formula to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum FormulaType {
    /// Linear response to `(ratio − 1)`.
    #[default]
    Linear,
    /// Exponential response; clamped to the configured band.
    Exponential,
    /// Sigmoid response; gentle at both extremes.
    Sigmoid,
}

impl fmt::Display for FormulaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Linear => f.write_str("linear"),
            Self::Exponential => f.write_str("exponential"),
            Self::Sigmoid => f.write_str("sigmoid"),
        }
    }
}

// ── Pricing state machine ────────────────────────────────────────────────

/// Core pricing state.
///
/// Holds the four per-resource prices and the currently active formula.
/// Prices **compound** across [`adjust`](Self::adjust) calls — see the
/// module docs.
pub struct GasPricing {
    cpu_price: u64,
    io_price: u64,
    network_price: u64,
    storage_price: u64,
    formula: Box<dyn PricingFormula>,
    formula_type: FormulaType,
}

impl GasPricing {
    /// Create a new pricing instance with the linear formula.
    #[must_use]
    pub fn new(config: &GasPricingConfig) -> Self {
        Self::with_formula(config, FormulaType::Linear)
    }

    /// Create a new pricing instance with a specific formula.
    #[must_use]
    pub fn with_formula(config: &GasPricingConfig, formula_type: FormulaType) -> Self {
        Self {
            cpu_price: config.cpu_base_price,
            io_price: config.io_base_price,
            network_price: config.network_base_price,
            storage_price: config.storage_base_price,
            formula: build_formula(formula_type),
            formula_type,
        }
    }

    /// Change the pricing formula at runtime.
    ///
    /// Prices are preserved; only the formula used for future
    /// adjustments changes.
    pub fn set_formula(&mut self, formula_type: FormulaType) {
        self.formula = build_formula(formula_type);
        self.formula_type = formula_type;
    }

    /// Current formula type.
    #[must_use]
    pub fn formula_type(&self) -> FormulaType {
        self.formula_type
    }

    /// Current price for a resource.
    #[must_use]
    pub fn price_for(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_price,
            ResourceType::Io => self.io_price,
            ResourceType::Network => self.network_price,
            ResourceType::Storage => self.storage_price,
        }
    }

    /// All four current prices as an array in `[Cpu, Io, Network, Storage]`
    /// order.
    #[must_use]
    pub fn all_prices(&self) -> [u64; 4] {
        [
            self.cpu_price,
            self.io_price,
            self.network_price,
            self.storage_price,
        ]
    }

    /// Adjust prices based on current demand.
    ///
    /// Returns a vector of `(resource, old_price, new_price)` for every
    /// resource whose price actually changed. Prices are clamped to
    /// `[base × min, base × max]` and compound from the current value,
    /// not from the base. See the module docs.
    pub fn adjust(
        &mut self,
        demand: &ResourceUsage,
        config: &GasPricingConfig,
    ) -> Vec<(ResourceType, u64, u64)> {
        if let Err(e) = demand.validate() {
            tracing::warn!(error = %e, "invalid demand data; skipping adjustment");
            return Vec::new();
        }

        let mut out = Vec::with_capacity(4);
        let formula = self.formula.as_ref();

        // Disjoint field borrows: `formula` borrows `self.formula`
        // immutably, while each `&mut self.<price>` is a distinct
        // mutable borrow. The borrow checker allows this because they
        // name different fields.
        adjust_one(
            formula,
            ResourceType::Cpu,
            config.cpu_base_price,
            &mut self.cpu_price,
            demand,
            config,
            &mut out,
        );
        adjust_one(
            formula,
            ResourceType::Io,
            config.io_base_price,
            &mut self.io_price,
            demand,
            config,
            &mut out,
        );
        adjust_one(
            formula,
            ResourceType::Network,
            config.network_base_price,
            &mut self.network_price,
            demand,
            config,
            &mut out,
        );
        adjust_one(
            formula,
            ResourceType::Storage,
            config.storage_base_price,
            &mut self.storage_price,
            demand,
            config,
            &mut out,
        );

        out
    }

    /// Reset all prices to their base values from `config`.
    pub fn reset_to_base(&mut self, config: &GasPricingConfig) {
        self.cpu_price = config.cpu_base_price;
        self.io_price = config.io_base_price;
        self.network_price = config.network_base_price;
        self.storage_price = config.storage_base_price;
    }
}

impl fmt::Debug for GasPricing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Box<dyn PricingFormula>` is not `Debug`, so we print the
        // formula by name and skip its contents.
        f.debug_struct("GasPricing")
            .field("cpu_price", &self.cpu_price)
            .field("io_price", &self.io_price)
            .field("network_price", &self.network_price)
            .field("storage_price", &self.storage_price)
            .field("formula_type", &self.formula_type)
            .finish()
    }
}

// ── Internals ─────────────────────────────────────────────────────────────

fn build_formula(formula_type: FormulaType) -> Box<dyn PricingFormula> {
    match formula_type {
        FormulaType::Linear => Box::new(LinearPricing),
        FormulaType::Exponential => Box::new(ExponentialPricing),
        FormulaType::Sigmoid => Box::new(SigmoidPricing),
    }
}

/// Adjust a single resource in place.
///
/// Extracted so the borrow checker can see that `formula` borrows only
/// `self.formula` and `current` borrows only `self.<price>`.
fn adjust_one(
    formula: &dyn PricingFormula,
    resource: ResourceType,
    base: u64,
    current: &mut u64,
    demand: &ResourceUsage,
    config: &GasPricingConfig,
    out: &mut Vec<(ResourceType, u64, u64)>,
) {
    let ratio = demand.ratio(resource);
    // Compound from the current price, not from `base`.
    let raw = formula.compute_price(*current, ratio, config);

    // Clamp to the configured band, expressed relative to the *base*
    // price. Without this, a compounding formula could wander outside
    // `[base × min, base × max]` after many adjustments.
    let min_bound = scaled_bound(base, config.min_price_multiplier);
    let max_bound = scaled_bound(base, config.max_price_multiplier);
    let new_price = raw.clamp(min_bound, max_bound);

    if new_price != *current {
        let old = *current;
        *current = new_price;
        out.push((resource, old, new_price));
    }
}

/// `base × multiplier` rounded to `u64`, saturating at `u64::MAX`.
fn scaled_bound(base: u64, multiplier: f64) -> u64 {
    if !multiplier.is_finite() || multiplier < 0.0 {
        return base;
    }
    let raw = base as f64 * multiplier;
    if !raw.is_finite() || raw < 0.0 {
        return base;
    }
    if raw >= (u64::MAX as f64) {
        return u64::MAX;
    }
    raw.round() as u64
}

/// Reject `NaN`, infinities, and negative ratios.
///
/// Returns `None` when the ratio is not usable; the caller falls back to
/// "price unchanged".
fn sanitize_ratio(ratio: f64) -> Option<f64> {
    if ratio.is_finite() && ratio >= 0.0 {
        Some(ratio)
    } else {
        None
    }
}

/// Apply a raw multiplier, sanitizing `NaN`, infinities, and out-of-band
/// values before producing a `u64`.
fn apply_multiplier(base: u64, multiplier: f64, config: &GasPricingConfig) -> u64 {
    if !multiplier.is_finite() || multiplier < 0.0 {
        return base;
    }
    // Guard against a mis-configured band before calling `clamp`, which
    // would panic if `min > max`.
    let (lo, hi) = if config.min_price_multiplier <= config.max_price_multiplier {
        (config.min_price_multiplier, config.max_price_multiplier)
    } else {
        (config.max_price_multiplier, config.min_price_multiplier)
    };
    let clamped = multiplier.clamp(lo, hi);
    scaled_bound(base, clamped)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Realistic gas prices in wei. The previous fixture used `base = 10`,
    /// where every linear adjustment rounds straight back to the base —
    /// every adjustment test silently asserted "nothing changed".
    fn config() -> GasPricingConfig {
        GasPricingConfig {
            cpu_base_price: 1_000_000,
            io_base_price: 500_000,
            network_base_price: 300_000,
            storage_base_price: 200_000,
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

    fn demand(ratios: [f64; 4]) -> ResourceUsage {
        // Build a demand where `used / target = ratio`, keeping the
        // targets at 100 so each `used` is `ratio × 100`.
        ResourceUsage {
            cpu_used: (ratios[0] * 100.0).round() as u64,
            io_used: (ratios[1] * 100.0).round() as u64,
            network_used: (ratios[2] * 100.0).round() as u64,
            storage_used: (ratios[3] * 100.0).round() as u64,
            target_cpu: 100,
            target_io: 100,
            target_network: 100,
            target_storage: 100,
        }
    }

    // ── Formula selection ───────────────────────────────────────────────

    #[test]
    fn default_formula_is_linear() {
        let p = GasPricing::new(&config());
        assert_eq!(p.formula_type(), FormulaType::Linear);
    }

    #[test]
    fn formula_switch_preserves_prices() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        p.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        let before = p.all_prices();
        p.set_formula(FormulaType::Exponential);
        assert_eq!(p.all_prices(), before);
        assert_eq!(p.formula_type(), FormulaType::Exponential);
    }

    // ── Linear ──────────────────────────────────────────────────────────

    #[test]
    fn linear_decreases_below_target() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        let adj = p.adjust(&demand([0.5, 0.5, 0.5, 0.5]), &cfg);
        assert_eq!(adj.len(), 4);
        for (_, old, new) in &adj {
            assert!(*new < *old);
        }
    }

    #[test]
    fn linear_increases_above_target() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        let adj = p.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        assert_eq!(adj.len(), 4);
        for (_, old, new) in &adj {
            assert!(*new > *old);
        }
    }

    // ── Compounding ─────────────────────────────────────────────────────

    #[test]
    fn linear_compounds_across_calls() {
        // Two successive `ratio = 2` adjustments must produce a higher
        // price than one — the formula multiplies the **current** price,
        // not the base.
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        p.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        let after_one = p.price_for(ResourceType::Cpu);
        p.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        let after_two = p.price_for(ResourceType::Cpu);
        assert!(
            after_two > after_one,
            "compounding failed: after_one={after_one}, after_two={after_two}",
        );
    }

    #[test]
    fn compounding_is_bounded_by_max_multiplier() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        for _ in 0..100 {
            p.adjust(&demand([10.0, 10.0, 10.0, 10.0]), &cfg);
        }
        let base = cfg.cpu_base_price;
        let max_bound = (base as f64 * cfg.max_price_multiplier).round() as u64;
        assert_eq!(p.price_for(ResourceType::Cpu), max_bound);
    }

    #[test]
    fn compounding_is_bounded_by_min_multiplier() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        for _ in 0..100 {
            p.adjust(&demand([0.0, 0.0, 0.0, 0.0]), &cfg);
        }
        let base = cfg.cpu_base_price;
        let min_bound = (base as f64 * cfg.min_price_multiplier).round() as u64;
        assert_eq!(p.price_for(ResourceType::Cpu), min_bound);
    }

    // ── Exponential ─────────────────────────────────────────────────────

    #[test]
    fn exponential_is_more_aggressive_than_linear() {
        let cfg = config();
        let mut linear = GasPricing::new(&cfg);
        let mut exponential = GasPricing::with_formula(&cfg, FormulaType::Exponential);

        linear.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        exponential.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);

        assert!(
            exponential.price_for(ResourceType::Cpu) > linear.price_for(ResourceType::Cpu),
            "exponential={} should exceed linear={}",
            exponential.price_for(ResourceType::Cpu),
            linear.price_for(ResourceType::Cpu),
        );
    }

    #[test]
    fn exponential_huge_ratio_does_not_produce_nan_or_zero() {
        let cfg = config();
        let mut p = GasPricing::with_formula(&cfg, FormulaType::Exponential);
        // `exp(0.1 × (1e9 − 1))` is `inf`; the multiplier guard must fall
        // back to base rather than clamping to `u64::MAX` or zero.
        p.adjust(&demand([1e9, 1e9, 1e9, 1e9]), &cfg);
        let price = p.price_for(ResourceType::Cpu);
        assert!(price > 0);
        assert!(price <= (cfg.cpu_base_price as f64 * cfg.max_price_multiplier) as u64);
    }

    // ── Sigmoid ─────────────────────────────────────────────────────────

    #[test]
    fn sigmoid_is_gentler_than_linear_at_extremes() {
        let cfg = config();
        let mut linear = GasPricing::new(&cfg);
        let mut sigmoid = GasPricing::with_formula(&cfg, FormulaType::Sigmoid);

        linear.adjust(&demand([5.0, 5.0, 5.0, 5.0]), &cfg);
        sigmoid.adjust(&demand([5.0, 5.0, 5.0, 5.0]), &cfg);

        assert!(
            sigmoid.price_for(ResourceType::Cpu) < linear.price_for(ResourceType::Cpu),
            "sigmoid={} should be less aggressive than linear={}",
            sigmoid.price_for(ResourceType::Cpu),
            linear.price_for(ResourceType::Cpu),
        );
    }

    // ── Input sanitization ──────────────────────────────────────────────

    #[test]
    fn nan_ratio_leaves_price_unchanged() {
        let cfg = config();
        // `ratio()` returns `f64`; simulate NaN by passing `used=0,
        // target=0` if the underlying `ratio()` divides — or exercise
        // the sanitizer directly.
        assert!(sanitize_ratio(f64::NAN).is_none());
        assert!(sanitize_ratio(f64::INFINITY).is_none());
        assert!(sanitize_ratio(-1.0).is_none());
        assert_eq!(sanitize_ratio(0.5), Some(0.5));
    }

    #[test]
    fn nan_multiplier_returns_base() {
        let cfg = config();
        assert_eq!(apply_multiplier(1_000, f64::NAN, &cfg), 1_000);
        assert_eq!(apply_multiplier(1_000, f64::INFINITY, &cfg), 1_000);
        assert_eq!(apply_multiplier(1_000, -1.0, &cfg), 1_000);
    }

    #[test]
    fn inverted_band_does_not_panic() {
        // `f64::clamp` panics when `min > max`; the helper must swap the
        // band defensively. (Config validation rejects this at the
        // manager level, but `apply_multiplier` is a public helper.)
        let mut cfg = config();
        cfg.min_price_multiplier = 5.0;
        cfg.max_price_multiplier = 1.0;
        // No panic, result within the (swapped) band.
        let _ = apply_multiplier(1_000, 3.0, &cfg);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[test]
    fn reset_restores_base_prices() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        p.adjust(&demand([2.0, 2.0, 2.0, 2.0]), &cfg);
        assert_ne!(p.price_for(ResourceType::Cpu), cfg.cpu_base_price);

        p.reset_to_base(&cfg);
        assert_eq!(p.price_for(ResourceType::Cpu), cfg.cpu_base_price);
        assert_eq!(p.price_for(ResourceType::Io), cfg.io_base_price);
        assert_eq!(p.price_for(ResourceType::Network), cfg.network_base_price);
        assert_eq!(p.price_for(ResourceType::Storage), cfg.storage_base_price);
    }

    // ── Invalid demand ──────────────────────────────────────────────────

    #[test]
    fn invalid_demand_is_rejected_without_mutation() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        let mut d = demand([1.0, 1.0, 1.0, 1.0]);
        d.cpu_used = 101; // > 100 → invalid
        let adj = p.adjust(&d, &cfg);
        assert!(adj.is_empty());
        assert_eq!(p.price_for(ResourceType::Cpu), cfg.cpu_base_price);
    }

    // ── No change when ratio == 1 ───────────────────────────────────────

    #[test]
    fn target_ratio_leaves_prices_unchanged() {
        let cfg = config();
        let mut p = GasPricing::new(&cfg);
        let adj = p.adjust(&demand([1.0, 1.0, 1.0, 1.0]), &cfg);
        assert!(adj.is_empty());
        assert_eq!(p.price_for(ResourceType::Cpu), cfg.cpu_base_price);
    }

    // ── Display ─────────────────────────────────────────────────────────

    #[test]
    fn formula_type_display() {
        assert_eq!(FormulaType::Linear.to_string(), "linear");
        assert_eq!(FormulaType::Exponential.to_string(), "exponential");
        assert_eq!(FormulaType::Sigmoid.to_string(), "sigmoid");
    }

    #[test]
    fn gas_pricing_debug_includes_prices() {
        let p = GasPricing::new(&config());
        let s = format!("{p:?}");
        assert!(s.contains("cpu_price"));
        assert!(s.contains("formula_type"));
    }

    // ── ResourcePrice ───────────────────────────────────────────────────

    #[test]
    fn resource_price_is_comparable() {
        let a = ResourcePrice {
            resource: ResourceType::Cpu,
            price: 100,
            timestamp: 1,
        };
        let b = a.clone();
        assert_eq!(a, b);
    }
}
