//! Resource metering for IONA gas pricing.
//!
//! Tracks usage of CPU, I/O, network, and storage resources. Provides
//! validation, per-resource inspection, and snapshot capabilities for
//! the adaptive pricing subsystem.
//!
//! # Unit semantics
//!
//! `ResourceUsage` fields have **inconsistent historical units**:
//!
//! - `*_used` values are **percentages** of some fixed per-block capacity.
//!   The validator caps them at [`MAX_USED_PERCENT`] (100). This is a
//!   deliberate safety bound: a caller cannot accidentally encode
//!   "used 500 %" and make the pricing formula overflow.
//! - `*_target` values are also percentages, but with a much looser bound
//!   ([`MAX_TARGET_PERCENT`] = 10 000 000) to remain backward-compatible
//!   with callers that used raw units before the percentage convention
//!   was established.
//!
//! **The two bounds are not in the same range.** A `target` above
//! [`MAX_USED_PERCENT`] is unreachable: `used` can never be that high, so
//! `ratio = used / target < 1` forever. Callers that want a resource to
//! be able to react to demand **must** keep `target ≤ MAX_USED_PERCENT`.
//! The helper [`ResourceUsage::has_reachable_target`] flags this case.
//!
//! When `target == 0`, the resource is treated as unconfigured. Its ratio
//! is [`NEUTRAL_RATIO`] (1.0), which downstream pricing interprets as
//! "no pressure to adjust". This is intentional; use
//! [`ResourceUsage::has_limit`] to check whether a resource is configured.
//!
//! # Example
//!
//! ```rust,ignore
//! use iona::gas::resource_meter::{ResourceMeter, ResourceType, ResourceUsage};
//!
//! let mut meter = ResourceMeter::new();
//! meter.record(ResourceType::Cpu, 80);
//!
//! let targets = ResourceUsage::targets_only([50, 50, 50, 50]);
//! let snapshot = meter.snapshot_with_targets(&targets);
//! assert_eq!(snapshot.ratio(ResourceType::Cpu), 1.6);
//! ```

use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

// ── Limits ────────────────────────────────────────────────────────────────

/// Maximum accepted value for a `*_used` field.
pub const MAX_USED_PERCENT: u64 = 100;

/// Maximum accepted value for a `*_target` field.
///
/// This is intentionally larger than [`MAX_USED_PERCENT`] for backward
/// compatibility; a target above `MAX_USED_PERCENT` is unreachable and
/// should be avoided (see module docs).
pub const MAX_TARGET_PERCENT: u64 = 10_000_000;

/// Ratio reported by [`ResourceUsage::ratio`] when a resource has no
/// configured target (`target == 0`).
pub const NEUTRAL_RATIO: f64 = 1.0;

// ── Resource type ─────────────────────────────────────────────────────────

/// Types of resources that can be metered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Cpu,
    Io,
    Network,
    Storage,
}

impl ResourceType {
    /// All four resource types, in canonical order.
    pub const ALL: [ResourceType; 4] = [
        ResourceType::Cpu,
        ResourceType::Io,
        ResourceType::Network,
        ResourceType::Storage,
    ];

    /// String representation for logging and metrics.
    #[must_use]
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
        f.write_str(self.as_str())
    }
}

// ── Errors ────────────────────────────────────────────────────────────────

/// Why [`ResourceUsage::validate`] rejected a value.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum ResourceUsageError {
    #[error("`{field}` is {value}, exceeds MAX_USED_PERCENT ({MAX_USED_PERCENT})")]
    UsedTooHigh {
        field: &'static str,
        value: u64,
    },
    #[error("`{field}` is {value}, exceeds MAX_TARGET_PERCENT ({MAX_TARGET_PERCENT})")]
    TargetTooHigh {
        field: &'static str,
        value: u64,
    },
}

// ── Usage snapshot ────────────────────────────────────────────────────────

/// Resource usage data for a block or transaction.
///
/// Fields come in pairs (`*_used`, `*_target`). See the module docs for
/// the unit semantics and the bounds on each family.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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
    /// All-zero usage. Equivalent to `ResourceUsage::default()`.
    #[must_use]
    pub const fn zero() -> Self {
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

    /// Build a usage struct with only targets set (used = 0).
    ///
    /// `targets` is ordered `[cpu, io, network, storage]`.
    #[must_use]
    pub const fn targets_only(targets: [u64; 4]) -> Self {
        Self {
            cpu_used: 0,
            io_used: 0,
            network_used: 0,
            storage_used: 0,
            target_cpu: targets[0],
            target_io: targets[1],
            target_network: targets[2],
            target_storage: targets[3],
        }
    }

    /// Validate the snapshot against [`MAX_USED_PERCENT`] and
    /// [`MAX_TARGET_PERCENT`].
    pub fn validate(&self) -> Result<(), ResourceUsageError> {
        for (value, field) in [
            (self.cpu_used, "cpu_used"),
            (self.io_used, "io_used"),
            (self.network_used, "network_used"),
            (self.storage_used, "storage_used"),
        ] {
            if value > MAX_USED_PERCENT {
                return Err(ResourceUsageError::UsedTooHigh { field, value });
            }
        }
        for (value, field) in [
            (self.target_cpu, "target_cpu"),
            (self.target_io, "target_io"),
            (self.target_network, "target_network"),
            (self.target_storage, "target_storage"),
        ] {
            if value > MAX_TARGET_PERCENT {
                return Err(ResourceUsageError::TargetTooHigh { field, value });
            }
        }
        Ok(())
    }

    /// Whether `resource` has a configured target (`target > 0`).
    #[must_use]
    pub fn has_limit(&self, resource: ResourceType) -> bool {
        self.target(resource) > 0
    }

    /// Whether `resource` has a target that `used` can actually reach
    /// given the `MAX_USED_PERCENT` cap.
    ///
    /// A target above [`MAX_USED_PERCENT`] makes the resource
    /// permanently "under target"; this helper flags it so a caller can
    /// log or reject such configurations.
    #[must_use]
    pub fn has_reachable_target(&self, resource: ResourceType) -> bool {
        let target = self.target(resource);
        target > 0 && target <= MAX_USED_PERCENT
    }

    /// Ratio of `used / target` for `resource`.
    ///
    /// Returns [`NEUTRAL_RATIO`] (1.0) when the resource has no target.
    /// This is the value the pricing formulas see: 1.0 means "no
    /// adjustment", which is exactly what "no configured target" should
    /// produce.
    #[must_use]
    pub fn ratio(&self, resource: ResourceType) -> f64 {
        let target = self.target(resource);
        if target == 0 {
            NEUTRAL_RATIO
        } else {
            self.used(resource) as f64 / target as f64
        }
    }

    /// `*_used` value for `resource`.
    #[must_use]
    pub fn used(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu_used,
            ResourceType::Io => self.io_used,
            ResourceType::Network => self.network_used,
            ResourceType::Storage => self.storage_used,
        }
    }

    /// `*_target` value for `resource`.
    #[must_use]
    pub fn target(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.target_cpu,
            ResourceType::Io => self.target_io,
            ResourceType::Network => self.target_network,
            ResourceType::Storage => self.target_storage,
        }
    }

    /// Set the `*_used` value for `resource`.
    ///
    /// **Does not** validate; a caller that wants a well-formed usage
    /// should call [`validate`](Self::validate) afterwards. This is
    /// intentional so a caller can construct a partially-filled struct
    /// during a block and validate once at the end.
    pub fn set_used(&mut self, resource: ResourceType, value: u64) {
        match resource {
            ResourceType::Cpu => self.cpu_used = value,
            ResourceType::Io => self.io_used = value,
            ResourceType::Network => self.network_used = value,
            ResourceType::Storage => self.storage_used = value,
        }
    }

    /// Set the `*_target` value for `resource`.
    ///
    /// **Does not** validate; see [`set_used`](Self::set_used).
    pub fn set_target(&mut self, resource: ResourceType, value: u64) {
        match resource {
            ResourceType::Cpu => self.target_cpu = value,
            ResourceType::Io => self.target_io = value,
            ResourceType::Network => self.target_network = value,
            ResourceType::Storage => self.target_storage = value,
        }
    }
}

// ── Meter ─────────────────────────────────────────────────────────────────

/// Accumulates resource usage during execution.
///
/// All record methods use saturating addition; a meter that runs long
/// enough saturates at `u64::MAX` rather than wrapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceMeter {
    cpu: u64,
    io: u64,
    network: u64,
    storage: u64,
    /// Unix seconds of the last reset. `None` until the first reset.
    last_reset: Option<u64>,
}

impl ResourceMeter {
    /// Create a fresh meter with all counters at zero.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    // ── Recording ───────────────────────────────────────────────────────

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

    /// Record usage for `resource`.
    pub fn record(&mut self, resource: ResourceType, amount: u64) {
        match resource {
            ResourceType::Cpu => self.record_cpu(amount),
            ResourceType::Io => self.record_io(amount),
            ResourceType::Network => self.record_network(amount),
            ResourceType::Storage => self.record_storage(amount),
        }
    }

    // ── Reset ───────────────────────────────────────────────────────────

    /// Zero every counter and update `last_reset`.
    ///
    /// If the system clock cannot be read, `last_reset` is left
    /// unchanged rather than set to a misleading `0`. This prevents
    /// [`seconds_since_reset`](Self::seconds_since_reset) from returning
    /// an absurd value after a clock error.
    pub fn reset(&mut self) {
        let ts = current_timestamp();
        let previous = self.last_reset;
        *self = Self::default();
        self.last_reset = if ts > 0 { Some(ts) } else { previous };
    }

    /// Zero a single resource counter.
    ///
    /// **Does not** update `last_reset` — the reset is partial, so the
    /// "time since last full reset" is still meaningful. If you want to
    /// restart the clock, call [`reset`](Self::reset) instead.
    pub fn reset_resource(&mut self, resource: ResourceType) {
        match resource {
            ResourceType::Cpu => self.cpu = 0,
            ResourceType::Io => self.io = 0,
            ResourceType::Network => self.network = 0,
            ResourceType::Storage => self.storage = 0,
        }
    }

    // ── Queries ─────────────────────────────────────────────────────────

    /// Current counter for `resource`.
    #[must_use]
    pub fn get(&self, resource: ResourceType) -> u64 {
        match resource {
            ResourceType::Cpu => self.cpu,
            ResourceType::Io => self.io,
            ResourceType::Network => self.network,
            ResourceType::Storage => self.storage,
        }
    }

    /// Snapshot of current usage with all targets left at zero.
    ///
    /// Every resource will report [`NEUTRAL_RATIO`] for its `ratio` until
    /// the caller supplies targets via
    /// [`snapshot_with_targets`](Self::snapshot_with_targets).
    #[must_use]
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

    /// Snapshot of current usage combined with `targets`' target fields.
    ///
    /// Only the four `target_*` fields of `targets` are read; its
    /// `*_used` fields are ignored.
    #[must_use]
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

    /// Seconds elapsed since the last call to [`reset`](Self::reset).
    ///
    /// Returns `None` when the meter has never been reset.
    #[must_use]
    pub fn seconds_since_reset(&self) -> Option<u64> {
        self.last_reset
            .map(|ts| current_timestamp().saturating_sub(ts))
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────

/// Current Unix timestamp in seconds. Returns `0` on error.
fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Validation ──────────────────────────────────────────────────────

    #[test]
    fn validate_accepts_in_range_usage() {
        let usage = ResourceUsage {
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
    }

    #[test]
    fn validate_rejects_used_above_max() {
        let mut usage = ResourceUsage::default();
        usage.cpu_used = MAX_USED_PERCENT + 1;
        assert!(matches!(
            usage.validate(),
            Err(ResourceUsageError::UsedTooHigh { field: "cpu_used", .. })
        ));
    }

    #[test]
    fn validate_rejects_target_above_max() {
        let mut usage = ResourceUsage::default();
        usage.target_cpu = MAX_TARGET_PERCENT + 1;
        assert!(matches!(
            usage.validate(),
            Err(ResourceUsageError::TargetTooHigh { field: "target_cpu", .. })
        ));
    }

    #[test]
    fn validate_accepts_boundary_values() {
        let mut usage = ResourceUsage::default();
        usage.cpu_used = MAX_USED_PERCENT;
        usage.target_cpu = MAX_TARGET_PERCENT;
        assert!(usage.validate().is_ok());
    }

    // ── Ratio ───────────────────────────────────────────────────────────

    #[test]
    fn ratio_computes_used_over_target() {
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
        assert!((usage.ratio(ResourceType::Cpu) - 0.8).abs() < 1e-9);
        assert!((usage.ratio(ResourceType::Io) - 0.8).abs() < 1e-9);
        assert!((usage.ratio(ResourceType::Network) - 0.2).abs() < 1e-9);
        assert!((usage.ratio(ResourceType::Storage) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn ratio_is_neutral_for_zero_target() {
        let usage = ResourceUsage {
            cpu_used: 100,
            target_cpu: 0,
            ..ResourceUsage::zero()
        };
        assert_eq!(usage.ratio(ResourceType::Cpu), NEUTRAL_RATIO);
    }

    #[test]
    fn ratio_can_exceed_one() {
        let usage = ResourceUsage {
            cpu_used: 90,
            target_cpu: 50,
            ..ResourceUsage::zero()
        };
        assert!((usage.ratio(ResourceType::Cpu) - 1.8).abs() < 1e-9);
    }

    // ── has_limit / has_reachable_target ────────────────────────────────

    #[test]
    fn has_limit_reports_zero_target_as_no_limit() {
        let usage = ResourceUsage {
            target_cpu: 0,
            target_io: 1,
            ..ResourceUsage::zero()
        };
        assert!(!usage.has_limit(ResourceType::Cpu));
        assert!(usage.has_limit(ResourceType::Io));
    }

    #[test]
    fn has_reachable_target_flags_unreachable_targets() {
        let usage = ResourceUsage {
            target_cpu: 50,
            target_io: 500,
            ..ResourceUsage::zero()
        };
        assert!(usage.has_reachable_target(ResourceType::Cpu));
        assert!(!usage.has_reachable_target(ResourceType::Io)); // 500 > 100
    }

    // ── Meter recording ─────────────────────────────────────────────────

    #[test]
    fn record_and_get_roundtrip() {
        let mut m = ResourceMeter::new();
        m.record_cpu(10);
        m.record_io(20);
        m.record_network(30);
        m.record_storage(40);

        assert_eq!(m.get(ResourceType::Cpu), 10);
        assert_eq!(m.get(ResourceType::Io), 20);
        assert_eq!(m.get(ResourceType::Network), 30);
        assert_eq!(m.get(ResourceType::Storage), 40);

        m.record(ResourceType::Cpu, 5);
        assert_eq!(m.get(ResourceType::Cpu), 15);
    }

    #[test]
    fn record_saturates_on_overflow() {
        let mut m = ResourceMeter::new();
        m.record_cpu(u64::MAX);
        m.record_cpu(1);
        assert_eq!(m.get(ResourceType::Cpu), u64::MAX);
    }

    // ── Reset ───────────────────────────────────────────────────────────

    #[test]
    fn reset_zeros_and_sets_timestamp() {
        let mut m = ResourceMeter::new();
        m.record_cpu(100);
        m.reset();
        assert_eq!(m.get(ResourceType::Cpu), 0);
        // `seconds_since_reset` returns 0 immediately after a reset
        // (unless the clock is unreadable, in which case it may be
        // `None` — both are valid).
        let elapsed = m.seconds_since_reset();
        assert!(elapsed.is_none() || elapsed.unwrap() < 2);
    }

    #[test]
    fn reset_resource_only_zeros_target() {
        let mut m = ResourceMeter::new();
        m.record_cpu(100);
        m.record_io(200);
        m.reset_resource(ResourceType::Cpu);
        assert_eq!(m.get(ResourceType::Cpu), 0);
        assert_eq!(m.get(ResourceType::Io), 200);
    }

    #[test]
    fn reset_resource_does_not_touch_last_reset() {
        let mut m = ResourceMeter::new();
        m.reset();
        let before = m.last_reset;
        m.record_cpu(50);
        m.reset_resource(ResourceType::Cpu);
        assert_eq!(m.last_reset, before);
    }

    #[test]
    fn seconds_since_reset_is_none_before_first_reset() {
        let m = ResourceMeter::new();
        assert!(m.seconds_since_reset().is_none());
    }

    // ── Snapshot ────────────────────────────────────────────────────────

    #[test]
    fn snapshot_leaves_targets_zero() {
        let mut m = ResourceMeter::new();
        m.record_cpu(50);
        let s = m.snapshot();
        assert_eq!(s.cpu_used, 50);
        assert_eq!(s.target_cpu, 0);
        // Ratio is neutral for every resource.
        for r in ResourceType::ALL {
            assert_eq!(s.ratio(r), NEUTRAL_RATIO);
        }
    }

    #[test]
    fn snapshot_with_targets_uses_target_fields() {
        let mut m = ResourceMeter::new();
        m.record_cpu(50);
        m.record_io(25);

        let targets = ResourceUsage::targets_only([100, 50, 100, 100]);
        let s = m.snapshot_with_targets(&targets);

        assert_eq!(s.cpu_used, 50);
        assert_eq!(s.io_used, 25);
        assert_eq!(s.target_cpu, 100);
        assert_eq!(s.target_io, 50);
        assert!((s.ratio(ResourceType::Cpu) - 0.5).abs() < 1e-9);
        assert!((s.ratio(ResourceType::Io) - 0.5).abs() < 1e-9);
    }

    #[test]
    fn snapshot_with_targets_ignores_source_used_fields() {
        let mut m = ResourceMeter::new();
        m.record_cpu(50);

        // `targets` has bogus `*_used` values that must be ignored.
        let targets = ResourceUsage {
            cpu_used: 999,
            target_cpu: 100,
            ..ResourceUsage::zero()
        };
        let s = m.snapshot_with_targets(&targets);
        assert_eq!(s.cpu_used, 50, "meter value must win");
    }

    // ── Set methods ─────────────────────────────────────────────────────

    #[test]
    fn set_used_and_set_target_roundtrip() {
        let mut u = ResourceUsage::zero();
        u.set_used(ResourceType::Cpu, 42);
        u.set_target(ResourceType::Cpu, 100);
        assert_eq!(u.used(ResourceType::Cpu), 42);
        assert_eq!(u.target(ResourceType::Cpu), 100);
    }

    #[test]
    fn set_methods_do_not_validate() {
        // Deliberately setting out-of-range values is allowed; the
        // caller must call `validate()` if they care.
        let mut u = ResourceUsage::zero();
        u.set_used(ResourceType::Cpu, MAX_USED_PERCENT + 1);
        assert!(u.validate().is_err());
    }

    // ── ResourceType::ALL ──────────────────────────────────────────────

    #[test]
    fn all_resource_types_are_enumerated() {
        assert_eq!(ResourceType::ALL.len(), 4);
        for r in ResourceType::ALL {
            assert!(!r.as_str().is_empty());
        }
    }

    #[test]
    fn resource_type_display_matches_as_str() {
        for r in ResourceType::ALL {
            assert_eq!(r.to_string(), r.as_str());
        }
    }

    // ── Default ─────────────────────────────────────────────────────────

    #[test]
    fn default_usage_is_zero() {
        assert_eq!(ResourceUsage::default(), ResourceUsage::zero());
    }

    #[test]
    fn default_meter_is_empty() {
        let m = ResourceMeter::default();
        for r in ResourceType::ALL {
            assert_eq!(m.get(r), 0);
        }
        assert!(m.seconds_since_reset().is_none());
    }
}
